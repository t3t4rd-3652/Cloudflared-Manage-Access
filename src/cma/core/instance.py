"""Instance unique et canal de commande local.

Un seul processus graphique possède le verrou du dossier de données. Les lancements suivants
(nouvelle fenêtre, commande `cma connect`) lui transmettent leur demande par un canal local
authentifié : tube nommé sous Windows, socket Unix ailleurs, clé partagée dans le dossier de données.
"""

from __future__ import annotations

import contextlib
import getpass
import hashlib
import logging
import os
import secrets as pysecrets
import sys
import tempfile
import threading
from collections.abc import Callable
from multiprocessing.connection import Client, Listener
from pathlib import Path
from typing import Any, BinaryIO, cast

from cma.paths import AppPaths

log = logging.getLogger(__name__)


class InstanceLock:
    """Verrou exclusif non bloquant sur un fichier ; libéré automatiquement si le processus meurt."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._handle: BinaryIO | None = None

    def acquire(self) -> bool:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        handle = self._path.open("a+b")
        try:
            if sys.platform == "win32":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            return False
        self._handle = handle
        return True

    def release(self) -> None:
        if self._handle is None:
            return
        with contextlib.suppress(OSError):
            if sys.platform == "win32":
                import msvcrt

                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        self._handle.close()
        self._handle = None


def ipc_address(paths: AppPaths) -> str:
    digest = hashlib.sha256(f"{getpass.getuser()}|{paths.data_dir}".encode()).hexdigest()
    if sys.platform == "win32":
        return rf"\\.\pipe\cloudflared-manage-access-{digest[:16]}"
    address = paths.data_dir / "cma.sock"
    # Longueur maximale du chemin d'un socket Unix, octet nul compris : 104 sous macOS, 108 sous Linux.
    limit = 104 if sys.platform == "darwin" else 108
    if len(os.fsencode(address)) < limit:
        return str(address)
    # Chemin trop long pour un socket Unix (dossier de données profond ; sous macOS, ~/Library/Application Support
    # suffit parfois) : socket dans le dossier propre à l'utilisateur (XDG_RUNTIME_DIR, sinon le dossier temporaire,
    # privé sous macOS), nommé d'après le dossier de données. La clé partagée reste dans le dossier de données.
    return str(user_runtime_dir() / f"cma-{digest[:16]}.sock")


def user_runtime_dir() -> Path:
    """Dossier propre à l'utilisateur pour un socket : XDG_RUNTIME_DIR (Linux, 0700), sinon le dossier temporaire."""
    runtime = os.environ.get("XDG_RUNTIME_DIR", "")
    return Path(runtime) if runtime and Path(runtime).is_dir() else Path(tempfile.gettempdir())


def ipc_authkey(paths: AppPaths) -> bytes:
    """Clé partagée du canal local : créée au premier lancement, lisible par l'utilisateur seul."""
    key_file = paths.ipc_key_file
    if not key_file.is_file():
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_text(pysecrets.token_hex(32), encoding="ascii")
        if sys.platform != "win32":
            key_file.chmod(0o600)
    return key_file.read_text(encoding="ascii").strip().encode("ascii")


class IpcServer:
    """Reçoit des commandes {"cmd": ...} et renvoie la réponse de `handler`, dans un thread dédié."""

    def __init__(self, paths: AppPaths, handler: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self._paths = paths
        self._handler = handler
        self._listener: Listener | None = None
        self._thread: threading.Thread | None = None
        self._stopping = False

    def start(self) -> None:
        address = ipc_address(self._paths)
        if sys.platform != "win32":
            with contextlib.suppress(FileNotFoundError):
                Path(address).unlink()
        self._listener = Listener(address, authkey=ipc_authkey(self._paths))
        self._thread = threading.Thread(target=self._serve, name="cma-ipc", daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        """Boucle d'accueil. Elle ne se termine qu'à réception de « __stop__ ».

        S'arrêter sur un simple drapeau laissait une course : le thread pouvait sortir juste avant la
        connexion d'arrêt, que le système acceptait alors sans que personne ne réponde à l'authentification.
        """
        assert self._listener is not None
        while True:
            try:
                conn = self._listener.accept()
            except Exception as exc:
                if self._stopping:
                    return
                log.warning("Canal local : connexion refusée (%s)", exc)
                continue
            with conn:
                if self._handle(conn):
                    return

    def _handle(self, conn: Any) -> bool:
        """Traite une commande. Renvoie True pour la commande d'arrêt."""
        try:
            message: object = conn.recv()
            if not isinstance(message, dict):
                conn.send({"ok": False, "error": "message invalide"})
                return False
            request = cast(dict[str, Any], message)
            if request.get("cmd") == "__stop__":
                conn.send({"ok": True})
                return True
            conn.send(self._handler(request))
        except (EOFError, OSError):
            return False
        except Exception as exc:
            log.exception("Canal local : erreur de traitement")
            with contextlib.suppress(Exception):
                conn.send({"ok": False, "error": str(exc)})
        return False

    def stop(self) -> None:
        self._stopping = True
        if self._listener is not None:
            # Débloque accept() par la commande d'arrêt, puis ferme l'écoute.
            if self._thread is not None and self._thread.is_alive():
                with contextlib.suppress(Exception):
                    send_command(self._paths, {"cmd": "__stop__"}, timeout=2)
            with contextlib.suppress(Exception):
                self._listener.close()
        if self._thread is not None:
            self._thread.join(3)


def _connect(paths: AppPaths, timeout: float) -> Any:
    """Client authentifié, avec un délai : l'authentification de multiprocessing n'en a aucun.

    La connexion est ouverte dans un thread ; au-delà de `timeout`, on abandonne (TimeoutError). Sans cela,
    une instance figée, ou un serveur qui s'arrête, bloquait la ligne de commande indéfiniment.
    """
    outcome: list[Any] = []

    def run() -> None:
        try:
            outcome.append(Client(ipc_address(paths), authkey=ipc_authkey(paths)))
        except BaseException as exc:
            outcome.append(exc)

    worker = threading.Thread(target=run, name="cma-ipc-client", daemon=True)
    worker.start()
    worker.join(timeout)
    if not outcome:
        raise TimeoutError("pas de réponse de l'instance en cours")
    if isinstance(outcome[0], BaseException):
        raise outcome[0]
    return outcome[0]


def send_command(paths: AppPaths, message: dict[str, Any], timeout: float = 30) -> dict[str, Any] | None:
    """Envoie une commande à l'instance en cours. None si aucune instance n'écoute."""
    try:
        conn = _connect(paths, min(timeout, 10))
    except TimeoutError:
        return {"ok": False, "error": "pas de réponse de l'instance en cours"}
    except (FileNotFoundError, ConnectionRefusedError, OSError):
        return None
    with conn:
        conn.send(message)
        if not conn.poll(timeout):
            return {"ok": False, "error": "pas de réponse de l'instance en cours"}
        reply: object = conn.recv()
        if not isinstance(reply, dict):
            return {"ok": False, "error": "réponse invalide"}
        return cast(dict[str, Any], reply)
