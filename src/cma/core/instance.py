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
import secrets as pysecrets
import sys
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
    if sys.platform == "win32":
        digest = hashlib.sha256(f"{getpass.getuser()}|{paths.data_dir}".encode()).hexdigest()
        return rf"\\.\pipe\cloudflared-manage-access-{digest[:16]}"
    return str(paths.data_dir / "cma.sock")


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
        assert self._listener is not None
        while not self._stopping:
            try:
                conn = self._listener.accept()
            except Exception as exc:
                if not self._stopping:
                    log.warning("Canal local : connexion refusée (%s)", exc)
                continue
            with conn:
                self._handle(conn)

    def _handle(self, conn: Any) -> None:
        try:
            message: object = conn.recv()
            if not isinstance(message, dict):
                conn.send({"ok": False, "error": "message invalide"})
                return
            request = cast(dict[str, Any], message)
            if request.get("cmd") == "__stop__":
                conn.send({"ok": True})
                return
            conn.send(self._handler(request))
        except (EOFError, OSError):
            return
        except Exception as exc:
            log.exception("Canal local : erreur de traitement")
            with contextlib.suppress(Exception):
                conn.send({"ok": False, "error": str(exc)})

    def stop(self) -> None:
        self._stopping = True
        if self._listener is not None:
            # Débloque accept() en se connectant soi-même, puis ferme l'écoute.
            with contextlib.suppress(Exception):
                send_command(self._paths, {"cmd": "__stop__"}, timeout=2)
            with contextlib.suppress(Exception):
                self._listener.close()
        if self._thread is not None:
            self._thread.join(3)


def send_command(paths: AppPaths, message: dict[str, Any], timeout: float = 30) -> dict[str, Any] | None:
    """Envoie une commande à l'instance en cours. None si aucune instance n'écoute."""
    try:
        conn = Client(ipc_address(paths), authkey=ipc_authkey(paths))
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
