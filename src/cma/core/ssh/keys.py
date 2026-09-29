"""Clés SSH : liste, génération ed25519, suppression, déploiement idempotent sur un serveur.

La génération est faite par asyncssh : ssh-keygen n'est plus nécessaire.
Le déploiement passe par SFTP : il lit authorized_keys, n'ajoute la clé que si elle manque,
fixe les droits (700 pour ~/.ssh, 600 pour le fichier) et relit le fichier pour vérifier.
"""

from __future__ import annotations

import logging
import os
import re
import socket
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import asyncssh
else:
    from cma.core.ssh._lazy import asyncssh

from cma.i18n import tr

log = logging.getLogger(__name__)

_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,60}$")
_PRIVATE_KEY_MARKERS = (b"PRIVATE KEY-----", b"PuTTY-User-Key-File")


class KeySource(StrEnum):
    APP = "app"
    USER = "user"


@dataclass(frozen=True)
class KeyInfo:
    path: Path
    algorithm: str
    fingerprint: str
    comment: str
    encrypted: bool
    source: KeySource

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def public_path(self) -> Path:
        return self.path.with_name(self.path.name + ".pub")


class DeployResult(StrEnum):
    ADDED = "added"
    ALREADY_PRESENT = "already_present"


def user_ssh_dir() -> Path:
    return Path.home() / ".ssh"


def _looks_like_private_key(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            head = handle.read(200)
    except OSError:
        return False
    return any(marker in head for marker in _PRIVATE_KEY_MARKERS)


def _is_encrypted(path: Path) -> bool:
    try:
        asyncssh.read_private_key(str(path))
    except asyncssh.KeyImportError as exc:
        return "passphrase" in str(exc).lower()
    except Exception:
        return False
    return False


def describe_key(path: Path, source: KeySource) -> KeyInfo | None:
    public = path.with_name(path.name + ".pub")
    algorithm = fingerprint = comment = ""
    try:
        if public.is_file():
            pub = asyncssh.read_public_key(str(public))
        else:
            pub = asyncssh.read_private_key(str(path)).convert_to_public()
        algorithm = pub.get_algorithm()
        fingerprint = pub.get_fingerprint("sha256")
        comment = pub.get_comment() or ""
    except Exception:
        if not public.is_file():
            # Clé chiffrée sans fichier .pub : on la liste quand même, l'empreinte viendra au déchiffrement.
            algorithm = tr("chiffrée")
    return KeyInfo(
        path=path,
        algorithm=algorithm,
        fingerprint=fingerprint,
        comment=comment,
        encrypted=_is_encrypted(path),
        source=source,
    )


def list_keys(keys_dir: Path, *, include_user_keys: bool = True) -> list[KeyInfo]:
    result: list[KeyInfo] = []
    sources = [(keys_dir, KeySource.APP)]
    if include_user_keys:
        sources.append((user_ssh_dir(), KeySource.USER))
    for directory, source in sources:
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if (
                not path.is_file()
                or path.suffix == ".pub"
                or path.name.startswith(("known_hosts", "authorized_keys", "config"))
            ):
                continue
            if not _looks_like_private_key(path):
                continue
            info = describe_key(path, source)
            if info is not None:
                result.append(info)
    return result


def resolve_key_path(key_path: str, keys_dir: Path) -> Path:
    """Chemin absolu d'une clé : les noms simples désignent une clé du dossier de l'application."""
    candidate = Path(key_path).expanduser()
    return candidate if candidate.is_absolute() else keys_dir / candidate


def generate_key(
    keys_dir: Path, name: str, *, passphrase: str | None = None, comment: str | None = None
) -> KeyInfo:
    name = name.strip()
    if not _KEY_NAME_RE.match(name):
        raise ValueError(
            tr("Nom de clé invalide : lettres, chiffres, point, tiret et soulignement uniquement.")
        )
    if not name.startswith("id_"):
        name = f"id_ed25519_{name}"
    path = keys_dir / name
    if path.exists() or path.with_name(name + ".pub").exists():
        raise FileExistsError(tr("Une clé nommée {name} existe déjà.").format(name=name))
    keys_dir.mkdir(parents=True, exist_ok=True)
    key = asyncssh.generate_private_key(  # pyright: ignore[reportUnknownMemberType]
        "ssh-ed25519", comment=comment or f"cma@{socket.gethostname()}"
    )
    if passphrase:
        key.write_private_key(str(path), passphrase=passphrase, cipher_name="aes256-ctr")  # pyright: ignore[reportUnknownMemberType]
    else:
        key.write_private_key(str(path))  # pyright: ignore[reportUnknownMemberType]
    key.write_public_key(str(path.with_name(name + ".pub")))  # pyright: ignore[reportUnknownMemberType]
    if sys.platform != "win32":
        os.chmod(path, 0o600)
    log.info("Clé SSH générée : %s", path)
    info = describe_key(path, KeySource.APP)
    assert info is not None
    return info


def delete_key(path: Path, keys_dir: Path) -> None:
    """Supprime une clé générée par l'application (jamais une clé de ~/.ssh)."""
    resolved = path.resolve()
    if resolved.parent != keys_dir.resolve():
        raise PermissionError(tr("Seules les clés du dossier de l'application peuvent être supprimées ici."))
    resolved.unlink(missing_ok=True)
    resolved.with_name(resolved.name + ".pub").unlink(missing_ok=True)


def public_key_line(path: Path, passphrase: str | None = None) -> str:
    public = path.with_name(path.name + ".pub")
    if public.is_file():
        return public.read_text(encoding="utf-8").strip()
    key = asyncssh.read_private_key(str(path), passphrase)
    return key.export_public_key("openssh").decode("ascii").strip()


def _key_blob(line: str) -> tuple[str, str] | None:
    parts = line.strip().split()
    for index, part in enumerate(parts[:-1]):
        if part.startswith(("ssh-", "ecdsa-", "sk-")):
            return part, parts[index + 1]
    return None


async def _read_text(sftp: Any, path: str) -> str:
    async with sftp.open(path, "r") as handle:
        return str(await handle.read())


async def deploy_public_key(conn: asyncssh.SSHClientConnection, public_line: str) -> DeployResult:
    """Ajoute la clé publique à ~/.ssh/authorized_keys du compte connecté, si elle n'y est pas déjà."""
    blob = _key_blob(public_line)
    if blob is None:
        raise ValueError(tr("Clé publique illisible."))
    async with conn.start_sftp_client() as sftp:
        if not await sftp.exists(".ssh"):
            await sftp.mkdir(".ssh")
        await sftp.chmod(".ssh", 0o700)
        content = ""
        if await sftp.exists(".ssh/authorized_keys"):
            content = await _read_text(sftp, ".ssh/authorized_keys")
        for line in content.splitlines():
            if _key_blob(line) == blob:
                return DeployResult.ALREADY_PRESENT
        prefix = "" if not content or content.endswith("\n") else "\n"
        async with sftp.open(".ssh/authorized_keys", "a") as handle:
            await handle.write(f"{prefix}{public_line.strip()}\n")
        await sftp.chmod(".ssh/authorized_keys", 0o600)
        check = await _read_text(sftp, ".ssh/authorized_keys")
    if not any(_key_blob(line) == blob for line in check.splitlines()):
        raise RuntimeError(tr("La clé n'apparaît pas dans authorized_keys après l'écriture."))
    return DeployResult.ADDED
