"""Transfert de fichiers SFTP sur la connexion SSH d'un profil : parcourir, télécharger, envoyer, ranger.

Chaque opération ouvre un canal SFTP sur la connexion existante (pas de nouvelle authentification). Les chemins
distants sont POSIX ; un nom saisi (dossier, renommage) ne peut pas contenir de séparateur.
"""

from __future__ import annotations

import asyncio
import posixpath
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    import asyncssh

from cma.i18n import tr

# (nom du fichier en cours, octets copiés, taille totale)
Progress = Callable[[str, int, int], None]


@dataclass(frozen=True)
class RemoteEntry:
    name: str
    path: str
    is_dir: bool
    size: int
    modified: datetime | None
    permissions: str  # « drwxr-xr-x »
    is_link: bool = False


def check_name(name: str) -> str:
    """Nom d'un fichier ou dossier distant à créer ou renommer ; ValueError s'il est inutilisable."""
    name = name.strip()
    if not name or name in (".", "..") or "/" in name or "\0" in name:
        raise ValueError(tr("Nom invalide : « {name} ».").format(name=name))
    return name


def _entry(directory: str, name: str, attrs: Any, is_dir: bool | None = None) -> RemoteEntry:
    mode = int(attrs.permissions or 0)
    mtime = attrs.mtime
    return RemoteEntry(
        name=name,
        path=posixpath.join(directory, name),
        is_dir=stat.S_ISDIR(mode) if is_dir is None else is_dir,
        size=int(attrs.size or 0),
        modified=datetime.fromtimestamp(mtime) if mtime else None,
        permissions=stat.filemode(mode) if mode else "",
        is_link=stat.S_ISLNK(mode),
    )


async def listing(
    conn: asyncssh.SSHClientConnection, path: str | None = None
) -> tuple[str, list[RemoteEntry]]:
    """Chemin absolu du dossier et son contenu, dossiers d'abord. Sans chemin : le dossier personnel."""
    async with conn.start_sftp_client() as sftp:
        directory = await sftp.realpath(path or ".")
        entries: list[RemoteEntry] = []
        for item in await sftp.readdir(directory):
            name = str(item.filename)
            if name in (".", ".."):
                continue
            entry = _entry(directory, name, item.attrs)
            if entry.is_link:  # un lien vers un dossier se parcourt comme un dossier
                entry = _entry(directory, name, item.attrs, is_dir=await sftp.isdir(entry.path))
            entries.append(entry)
    entries.sort(key=lambda e: (not e.is_dir, e.name.casefold()))
    return directory, entries


def _handler(progress: Progress | None) -> Callable[[bytes, bytes, int, int], None] | None:
    if progress is None:
        return None

    def handle(source: bytes, _target: bytes, copied: int, total: int) -> None:
        progress(posixpath.basename(source.decode("utf-8", "replace")), copied, total)

    return handle


async def download(
    conn: asyncssh.SSHClientConnection,
    remote_paths: list[str],
    local_dir: Path,
    progress: Progress | None = None,
) -> list[Path]:
    """Copie fichiers et dossiers (récursivement) dans `local_dir`. Renvoie les chemins locaux créés."""
    await asyncio.to_thread(local_dir.mkdir, parents=True, exist_ok=True)
    async with conn.start_sftp_client() as sftp:
        await sftp.get(
            remote_paths, str(local_dir), recurse=True, preserve=True, progress_handler=_handler(progress)
        )
    return [local_dir / posixpath.basename(p.rstrip("/")) for p in remote_paths]


async def upload(
    conn: asyncssh.SSHClientConnection,
    local_paths: list[Path],
    remote_dir: str,
    progress: Progress | None = None,
) -> list[str]:
    """Envoie fichiers et dossiers (récursivement) dans `remote_dir`. Renvoie les chemins distants créés."""
    async with conn.start_sftp_client() as sftp:
        await sftp.put(
            [str(p) for p in local_paths],
            remote_dir,
            recurse=True,
            preserve=True,
            progress_handler=_handler(progress),
        )
    return [posixpath.join(remote_dir, p.name) for p in local_paths]


async def existing(conn: asyncssh.SSHClientConnection, remote_dir: str, names: list[str]) -> list[str]:
    """Ceux de `names` qui existent déjà dans `remote_dir` (pour demander avant de les remplacer)."""
    async with conn.start_sftp_client() as sftp:
        return [name for name in names if await sftp.exists(posixpath.join(remote_dir, name))]


async def make_dir(conn: asyncssh.SSHClientConnection, remote_dir: str, name: str) -> str:
    path = posixpath.join(remote_dir, check_name(name))
    async with conn.start_sftp_client() as sftp:
        await sftp.mkdir(path)
    return path


async def rename(conn: asyncssh.SSHClientConnection, path: str, new_name: str) -> str:
    target = posixpath.join(posixpath.dirname(path), check_name(new_name))
    async with conn.start_sftp_client() as sftp:
        if await sftp.exists(target):
            raise FileExistsError(tr("« {name} » existe déjà.").format(name=new_name.strip()))
        await sftp.rename(path, target)
    return target


async def remove(conn: asyncssh.SSHClientConnection, entry: RemoteEntry) -> None:
    """Supprime un fichier, ou un dossier avec tout son contenu. Un lien est supprimé, pas sa cible."""
    async with conn.start_sftp_client() as sftp:
        if entry.is_dir and not entry.is_link:
            await cast(Any, sftp).rmtree(entry.path)  # signature mal typée dans asyncssh
        else:
            await sftp.remove(entry.path)
