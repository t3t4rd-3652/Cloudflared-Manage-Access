"""Nouvelles versions de CMA : vérification, téléchargement vérifié de l'installeur et installation.

La mise à jour automatique ne s'applique qu'à une copie installée par l'installeur Windows. En mode
portable ou depuis les sources, l'application propose seulement la page de la release.

L'installeur téléchargé est vérifié par son empreinte SHA-256 : celle publiée par GitHub pour le fichier
(champ `digest`) ou, à défaut, celle du fichier SHA256SUMS.txt joint à la release. Sans empreinte,
l'installation est refusée. S'il est signé, sa signature Authenticode doit être valide.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from cma import REPO_URL, __version__
from cma.core.cloudflared.binary import USER_AGENT, DownloadError, ReleaseAsset, is_newer
from cma.i18n import tr
from cma.paths import is_frozen, portable_data_dir

LATEST_API = REPO_URL.replace("https://github.com/", "https://api.github.com/repos/") + "/releases/latest"
APP_ID = "{D59636E8-D9FE-495F-92B0-B83E09A8BA54}"
UNINSTALL_KEY = rf"Software\Microsoft\Windows\CurrentVersion\Uninstall\{APP_ID}_is1"
SUMS_NAME = "SHA256SUMS.txt"


@dataclass(frozen=True)
class UpdateInfo:
    current: str
    latest: str | None
    url: str | None
    assets: tuple[ReleaseAsset, ...] = field(default=())

    @property
    def available(self) -> bool:
        return is_newer(self.latest, self.current)

    @property
    def installer(self) -> ReleaseAsset | None:
        if not self.latest:
            return None
        name = f"CloudflaredManageAccess-{self.latest}-setup.exe"
        return next((a for a in self.assets if a.name == name), None)

    def asset(self, name: str) -> ReleaseAsset | None:
        return next((a for a in self.assets if a.name == name), None)


def _request(url: str) -> urllib.request.Request:
    return urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    )


def _assets(data: dict[str, Any]) -> tuple[ReleaseAsset, ...]:
    assets: list[ReleaseAsset] = []
    for item in cast(list[dict[str, Any]], data.get("assets") or []):
        digest = str(item.get("digest") or "")
        assets.append(
            ReleaseAsset(
                name=str(item.get("name", "")),
                url=str(item.get("browser_download_url", "")),
                size=int(item.get("size") or 0),
                sha256=digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else None,
            )
        )
    return tuple(assets)


def check_for_update(timeout: float = 10) -> UpdateInfo:
    """Dernière release publiée. `latest` vaut None si le projet n'a encore publié aucune release."""
    try:
        with urllib.request.urlopen(_request(LATEST_API), timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return UpdateInfo(__version__, None, None)
        raise
    latest = str(data.get("tag_name", "")).lstrip("vV") or None
    return UpdateInfo(__version__, latest, data.get("html_url"), _assets(data))


# --- Installation -----------------------------------------------------------------------------------


def installed_location() -> Path | None:
    """Dossier d'installation enregistré par l'installeur (HKCU), ou None."""
    if sys.platform != "win32":
        return None
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY) as key:
            value, _kind = winreg.QueryValueEx(key, "InstallLocation")
    except OSError:
        return None
    return Path(str(value)) if value else None


def can_self_update() -> bool:
    """Vrai pour une copie installée par l'installeur, qui tourne depuis son dossier d'installation."""
    if sys.platform != "win32" or not is_frozen() or portable_data_dir() is not None:
        return False
    location = installed_location()
    if location is None:
        return False
    try:
        return Path(sys.executable).resolve().parent == location.resolve()
    except OSError:
        return False


def _published_sums(info: UpdateInfo, timeout: float) -> dict[str, str]:
    sums = info.asset(SUMS_NAME)
    if sums is None:
        return {}
    with urllib.request.urlopen(_request(sums.url), timeout=timeout) as response:
        text = response.read().decode("utf-8", "replace")
    result: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and len(parts[0]) == 64:
            result[parts[-1].lstrip("*")] = parts[0].lower()
    return result


def expected_sha256(info: UpdateInfo, asset: ReleaseAsset, timeout: float = 30) -> str:
    if asset.sha256:
        return asset.sha256
    digest = _published_sums(info, timeout).get(asset.name)
    if not digest:
        raise DownloadError(
            tr("La release ne publie pas d'empreinte SHA-256 pour {name} : téléchargement refusé.").format(
                name=asset.name
            )
        )
    return digest


def download_installer(
    info: UpdateInfo,
    dest_dir: Path,
    *,
    progress: Callable[[int, int | None], None] | None = None,
    cancel: threading.Event | None = None,
    timeout: float = 60,
    verify_signature: Callable[[Path], tuple[bool, str]] | None = None,
) -> Path:
    """Télécharge l'installeur de la dernière version et vérifie son empreinte. Renvoie son chemin."""
    asset = info.installer
    if asset is None:
        raise DownloadError(tr("Cette release ne contient pas d'installeur Windows."))
    expected = expected_sha256(info, asset, timeout)
    dest_dir.mkdir(parents=True, exist_ok=True)
    partial = dest_dir / f".{asset.name}.part"
    final = dest_dir / asset.name
    digest = hashlib.sha256()
    received = 0
    try:
        with (
            urllib.request.urlopen(_request(asset.url), timeout=timeout) as response,
            partial.open("wb") as out,
        ):
            total = int(response.headers.get("Content-Length") or asset.size or 0) or None
            while True:
                if cancel is not None and cancel.is_set():
                    raise DownloadError(tr("Téléchargement annulé."))
                chunk = response.read(256 * 1024)
                if not chunk:
                    break
                out.write(chunk)
                digest.update(chunk)
                received += len(chunk)
                if progress is not None:
                    progress(received, total)
        if digest.hexdigest() != expected:
            raise DownloadError(
                tr("Empreinte SHA-256 incorrecte : fichier corrompu ou altéré, il a été supprimé.")
            )
        os.replace(partial, final)
    finally:
        partial.unlink(missing_ok=True)
    check = verify_signature or signature_is_acceptable
    ok, detail = check(final)
    if not ok:
        final.unlink(missing_ok=True)
        raise DownloadError(tr("Signature de l'installeur invalide : {detail}").format(detail=detail))
    return final


def signature_is_acceptable(path: Path) -> tuple[bool, str]:
    """Un installeur non signé est accepté (l'empreinte suffit) ; un installeur signé doit l'être correctement."""
    if sys.platform != "win32":
        return True, ""
    script = "(Get-AuthenticodeSignature -LiteralPath $env:CMA_VERIFY_PATH).Status.ToString()"
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "CMA_VERIFY_PATH": str(path)},
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    status = result.stdout.strip()
    return status in ("Valid", "NotSigned"), status


def installer_command(installer: Path, *, relaunch: bool = True) -> list[str]:
    """Installation silencieuse (sans question), puis relance de CMA si demandé."""
    args = [str(installer), "/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CLOSEAPPLICATIONS"]
    if relaunch:
        args.append("/RELAUNCH=1")
    return args


def launch_installer(installer: Path, *, relaunch: bool = True, wait_pid: int | None = None) -> None:
    """Lance l'installeur détaché, une fois CMA fermé : il remplace les fichiers puis relance l'application.

    Un PowerShell caché attend la fin du processus `wait_pid` (CMA) avant de démarrer l'installeur, pour que
    les fichiers de l'application ne soient plus verrouillés. Les chemins passent par l'environnement.
    """
    args = installer_command(installer, relaunch=relaunch)
    script = (
        "Wait-Process -Id ([int]$env:CMA_WAIT_PID) -Timeout 120 -ErrorAction SilentlyContinue; "
        "Start-Process -FilePath $env:CMA_INSTALLER -ArgumentList $env:CMA_INSTALLER_ARGS"
    )
    env = {
        **os.environ,
        "CMA_WAIT_PID": str(wait_pid if wait_pid is not None else os.getpid()),
        "CMA_INSTALLER": args[0],
        "CMA_INSTALLER_ARGS": " ".join(args[1:]),
    }
    flags = 0
    if sys.platform == "win32":
        flags = (
            subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        )
    subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script],
        env=env,
        close_fds=True,
        creationflags=flags,
    )
