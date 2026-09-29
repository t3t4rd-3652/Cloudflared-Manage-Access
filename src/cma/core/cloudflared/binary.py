"""Le binaire cloudflared : détection, version, dernière release, téléchargement vérifié.

Le téléchargement contrôle le condensat SHA-256 publié par l'API GitHub (champ `digest` de chaque
fichier de release) et, sous Windows, la signature Authenticode « Cloudflare, Inc. ».
Les fonctions réseau sont bloquantes : le moteur les appelle via `asyncio.to_thread`.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cma import __version__
from cma.i18n import tr
from cma.paths import AppPaths

log = logging.getLogger(__name__)

LATEST_RELEASE_API = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest"
DOWNLOAD_PAGE = "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
USER_AGENT = f"CloudflaredManageAccess/{__version__}"
VERSION_RE = re.compile(r"version\s+(\d+\.\d+\.\d+)")
_EXE = ".exe" if sys.platform == "win32" else ""


class DownloadError(RuntimeError):
    """Téléchargement impossible, interrompu ou refusé par une vérification."""


@dataclass(frozen=True)
class ReleaseAsset:
    name: str
    url: str
    size: int
    sha256: str | None


@dataclass(frozen=True)
class ReleaseInfo:
    version: str
    html_url: str
    assets: tuple[ReleaseAsset, ...]

    def asset(self, name: str) -> ReleaseAsset | None:
        return next((a for a in self.assets if a.name == name), None)


def parse_version(text: str) -> str | None:
    match = VERSION_RE.search(text)
    return match.group(1) if match else None


def version_tuple(version: str | None) -> tuple[int, ...]:
    if not version:
        return ()
    return tuple(int(part) for part in re.findall(r"\d+", version)[:3])


def is_newer(candidate: str | None, current: str | None) -> bool:
    return bool(candidate) and version_tuple(candidate) > version_tuple(current)


def asset_name(system: str | None = None, machine: str | None = None) -> str:
    """Nom du fichier de release adapté au système. Windows ARM64 utilise la version amd64 (émulée)."""
    system = system or platform.system()
    machine = (machine or platform.machine()).lower()
    if system == "Windows":
        arch = "386" if machine in ("x86", "i386", "i686") else "amd64"
        return f"cloudflared-windows-{arch}.exe"
    if system == "Darwin":
        return f"cloudflared-darwin-{'arm64' if machine in ('arm64', 'aarch64') else 'amd64'}.tgz"
    arch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "armhf",
        "armv6l": "arm",
        "i386": "386",
        "i686": "386",
    }.get(machine, "amd64")
    return f"cloudflared-linux-{arch}"


def candidate_paths(paths: AppPaths) -> list[Path]:
    """Emplacements habituels de cloudflared, du plus probable au moins probable."""
    found: list[Path] = []
    which = shutil.which("cloudflared")
    if which:
        found.append(Path(which))
    if sys.platform == "win32":
        local = os.environ.get("LOCALAPPDATA", "")
        for base in (
            Path(local) / "Microsoft" / "WinGet" / "Links",
            Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "cloudflared",
            Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "cloudflared",
        ):
            found.append(base / "cloudflared.exe")
    else:
        found += [
            Path("/usr/local/bin/cloudflared"),
            Path("/usr/bin/cloudflared"),
            Path("/opt/homebrew/bin/cloudflared"),
        ]
    downloaded = sorted(
        paths.bin_dir.glob(f"cloudflared-*{_EXE}"), key=lambda p: version_tuple(p.stem), reverse=True
    )
    found += downloaded
    found.append(paths.data_dir / "cloudflared-windows-amd64.exe")  # emplacement de la v1
    unique: list[Path] = []
    seen: set[str] = set()
    for path in found:
        key = os.path.normcase(str(path))
        if key not in seen and path.is_file():
            seen.add(key)
            unique.append(path)
    return unique


def detect(paths: AppPaths, configured: str | None) -> Path | None:
    if configured and Path(configured).is_file():
        return Path(configured)
    candidates = candidate_paths(paths)
    return candidates[0] if candidates else None


async def read_version(binary: Path, timeout: float = 15) -> str | None:
    kwargs: dict[str, Any] = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        proc = await asyncio.create_subprocess_exec(
            str(binary),
            "--version",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            **kwargs,
        )
        output, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except (OSError, TimeoutError) as exc:
        log.warning("Impossible de lire la version de %s : %s", binary, exc)
        return None
    return parse_version(output.decode("utf-8", "replace"))


def _http_get(url: str, timeout: float) -> Any:
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    )
    return urllib.request.urlopen(request, timeout=timeout)


def fetch_latest_release(
    cache_file: Path | None = None, *, max_age: float = 86400, timeout: float = 15
) -> ReleaseInfo:
    """Dernière release publiée sur GitHub. Le résultat est gardé en cache `max_age` secondes."""
    if cache_file is not None and cache_file.is_file() and time.time() - cache_file.stat().st_mtime < max_age:
        try:
            return _release_from_json(json.loads(cache_file.read_text(encoding="utf-8")))
        except Exception:
            log.debug("Cache de release illisible, nouvelle requête")
    with _http_get(LATEST_RELEASE_API, timeout) as response:
        data = json.loads(response.read().decode("utf-8"))
    if cache_file is not None:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps(data), encoding="utf-8")
    return _release_from_json(data)


def _release_from_json(data: dict[str, Any]) -> ReleaseInfo:
    assets: list[ReleaseAsset] = []
    for item in data.get("assets", []):
        digest = item.get("digest") or ""
        assets.append(
            ReleaseAsset(
                name=item["name"],
                url=item["browser_download_url"],
                size=int(item.get("size") or 0),
                sha256=digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else None,
            )
        )
    return ReleaseInfo(
        version=str(data["tag_name"]).lstrip("v"), html_url=data.get("html_url", ""), assets=tuple(assets)
    )


def powershell_env(**extra: str) -> dict[str, str]:
    """Environnement de Windows PowerShell 5.1 sans PSModulePath hérité.

    Lancé depuis PowerShell 7, powershell.exe hérite d'un PSModulePath qui pointe vers les modules de la
    version 7 : il ne charge plus Microsoft.PowerShell.Security, et Get-AuthenticodeSignature n'existe plus.
    """
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    env.update(extra)
    return env


def verify_authenticode(path: Path) -> tuple[bool, str]:
    """Windows : signature Authenticode valide et émise pour Cloudflare. Le chemin passe par l'environnement."""
    if sys.platform != "win32":
        return True, ""
    script = (
        "$s = Get-AuthenticodeSignature -LiteralPath $env:CMA_VERIFY_PATH; "
        "Write-Output $s.Status.ToString(); "
        "if ($s.SignerCertificate) { Write-Output $s.SignerCertificate.Subject }"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            env=powershell_env(CMA_VERIFY_PATH=str(path)),
            capture_output=True,
            timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    lines = result.stdout.decode("utf-8", "replace").strip().splitlines()
    status = lines[0].strip() if lines else ""
    subject = lines[1].strip() if len(lines) > 1 else ""
    ok = status == "Valid" and 'O="Cloudflare, Inc."' in subject
    return ok, f"{status} {subject}".strip()


def download_release_binary(
    release: ReleaseInfo,
    dest_dir: Path,
    *,
    name: str | None = None,
    progress: Callable[[int, int | None], None] | None = None,
    cancel: threading.Event | None = None,
    timeout: float = 60,
) -> Path:
    """Télécharge, vérifie et installe cloudflared dans `dest_dir`. Renvoie le chemin de l'exécutable."""
    name = name or asset_name()
    asset = release.asset(name)
    if asset is None:
        raise DownloadError(
            tr("Aucun fichier {name} dans la release {version}.").format(name=name, version=release.version)
        )
    if not asset.sha256:
        raise DownloadError(
            tr("La release ne publie pas d'empreinte SHA-256 pour {name} : téléchargement refusé.").format(
                name=name
            )
        )

    dest_dir.mkdir(parents=True, exist_ok=True)
    partial = dest_dir / f".{asset.name}.part"
    digest = hashlib.sha256()
    received = 0
    try:
        with _http_get(asset.url, timeout) as response, partial.open("wb") as handle:
            total = int(response.headers.get("Content-Length") or asset.size or 0) or None
            while True:
                if cancel is not None and cancel.is_set():
                    raise DownloadError(tr("Téléchargement annulé."))
                chunk = response.read(256 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
                digest.update(chunk)
                received += len(chunk)
                if progress is not None:
                    progress(received, total)
        if digest.hexdigest() != asset.sha256:
            raise DownloadError(
                tr("Empreinte SHA-256 incorrecte : fichier corrompu ou altéré, il a été supprimé.")
            )

        final = dest_dir / f"cloudflared-{release.version}{_EXE}"
        if asset.name.endswith(".tgz"):
            with tarfile.open(partial, "r:gz") as archive:
                member = next(
                    (m for m in archive.getmembers() if Path(m.name).name == "cloudflared" and m.isfile()),
                    None,
                )
                if member is None:
                    raise DownloadError(tr("L'archive ne contient pas cloudflared."))
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise DownloadError(tr("L'archive ne contient pas cloudflared."))
                tmp = dest_dir / f".{final.name}.tmp"
                tmp.write_bytes(extracted.read())
                os.replace(tmp, final)
            partial.unlink()
        else:
            os.replace(partial, final)
        if sys.platform != "win32":
            final.chmod(0o755)
        else:
            ok, detail = verify_authenticode(final)
            if not ok:
                final.unlink(missing_ok=True)
                raise DownloadError(
                    tr("Signature Authenticode invalide ({detail}) : fichier supprimé.").format(detail=detail)
                )
        log.info("cloudflared %s installé dans %s", release.version, final)
        return final
    finally:
        partial.unlink(missing_ok=True)
