"""Emplacements des données de l'application et des ressources embarquées."""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path

# Nom historique du dossier de données, partagé avec la v1 : la migration lit les fichiers v1 sur place.
DATA_DIR_NAME = "CloudflaredManager"


def is_frozen() -> bool:
    """Vrai quand l'application tourne depuis un exécutable PyInstaller."""
    return bool(getattr(sys, "frozen", False))


def default_data_dir() -> Path:
    system = platform.system()
    if system == "Windows":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / DATA_DIR_NAME
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / DATA_DIR_NAME
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / DATA_DIR_NAME


def portable_data_dir() -> Path | None:
    """Mode portable : un dossier `data` à côté de l'exécutable reçoit toutes les données."""
    if is_frozen():
        candidate = Path(sys.executable).resolve().parent / "data"
        if candidate.is_dir():
            return candidate
    return None


@dataclass(frozen=True)
class AppPaths:
    data_dir: Path
    portable: bool = False

    @property
    def config_file(self) -> Path:
        return self.data_dir / "config.json"

    @property
    def backups_dir(self) -> Path:
        return self.data_dir / "backups"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def keys_dir(self) -> Path:
        return self.data_dir / "ssh_keys"

    @property
    def known_hosts(self) -> Path:
        return self.data_dir / "known_hosts"

    @property
    def bin_dir(self) -> Path:
        return self.data_dir / "bin"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def lock_file(self) -> Path:
        return self.data_dir / "cma.lock"

    @property
    def ipc_key_file(self) -> Path:
        return self.data_dir / "ipc.key"

    @property
    def encrypted_secrets_file(self) -> Path:
        return self.data_dir / "secrets.enc.json"

    def ensure(self) -> None:
        for directory in (
            self.data_dir,
            self.backups_dir,
            self.logs_dir,
            self.keys_dir,
            self.bin_dir,
            self.cache_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)


def resolve_paths(override: str | os.PathLike[str] | None = None) -> AppPaths:
    """Ordre de priorité : argument --data-dir, variable CMA_DATA_DIR, mode portable, emplacement standard."""
    if override:
        return AppPaths(Path(override).expanduser().resolve())
    env = os.environ.get("CMA_DATA_DIR")
    if env:
        return AppPaths(Path(env).expanduser().resolve())
    portable = portable_data_dir()
    if portable is not None:
        return AppPaths(portable, portable=True)
    return AppPaths(default_data_dir())


def resources_dir() -> Path:
    return Path(__file__).resolve().parent / "resources"


def resource_path(*parts: str) -> Path:
    return resources_dir().joinpath(*parts)


def ports_report_script() -> str:
    """Contenu de ports-report : copie embarquée (exécutable, paquet) ou source du dépôt."""
    candidates = [
        resource_path("ports-report"),
        Path(__file__).resolve().parents[2] / "server" / "ports-report",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8").replace("\r\n", "\n")
    raise FileNotFoundError("ports-report introuvable dans les ressources de l'application")


def ports_report_windows_script() -> str:
    """Contenu de ports-report.ps1, la version Windows (PowerShell) de ports-report."""
    candidates = [
        resource_path("ports-report.ps1"),
        Path(__file__).resolve().parents[2] / "server" / "ports-report.ps1",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8-sig").replace("\r\n", "\n")
    raise FileNotFoundError("ports-report.ps1 introuvable dans les ressources de l'application")
