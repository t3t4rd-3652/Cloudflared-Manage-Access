"""Stockage de la configuration : un seul fichier `config.json` versionné.

- Toute écriture est atomique (fichier temporaire puis remplacement).
- La première écriture de chaque session sauvegarde l'ancienne version dans `backups/`.
- Un fichier illisible est mis de côté, et la dernière sauvegarde valide est restaurée.
- Une configuration écrite par une version plus récente est ouverte en lecture seule.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import threading
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from cma.core.fsutil import atomic_write_text
from cma.core.models import SCHEMA_VERSION, Config
from cma.i18n import tr
from cma.paths import AppPaths

log = logging.getLogger(__name__)


class ConfigReadOnlyError(RuntimeError):
    """La configuration vient d'une version plus récente : elle n'est pas modifiable ici."""


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S-%f")


class ConfigStore:
    def __init__(self, paths: AppPaths, max_backups: int = 10) -> None:
        self._paths = paths
        self._max_backups = max_backups
        self._lock = threading.RLock()
        self._config = Config()
        self._listeners: list[Callable[[], None]] = []
        self._backed_up_this_session = False
        self.read_only = False

    @property
    def path(self) -> Path:
        return self._paths.config_file

    def exists(self) -> bool:
        return self.path.exists()

    # --- Lecture -----------------------------------------------------------------

    def load(self) -> list[str]:
        """Charge la configuration et renvoie les avertissements à montrer à l'utilisateur."""
        warnings: list[str] = []
        with self._lock:
            if not self.path.exists():
                self._config = Config()
                return warnings
            try:
                config = self._parse(self.path)
            except Exception as exc:
                corrupt = self.path.with_name(f"config.json.corrupt-{_stamp()}")
                os.replace(self.path, corrupt)
                log.error("Configuration illisible, mise de côté sous %s : %s", corrupt.name, exc)
                warnings.append(
                    tr(
                        "Le fichier de configuration était illisible. Il a été mis de côté sous {name}."
                    ).format(name=corrupt.name)
                )
                restored = self._latest_valid_backup()
                if restored is not None:
                    config, backup = restored
                    atomic_write_text(self.path, config.model_dump_json(indent=2) + "\n")
                    warnings.append(
                        tr("La configuration a été restaurée depuis la sauvegarde {name}.").format(
                            name=backup.name
                        )
                    )
                else:
                    config = Config()
            if config.schema_version > SCHEMA_VERSION:
                self.read_only = True
                warnings.append(
                    tr(
                        "Cette configuration a été écrite par une version plus récente de CMA. "
                        "Elle est ouverte en lecture seule."
                    )
                )
            self._config = config
        return warnings

    @staticmethod
    def _parse(path: Path) -> Config:
        data = json.loads(path.read_text(encoding="utf-8"))
        return Config.model_validate(data)

    def _latest_valid_backup(self) -> tuple[Config, Path] | None:
        for backup in self.list_backups():
            try:
                return self._parse(backup), backup
            except Exception as exc:
                log.warning("Sauvegarde %s inutilisable : %s", backup.name, exc)
        return None

    def snapshot(self) -> Config:
        """Copie indépendante de la configuration courante."""
        with self._lock:
            return self._config.model_copy(deep=True)

    # --- Écriture ------------------------------------------------------------------

    def update[T](self, mutator: Callable[[Config], T]) -> T:
        """Applique `mutator` à une copie, valide le résultat, l'écrit, puis le publie."""
        with self._lock:
            if self.read_only:
                raise ConfigReadOnlyError(tr("Configuration en lecture seule"))
            draft = self._config.model_copy(deep=True)
            result = mutator(draft)
            validated = Config.model_validate(draft.model_dump(mode="json"))
            self._write(validated)
            self._config = validated
        self._notify()
        return result

    def replace(self, config: Config) -> None:
        with self._lock:
            if self.read_only:
                raise ConfigReadOnlyError(tr("Configuration en lecture seule"))
            validated = Config.model_validate(config.model_dump(mode="json"))
            self._write(validated)
            self._config = validated
        self._notify()

    def _write(self, config: Config) -> None:
        if not self._backed_up_this_session and self.path.exists():
            self.backup("session")
            self._backed_up_this_session = True
        atomic_write_text(self.path, config.model_dump_json(indent=2) + "\n")

    # --- Sauvegardes ---------------------------------------------------------------

    def backup(self, reason: str = "") -> Path | None:
        with self._lock:
            if not self.path.exists():
                return None
            self._paths.backups_dir.mkdir(parents=True, exist_ok=True)
            suffix = f"-{reason}" if reason else ""
            target = self._paths.backups_dir / f"config-{_stamp()}{suffix}.json"
            shutil.copy2(self.path, target)
            self._rotate()
            return target

    def list_backups(self) -> list[Path]:
        if not self._paths.backups_dir.is_dir():
            return []
        return sorted(self._paths.backups_dir.glob("config-*.json"), key=lambda p: p.name, reverse=True)

    def _rotate(self) -> None:
        for old in self.list_backups()[self._max_backups :]:
            try:
                old.unlink()
            except OSError as exc:
                log.warning("Impossible de supprimer l'ancienne sauvegarde %s : %s", old, exc)

    # --- Abonnements -----------------------------------------------------------------

    def add_listener(self, callback: Callable[[], None]) -> None:
        self._listeners.append(callback)

    def _notify(self) -> None:
        for callback in list(self._listeners):
            try:
                callback()
            except Exception:
                log.exception("Erreur dans un abonné à la configuration")
