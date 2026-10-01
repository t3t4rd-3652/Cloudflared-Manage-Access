"""État d'affichage mémorisé d'un lancement à l'autre (largeurs et ordre des colonnes).

Le fichier `ui-state.ini` vit dans le dossier de données : il suit donc la version portable. Rien de sensible
n'y est écrit, seulement la géométrie des en-têtes de tableaux.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QByteArray, QSettings, QTimer
from PySide6.QtWidgets import QHeaderView

_settings: QSettings | None = None


def configure(path: Path | None) -> None:
    """Choisit le fichier d'état ; None désactive la mémorisation (tests, captures)."""
    global _settings
    _settings = QSettings(str(path), QSettings.Format.IniFormat) if path is not None else None


def remember_header(header: QHeaderView, key: str) -> None:
    """Restaure la géométrie de l'en-tête `key` puis l'enregistre à chaque changement (regroupé à 400 ms)."""
    settings = _settings
    if settings is None:
        return
    name = f"headers/{key}"
    saved = settings.value(name)
    if isinstance(saved, QByteArray) and not saved.isEmpty():
        header.restoreState(saved)
    timer = QTimer(header)
    timer.setSingleShot(True)
    timer.setInterval(400)

    def save() -> None:
        if _settings is settings:
            settings.setValue(name, header.saveState())

    timer.timeout.connect(save)
    header.sectionResized.connect(lambda *_a: timer.start())
    header.sectionMoved.connect(lambda *_a: timer.start())
