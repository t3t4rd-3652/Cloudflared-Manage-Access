"""Verrouillage de l'interface (coffre chiffré) : un panneau couvre la fenêtre jusqu'à la phrase de passe.

Les sessions continuent pendant le verrouillage : les secrets dont elles ont besoin restent en mémoire.
Le verrouillage empêche seulement de consulter, copier ou modifier quoi que ce soit dans la fenêtre.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, Qt, QTimer, Signal
from PySide6.QtGui import QCursor
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QLineEdit, QVBoxLayout, QWidget

from cma.i18n import tr
from cma.ui.icons import set_glyph
from cma.ui.widgets import label, primary_button, title


def _system_idle_seconds() -> float | None:
    """Inactivité du poste selon Windows (GetLastInputInfo), ou None ailleurs."""
    if sys.platform != "win32":
        return None
    import ctypes

    class LastInputInfo(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

    info = LastInputInfo()
    info.cbSize = ctypes.sizeof(LastInputInfo)
    windows: Any = ctypes
    if not windows.windll.user32.GetLastInputInfo(ctypes.byref(info)):
        return None
    elapsed = (windows.windll.kernel32.GetTickCount() - info.dwTime) & 0xFFFFFFFF
    return elapsed / 1000


class IdleWatcher(QObject):
    """Durée d'inactivité de l'utilisateur, sans filtre d'événements sur toute l'application.

    Sous Windows : l'inactivité du poste (clavier et souris). Ailleurs : la position du curseur, relevée toutes
    les 5 s.
    """

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.last_input = time.monotonic()
        self._cursor = QCursor.pos()
        self._timer = QTimer(self)
        self._timer.setInterval(5_000)
        self._timer.timeout.connect(self._sample)
        self._timer.start()

    def _sample(self) -> None:
        position = QCursor.pos()
        if position != self._cursor:
            self._cursor = position
            self.last_input = time.monotonic()

    def idle_seconds(self) -> float:
        own = time.monotonic() - self.last_input
        system = _system_idle_seconds()
        return own if system is None else min(own, system)

    def reset(self) -> None:
        self.last_input = time.monotonic()


class LockPanel(QFrame):
    unlocked = Signal()

    def __init__(self, parent: QWidget, check: Callable[[str], bool]) -> None:
        super().__init__(parent)
        self.setObjectName("LockPanel")
        self._check = check
        outer = QHBoxLayout(self)
        outer.addStretch()
        column = QVBoxLayout()
        column.addStretch()
        glyph = QLabel()
        set_glyph(glyph, "lock", "accent", 48)
        glyph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        column.addWidget(glyph)
        heading = title(tr("CMA est verrouillé"), "SectionTitle")
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        column.addWidget(heading)
        text = label(
            tr("Les sessions continuent. Saisissez la phrase de passe du coffre pour revenir."),
            "muted",
            wrap=True,
        )
        text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        column.addWidget(text)
        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase.setAccessibleName(tr("Phrase de passe du coffre"))
        self.passphrase.setMinimumWidth(320)
        self.passphrase.returnPressed.connect(self.try_unlock)
        column.addWidget(self.passphrase)
        self.error = label("", "error")
        self.error.setAlignment(Qt.AlignmentFlag.AlignCenter)
        column.addWidget(self.error)
        unlock = primary_button(tr("Déverrouiller"), "lock-open")
        unlock.clicked.connect(self.try_unlock)
        column.addWidget(unlock, 0, Qt.AlignmentFlag.AlignCenter)
        column.addStretch()
        outer.addLayout(column)
        outer.addStretch()

    def try_unlock(self) -> None:
        if self._check(self.passphrase.text()):
            self.passphrase.clear()
            self.error.setText("")
            self.unlocked.emit()
        else:
            self.passphrase.selectAll()
            self.error.setText(tr("Phrase de passe incorrecte."))
