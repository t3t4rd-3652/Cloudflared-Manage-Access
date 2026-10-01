"""Palette de commandes (Ctrl+K) : chercher un accès, un serveur ou une action, et l'exécuter au clavier.

Le verbe affiché suit l'état réel (« Connecter » ou « Arrêter ») pour éviter toute confusion sur un accès déjà
ouvert. La recherche est locale : chaque mot saisi doit apparaître, sans tenir compte des accents ni de la casse.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QDialog, QLineEdit, QListWidget, QListWidgetItem, QVBoxLayout, QWidget

from cma.i18n import tr
from cma.ui.icons import app_icon, token_icon
from cma.ui.widgets import label

MAX_RESULTS = 60
ENTRY_ROLE = Qt.ItemDataRole.UserRole


@dataclass
class PaletteEntry:
    section: str
    text: str
    run: Callable[[], None]
    detail: str = ""
    icon: str = "arrow-right"
    keywords: str = ""
    _haystack: str = field(default="", init=False, repr=False)

    def haystack(self) -> str:
        if not self._haystack:
            self._haystack = fold(" ".join((self.text, self.detail, self.keywords, self.section)))
        return self._haystack


def fold(text: str) -> str:
    """Minuscules sans accents, pour une recherche tolérante."""
    decomposed = unicodedata.normalize("NFKD", text.casefold())
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def matches(entry: PaletteEntry, query: str) -> bool:
    words = fold(query).split()
    haystack = entry.haystack()
    return all(word in haystack for word in words)


class CommandPalette(QDialog):
    def __init__(self, parent: QWidget | None, entries: list[PaletteEntry]) -> None:
        super().__init__(parent)
        self.entries = entries
        self.setWindowTitle(tr("Palette de commandes"))
        self.setWindowIcon(app_icon())
        self.setMinimumWidth(620)
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText(tr("Rechercher un accès, un serveur ou une action…"))
        self.search.setAccessibleName(tr("Rechercher une commande"))
        self.search.setClearButtonEnabled(True)
        layout.addWidget(self.search)
        self.results = QListWidget()
        self.results.setAccessibleName(tr("Résultats"))
        self.results.setUniformItemSizes(False)
        layout.addWidget(self.results, 1)
        self.empty = label(tr("Aucun résultat pour cette recherche."), "muted")
        layout.addWidget(self.empty)
        layout.addWidget(label(tr("Entrée : exécuter · Échap : fermer · ↑↓ : choisir"), "meta"))
        self.search.textChanged.connect(self._filter)
        self.results.itemActivated.connect(lambda _i: self.run_current())
        self.search.installEventFilter(self)
        self.resize(680, 460)
        self._filter("")

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        # Les flèches et Entrée agissent sur la liste sans quitter le champ de recherche.
        if watched is self.search and event.type() == QEvent.Type.KeyPress and isinstance(event, QKeyEvent):
            key = event.key()
            if key in (Qt.Key.Key_Down, Qt.Key.Key_Up):
                self._move(1 if key == Qt.Key.Key_Down else -1)
                return True
            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                self.run_current()
                return True
        return super().eventFilter(watched, event)

    def _filter(self, query: str) -> None:
        self.results.clear()
        shown = 0
        section = None
        for entry in self.entries:
            if not matches(entry, query):
                continue
            if shown >= MAX_RESULTS:
                break
            if entry.section != section:
                section = entry.section
                header = QListWidgetItem(section.upper())
                header.setFlags(Qt.ItemFlag.NoItemFlags)
                self.results.addItem(header)
            text = f"{entry.text}   —   {entry.detail}" if entry.detail else entry.text
            item = QListWidgetItem(token_icon(entry.icon), text)
            item.setData(ENTRY_ROLE, entry)
            item.setToolTip(entry.detail or entry.text)
            self.results.addItem(item)
            shown += 1
        self.empty.setVisible(shown == 0)
        self._move(1, from_start=True)

    def _selectable_rows(self) -> list[int]:
        return [
            row
            for row in range(self.results.count())
            if (item := self.results.item(row)) is not None and item.flags() & Qt.ItemFlag.ItemIsSelectable
        ]

    def _move(self, step: int, *, from_start: bool = False) -> None:
        rows = self._selectable_rows()
        if not rows:
            return
        current = self.results.currentRow()
        if from_start or current not in rows:
            target = rows[0]
        else:
            index = rows.index(current) + step
            target = rows[max(0, min(len(rows) - 1, index))]
        self.results.setCurrentRow(target)

    def current_entry(self) -> PaletteEntry | None:
        item = self.results.currentItem()
        entry = item.data(ENTRY_ROLE) if item is not None else None
        return entry if isinstance(entry, PaletteEntry) else None

    def run_current(self) -> None:
        entry = self.current_entry()
        if entry is None:
            return
        self.accept()
        entry.run()
