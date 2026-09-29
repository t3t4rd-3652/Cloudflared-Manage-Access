"""Éléments communs aux vues maître-détail : liste filtrable et groupée, questions de confirmation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QAction, QBrush, QColor, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLineEdit,
    QMenu,
    QMessageBox,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.i18n import tr
from cma.ui.icons import dot_icon, icon
from cma.ui.theme import current_tokens
from cma.ui.widgets import tool_button

ID_ROLE = Qt.ItemDataRole.UserRole


@dataclass(frozen=True)
class ListEntry:
    id: str
    name: str
    group: str = ""
    favorite: bool = False
    status_color: str | None = None
    detail: str = ""


class ProfileList(QWidget):
    """Liste de gauche : recherche, groupes repliables, favoris en tête, pastille d'état.

    L'action d'icône « trash » répond aussi à la touche Suppr quand la liste a le focus.
    `group_actions` fournit le menu contextuel d'un groupe (clic droit sur son titre).
    """

    selected = Signal(str)

    def __init__(
        self,
        placeholder: str,
        actions: list[tuple[str, str, Callable[[], None]]],
        *,
        grouped: bool = True,
        group_actions: Callable[[str], list[tuple[str, str, Callable[[], None]]]] | None = None,
    ) -> None:
        super().__init__()
        self._group_actions = group_actions
        self._grouped = grouped
        self._entries: list[ListEntry] = []
        self._suppress = False
        self.setMinimumWidth(250)
        self.setMaximumWidth(360)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.search = QLineEdit()
        self.search.setPlaceholderText(placeholder)
        self.search.setClearButtonEnabled(True)
        self.search.addAction(
            QAction(icon("search"), "", self.search), QLineEdit.ActionPosition.LeadingPosition
        )
        self.search.textChanged.connect(lambda _t: self._rebuild())
        layout.addWidget(self.search)
        toolbar = QHBoxLayout()
        toolbar.setSpacing(2)
        for icon_name, tooltip, callback in actions:
            toolbar.addWidget(tool_button(icon_name, tooltip, callback))
        toolbar.addStretch()
        layout.addLayout(toolbar)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setRootIsDecorated(grouped)
        self.tree.setIndentation(14 if grouped else 0)
        self.tree.setUniformRowHeights(True)
        self.tree.itemSelectionChanged.connect(self._on_selection)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self.tree, 1)
        for icon_name, _tooltip, callback in actions:
            if icon_name == "trash":
                shortcut = QShortcut(QKeySequence(QKeySequence.StandardKey.Delete), self.tree)
                shortcut.setContext(Qt.ShortcutContext.WidgetShortcut)
                shortcut.activated.connect(callback)

    def set_entries(self, entries: list[ListEntry]) -> None:
        self._entries = entries
        self._rebuild()

    def current_id(self) -> str | None:
        item = self.tree.currentItem()
        if item is None:
            return None
        value = item.data(0, ID_ROLE)
        return str(value) if value else None

    def select(self, entry_id: str | None) -> None:
        if entry_id is None:
            self.tree.clearSelection()
            return
        iterator = [self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount())]
        while iterator:
            item = iterator.pop(0)
            if item is None:
                continue
            if item.data(0, ID_ROLE) == entry_id:
                self.tree.setCurrentItem(item)
                return
            iterator.extend(item.child(i) for i in range(item.childCount()))

    def focus_search(self) -> None:
        self.search.setFocus()
        self.search.selectAll()

    def _matches(self, entry: ListEntry, needle: str) -> bool:
        return not needle or any(needle in value.lower() for value in (entry.name, entry.group, entry.detail))

    def _rebuild(self) -> None:
        current = self.current_id()
        self._suppress = True
        self.tree.clear()
        needle = self.search.text().strip().lower()
        entries = [e for e in self._entries if self._matches(e, needle)]
        entries.sort(key=lambda e: (not e.favorite, e.name.lower()))
        groups: dict[str, QTreeWidgetItem] = {}
        muted = current_tokens().muted
        for entry in entries:
            item = QTreeWidgetItem([("★ " if entry.favorite else "") + entry.name])
            item.setData(0, ID_ROLE, entry.id)
            item.setToolTip(0, entry.detail or entry.name)
            item.setIcon(0, dot_icon(entry.status_color) if entry.status_color else dot_icon("#00000000"))
            group_name = entry.group.strip() if self._grouped else ""
            if group_name:
                parent = groups.get(group_name.lower())
                if parent is None:
                    parent = QTreeWidgetItem([group_name])
                    parent.setFlags(parent.flags() & ~Qt.ItemFlag.ItemIsSelectable)
                    parent.setForeground(0, muted_brush(muted))
                    groups[group_name.lower()] = parent
                    self.tree.addTopLevelItem(parent)
                    parent.setExpanded(True)
                parent.addChild(item)
            else:
                self.tree.addTopLevelItem(item)
        self._suppress = False
        if current:
            self.select(current)

    def group_menu(self, pos: QPoint) -> QMenu | None:
        """Menu contextuel du titre de groupe situé en `pos`, ou None s'il n'y en a pas."""
        item = self.tree.itemAt(pos)
        if item is None or item.data(0, ID_ROLE) or self._group_actions is None:
            return None
        entries = self._group_actions(item.text(0))
        if not entries:
            return None
        menu = QMenu(self)
        for icon_name, text, callback in entries:
            menu.addAction(icon(icon_name), text, callback)
        return menu

    def _context_menu(self, pos: QPoint) -> None:
        menu = self.group_menu(pos)
        if menu is not None:
            menu.exec(self.tree.viewport().mapToGlobal(pos))
            menu.deleteLater()

    def _on_selection(self) -> None:
        if not self._suppress:
            self.selected.emit(self.current_id() or "")


def muted_brush(color: str) -> QBrush:
    return QBrush(QColor(color))


def ask_unsaved(parent: QWidget, name: str) -> str:
    """« save », « discard » ou « cancel »."""
    box = QMessageBox(parent)
    box.setWindowTitle(tr("Modifications non enregistrées"))
    box.setText(tr("Le profil « {name} » a des modifications non enregistrées.").format(name=name))
    save = box.addButton(tr("Enregistrer"), QMessageBox.ButtonRole.AcceptRole)
    discard = box.addButton(tr("Abandonner"), QMessageBox.ButtonRole.DestructiveRole)
    box.addButton(tr("Annuler"), QMessageBox.ButtonRole.RejectRole)
    box.setDefaultButton(save)
    box.exec()
    clicked = box.clickedButton()
    if clicked is save:
        return "save"
    if clicked is discard:
        return "discard"
    return "cancel"


def confirm(parent: QWidget, heading: str, text: str) -> bool:
    return QMessageBox.question(parent, heading, text) == QMessageBox.StandardButton.Yes
