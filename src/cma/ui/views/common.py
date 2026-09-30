"""Éléments communs aux vues liste–détail : liste groupée et filtrable, confirmations (§4.0, §4.3, §4.21)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLineEdit,
    QMenu,
    QMessageBox,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.i18n import tr
from cma.ui.icons import dot_icon, token_icon
from cma.ui.theme import current_tokens
from cma.ui.widgets import primary_button, tool_button

ID_ROLE = Qt.ItemDataRole.UserRole
GROUP_ROLE = Qt.ItemDataRole.UserRole + 1

Action = tuple[str, str, Callable[[], None]]


@dataclass(frozen=True)
class ListEntry:
    id: str
    name: str
    group: str = ""
    favorite: bool = False
    status_color: str | None = None
    detail: str = ""
    status_text: str = ""


class ProfileList(QWidget):
    """Liste de gauche : recherche, « Nouveau… », menu « ⋯ », groupes repliables avec leur compte.

    - Les favoris sont en tête de leur groupe, les autres triés par nom.
    - L'action d'icône « trash » répond aussi à la touche Suppr, seulement quand l'arbre a le focus.
    - Clic droit sur un groupe : `group_actions` ; sur un objet : `item_actions` (même contenu que « ⋯ »).
    """

    selected = Signal(str)

    def __init__(
        self,
        placeholder: str,
        actions: list[Action],
        *,
        grouped: bool = True,
        name: str = "",
        new_action: tuple[str, Callable[[], None]] | None = None,
        group_actions: Callable[[str], list[Action]] | None = None,
        item_actions: Callable[[str], list[Action]] | None = None,
    ) -> None:
        super().__init__()
        self._group_actions = group_actions
        self._item_actions = item_actions
        self._grouped = grouped
        self._entries: list[ListEntry] = []
        self._suppress = False
        self.setMinimumWidth(216)
        self.setMaximumWidth(360)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText(placeholder)
        self.search.setAccessibleName(placeholder)
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(lambda _t: self._rebuild())
        layout.addWidget(self.search)
        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        if new_action is not None:
            self.new_button = primary_button(new_action[0], "plus")
            self.new_button.clicked.connect(new_action[1])
            toolbar.addWidget(self.new_button, 1)
        self.more_button = tool_button("dots", tr("Actions sur la liste"), flat=False)
        self.more_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.actions_menu = QMenu(self.more_button)
        for icon_name, text, callback in actions:
            self.actions_menu.addAction(token_icon(icon_name), text, callback)
        self.more_button.setMenu(self.actions_menu)
        toolbar.addWidget(self.more_button)
        if new_action is None:
            toolbar.addStretch()
        layout.addLayout(toolbar)
        self.tree = QTreeWidget()
        self.tree.setAccessibleName(name or placeholder)
        self.tree.setHeaderHidden(True)
        self.tree.setRootIsDecorated(grouped)
        self.tree.setIndentation(16 if grouped else 0)
        self.tree.setUniformRowHeights(True)
        self.tree.itemSelectionChanged.connect(self._on_selection)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self.tree, 1)
        for icon_name, _text, callback in actions:
            if icon_name == "trash":
                shortcut = QShortcut(QKeySequence(QKeySequence.StandardKey.Delete), self.tree)
                shortcut.setContext(Qt.ShortcutContext.WidgetShortcut)
                shortcut.activated.connect(callback)
        menu_shortcut = QShortcut(QKeySequence("Shift+F10"), self.tree)
        menu_shortcut.setContext(Qt.ShortcutContext.WidgetShortcut)
        menu_shortcut.activated.connect(self._keyboard_menu)

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
        counts: dict[str, int] = {}
        muted = current_tokens().muted
        for entry in entries:
            item = QTreeWidgetItem([("★ " if entry.favorite else "") + entry.name])
            item.setData(0, ID_ROLE, entry.id)
            item.setToolTip(0, entry.detail or entry.name)
            description = ", ".join(
                part
                for part in (tr("favori") if entry.favorite else "", entry.status_text, entry.detail)
                if part
            )
            item.setData(0, Qt.ItemDataRole.AccessibleDescriptionRole, description)
            item.setIcon(0, dot_icon(entry.status_color) if entry.status_color else dot_icon("#00000000"))
            group_name = entry.group.strip() if self._grouped else ""
            if group_name:
                key = group_name.lower()
                parent = groups.get(key)
                if parent is None:
                    parent = QTreeWidgetItem([group_name])
                    parent.setData(0, GROUP_ROLE, group_name)
                    parent.setFlags(parent.flags() & ~Qt.ItemFlag.ItemIsSelectable)
                    parent.setForeground(0, muted_brush(muted))
                    groups[key] = parent
                    self.tree.addTopLevelItem(parent)
                    parent.setExpanded(True)
                parent.addChild(item)
                counts[key] = counts.get(key, 0) + 1
            else:
                self.tree.addTopLevelItem(item)
        for key, parent in groups.items():
            parent.setText(0, f"{parent.data(0, GROUP_ROLE)} ({counts[key]})")
        if needle and not entries:
            empty = QTreeWidgetItem([tr("Aucun résultat pour cette recherche.")])
            empty.setFlags(Qt.ItemFlag.NoItemFlags)
            self.tree.addTopLevelItem(empty)
        # La sélection est restaurée sans émettre `selected` : ce n'est pas un choix de l'utilisateur.
        # Émettre ici relançait la question « modifications non enregistrées » pendant l'enregistrement
        # lui-même, en boucle jusqu'au plantage.
        if current:
            self.select(current)
        self._suppress = False

    def _menu_for(self, entries: list[Action]) -> QMenu | None:
        if not entries:
            return None
        menu = QMenu(self)
        for icon_name, text, callback in entries:
            menu.addAction(token_icon(icon_name), text, callback)
        return menu

    def group_menu(self, pos: QPoint) -> QMenu | None:
        """Menu contextuel du titre de groupe situé en `pos`, ou None s'il n'y en a pas."""
        item = self.tree.itemAt(pos)
        if item is None or item.data(0, ID_ROLE) or self._group_actions is None:
            return None
        group = item.data(0, GROUP_ROLE)
        if not group:
            return None
        return self._menu_for(self._group_actions(str(group)))

    def item_menu(self, pos: QPoint) -> QMenu | None:
        """Menu contextuel de l'objet situé en `pos` (mêmes actions que « ⋯ » pour cet objet)."""
        item = self.tree.itemAt(pos)
        entry_id = item.data(0, ID_ROLE) if item is not None else None
        if not entry_id or self._item_actions is None:
            return None
        return self._menu_for(self._item_actions(str(entry_id)))

    def _context_menu(self, pos: QPoint) -> None:
        item = self.tree.itemAt(pos)
        if item is not None and item.data(0, ID_ROLE):
            self.tree.setCurrentItem(item)
        menu = self.group_menu(pos) or self.item_menu(pos)
        if menu is not None:
            menu.exec(self.tree.viewport().mapToGlobal(pos))
            menu.deleteLater()

    def _keyboard_menu(self) -> None:
        item = self.tree.currentItem()
        if item is not None:
            self._context_menu(self.tree.visualItemRect(item).center())

    def _on_selection(self) -> None:
        if not self._suppress:
            self.selected.emit(self.current_id() or "")


def muted_brush(color: str) -> QBrush:
    return QBrush(QColor(color))


def ask_unsaved(parent: QWidget, name: str) -> str:
    """« Enregistrer les modifications ? » : « save », « discard » ou « cancel » (§4.21)."""
    box = QMessageBox(parent)
    box.setWindowTitle(tr("Enregistrer les modifications ?"))
    box.setIcon(QMessageBox.Icon.Question)
    box.setText(tr("Enregistrer les modifications ?"))
    box.setInformativeText(tr("« {name} » a été modifié.").format(name=name))
    box.addButton(tr("Annuler"), QMessageBox.ButtonRole.RejectRole)
    discard = box.addButton(tr("Abandonner"), QMessageBox.ButtonRole.DestructiveRole)
    save = box.addButton(tr("Enregistrer"), QMessageBox.ButtonRole.AcceptRole)
    box.setDefaultButton(save)
    box.exec()
    clicked = box.clickedButton()
    if clicked is save:
        return "save"
    if clicked is discard:
        return "discard"
    return "cancel"


def confirm(parent: QWidget, heading: str, text: str, action: str | None = None) -> bool:
    """Confirmation d'une action : « Annuler » par défaut, l'action nommée par son verbe (§4.21)."""
    box = QMessageBox(parent)
    box.setWindowTitle(heading)
    box.setIcon(QMessageBox.Icon.Question)
    box.setText(heading)
    box.setInformativeText(text)
    cancel = box.addButton(tr("Annuler"), QMessageBox.ButtonRole.RejectRole)
    proceed = box.addButton(action or tr("Confirmer"), QMessageBox.ButtonRole.DestructiveRole)
    box.setDefaultButton(cancel)
    box.setEscapeButton(cancel)
    box.exec()
    return box.clickedButton() is proceed
