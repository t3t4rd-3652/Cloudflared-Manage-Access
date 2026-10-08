"""Éléments communs aux vues liste–détail : liste en cartes, en-tête d'objet, sections de formulaire, confirmations
(§4.0, §4.3, §4.21).

La liste reste un `QTreeWidget` (modèle de données, sélection, menus et tests s'appuient dessus) : seul le rendu
change, comme pour les tunnels de la vue Cloudflare. Chaque objet est une ligne-carte (pictogramme teinté par
l'état, nom, état en toutes lettres et détail technique) ; les groupes sont des intertitres repliables.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtCore import QModelIndex, QPersistentModelIndex, QPoint, QRect, QRectF, QSize, Qt, Signal
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QKeySequence,
    QMouseEvent,
    QPainter,
    QPen,
    QResizeEvent,
    QShortcut,
)
from PySide6.QtWidgets import (
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QScrollArea,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.models import ServiceType
from cma.i18n import tr
from cma.ui.icons import icon, set_glyph, token_icon
from cma.ui.theme import current_tokens, status_colors
from cma.ui.widgets import StatusPill, clear_items, label, primary_button, set_status, title, tool_button

ID_ROLE = Qt.ItemDataRole.UserRole
GROUP_ROLE = Qt.ItemDataRole.UserRole + 1
ENTRY_ROLE = Qt.ItemDataRole.UserRole + 2
COUNT_ROLE = Qt.ItemDataRole.UserRole + 3

# Géométrie des lignes de la liste.
ENTRY_HEIGHT = 58
GROUP_HEIGHT = 34
TILE_SIZE = 36

Action = tuple[str, str, Callable[[], None]]

SERVICE_ICONS = {
    ServiceType.SSH: "terminal-2",
    ServiceType.RDP: "device-desktop",
    ServiceType.SMB: "folder",
    ServiceType.MONGODB: "database",
    ServiceType.POSTGRESQL: "database",
    ServiceType.MYSQL: "database",
    ServiceType.REDIS: "database",
    ServiceType.HTTP: "world",
    ServiceType.HTTPS: "world",
}


@dataclass(frozen=True)
class ListEntry:
    id: str
    name: str
    group: str = ""
    favorite: bool = False
    tone: str | None = None  # teinte d'état : success, info, warning, danger ; None au repos
    detail: str = ""
    status_text: str = ""
    icon: str = "circle-filled"


class EntryTree(QTreeWidget):
    """Arbre de la liste : un clic sur un intertitre de groupe le replie ou le déplie."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("EntryList")
        self.setHeaderHidden(True)
        self.setRootIsDecorated(False)
        self.setIndentation(0)
        self.setUniformRowHeights(False)
        self.setExpandsOnDoubleClick(False)
        self.setMouseTracking(True)
        self.viewport().setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollMode(QTreeWidget.ScrollMode.ScrollPerPixel)
        self.setItemDelegate(EntryDelegate(self))

    def mousePressEvent(self, event: QMouseEvent) -> None:
        item = self.itemAt(event.position().toPoint())
        if (
            event.button() == Qt.MouseButton.LeftButton
            and item is not None
            and item.data(0, GROUP_ROLE)
            and not item.data(0, ID_ROLE)
        ):
            item.setExpanded(not item.isExpanded())
        super().mousePressEvent(event)


def _resized(font: QFont, delta: float, weight: QFont.Weight | None = None) -> QFont:
    result = QFont(font)
    result.setPointSizeF(max(7.5, font.pointSizeF() + delta))
    if weight is not None:
        result.setWeight(weight)
    return result


class EntryDelegate(QStyledItemDelegate):
    """Dessine les objets en lignes-cartes et les groupes en intertitres (nom, nombre, chevron)."""

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> QSize:
        if index.data(ENTRY_ROLE) is not None:
            return QSize(0, ENTRY_HEIGHT)
        if index.data(GROUP_ROLE):
            return QSize(0, GROUP_HEIGHT + (6 if index.row() else 0))
        return QSize(0, 40)

    def paint(
        self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex
    ) -> None:
        rect = QRect(option.rect)  # type: ignore[attr-defined]
        font = QFont(option.font)  # type: ignore[attr-defined]
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setClipRect(rect)
        entry = index.data(ENTRY_ROLE)
        if isinstance(entry, ListEntry):
            self._paint_entry(painter, rect, font, option.state, entry)  # type: ignore[attr-defined]
        elif index.data(GROUP_ROLE):
            self._paint_group(painter, rect, font, index)
        else:
            painter.setPen(QColor(current_tokens().muted))
            painter.setFont(font)
            painter.drawText(
                rect.adjusted(12, 0, -12, 0),
                Qt.AlignmentFlag.AlignVCenter | Qt.TextFlag.TextWordWrap,
                str(index.data() or ""),
            )
        painter.restore()

    def _paint_group(
        self, painter: QPainter, rect: QRect, font: QFont, index: QModelIndex | QPersistentModelIndex
    ) -> None:
        tokens = current_tokens()
        band = QRect(rect.left(), rect.bottom() - GROUP_HEIGHT + 1, rect.width(), GROUP_HEIGHT)
        middle = band.center().y()
        view = self.parent()
        expanded = isinstance(view, QTreeWidget) and view.isExpanded(index)
        icon("chevron-down" if expanded else "chevron-right", tokens.muted).paint(
            painter, QRect(band.left() + 8, middle - 7, 14, 14)
        )
        group_font = _resized(font, -1.0, QFont.Weight.DemiBold)
        metrics = QFontMetrics(group_font)
        count = str(index.data(COUNT_ROLE) or "")
        count_width = metrics.horizontalAdvance(count) + 14 if count else 0
        left = band.left() + 28
        width = max(0, band.right() - 10 - left - count_width - 8)
        name = metrics.elidedText(str(index.data(GROUP_ROLE)).upper(), Qt.TextElideMode.ElideRight, width)
        painter.setFont(group_font)
        painter.setPen(QColor(tokens.muted))
        painter.drawText(QRect(left, band.top(), width, band.height()), Qt.AlignmentFlag.AlignVCenter, name)
        if count:
            x = left + metrics.horizontalAdvance(name) + 8
            pill = QRectF(x, middle - 9, count_width, 18)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(tokens.neutral_bg))
            painter.drawRoundedRect(pill, 9, 9)
            painter.setPen(QColor(tokens.muted))
            painter.drawText(pill, Qt.AlignmentFlag.AlignCenter, count)

    def _paint_entry(
        self, painter: QPainter, rect: QRect, font: QFont, state: QStyle.StateFlag, entry: ListEntry
    ) -> None:
        tokens = current_tokens()
        inner = QRectF(rect).adjusted(4, 2, -4, -2)
        if state & QStyle.StateFlag.State_Selected:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(tokens.selected))
            painter.drawRoundedRect(inner, 8, 8)
            painter.setBrush(QColor(tokens.accent))
            painter.drawRoundedRect(QRectF(inner.left(), inner.top() + 10, 3, inner.height() - 20), 1.5, 1.5)
        elif state & QStyle.StateFlag.State_MouseOver:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(tokens.hover))
            painter.drawRoundedRect(inner, 8, 8)
        if state & QStyle.StateFlag.State_HasFocus:
            painter.setPen(QPen(QColor(tokens.focus), 1))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(inner.adjusted(0.5, 0.5, -0.5, -0.5), 8, 8)
        middle = int(inner.center().y())
        fg, bg = status_colors(entry.tone, tokens) if entry.tone else (tokens.accent, tokens.neutral_bg)
        tile = QRectF(inner.left() + 10, middle - TILE_SIZE / 2, TILE_SIZE, TILE_SIZE)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(bg))
        painter.drawRoundedRect(tile, 9, 9)
        icon(entry.icon, fg).paint(painter, tile.toRect().adjusted(8, 8, -8, -8))
        left = int(tile.right()) + 12
        width = max(0, int(inner.right()) - 10 - left)
        name_font = _resized(font, 0.5, QFont.Weight.DemiBold)
        meta_font = _resized(font, -1.0)
        name_metrics, meta_metrics = QFontMetrics(name_font), QFontMetrics(meta_font)
        y = middle - (name_metrics.height() + meta_metrics.height() + 2) // 2
        star = 18 if entry.favorite else 0
        name = name_metrics.elidedText(entry.name, Qt.TextElideMode.ElideRight, max(0, width - star))
        painter.setFont(name_font)
        painter.setPen(QColor(tokens.text))
        painter.drawText(QRect(left, y, width, name_metrics.height()), Qt.AlignmentFlag.AlignVCenter, name)
        if entry.favorite:
            x = left + name_metrics.horizontalAdvance(name) + 5
            top = y + (name_metrics.height() - 13) // 2
            icon("star-filled", tokens.warning).paint(painter, QRect(x, top, 13, 13))
        y += name_metrics.height() + 2
        painter.setFont(meta_font)
        x = left
        if entry.status_text:
            status = meta_metrics.elidedText(f"● {entry.status_text}", Qt.TextElideMode.ElideRight, width)
            painter.setPen(QColor(fg if entry.tone else tokens.muted))
            painter.drawText(QRect(x, y, width, meta_metrics.height()), Qt.AlignmentFlag.AlignVCenter, status)
            x += meta_metrics.horizontalAdvance(status)
        if entry.detail and x < left + width:
            detail = (" · " if entry.status_text else "") + entry.detail
            detail = meta_metrics.elidedText(detail, Qt.TextElideMode.ElideMiddle, left + width - x)
            painter.setPen(QColor(tokens.muted))
            painter.drawText(
                QRect(x, y, left + width - x, meta_metrics.height()), Qt.AlignmentFlag.AlignVCenter, detail
            )


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
        self.setMinimumWidth(240)
        self.setMaximumWidth(380)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(8)
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
        self.search = QLineEdit()
        self.search.setPlaceholderText(placeholder)
        self.search.setAccessibleName(placeholder)
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(lambda _t: self._rebuild())
        layout.addWidget(self.search)
        self.tree = EntryTree()
        self.tree.setAccessibleName(name or placeholder)
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
        collapsed = {
            str(item.data(0, GROUP_ROLE)).lower()
            for item in (self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount()))
            if item is not None and item.data(0, GROUP_ROLE) and not item.isExpanded()
        }
        self._suppress = True
        clear_items(self.tree)
        needle = self.search.text().strip().lower()
        entries = [e for e in self._entries if self._matches(e, needle)]
        entries.sort(key=lambda e: (not e.favorite, e.name.lower()))
        groups: dict[str, QTreeWidgetItem] = {}
        counts: dict[str, int] = {}
        loose: list[QTreeWidgetItem] = []
        for entry in entries:
            item = QTreeWidgetItem([("★ " if entry.favorite else "") + entry.name])
            item.setData(0, ID_ROLE, entry.id)
            item.setData(0, ENTRY_ROLE, entry)
            item.setToolTip(0, entry.detail or entry.name)
            description = ", ".join(
                part
                for part in (tr("favori") if entry.favorite else "", entry.status_text, entry.detail)
                if part
            )
            item.setData(0, Qt.ItemDataRole.AccessibleDescriptionRole, description)
            group_name = entry.group.strip() if self._grouped else ""
            if group_name:
                key = group_name.lower()
                parent = groups.get(key)
                if parent is None:
                    parent = QTreeWidgetItem([group_name])
                    parent.setData(0, GROUP_ROLE, group_name)
                    parent.setFlags(parent.flags() & ~Qt.ItemFlag.ItemIsSelectable)
                    groups[key] = parent
                    self.tree.addTopLevelItem(parent)
                    parent.setExpanded(key not in collapsed or bool(needle))
                parent.addChild(item)
                counts[key] = counts.get(key, 0) + 1
            else:
                loose.append(item)
        # Les objets sans groupe viennent en tête, avant les intertitres.
        for position, item in enumerate(loose):
            self.tree.insertTopLevelItem(position, item)
        for key, parent in groups.items():
            parent.setText(0, f"{parent.data(0, GROUP_ROLE)} ({counts[key]})")
            parent.setData(0, COUNT_ROLE, counts[key])
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


# --- Page et éditeur ------------------------------------------------------------------------------------


def page_header(layout: QVBoxLayout, heading: str, subtitle: str) -> None:
    """Titre de page et phrase d'explication, communs aux vues liste–détail."""
    layout.addWidget(title(heading))
    layout.addWidget(label(subtitle, "muted", wrap=True))
    layout.addSpacing(12)


class ObjectHeader(QFrame):
    """En-tête de l'objet sélectionné, en carte : pictogramme teinté par l'état, nom et pastille d'état, ligne
    technique (adresse, identifiant), ligne de contexte, puis les actions.

    Les actions sont à droite du texte, ou dessous quand la carte est trop étroite pour garder au nom et à
    l'adresse une largeur lisible (fenêtre réduite, grande échelle d'affichage).
    """

    # Largeur gardée au texte avant de passer les actions dessous : celle du nom et de l'adresse, bornée.
    TEXT_MIN, TEXT_MAX = 220, 360

    def __init__(self, icon_name: str) -> None:
        super().__init__()
        self.setObjectName("Card")
        self._icon = icon_name
        self._stacked: bool | None = None
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(16, 14, 16, 14)
        self.grid.setHorizontalSpacing(14)
        self.grid.setVerticalSpacing(10)
        self.grid.setColumnStretch(1, 1)
        self.tile = QLabel()
        self.tile.setProperty("role", "iconTile")
        self.tile.setFixedSize(48, 48)
        self.tile.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.grid.addWidget(self.tile, 0, 0, Qt.AlignmentFlag.AlignTop)
        texts = QVBoxLayout()
        texts.setSpacing(2)
        first = QHBoxLayout()
        first.setSpacing(10)
        self.title = title("", "ObjectTitle")
        self.pill = StatusPill()
        first.addWidget(self.title)
        first.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignVCenter)
        first.addStretch()
        texts.addLayout(first)
        self.subtitle = label("", "mono", wrap=True, selectable=True)
        self.context = label("", "meta", wrap=True)
        texts.addWidget(self.subtitle)
        texts.addWidget(self.context)
        # Un QLabel à retour à la ligne annonce une largeur minimale élevée : la carte ne pourrait plus rétrécir
        # (ni la fenêtre), et les actions ne passeraient jamais dessous.
        self.title.setWordWrap(False)
        self.title.setMinimumWidth(1)
        for text_label in (self.subtitle, self.context):
            text_label.setMinimumWidth(80)
        self.grid.addLayout(texts, 0, 1)
        self.action_host = QWidget()
        self.action_bar = QHBoxLayout(self.action_host)
        self.action_bar.setContentsMargins(0, 0, 0, 0)
        self.action_bar.setSpacing(8)
        self.set_tone(None)
        self.arrange()

    def add_action(self, widget: QWidget) -> None:
        self.action_bar.addWidget(widget, 0, Qt.AlignmentFlag.AlignVCenter)

    def set_icon(self, name: str, tone: str | None = None) -> None:
        self._icon = name
        self.set_tone(tone)

    def set_tone(self, tone: str | None) -> None:
        """Teinte du pictogramme : success, info, warning, danger, ou None (au repos, couleur d'accent)."""
        set_status(self.tile, tone or "idle")
        set_glyph(self.tile, self._icon, tone or "accent", 26)
        self.arrange()

    def arrange(self) -> None:
        """Actions à droite, ou sous le texte si la carte n'a pas la place (rappelé à chaque changement d'état,
        puisque les actions visibles en dépendent)."""
        stacked = self.width() < self.needed_width()
        if stacked == self._stacked:
            return
        self._stacked = stacked
        self.grid.removeWidget(self.action_host)
        if stacked:
            self.grid.addWidget(self.action_host, 1, 1, Qt.AlignmentFlag.AlignLeft)
        else:
            self.grid.addWidget(self.action_host, 0, 2, Qt.AlignmentFlag.AlignVCenter)

    def needed_width(self) -> int:
        """Largeur à partir de laquelle texte et actions tiennent sur une seule rangée."""
        margins = self.grid.contentsMargins()
        # Largeur des boutons visibles, calculée ici : la taille du conteneur n'est mise à jour qu'au prochain
        # passage de la boucle d'événements, après qu'un bouton a été masqué ou montré.
        widgets = (self.action_bar.itemAt(i) for i in range(self.action_bar.count()))
        buttons = [
            w for w in (item.widget() for item in widgets if item is not None) if w and not w.isHidden()
        ]
        spacing = self.action_bar.spacing() * max(0, len(buttons) - 1)
        actions = sum(w.sizeHint().width() for w in buttons) + spacing
        return (
            margins.left()
            + margins.right()
            + self.tile.width()
            + 2 * self.grid.horizontalSpacing()
            + self._text_width()
            + actions
        )

    def _text_width(self) -> int:
        name = self.title.fontMetrics().horizontalAdvance(self.title.text())
        pill = self.pill.sizeHint().width() + 10 if not self.pill.isHidden() else 0
        address = self.subtitle.fontMetrics().horizontalAdvance(self.subtitle.text())
        return max(self.TEXT_MIN, min(self.TEXT_MAX, max(name + pill, address)))

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self.arrange()


class FormCard(QFrame):
    """Section de formulaire en carte : intertitre, phrase d'aide facultative, champs à libellé au-dessus."""

    def __init__(self, heading: str, description: str = "") -> None:
        super().__init__()
        self.setProperty("role", "panel")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(18, 14, 18, 16)
        self.body.setSpacing(6)
        self.heading = title(heading, "SectionTitle")
        self.body.addWidget(self.heading)
        self.description = label(description, "muted", wrap=True)
        self.description.setVisible(bool(description))
        self.body.addWidget(self.description)
        self.form = new_form()
        self.body.addLayout(self.form)


def new_form() -> QFormLayout:
    form = QFormLayout()
    form.setContentsMargins(0, 4, 0, 0)
    form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
    form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
    form.setVerticalSpacing(6)
    return form


def side_by_side(*columns: tuple[str, QWidget, int]) -> QWidget:
    """Champs côte à côte, chacun avec son libellé au-dessus (une petite grille par colonne, nommée pour les
    lecteurs d'écran comme une ligne de formulaire ordinaire)."""
    host = QWidget()
    row = QHBoxLayout(host)
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(12)
    for text, widget, stretch in columns:
        form = new_form()
        form.setContentsMargins(0, 0, 0, 0)
        form.addRow(text, widget)
        row.addLayout(form, stretch)
    return host


def card_page(max_width: int = 760) -> tuple[QScrollArea, QVBoxLayout]:
    """Page défilante de cartes, largeur bornée ; l'appelant ajoute ses cartes puis un `addStretch()`."""
    scroll = QScrollArea()
    scroll.setObjectName("PageScroll")
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    host = QWidget()
    outer = QHBoxLayout(host)
    outer.setContentsMargins(0, 12, 12, 12)
    column = QWidget()
    column.setMaximumWidth(max_width)
    body = QVBoxLayout(column)
    body.setContentsMargins(0, 0, 0, 0)
    body.setSpacing(12)
    outer.addWidget(column, 1)
    outer.addStretch(0)
    scroll.setWidget(host)
    return scroll, body


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
