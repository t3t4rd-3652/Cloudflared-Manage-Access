"""Rendu de la vue Cloudflare : tuiles de chiffres clés et tunnels dessinés en cartes.

Le `QTreeWidget` reste le modèle de données et de sélection ; seul le délégué change le rendu.
"""

from __future__ import annotations

from PySide6.QtCore import (
    QModelIndex,
    QPersistentModelIndex,
    QPointF,
    QRect,
    QRectF,
    QSize,
    Qt,
    Signal,
)
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontMetrics,
    QMouseEvent,
    QPainter,
    QPen,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTreeWidget,
    QVBoxLayout,
)

from cma.core.cfapi import IngressRule, Tunnel
from cma.i18n import tr
from cma.ui.icons import icon, set_glyph
from cma.ui.theme import current_tokens, mono_font, status_colors
from cma.ui.views.cloud.helpers import tunnel_state
from cma.ui.widgets import label

TUNNEL_ROLE = 256
RULE_ROLE = 257
PROTECTED_ROLE = 258
PROFILE_ROLE = 259
TOKEN_ROLE = 260  # tableau des service tokens du compte

# Géométrie des cartes de tunnel.
CARD_GAP = 12
CARD_RADIUS = 10.0
CARD_PADDING = 8
HEADER_HEIGHT = 62
HOST_HEIGHT = 44
TEXT_LEFT = 88
CHEVRON_ZONE = 36


DATABASE_PORTS = {"1433", "1521", "3306", "5432", "6379", "27017"}


def service_icon(service: str) -> str:
    """Icône d'un service publié, d'après son schéma (ssh://, rdp://, http://…) et son port."""
    scheme, _, rest = service.partition("://")
    scheme = scheme.lower()
    if scheme == "tcp" and rest.rsplit(":", 1)[-1].strip("/") in DATABASE_PORTS:
        return "database"
    return {
        "ssh": "terminal-2",
        "rdp": "device-desktop",
        "http": "world-www",
        "https": "world-www",
        "smb": "folder",
        "tcp": "plug-connected",
        "unix": "plug-connected",
    }.get(scheme, "link")


class StatTile(QFrame):
    """Chiffre clé du compte (tunnels, noms d'hôte…) ; un clic ouvre l'onglet correspondant."""

    clicked = Signal()

    def __init__(self, icon_name: str, caption: str) -> None:
        super().__init__()
        self.setProperty("role", "tile")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumWidth(150)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)
        self.glyph = QLabel()
        set_glyph(self.glyph, icon_name, "accent", 24)
        layout.addWidget(self.glyph, 0, Qt.AlignmentFlag.AlignTop)
        texts = QVBoxLayout()
        texts.setSpacing(0)
        self.value = QLabel("—")
        self.value.setStyleSheet("font-size: 18pt; font-weight: 600;")
        self.caption = label(caption, "muted")
        self.detail = label("", "meta")
        texts.addWidget(self.value)
        texts.addWidget(self.caption)
        texts.addWidget(self.detail)
        layout.addLayout(texts, 1)
        self._caption = caption

    def set_values(self, value: int | None, detail: str = "", tone: str | None = None) -> None:
        self.value.setText("—" if value is None else str(value))
        self.detail.setText(detail)
        self.detail.setVisible(bool(detail))
        if tone is not None:
            self.detail.setStyleSheet(f"color: {status_colors(tone, current_tokens())[0]};")
        else:
            self.detail.setStyleSheet("")
        self.setAccessibleName(f"{self._caption} : {self.value.text()}" + (f", {detail}" if detail else ""))

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class TunnelTree(QTreeWidget):
    """Arbre des tunnels présenté en cartes : un tunnel par carte, ses noms d'hôte en lignes."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("CardTree")
        self.setColumnCount(3)
        self.setHeaderHidden(True)
        self.setRootIsDecorated(False)
        self.setIndentation(0)
        self.setUniformRowHeights(False)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setMouseTracking(True)
        self.viewport().setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        # Le service et l'état restent des colonnes (lecture, tests) mais la carte les dessine elle-même.
        self.setColumnHidden(1, True)
        self.setColumnHidden(2, True)
        self.setItemDelegate(TunnelDelegate(self))

    def mousePressEvent(self, event: QMouseEvent) -> None:
        position = event.position().toPoint()
        item = self.itemAt(position)
        if (
            event.button() == Qt.MouseButton.LeftButton
            and item is not None
            and item.parent() is None
            and item.childCount()
            and position.x() < CHEVRON_ZONE
        ):
            item.setExpanded(not item.isExpanded())
        super().mousePressEvent(event)


def _is_last_child(index: QModelIndex | QPersistentModelIndex) -> bool:
    parent = index.parent()
    return parent.isValid() and index.row() == index.model().rowCount(parent) - 1


def _resized(font: QFont, delta: float, weight: QFont.Weight | None = None) -> QFont:
    result = QFont(font)
    result.setPointSizeF(max(7.5, font.pointSizeF() + delta))
    if weight is not None:
        result.setWeight(weight)
    return result


class TunnelDelegate(QStyledItemDelegate):
    """Dessine chaque tunnel comme une carte : en-tête (état, nom, résumé), puis une ligne par nom d'hôte.

    La carte s'étend sur plusieurs lignes de l'arbre : chaque ligne dessine sa part du même rectangle
    arrondi, prolongé au-delà de ses bords quand la carte continue, et rogné à la ligne.
    """

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> QSize:
        if not index.parent().isValid():
            return QSize(0, HEADER_HEIGHT + (CARD_GAP if index.row() else 0))
        return QSize(0, HOST_HEIGHT + (CARD_PADDING if _is_last_child(index) else 0))

    def paint(
        self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex
    ) -> None:
        tokens = current_tokens()
        rect = QRect(option.rect)  # type: ignore[attr-defined]
        state = option.state  # type: ignore[attr-defined]
        font = QFont(option.font)  # type: ignore[attr-defined]
        top_level = not index.parent().isValid()
        view = self.parent()
        children = index.model().rowCount(index) if top_level else 0
        expanded = top_level and isinstance(view, QTreeWidget) and view.isExpanded(index)
        if top_level:
            band = QRect(
                rect.left(), rect.top() + (CARD_GAP if index.row() else 0), rect.width(), HEADER_HEIGHT
            )
            open_below = expanded and children > 0
        else:
            band = QRect(rect.left(), rect.top(), rect.width(), HOST_HEIGHT)
            open_below = not _is_last_child(index)
        reach = int(2 * CARD_RADIUS)
        top = band.top() if top_level else rect.top() - reach
        bottom = rect.bottom() + reach if open_below else rect.bottom()
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setClipRect(rect)
        painter.setPen(QPen(QColor(tokens.border), 1))
        painter.setBrush(QColor(tokens.surface))
        card = QRectF(rect.left() + 1.5, top + 0.5, rect.width() - 3, bottom - top)
        painter.drawRoundedRect(card, CARD_RADIUS, CARD_RADIUS)
        inner = QRectF(band).adjusted(6, 4 if top_level else 2, -6, -4 if top_level else -2)
        if state & QStyle.StateFlag.State_Selected:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(tokens.selected))
            painter.drawRoundedRect(inner, 6, 6)
            painter.setBrush(QColor(tokens.accent))
            painter.drawRoundedRect(QRectF(inner.left(), inner.top() + 7, 3, inner.height() - 14), 1.5, 1.5)
        elif state & QStyle.StateFlag.State_MouseOver:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(tokens.hover))
            painter.drawRoundedRect(inner, 6, 6)
        if state & QStyle.StateFlag.State_HasFocus:
            painter.setPen(QPen(QColor(tokens.focus), 1))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(inner.adjusted(0.5, 0.5, -0.5, -0.5), 6, 6)
        if top_level:
            self._paint_tunnel(painter, band, font, index, children, expanded)
        else:
            self._paint_host(painter, band, font, index)
        painter.restore()

    def _paint_tunnel(
        self,
        painter: QPainter,
        band: QRect,
        font: QFont,
        index: QModelIndex | QPersistentModelIndex,
        children: int,
        expanded: bool,
    ) -> None:
        tokens = current_tokens()
        tunnel = index.data(TUNNEL_ROLE)
        text, tone, symbol = tunnel_state(tunnel.status if isinstance(tunnel, Tunnel) else "")
        fg, bg = status_colors(tone, tokens)
        middle = band.center().y()
        if children:
            chevron = "chevron-down" if expanded else "chevron-right"
            icon(chevron, tokens.muted).paint(painter, QRect(band.left() + 14, middle - 8, 16, 16))
        tile = QRectF(band.left() + 38, middle - 18, 36, 36)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(bg))
        painter.drawRoundedRect(tile, 9, 9)
        icon("cloud", fg).paint(painter, tile.toRect().adjusted(8, 8, -8, -8))
        pill_font = _resized(font, -0.5, QFont.Weight.DemiBold)
        pill_text = f"{symbol} {text}"
        pill_width = QFontMetrics(pill_font).horizontalAdvance(pill_text) + 24
        pill = QRectF(band.right() - 16 - pill_width, middle - 12, pill_width, 24)
        painter.drawRoundedRect(pill, 12, 12)
        painter.setFont(pill_font)
        painter.setPen(QColor(fg))
        painter.drawText(pill, Qt.AlignmentFlag.AlignCenter, pill_text)
        left = band.left() + TEXT_LEFT
        width = max(0, int(pill.left()) - 12 - left)
        name_font = _resized(font, 1.5, QFont.Weight.DemiBold)
        meta_font = _resized(font, -0.5)
        name_metrics, meta_metrics = QFontMetrics(name_font), QFontMetrics(meta_font)
        y = middle - (name_metrics.height() + meta_metrics.height() + 2) // 2
        painter.setFont(name_font)
        painter.setPen(QColor(tokens.text))
        name = name_metrics.elidedText(str(index.data()), Qt.TextElideMode.ElideRight, width)
        painter.drawText(QRect(left, y, width, name_metrics.height()), Qt.AlignmentFlag.AlignVCenter, name)
        painter.setFont(meta_font)
        painter.setPen(QColor(tokens.muted))
        summary = meta_metrics.elidedText(
            str(index.model().index(index.row(), 1, index.parent()).data() or ""),
            Qt.TextElideMode.ElideRight,
            width,
        )
        y += name_metrics.height() + 2
        painter.drawText(QRect(left, y, width, meta_metrics.height()), Qt.AlignmentFlag.AlignVCenter, summary)
        if expanded and children:
            painter.setPen(QPen(QColor(tokens.border), 1))
            line = band.bottom() + 0.5
            painter.drawLine(QPointF(band.left() + 16, line), QPointF(band.right() - 16, line))

    def _paint_host(
        self, painter: QPainter, band: QRect, font: QFont, index: QModelIndex | QPersistentModelIndex
    ) -> None:
        tokens = current_tokens()
        rule = index.data(RULE_ROLE)
        service = rule.service if isinstance(rule, IngressRule) else ""
        middle = band.center().y()
        tile = QRectF(band.left() + 42, middle - 14, 28, 28)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(tokens.window))
        painter.drawRoundedRect(tile, 7, 7)
        icon(service_icon(service), tokens.muted).paint(painter, tile.toRect().adjusted(6, 6, -6, -6))
        badge_font = _resized(font, -1.0, QFont.Weight.DemiBold)
        badge_metrics = QFontMetrics(badge_font)
        badges: list[tuple[str, str, str]] = []
        if index.data(PROFILE_ROLE):
            badges.append((tr("Profil CMA"), "circle-check", "info"))
        if index.data(PROTECTED_ROLE):
            badges.append((tr("Access"), "shield-check", "success"))
        else:
            badges.append((tr("Non protégé"), "alert-triangle", "warning"))
        x = band.right() - 16
        painter.setFont(badge_font)
        for text, name, tone in reversed(badges):
            fg, bg = status_colors(tone, tokens)
            width = badge_metrics.horizontalAdvance(text) + 34
            badge = QRectF(x - width, middle - 11, width, 22)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(bg))
            painter.drawRoundedRect(badge, 11, 11)
            icon(name, fg).paint(painter, QRect(int(badge.left()) + 9, middle - 7, 14, 14))
            painter.setPen(QColor(fg))
            painter.drawText(badge.adjusted(27, 0, -8, 0), Qt.AlignmentFlag.AlignVCenter, text)
            x = int(badge.left()) - 6
        left = band.left() + TEXT_LEFT
        column = left + int((band.right() - 16 - left) * 0.42)
        host_width = max(0, column - 16 - left)
        painter.setFont(font)
        painter.setPen(QColor(tokens.text))
        host = QFontMetrics(font).elidedText(str(index.data()), Qt.TextElideMode.ElideMiddle, host_width)
        painter.drawText(
            QRect(left, band.top(), host_width, band.height()), Qt.AlignmentFlag.AlignVCenter, host
        )
        mono = mono_font(9.0)
        service_width = max(0, x - 12 - column)
        service = QFontMetrics(mono).elidedText(service, Qt.TextElideMode.ElideMiddle, service_width)
        painter.setFont(mono)
        painter.setPen(QColor(tokens.muted))
        painter.drawText(
            QRect(column, band.top(), service_width, band.height()), Qt.AlignmentFlag.AlignVCenter, service
        )


# --- Vue ----------------------------------------------------------------------------------------------------
