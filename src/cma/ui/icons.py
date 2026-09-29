"""Icônes SVG (Tabler Icons, licence MIT) teintées à la volée, et icône de l'application."""

from __future__ import annotations

from functools import lru_cache

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

from cma.paths import resource_path
from cma.ui.theme import ICON_COLOR

_SIZES = (16, 20, 24, 32, 40, 48, 64)


def _render(svg: bytes, size: int) -> QPixmap:
    renderer = QSvgRenderer(QByteArray(svg))
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter, QRectF(0, 0, size, size))
    painter.end()
    return pixmap


@lru_cache(maxsize=512)
def icon(name: str, color: str = ICON_COLOR) -> QIcon:
    path = resource_path("icons", f"{name}.svg")
    svg = path.read_text(encoding="utf-8").replace("currentColor", color).encode("utf-8")
    result = QIcon()
    for size in _SIZES:
        result.addPixmap(_render(svg, size))
    return result


@lru_cache(maxsize=1)
def app_icon() -> QIcon:
    svg = resource_path("app-icon.svg").read_bytes()
    result = QIcon()
    for size in (16, 20, 24, 32, 40, 48, 64, 96, 128, 256):
        result.addPixmap(_render(svg, size))
    return result


@lru_cache(maxsize=16)
def app_icon_with_status(color: str | None) -> QIcon:
    """Icône de la zone de notification : l'icône de l'application avec une pastille d'état."""
    if color is None:
        return app_icon()
    svg = resource_path("app-icon.svg").read_bytes()
    result = QIcon()
    for size in (16, 20, 24, 32, 48, 64):
        pixmap = _render(svg, size)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        diameter = max(6, int(size * 0.42))
        painter.setPen(QColor("#FFFFFF"))
        painter.setBrush(QColor(color))
        painter.drawEllipse(size - diameter - 1, size - diameter - 1, diameter, diameter)
        painter.end()
        result.addPixmap(pixmap)
    return result


def dot_icon(color: str, size: int = 12) -> QIcon:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(color))
    painter.drawEllipse(1, 1, size - 2, size - 2)
    painter.end()
    return QIcon(pixmap)
