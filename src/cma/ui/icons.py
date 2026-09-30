"""Icônes SVG (Tabler Icons, licence MIT) teintées à la volée, et icône de l'application.

Une icône posée par `set_icon` est liée à un jeton de couleur (texte, accent, danger…) : elle est
recolorée à chaque changement de thème par `refresh_themed_icons`, appelé par le gestionnaire de thème.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QApplication, QWidget

from cma.paths import resource_path
from cma.ui.theme import ICON_COLOR, current_tokens

_SIZES = (16, 20, 24, 32, 40, 48, 64)
_PROPERTY = "cmaIcon"


def _render(svg: bytes, size: int) -> QPixmap:
    renderer = QSvgRenderer(QByteArray(svg))
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter, QRectF(0, 0, size, size))
    painter.end()
    return pixmap


@lru_cache(maxsize=1024)
def icon(name: str, color: str = ICON_COLOR) -> QIcon:
    path = resource_path("icons", f"{name}.svg")
    svg = path.read_text(encoding="utf-8").replace("currentColor", color).encode("utf-8")
    result = QIcon()
    for size in _SIZES:
        result.addPixmap(_render(svg, size))
    return result


def token_icon(name: str, tint: str = "text") -> QIcon:
    """Icône dans la couleur d'un jeton du thème courant (`text`, `muted`, `accent`, `on_accent`, `danger`…)."""
    return icon(name, str(getattr(current_tokens(), tint)))


def set_icon(widget: Any, name: str, tint: str = "text") -> None:
    """Pose une icône liée à un jeton : elle suivra les changements de thème."""
    widget.setProperty(_PROPERTY, f"{name}|{tint}")
    widget.setIcon(token_icon(name, tint))


def refresh_themed_icons() -> None:
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        return
    for widget in app.allWidgets():
        spec = widget.property(_PROPERTY)
        if isinstance(spec, str) and "|" in spec and hasattr(widget, "setIcon"):
            name, tint = spec.split("|", 1)
            widget.setIcon(token_icon(name, tint))  # type: ignore[attr-defined]


def glyph_pixmap(name: str, tint: str = "text", size: int = 20) -> QPixmap:
    return token_icon(name, tint).pixmap(size, size)


def set_glyph(label: QWidget, name: str, tint: str = "text", size: int = 20) -> None:
    """Pictogramme d'un QLabel, lié à un jeton comme `set_icon`."""
    label.setProperty("cmaGlyph", f"{name}|{tint}|{size}")
    label.setPixmap(glyph_pixmap(name, tint, size))  # type: ignore[attr-defined]


def refresh_themed_glyphs() -> None:
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        return
    for widget in app.allWidgets():
        spec = widget.property("cmaGlyph")
        if isinstance(spec, str) and spec.count("|") == 2:
            name, tint, size = spec.split("|")
            widget.setPixmap(glyph_pixmap(name, tint, int(size)))  # type: ignore[attr-defined]


@lru_cache(maxsize=1)
def app_icon() -> QIcon:
    svg = resource_path("app-icon.svg").read_bytes()
    result = QIcon()
    for size in (16, 20, 24, 32, 40, 48, 64, 96, 128, 256):
        result.addPixmap(_render(svg, size))
    return result


_STATUS_SYMBOL_PATHS = {
    # Symbole blanc dessiné dans la pastille : l'état ne repose jamais sur la couleur seule (§4.26).
    "ok": "M5 12l4 4l10 -10",
    "warn": "M12 6v7M12 17.5v.5",
    "error": "M7 7l10 10M17 7l-10 10",
}


@lru_cache(maxsize=16)
def app_icon_with_status(color: str | None, symbol: str | None = None) -> QIcon:
    """Icône de la zone de notification : l'icône de l'application avec une pastille et un symbole d'état."""
    if color is None:
        return app_icon()
    svg = resource_path("app-icon.svg").read_bytes()
    result = QIcon()
    for size in (16, 20, 24, 32, 48, 64):
        pixmap = _render(svg, size)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        diameter = max(8, int(size * 0.5))
        x = y = size - diameter
        painter.setPen(QColor("#FFFFFF"))
        painter.setBrush(QColor(color))
        painter.drawEllipse(x, y, diameter - 1, diameter - 1)
        path_data = _STATUS_SYMBOL_PATHS.get(symbol or "")
        if path_data:
            mark = (
                '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#FFFFFF" '
                f'stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"><path d="{path_data}"/></svg>'
            ).encode()
            inset = diameter * 0.18
            QSvgRenderer(QByteArray(mark)).render(
                painter, QRectF(x + inset, y + inset, diameter - 2 * inset - 1, diameter - 2 * inset - 1)
            )
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
