"""Thème : style Windows 11 natif si disponible (Fusion sinon), clair, sombre ou selon le système.

Les couleurs sont des jetons (voir `Tokens`) : les feuilles de style ne visent que les widgets propres
à CMA (cartes, barre latérale, pastilles d'état, bandeaux) et laissent les contrôles standard au style natif.
Les couleurs d'état respectent un contraste WCAG AA et sont toujours doublées d'un texte.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QColor, QGuiApplication, QPalette
from PySide6.QtWidgets import QApplication, QStyleFactory

from cma.core.models import Theme
from cma.core.sessions import SessionState


@dataclass(frozen=True)
class Tokens:
    dark: bool
    window: str
    surface: str
    sidebar: str
    border: str
    text: str
    muted: str
    accent: str
    accent_text: str
    hover: str
    success: str
    success_bg: str
    warning: str
    warning_bg: str
    danger: str
    danger_bg: str
    neutral: str
    neutral_bg: str
    info: str
    info_bg: str


LIGHT = Tokens(
    dark=False,
    window="#F4F5F7",
    surface="#FFFFFF",
    sidebar="#ECEEF1",
    border="#D8DCE2",
    text="#1B1F24",
    muted="#59636E",
    accent="#1F6FD1",
    accent_text="#FFFFFF",
    hover="#E2E6EB",
    success="#1A7F37",
    success_bg="#DAFBE1",
    warning="#8A5A00",
    warning_bg="#FFF4C2",
    danger="#C4232D",
    danger_bg="#FFEBE9",
    neutral="#57606A",
    neutral_bg="#EAEEF2",
    info="#0B5CAD",
    info_bg="#DDEEFF",
)

DARK = Tokens(
    dark=True,
    window="#1A1C20",
    surface="#23262B",
    sidebar="#1F2125",
    border="#353941",
    text="#E6E8EB",
    muted="#9DA5B0",
    accent="#5A9EFF",
    accent_text="#0A1220",
    hover="#2C3037",
    success="#4AC26B",
    success_bg="#15351F",
    warning="#E3B341",
    warning_bg="#3A2D0B",
    danger="#FF7B72",
    danger_bg="#421A1C",
    neutral="#A0A8B3",
    neutral_bg="#2D3137",
    info="#79B8FF",
    info_bg="#12304D",
)

ICON_COLOR = "#7D8794"  # lisible sur les deux thèmes (contraste ≥ 3:1 pour un élément d'interface)

_current: Tokens = LIGHT


def current_tokens() -> Tokens:
    """Jetons du thème actif (clair ou sombre)."""
    return _current


def state_colors(state: SessionState, tokens: Tokens) -> tuple[str, str]:
    """(texte, fond) de la pastille d'un état de session."""
    return {
        SessionState.LISTENING: (tokens.success, tokens.success_bg),
        SessionState.STARTING: (tokens.warning, tokens.warning_bg),
        SessionState.DEGRADED: (tokens.warning, tokens.warning_bg),
        SessionState.RECONNECTING: (tokens.warning, tokens.warning_bg),
        SessionState.ERROR: (tokens.danger, tokens.danger_bg),
        SessionState.STOPPED: (tokens.neutral, tokens.neutral_bg),
    }[state]


def _stylesheet(t: Tokens) -> str:
    return f"""
QWidget#AppRoot {{ background: {t.window}; }}
QWidget#Sidebar {{ background: {t.sidebar}; border-right: 1px solid {t.border}; }}
QListWidget#SidebarList {{ background: transparent; border: none; outline: none; font-size: 10.5pt; }}
QListWidget#SidebarList::item {{ padding: 9px 12px; margin: 2px 8px; border-radius: 6px; color: {t.text}; }}
QListWidget#SidebarList::item:hover {{ background: {t.hover}; }}
QListWidget#SidebarList::item:selected {{ background: {t.surface}; color: {t.accent}; font-weight: 600; }}
QLabel#AppTitle {{ font-size: 10.5pt; font-weight: 600; color: {t.text}; }}
QLabel#PageTitle {{ font-size: 16pt; font-weight: 600; color: {t.text}; }}
QLabel#SectionTitle {{ font-size: 11pt; font-weight: 600; color: {t.text}; padding-top: 6px; }}
QLabel[role="muted"] {{ color: {t.muted}; }}
QLabel[role="mono"] {{ font-family: "Cascadia Mono", "Consolas", "DejaVu Sans Mono", monospace; }}
QLabel[role="error"] {{ color: {t.danger}; }}
QLabel[role="warning"] {{ color: {t.warning}; }}
QLabel[role="success"] {{ color: {t.success}; }}
QFrame#Card {{ background: {t.surface}; border: 1px solid {t.border}; border-radius: 10px; }}
QFrame#Card:hover {{ border-color: {t.accent}; }}
QFrame#Panel {{ background: {t.surface}; border: 1px solid {t.border}; border-radius: 10px; }}
QFrame#EmptyState {{ background: transparent; border: 1px dashed {t.border}; border-radius: 12px; }}
QLabel#Pill {{ border-radius: 10px; padding: 2px 10px; font-weight: 600; font-size: 9pt; }}
QLabel#Badge {{ border-radius: 8px; padding: 1px 8px; font-size: 8.5pt; color: {t.muted}; background: {t.neutral_bg}; }}
QFrame#Banner {{ border-radius: 8px; border: 1px solid {t.border}; }}
QFrame#Banner[level="info"] {{ background: {t.info_bg}; border-color: {t.info}; }}
QFrame#Banner[level="success"] {{ background: {t.success_bg}; border-color: {t.success}; }}
QFrame#Banner[level="warning"] {{ background: {t.warning_bg}; border-color: {t.warning}; }}
QFrame#Banner[level="error"] {{ background: {t.danger_bg}; border-color: {t.danger}; }}
QPushButton[primary="true"] {{ background: {t.accent}; color: {t.accent_text}; border: 1px solid {t.accent};
    border-radius: 6px; padding: 6px 16px; font-weight: 600; }}
QPushButton[primary="true"]:hover {{ background: {t.info}; border-color: {t.info}; }}
QPushButton[primary="true"]:disabled {{ background: {t.neutral_bg}; color: {t.muted}; border-color: {t.border}; }}
QPushButton[danger="true"] {{ color: {t.danger}; }}
QLineEdit[invalid="true"], QPlainTextEdit[invalid="true"], QComboBox[invalid="true"] {{ border: 1px solid {t.danger}; }}
QScrollArea#PageScroll, QScrollArea#PageScroll > QWidget > QWidget {{ background: transparent; border: none; }}
QToolButton#Chip {{ border: 1px solid {t.border}; border-radius: 14px; padding: 4px 12px 4px 8px;
    background: {t.surface}; color: {t.text}; }}
QToolButton#Chip:hover {{ border-color: {t.accent}; }}
QToolButton#Chip:checked {{ background: {t.success_bg}; border-color: {t.success}; color: {t.text}; }}
QStatusBar {{ background: {t.sidebar}; border-top: 1px solid {t.border}; color: {t.muted}; }}
QStatusBar QLabel {{ color: {t.muted}; padding: 0 6px; }}
"""


class ThemeManager(QObject):
    """Applique le thème et suit les changements du système quand le thème est « système »."""

    changed = Signal()

    def __init__(self, app: QApplication, theme: Theme = Theme.SYSTEM) -> None:
        super().__init__(app)
        self._app = app
        self._theme = theme
        self.tokens = LIGHT
        self.native_style = self._pick_style()
        hints = QGuiApplication.styleHints()
        hints.colorSchemeChanged.connect(lambda _scheme: self._refresh())

    def _pick_style(self) -> str:
        available: list[str] = QStyleFactory.keys()  # méthode statique Qt, pas un dictionnaire
        keys = [str(name).lower() for name in available]
        if sys.platform == "win32" and "windows11" in keys:
            name = "windows11"
        elif sys.platform == "darwin" and "macos" in keys:
            name = "macos"
        else:
            name = "Fusion"
        self._app.setStyle(name)
        return name

    def set_theme(self, theme: Theme) -> None:
        self._theme = theme
        self.apply()

    def is_dark(self) -> bool:
        if self._theme == Theme.DARK:
            return True
        if self._theme == Theme.LIGHT:
            return False
        return QGuiApplication.styleHints().colorScheme() == Qt.ColorScheme.Dark

    def apply(self) -> None:
        hints = QGuiApplication.styleHints()
        scheme = {Theme.DARK: Qt.ColorScheme.Dark, Theme.LIGHT: Qt.ColorScheme.Light}.get(
            self._theme, Qt.ColorScheme.Unknown
        )
        hints.setColorScheme(scheme)
        self._refresh()

    def _refresh(self) -> None:
        global _current
        self.tokens = DARK if self.is_dark() else LIGHT
        _current = self.tokens
        if self.native_style == "Fusion":
            palette = _fusion_palette(self.tokens)
        else:
            palette = QPalette(self._app.palette())
        # Une seule couleur d'accent, celle de l'application, quel que soit l'accent choisi dans Windows.
        for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive):
            palette.setColor(group, QPalette.ColorRole.Accent, QColor(self.tokens.accent))
            palette.setColor(group, QPalette.ColorRole.Highlight, QColor(self.tokens.accent))
            palette.setColor(group, QPalette.ColorRole.HighlightedText, QColor(self.tokens.accent_text))
        self._app.setPalette(palette)
        self._app.setStyleSheet(_stylesheet(self.tokens))
        self.changed.emit()


def _fusion_palette(t: Tokens) -> QPalette:
    palette = QPalette()
    roles = {
        QPalette.ColorRole.Window: t.window,
        QPalette.ColorRole.WindowText: t.text,
        QPalette.ColorRole.Base: t.surface,
        QPalette.ColorRole.AlternateBase: t.sidebar,
        QPalette.ColorRole.Text: t.text,
        QPalette.ColorRole.Button: t.surface,
        QPalette.ColorRole.ButtonText: t.text,
        QPalette.ColorRole.Highlight: t.accent,
        QPalette.ColorRole.HighlightedText: t.accent_text,
        QPalette.ColorRole.ToolTipBase: t.surface,
        QPalette.ColorRole.ToolTipText: t.text,
        QPalette.ColorRole.PlaceholderText: t.muted,
        QPalette.ColorRole.Link: t.accent,
    }
    for role, color in roles.items():
        palette.setColor(role, QColor(color))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(t.muted))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(t.muted))
    return palette
