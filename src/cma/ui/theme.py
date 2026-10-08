"""Thème « ardoise et bleu » : jetons de couleur, palette Qt et feuille de style.

- Chaque couple texte/fond autorisé atteint 4,5:1, les bordures de contrôle et le repère de focus au moins
  3:1 (vérifié par `tests/unit/test_contrast.py`).
- `border` est une séparation décorative ; `control` est la limite d'un champ ou d'un bouton.
- Le bleu sert aux actions et à la sélection ; les teintes sémantiques servent aux seuls états.
- Le style natif `windows11` est conservé pour les sous-contrôles ; la feuille de style complète le reste.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontDatabase, QGuiApplication, QPalette
from PySide6.QtWidgets import QApplication, QStyleFactory

from cma.core.models import Theme
from cma.core.sessions import SessionState
from cma.ui.states import ICON_OF_STATE, STATUS_OF_STATE, SYMBOL_OF_STATE  # noqa: F401 (réexport)


@dataclass(frozen=True)
class Tokens:
    dark: bool
    window: str
    surface: str
    sidebar: str
    text: str
    muted: str
    border: str
    control: str
    hover: str
    pressed: str
    selected: str
    accent: str
    primary_hover: str
    primary_pressed: str
    on_accent: str
    focus: str
    success: str
    success_bg: str
    warning: str
    warning_bg: str
    danger: str
    danger_bg: str
    info: str
    info_bg: str
    neutral: str
    neutral_bg: str
    disabled: str
    disabled_bg: str

    @property
    def accent_text(self) -> str:
        """Ancien nom de `on_accent`."""
        return self.on_accent


LIGHT = Tokens(
    dark=False,
    window="#F3F6F8",
    surface="#FFFFFF",
    sidebar="#E9EFF3",
    text="#172B3A",
    muted="#4B5D6B",
    border="#C6D1DB",
    control="#708392",
    hover="#E6EEF5",
    pressed="#D8E5F0",
    selected="#E3EEFC",
    accent="#165DB5",
    primary_hover="#124F9B",
    primary_pressed="#104386",
    on_accent="#FFFFFF",
    focus="#165DB5",
    success="#17633D",
    success_bg="#E7F4EC",
    warning="#784700",
    warning_bg="#FFF1D6",
    danger="#AE2633",
    danger_bg="#FDECEE",
    info="#165DB5",
    info_bg="#E3EEFC",
    neutral="#4B5D6B",
    neutral_bg="#E9EFF3",
    disabled="#526472",
    disabled_bg="#E9EFF3",
)

DARK = Tokens(
    dark=True,
    window="#111A22",
    surface="#1B2935",
    sidebar="#15212B",
    text="#F1F5F9",
    muted="#B6C4D2",
    border="#3A4D5E",
    control="#8499AB",
    hover="#263B4C",
    pressed="#30495E",
    selected="#223F5B",
    accent="#80B8FF",
    primary_hover="#A2CCFF",
    primary_pressed="#6BA6F0",
    on_accent="#111A22",
    focus="#80B8FF",
    success="#87D7AC",
    success_bg="#173C2C",
    warning="#FFD28A",
    warning_bg="#493419",
    danger="#FFABB2",
    danger_bg="#4A242B",
    info="#80B8FF",
    info_bg="#223F5B",
    neutral="#B6C4D2",
    neutral_bg="#15212B",
    disabled="#9BACBB",
    disabled_bg="#263541",
)

# Couleur par défaut des icônes créées sans jeton explicite : lisible (≥ 3:1) sur les deux thèmes.
ICON_COLOR = "#7D8794"

_current: Tokens = LIGHT


def current_tokens() -> Tokens:
    """Jetons du thème actif (clair ou sombre)."""
    return _current


# --- États de session : libellé, symbole et teinte ------------------------------------------------------

# Tables des états de session : définies sans Qt dans cma.ui.states, reprises ici pour les vues.


def status_colors(status: str, tokens: Tokens) -> tuple[str, str]:
    """(texte, fond) d'une teinte sémantique : success, warning, danger, info ou neutral."""
    return {
        "success": (tokens.success, tokens.success_bg),
        "warning": (tokens.warning, tokens.warning_bg),
        "danger": (tokens.danger, tokens.danger_bg),
        "info": (tokens.info, tokens.info_bg),
        "neutral": (tokens.neutral, tokens.neutral_bg),
    }[status]


def state_colors(state: SessionState, tokens: Tokens) -> tuple[str, str]:
    """(texte, fond) de la pastille d'un état de session."""
    return status_colors(STATUS_OF_STATE[state], tokens)


# --- Polices ----------------------------------------------------------------------------------------------


def ui_font_family() -> str:
    families = set(QFontDatabase.families())
    for name in ("Segoe UI Variable Text", "Segoe UI Variable", "Segoe UI"):
        if name in families:
            return name
    return QApplication.font().family()


def mono_font_family() -> str:
    families = set(QFontDatabase.families())
    for name in ("Cascadia Mono", "Consolas"):
        if name in families:
            return name
    return QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont).family()


def mono_font(point_size: float = 10) -> QFont:
    font = QFont(mono_font_family())
    font.setPointSizeF(point_size)
    font.setStyleHint(QFont.StyleHint.Monospace)
    return font


# --- Feuille de style -------------------------------------------------------------------------------


def indicator_files(t: Tokens) -> dict[str, str]:
    """Indicateurs de cases et de radios en SVG, dessinés depuis les jetons.

    Dès qu'une feuille de style s'applique, les indicateurs natifs de `windows11` perdent leur remplissage :
    une case cochée devient une coche sans fond, un radio choisi disparaît (§8.2, variante SVG prévue).
    """
    shapes = {
        "cb-off": f'<rect x="1" y="1" width="16" height="16" rx="4" fill="{t.surface}" stroke="{t.control}" stroke-width="2"/>',
        "cb-on": f'<rect width="18" height="18" rx="4" fill="{t.accent}"/>'
        f'<path d="M4.5 9.5l3 3l6 -7" fill="none" stroke="{t.on_accent}" stroke-width="2" '
        'stroke-linecap="round" stroke-linejoin="round"/>',
        "cb-mixed": f'<rect width="18" height="18" rx="4" fill="{t.accent}"/>'
        f'<path d="M5 9h8" stroke="{t.on_accent}" stroke-width="2" stroke-linecap="round"/>',
        "cb-disabled": f'<rect x="1" y="1" width="16" height="16" rx="4" fill="{t.disabled_bg}" stroke="{t.control}" stroke-width="2"/>',
        "cb-disabled-on": f'<rect x="1" y="1" width="16" height="16" rx="4" fill="{t.disabled_bg}" stroke="{t.control}" stroke-width="2"/>'
        f'<path d="M4.5 9.5l3 3l6 -7" fill="none" stroke="{t.disabled}" stroke-width="2" '
        'stroke-linecap="round" stroke-linejoin="round"/>',
        "rb-off": f'<circle cx="9" cy="9" r="8" fill="{t.surface}" stroke="{t.control}" stroke-width="2"/>',
        "rb-on": f'<circle cx="9" cy="9" r="9" fill="{t.accent}"/><circle cx="9" cy="9" r="4" fill="{t.on_accent}"/>',
        "rb-disabled": f'<circle cx="9" cy="9" r="8" fill="{t.disabled_bg}" stroke="{t.control}" stroke-width="2"/>',
        "rb-disabled-on": f'<circle cx="9" cy="9" r="8" fill="{t.disabled_bg}" stroke="{t.control}" stroke-width="2"/>'
        f'<circle cx="9" cy="9" r="4" fill="{t.disabled}"/>',
    }
    folder = Path(tempfile.gettempdir()) / "cma-theme"
    folder.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    for name, body in shapes.items():
        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 18 18">{body}</svg>'
        )
        digest = hashlib.sha256(svg.encode()).hexdigest()[:12]
        target = folder / f"{name}-{digest}.svg"
        if not target.is_file():
            target.write_text(svg, encoding="utf-8")
        paths[name] = target.as_posix()
    return paths


def stylesheet(t: Tokens, ui_font: str = "Segoe UI", mono: str = "Cascadia Mono") -> str:
    """QSS complète de l'application, commune aux deux thèmes."""
    badges = "\n".join(
        f'QLabel[role="badge"][status="{name}"] {{ background-color: {bg}; color: {fg}; '
        f"border: 1px solid {fg}; border-radius: 4px; }}\n"
        f'QFrame[role="banner"][status="{name}"] {{ background-color: {bg}; border: 1px solid {fg}; '
        f"border-radius: 8px; }}\n"
        f'QFrame[role="banner"][status="{name}"] QLabel {{ color: {t.text}; background-color: transparent; }}\n'
        f'QFrame[role="banner"][status="{name}"] QLabel[role="bannerTitle"] {{ color: {fg}; }}\n'
        f'QLabel[role="stateText"][status="{name}"] {{ color: {fg}; font-weight: 600; }}\n'
        f'QFrame[role="session"][status="{name}"] QFrame[role="marker"] {{ background-color: {fg}; }}\n'
        f'QLabel[role="iconTile"][status="{name}"] {{ background-color: {bg}; }}'
        for name, (fg, bg) in {
            "success": (t.success, t.success_bg),
            "warning": (t.warning, t.warning_bg),
            "danger": (t.danger, t.danger_bg),
            "info": (t.info, t.info_bg),
            "neutral": (t.neutral, t.neutral_bg),
        }.items()
    )
    ind = indicator_files(t)
    indicators = (
        "QCheckBox::indicator, QRadioButton::indicator, QAbstractItemView::indicator "
        "{ width: 18px; height: 18px; }\n"
        f"QCheckBox::indicator:unchecked, QAbstractItemView::indicator:unchecked {{ image: url({ind['cb-off']}); }}\n"
        f"QCheckBox::indicator:checked, QAbstractItemView::indicator:checked {{ image: url({ind['cb-on']}); }}\n"
        f"QCheckBox::indicator:indeterminate, QAbstractItemView::indicator:indeterminate "
        f"{{ image: url({ind['cb-mixed']}); }}\n"
        f"QCheckBox::indicator:unchecked:disabled {{ image: url({ind['cb-disabled']}); }}\n"
        f"QCheckBox::indicator:checked:disabled {{ image: url({ind['cb-disabled-on']}); }}\n"
        f"QRadioButton::indicator:unchecked {{ image: url({ind['rb-off']}); }}\n"
        f"QRadioButton::indicator:checked {{ image: url({ind['rb-on']}); }}\n"
        f"QRadioButton::indicator:unchecked:disabled {{ image: url({ind['rb-disabled']}); }}\n"
        f"QRadioButton::indicator:checked:disabled {{ image: url({ind['rb-disabled-on']}); }}\n"
    )
    return (
        indicators
        + f"""
QWidget {{ color: {t.text}; font-family: "{ui_font}"; font-size: 10.5pt; }}
QWidget#AppRoot, QDialog, QWizard, QWizardPage {{ background-color: {t.window}; }}
QWidget#PageBody {{ background-color: {t.window}; }}
#Sidebar {{ background-color: {t.sidebar}; border-right: 1px solid {t.border}; }}
QStatusBar {{ background-color: {t.sidebar}; border-top: 1px solid {t.border}; }}
QStatusBar QLabel {{ color: {t.muted}; padding: 0 6px; }}
QStatusBar::item {{ border: none; }}

QFrame#Card, QFrame[role="panel"], QFrame[role="session"], QFrame[role="tile"] {{
    background-color: {t.surface}; border: 1px solid {t.border}; border-radius: 8px;
}}
QFrame[role="session"] QFrame[role="marker"] {{ border: none; border-radius: 2px; }}
QFrame#LockPanel {{ background-color: {t.window}; }}
QFrame#EmptyState, QFrame[role="empty"] {{ background-color: transparent; border: none; }}
QFrame[role="separator"] {{ background-color: {t.border}; border: none; max-height: 1px; min-height: 1px; }}
QScrollArea#PageScroll, QScrollArea#PageScroll > QWidget > QWidget {{ background: transparent; border: none; }}

QLabel#AppTitle {{ font-size: 13pt; font-weight: 600; }}
QLabel#PageTitle, QLabel[role="title"] {{ font-size: 20pt; font-weight: 600; }}
QLabel#ObjectTitle, QLabel[role="objectTitle"] {{ font-size: 16pt; font-weight: 600; }}
QLabel#SectionTitle, QLabel[role="section"] {{ font-size: 11pt; font-weight: 600; }}
QLabel[role="group"] {{ color: {t.muted}; font-size: 9.5pt; font-weight: 600; }}
QLabel[role="muted"], QLabel[role="meta"] {{ color: {t.muted}; }}
QLabel[role="meta"] {{ font-size: 9.5pt; }}
QLabel[role="mono"], QPlainTextEdit[role="code"], QTableView[role="mono"] {{ font-family: "{mono}"; font-size: 10pt; }}
QLabel[role="error"] {{ color: {t.danger}; }}
QLabel[role="warning"] {{ color: {t.warning}; }}
QLabel[role="success"] {{ color: {t.success}; }}
QLabel[role="badge"], QLabel#Pill {{ padding: 3px 8px; border-radius: 4px; font-size: 9.5pt; font-weight: 600; }}
QLabel#Badge, QLabel[role="kind"] {{
    padding: 2px 6px; border-radius: 4px; font-size: 9.5pt; color: {t.muted}; background-color: {t.neutral_bg};
}}
QLabel[role="count"] {{
    padding: 1px 6px; border-radius: 4px; font-size: 9.5pt; font-weight: 600;
    color: {t.warning}; background-color: {t.warning_bg};
}}
{badges}

QPushButton, QToolButton {{
    color: {t.text}; background-color: {t.surface};
    border: 2px solid {t.control}; border-radius: 6px;
    padding: 6px 12px; min-height: 20px;
}}
QToolButton[role="icon"] {{ min-width: 20px; min-height: 20px; padding: 4px; }}
QToolButton[role="icon"][flat="true"] {{ border-color: transparent; background-color: transparent; }}
QPushButton:hover, QToolButton:hover {{ background-color: {t.hover}; }}
QPushButton:pressed, QToolButton:pressed {{ background-color: {t.pressed}; }}
QPushButton:checked, QToolButton:checked {{ background-color: {t.selected}; }}
QPushButton[role="primary"] {{
    color: {t.on_accent}; background-color: {t.accent}; border-color: {t.accent}; font-weight: 600;
}}
QPushButton[role="primary"]:hover {{ background-color: {t.primary_hover}; border-color: {t.primary_hover}; }}
QPushButton[role="primary"]:pressed {{ background-color: {t.primary_pressed}; border-color: {t.primary_pressed}; }}
QPushButton[role="danger"], QToolButton[role="danger"] {{ color: {t.danger}; }}
QPushButton[role="link"], QToolButton[role="link"] {{
    color: {t.accent}; border-color: transparent; background-color: transparent; padding: 6px 8px;
}}
QPushButton[role="link"]:hover, QToolButton[role="link"]:hover {{ background-color: {t.hover}; }}
QPushButton:focus, QToolButton:focus {{ border-color: {t.focus}; }}
QPushButton[role="primary"]:focus {{ border-color: {t.on_accent}; }}
QToolButton::menu-button {{ border: none; border-left: 1px solid {t.control}; width: 20px; }}
QPushButton::menu-indicator {{ subcontrol-position: right center; right: 6px; }}
QPushButton[role="tileBody"] {{
    border: 2px solid transparent; background-color: transparent; text-align: left; padding: 0px;
}}
QPushButton[role="tileBody"]:hover {{ background-color: {t.hover}; }}
QPushButton[role="tileBody"]:pressed {{ background-color: {t.pressed}; }}
QPushButton[role="tileBody"]:focus {{ border-color: {t.focus}; }}
QPushButton[role="tileBody"] QLabel {{ background: transparent; }}
QFrame[role="focusShell"] {{ border: 2px solid transparent; border-radius: 8px; }}
QFrame[role="focusShell"][focusWithin="true"] {{ border-color: {t.focus}; }}

QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QSpinBox {{
    color: {t.text}; background-color: {t.surface};
    border: 2px solid {t.control}; border-radius: 6px;
    padding: 5px 6px; min-height: 20px;
    selection-color: {t.text}; selection-background-color: {t.selected};
}}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus {{
    border-color: {t.focus};
}}
QLineEdit[invalid="true"], QSpinBox[invalid="true"], QPlainTextEdit[invalid="true"], QComboBox[invalid="true"] {{
    border-color: {t.danger};
}}
QLineEdit:read-only {{ background-color: {t.window}; }}
QComboBox QAbstractItemView {{ border: 1px solid {t.control}; }}
QCheckBox, QRadioButton {{ spacing: 8px; min-height: 28px; background: transparent; }}

QAbstractItemView {{
    background-color: {t.surface}; alternate-background-color: {t.surface};
    color: {t.text}; border: 1px solid {t.border};
    selection-color: {t.text}; selection-background-color: {t.selected};
    gridline-color: {t.border};
}}
QAbstractItemView::item {{ min-height: 30px; padding: 2px 6px; }}
QAbstractItemView::item:hover {{ background-color: {t.hover}; }}
QAbstractItemView::item:selected {{ background-color: {t.selected}; color: {t.text}; }}
QTreeView::branch {{ background: transparent; }}
QTreeView::branch:selected {{ background-color: {t.selected}; }}
QTreeView::item {{ border-left: 3px solid transparent; }}
QTreeView::item:selected {{ border-left: 3px solid {t.accent}; }}
QTreeView#CardTree {{ background: transparent; border: none; outline: none; }}
QTreeView#CardTree::item, QTreeView#CardTree::item:hover, QTreeView#CardTree::item:selected {{
    background: transparent; border: none; padding: 0; min-height: 0;
}}
QTreeView#CardTree::branch {{ background: transparent; border: none; }}
QTableView#CardTable {{ background: transparent; border: none; outline: none; }}
QTableView#CardTable::item, QTableView#CardTable::item:hover, QTableView#CardTable::item:selected {{
    background: transparent; border: none; padding: 0; color: {t.text};
}}
QTreeView#EntryList {{
    background-color: {t.surface}; border: 1px solid {t.border}; border-radius: 8px; padding: 4px;
    outline: none;
}}
QTreeView#EntryList::item, QTreeView#EntryList::item:hover, QTreeView#EntryList::item:selected {{
    background: transparent; border: none; padding: 0; min-height: 0;
}}
QTreeView#EntryList::branch {{ background: transparent; border: none; }}
QLabel[role="iconTile"] {{ border-radius: 12px; background-color: {t.selected}; }}
QListView#Navigation {{ background-color: transparent; border: none; outline: none; }}
QListView#Navigation::item {{
    min-height: 36px; padding: 2px 10px; margin: 1px 8px; border-radius: 6px;
    border-left: 3px solid transparent;
}}
QListView#Navigation::item:hover {{ background-color: {t.hover}; }}
QListView#Navigation::item:selected {{
    background-color: {t.selected}; color: {t.text}; border-left: 3px solid {t.accent}; font-weight: 600;
}}
QListView#Navigation::item:disabled {{
    color: {t.muted}; background: transparent; font-size: 9.5pt; font-weight: 600;
    min-height: 24px; padding-top: 12px;
}}
QHeaderView::section {{
    background-color: {t.sidebar}; color: {t.text}; padding: 6px 8px; border: none;
    border-bottom: 1px solid {t.border}; font-weight: 600;
}}

QTabWidget::pane {{ border: 1px solid {t.border}; background-color: {t.surface}; top: -1px; }}
QTabBar::tab {{
    background-color: transparent; color: {t.text}; padding: 8px 14px;
    border: none; border-bottom: 2px solid transparent;
}}
QTabBar::tab:hover {{ background-color: {t.hover}; }}
QTabBar::tab:selected {{ background-color: {t.surface}; border-bottom: 2px solid {t.accent}; font-weight: 600; }}
QTabBar::tab:focus {{ color: {t.accent}; }}
QTabWidget[role="plain"]::pane {{ border: none; border-top: 1px solid {t.border}; background: transparent; }}

QSplitter::handle {{ background-color: {t.window}; }}
QSplitter::handle:hover {{ background-color: {t.hover}; }}
QMenu {{ background-color: {t.surface}; color: {t.text}; border: 1px solid {t.control}; padding: 4px; }}
QMenu::item {{ padding: 7px 24px 7px 12px; border-radius: 4px; }}
QMenu::item:selected {{ background-color: {t.selected}; color: {t.text}; }}
QMenu::item:disabled {{ color: {t.disabled}; background: transparent; }}
QMenu::separator {{ height: 1px; background-color: {t.border}; margin: 4px 8px; }}
QToolTip {{ background-color: {t.surface}; color: {t.text}; border: 1px solid {t.control}; padding: 6px; }}
QProgressBar {{ background-color: {t.sidebar}; border: 1px solid {t.control}; border-radius: 4px; max-height: 8px; }}
QProgressBar::chunk {{ background-color: {t.accent}; border-radius: 3px; }}

QPushButton:disabled, QToolButton:disabled, QLineEdit:disabled,
QPlainTextEdit:disabled, QTextEdit:disabled, QComboBox:disabled, QSpinBox:disabled,
QPushButton[role="primary"]:disabled, QPushButton[role="danger"]:disabled, QPushButton[role="link"]:disabled {{
    color: {t.disabled}; background-color: {t.disabled_bg}; border-color: {t.control};
}}
QPushButton[role="link"]:disabled {{ background-color: transparent; border-color: transparent; }}
QTabBar::tab:disabled {{ color: {t.disabled}; }}
"""
    )


# --- Gestionnaire -----------------------------------------------------------------------------------


class ThemeManager(QObject):
    """Applique le thème et suit les changements du système quand le thème est « système »."""

    changed = Signal()

    def __init__(self, app: QApplication, theme: Theme = Theme.SYSTEM) -> None:
        super().__init__(app)
        self._app = app
        self._theme = theme
        self.tokens = LIGHT
        self.native_style = self._pick_style()
        self.ui_font = ui_font_family()
        self.mono_font = mono_font_family()
        font = QFont(self.ui_font)
        font.setPointSizeF(10.5)
        app.setFont(font)
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
        self._app.setPalette(build_palette(self.tokens))
        self._app.setStyleSheet(stylesheet(self.tokens, self.ui_font, self.mono_font))
        from cma.ui.icons import refresh_themed_glyphs, refresh_themed_icons

        refresh_themed_icons()
        refresh_themed_glyphs()
        self.changed.emit()


def build_palette(t: Tokens) -> QPalette:
    """Palette Qt construite depuis les mêmes jetons que la feuille de style (§8.3)."""
    palette = QPalette()
    roles = {
        QPalette.ColorRole.Window: t.window,
        QPalette.ColorRole.WindowText: t.text,
        QPalette.ColorRole.Base: t.surface,
        QPalette.ColorRole.AlternateBase: t.window,
        QPalette.ColorRole.Text: t.text,
        QPalette.ColorRole.Button: t.surface,
        QPalette.ColorRole.ButtonText: t.text,
        QPalette.ColorRole.Highlight: t.selected,
        QPalette.ColorRole.HighlightedText: t.text,
        QPalette.ColorRole.Accent: t.accent,
        QPalette.ColorRole.ToolTipBase: t.surface,
        QPalette.ColorRole.ToolTipText: t.text,
        QPalette.ColorRole.PlaceholderText: t.muted,
        QPalette.ColorRole.Link: t.accent,
        QPalette.ColorRole.BrightText: t.on_accent,
        QPalette.ColorRole.Mid: t.control,
        QPalette.ColorRole.Midlight: t.border,
        QPalette.ColorRole.Light: t.surface,
        QPalette.ColorRole.Dark: t.control,
        QPalette.ColorRole.Shadow: t.control,
    }
    for role, color in roles.items():
        palette.setColor(role, QColor(color))
    for role in (QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText, QPalette.ColorRole.WindowText):
        palette.setColor(QPalette.ColorGroup.Disabled, role, QColor(t.disabled))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Button, QColor(t.disabled_bg))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Base, QColor(t.disabled_bg))
    return palette
