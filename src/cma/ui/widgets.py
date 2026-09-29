"""Widgets réutilisables : pastille d'état, bandeaux, état vide, champ secret, champ de port, sections de formulaire."""

from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication, QIntValidator, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from cma.core.netutil import PortStatus, check_local_port
from cma.core.sessions import SessionState
from cma.i18n import tr
from cma.ui.icons import icon
from cma.ui.theme import current_tokens, state_colors


def set_role(widget: QWidget, role: str) -> None:
    widget.setProperty("role", role)
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def set_flag(widget: QWidget, name: str, value: bool) -> None:
    widget.setProperty(name, "true" if value else "false")
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def label(text: str = "", role: str | None = None, *, wrap: bool = False, selectable: bool = False) -> QLabel:
    widget = QLabel(text)
    if role:
        widget.setProperty("role", role)
    widget.setWordWrap(wrap)
    if selectable:
        widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return widget


def title(text: str, object_name: str = "PageTitle") -> QLabel:
    widget = QLabel(text)
    widget.setObjectName(object_name)
    return widget


def primary_button(text: str, icon_name: str | None = None) -> QPushButton:
    button = QPushButton(text)
    button.setProperty("primary", "true")
    if icon_name:
        button.setIcon(icon(icon_name, "#FFFFFF"))
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


def button(
    text: str, icon_name: str | None = None, *, tooltip: str | None = None, danger: bool = False
) -> QPushButton:
    widget = QPushButton(text)
    if icon_name:
        widget.setIcon(icon(icon_name))
    if tooltip:
        widget.setToolTip(tooltip)
    if danger:
        widget.setProperty("danger", "true")
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    return widget


def tool_button(icon_name: str, tooltip: str, callback: Callable[[], None] | None = None) -> QToolButton:
    widget = QToolButton()
    widget.setIcon(icon(icon_name))
    widget.setIconSize(QSize(18, 18))
    widget.setToolTip(tooltip)
    widget.setAccessibleName(tooltip)
    widget.setAutoRaise(True)
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    if callback is not None:
        widget.clicked.connect(callback)
    return widget


def copy_to_clipboard(text: str) -> None:
    QGuiApplication.clipboard().setText(text)


class StatusPill(QLabel):
    """Pastille colorée : l'état est toujours écrit en toutes lettres, pas seulement porté par la couleur."""

    def __init__(self, state: SessionState | None = None, text: str | None = None) -> None:
        super().__init__()
        self.setObjectName("Pill")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        if state is not None:
            self.set_state(state, text)

    def set_state(self, state: SessionState, text: str | None = None) -> None:
        fg, bg = state_colors(state, current_tokens())
        self.set_colors(f"● {text or state.label}", fg, bg)

    def set_colors(self, text: str, fg: str, bg: str) -> None:
        self.setText(text)
        self.setStyleSheet(f"color: {fg}; background: {bg};")
        self.setAccessibleName(text.lstrip("● "))


class Banner(QFrame):
    """Bandeau d'information dans la fenêtre, à la place des boîtes modales."""

    closed = Signal()

    ICONS: ClassVar[dict[str, str]] = {
        "info": "info-circle",
        "success": "circle-check",
        "warning": "alert-triangle",
        "error": "circle-x",
    }

    def __init__(
        self,
        level: str,
        text: str,
        *,
        action: tuple[str, Callable[[], None]] | None = None,
        timeout_ms: int | None = None,
    ) -> None:
        super().__init__()
        self.setObjectName("Banner")
        self.setProperty("level", level)
        tokens = current_tokens()
        color = {
            "info": tokens.info,
            "success": tokens.success,
            "warning": tokens.warning,
            "error": tokens.danger,
        }[level]
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 8, 8)
        glyph = QLabel()
        glyph.setPixmap(icon(self.ICONS[level], color).pixmap(20, 20))
        layout.addWidget(glyph, 0, Qt.AlignmentFlag.AlignTop)
        text_label = label(text, wrap=True, selectable=True)
        text_label.setStyleSheet(f"color: {tokens.text};")
        layout.addWidget(text_label, 1)
        if action is not None:
            action_button = QPushButton(action[0])
            action_button.clicked.connect(action[1])
            action_button.clicked.connect(self.dismiss)
            layout.addWidget(action_button, 0, Qt.AlignmentFlag.AlignTop)
        close = tool_button("x", tr("Fermer"), self.dismiss)
        layout.addWidget(close, 0, Qt.AlignmentFlag.AlignTop)
        if timeout_ms:
            QTimer.singleShot(timeout_ms, self.dismiss)

    def dismiss(self) -> None:
        if self.isVisible() or self.parent() is not None:
            self.hide()
            self.closed.emit()
            self.deleteLater()


class BannerStack(QWidget):
    MAX_BANNERS = 4

    def __init__(self) -> None:
        super().__init__()
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(6)
        self.hide()

    def show_message(
        self,
        level: str,
        text: str,
        *,
        action: tuple[str, Callable[[], None]] | None = None,
        timeout_ms: int | None = None,
    ) -> Banner:
        if timeout_ms is None and level in ("info", "success"):
            timeout_ms = 6000
        while self._layout.count() >= self.MAX_BANNERS:
            item = self._layout.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.deleteLater()
        banner = Banner(level, text, action=action, timeout_ms=timeout_ms)
        banner.closed.connect(self._update_visibility)
        self._layout.addWidget(banner)
        self.show()
        return banner

    def _update_visibility(self) -> None:
        QTimer.singleShot(0, lambda: self.setVisible(self._has_visible_banner()))

    def _has_visible_banner(self) -> bool:
        for index in range(self._layout.count()):
            item = self._layout.itemAt(index)
            widget = item.widget() if item is not None else None
            if widget is not None and not widget.isHidden():
                return True
        return False


class EmptyState(QFrame):
    def __init__(
        self, icon_name: str, heading: str, text: str, actions: list[QPushButton] | None = None
    ) -> None:
        super().__init__()
        self.setObjectName("EmptyState")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 32, 24, 32)
        layout.setSpacing(8)
        glyph = QLabel()
        glyph.setPixmap(icon(icon_name).pixmap(48, 48))
        glyph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(glyph)
        head = title(heading, "SectionTitle")
        head.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(head)
        body = label(text, "muted", wrap=True)
        body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(body)
        if actions:
            row = QHBoxLayout()
            row.addStretch()
            for action in actions:
                row.addWidget(action)
            row.addStretch()
            layout.addLayout(row)


class SecretField(QWidget):
    """Champ masqué avec boutons « afficher » et « copier ». `reveal_provider` charge le secret à la demande."""

    changed = Signal()

    def __init__(self, placeholder: str = "") -> None:
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit.setPlaceholderText(placeholder)
        self.edit.textEdited.connect(lambda _t: self.changed.emit())
        self.toggle = tool_button("eye", tr("Afficher ou masquer"), self._toggle)
        self.copy = tool_button("copy", tr("Copier"), lambda: copy_to_clipboard(self.edit.text()))
        layout.addWidget(self.edit, 1)
        layout.addWidget(self.toggle)
        layout.addWidget(self.copy)

    def _toggle(self) -> None:
        hidden = self.edit.echoMode() == QLineEdit.EchoMode.Password
        self.edit.setEchoMode(QLineEdit.EchoMode.Normal if hidden else QLineEdit.EchoMode.Password)
        self.toggle.setIcon(icon("eye-off" if hidden else "eye"))

    def text(self) -> str:
        return self.edit.text()

    def set_text(self, value: str) -> None:
        self.edit.setText(value)
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.toggle.setIcon(icon("eye"))


class PortField(QWidget):
    """Port local avec vérification en direct (libre, occupé, réservé par Windows) et bouton « port libre »."""

    changed = Signal()

    def __init__(self, suggest: Callable[[int | None], int | None], host_provider: Callable[[], str]) -> None:
        super().__init__()
        self._suggest = suggest
        self._host_provider = host_provider
        self._ignore_port: int | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        row = QHBoxLayout()
        row.setSpacing(4)
        self.edit = QLineEdit()
        self.edit.setValidator(QIntValidator(1, 65535, self))
        self.edit.setMaximumWidth(110)
        self.edit.setPlaceholderText("2222")
        self.edit.textEdited.connect(self._on_edit)
        self.auto = button(tr("Port libre"), "refresh", tooltip=tr("Choisir un port local libre"))
        self.auto.clicked.connect(self._auto)
        row.addWidget(self.edit)
        row.addWidget(self.auto)
        row.addStretch()
        layout.addLayout(row)
        self.status = label("", "muted")
        layout.addWidget(self.status)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(300)
        self._timer.timeout.connect(self.check)

    def value(self) -> int | None:
        text = self.edit.text().strip()
        return int(text) if text.isdigit() and 0 < int(text) < 65536 else None

    def set_value(self, port: int | None, *, own_port: int | None = None) -> None:
        """`own_port` : port déjà utilisé par la session de ce profil (à ne pas signaler comme occupé)."""
        self._ignore_port = own_port
        self.edit.setText("" if port is None else str(port))
        self.check()

    def _on_edit(self, _text: str) -> None:
        self.changed.emit()
        self._timer.start()

    def _auto(self) -> None:
        port = self._suggest(self.value())
        if port is not None:
            self.edit.setText(str(port))
            self.changed.emit()
            self.check()

    def check(self) -> None:
        port = self.value()
        if port is None:
            self.status.setText(tr("Port requis (1 à 65535)") if self.edit.text() else "")
            set_role(self.status, "muted")
            return
        if port == self._ignore_port:
            self.status.setText(tr("Utilisé par la session de ce profil"))
            set_role(self.status, "muted")
            return
        result = check_local_port(self._host_provider() or "127.0.0.1", port)
        if result.status == PortStatus.FREE:
            self.status.setText(tr("Port libre"))
            set_role(self.status, "success")
        else:
            self.status.setText(result.message)
            set_role(self.status, "error" if result.status == PortStatus.RESERVED else "warning")


class FieldError(QLabel):
    def __init__(self) -> None:
        super().__init__()
        self.setProperty("role", "error")
        self.setWordWrap(True)
        self.hide()

    def show_error(self, message: str | None) -> None:
        self.setText(message or "")
        self.setVisible(bool(message))


def with_error(field: QWidget, error: FieldError) -> QWidget:
    container = QWidget()
    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(2)
    layout.addWidget(field)
    layout.addWidget(error)
    return container


def hline() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFrameShadow(QFrame.Shadow.Plain)
    line.setStyleSheet(f"color: {current_tokens().border};")
    return line


def add_shortcut(
    parent: QWidget, sequence: QKeySequence | QKeySequence.StandardKey | str, callback: Callable[[], object]
) -> QShortcut:
    shortcut = QShortcut(sequence if isinstance(sequence, QKeySequence) else QKeySequence(sequence), parent)
    shortcut.activated.connect(callback)
    return shortcut
