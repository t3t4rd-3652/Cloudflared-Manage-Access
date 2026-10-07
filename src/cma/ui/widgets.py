"""Widgets réutilisables : boutons à rôles, pastille d'état, bandeaux, état vide, champ secret, champ de port.

Les couleurs viennent de la feuille de style (propriétés `role` et `status`, voir `theme.stylesheet`) ;
aucun widget ne fixe de couleur en dur. Un état est toujours écrit en toutes lettres, avec un symbole.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar

from PySide6.QtCore import QEvent, QObject, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QEnterEvent, QGuiApplication, QIntValidator, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.netutil import PortStatus, check_local_port
from cma.core.sessions import SessionState
from cma.i18n import tr
from cma.ui.icons import set_glyph, set_icon
from cma.ui.theme import STATUS_OF_STATE, SYMBOL_OF_STATE


def repolish(widget: QWidget) -> None:
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    widget.update()


def set_role(widget: QWidget, role: str) -> None:
    if widget.property("role") != role:
        widget.setProperty("role", role)
        repolish(widget)


def set_flag(widget: QWidget, name: str, value: bool) -> None:
    text = "true" if value else "false"
    if widget.property(name) != text:
        widget.setProperty(name, text)
        repolish(widget)


def set_status(widget: QWidget, status: str) -> None:
    if widget.property("status") != status:
        widget.setProperty("status", status)
        repolish(widget)


def label(text: str = "", role: str | None = None, *, wrap: bool = False, selectable: bool = False) -> QLabel:
    widget = QLabel(text)
    if role:
        widget.setProperty("role", role)
    widget.setWordWrap(wrap)
    if selectable:
        widget.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
    return widget


def title(text: str, object_name: str = "PageTitle") -> QLabel:
    widget = QLabel(text)
    widget.setObjectName(object_name)
    widget.setWordWrap(object_name != "PageTitle")
    return widget


def group_label(text: str) -> QLabel:
    """Titre de groupe en petites capitales (« FAVORIS », « À VÉRIFIER · 2 »)."""
    return label(text.upper(), "group")


def primary_button(text: str, icon_name: str | None = None) -> QPushButton:
    button = QPushButton(text)
    button.setProperty("role", "primary")
    if icon_name:
        set_icon(button, icon_name, "on_accent")
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    return button


def button(
    text: str,
    icon_name: str | None = None,
    *,
    tooltip: str | None = None,
    danger: bool = False,
    link: bool = False,
) -> QPushButton:
    widget = QPushButton(text)
    tint = "danger" if danger else ("accent" if link else "text")
    if icon_name:
        set_icon(widget, icon_name, tint)
    if tooltip:
        widget.setToolTip(tooltip)
    if danger:
        widget.setProperty("role", "danger")
    elif link:
        widget.setProperty("role", "link")
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    return widget


def tool_button(
    icon_name: str,
    tooltip: str,
    callback: Callable[[], None] | None = None,
    *,
    flat: bool = True,
    tint: str = "text",
) -> QToolButton:
    """Bouton iconique de 32 × 32 px au moins, avec nom accessible et infobulle (§6.4)."""
    widget = QToolButton()
    set_icon(widget, icon_name, tint)
    widget.setIconSize(QSize(18, 18))
    widget.setMinimumSize(QSize(32, 32))
    widget.setToolTip(tooltip)
    widget.setAccessibleName(tooltip)
    widget.setProperty("role", "icon")
    widget.setProperty("flat", "true" if flat else "false")
    widget.setCursor(Qt.CursorShape.PointingHandCursor)
    if callback is not None:
        widget.clicked.connect(callback)
    return widget


def clear_items(widget: QTreeWidget | QTableWidget | QListWidget, keep_rows: int = 0) -> None:
    """Vide un arbre, un tableau ou une liste en reprenant chaque élément : Python, seul propriétaire, le libère une
    fois. Pour un tableau, `keep_rows` lignes vides restent (prêtes pour `setItem`).

    `clear()`, `setRowCount()` ou un `setItem` sur une case occupée font détruire les éléments par Qt. Les
    éléments (QTreeWidgetItem, QTableWidgetItem, QListWidgetItem) n'étant pas des QObject, PySide ne le voit pas :
    une enveloppe Python peut ensuite libérer le même élément une seconde fois (« free(): invalid pointer » et
    abandon sous Linux, constatés en CI ; corruption silencieuse ailleurs). Les signaux de sélection émis pendant
    la reprise restent à bloquer par l'appelant s'il le faut.
    """
    if isinstance(widget, QTreeWidget):

        def detach(item: QTreeWidgetItem) -> None:
            for child in item.takeChildren():
                detach(child)

        while widget.topLevelItemCount():
            item = widget.takeTopLevelItem(0)
            if item is not None:
                detach(item)
    elif isinstance(widget, QTableWidget):
        for row in range(widget.rowCount()):
            for column in range(widget.columnCount()):
                widget.takeItem(row, column)
        widget.setRowCount(0)
        widget.setRowCount(keep_rows)
    else:
        while widget.count():
            widget.takeItem(0)


def copy_to_clipboard(text: str) -> None:
    QGuiApplication.clipboard().setText(text)


def separator() -> QFrame:
    line = QFrame()
    line.setProperty("role", "separator")
    line.setFixedHeight(1)
    return line


class StatusPill(QLabel):
    """Pastille d'état : symbole + libellé en toutes lettres, jamais la couleur seule."""

    def __init__(self, state: SessionState | None = None, text: str | None = None) -> None:
        super().__init__()
        self.setObjectName("Pill")
        self.setProperty("role", "badge")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        if state is not None:
            self.set_state(state, text)

    def set_state(self, state: SessionState, text: str | None = None) -> None:
        self.set_status(text or state.label, STATUS_OF_STATE[state], SYMBOL_OF_STATE[state])

    def set_status(self, text: str, status: str, symbol: str | None = None) -> None:
        self.setText(f"{symbol} {text}" if symbol else text)
        self.setAccessibleName(text)
        set_status(self, status)


class Banner(QFrame):
    """Bandeau dans la fenêtre, à la place des boîtes modales (§4.1).

    Les messages d'information et de succès disparaissent après 5 s ; le délai est suspendu tant que le
    pointeur survole le bandeau ou que le focus est sur l'un de ses boutons. Avertissements et erreurs
    restent jusqu'à fermeture.
    """

    closed = Signal()

    ICONS: ClassVar[dict[str, str]] = {
        "info": "info-circle",
        "success": "circle-check",
        "warning": "alert-triangle",
        "error": "circle-x",
    }
    STATUS: ClassVar[dict[str, str]] = {
        "info": "info",
        "success": "success",
        "warning": "warning",
        "error": "danger",
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
        self.setProperty("role", "banner")
        self.setProperty("status", self.STATUS[level])
        self.level = level
        self.text = text
        self.count = 1
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 8, 8)
        layout.setSpacing(10)
        glyph = QLabel()
        set_glyph(glyph, self.ICONS[level], self.STATUS[level], 20)
        layout.addWidget(glyph, 0, Qt.AlignmentFlag.AlignTop)
        self.text_label = label(text, wrap=True, selectable=True)
        layout.addWidget(self.text_label, 1)
        if action is not None:
            action_button = QPushButton(action[0])
            action_button.clicked.connect(action[1])
            action_button.clicked.connect(self.dismiss)
            layout.addWidget(action_button, 0, Qt.AlignmentFlag.AlignTop)
        short = text if len(text) <= 60 else text[:57] + "…"
        close = tool_button("x", tr("Fermer la notification : {title}").format(title=short), self.dismiss)
        layout.addWidget(close, 0, Qt.AlignmentFlag.AlignTop)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._expire)
        self._timeout = timeout_ms
        if timeout_ms:
            self._timer.start(timeout_ms)

    def repeat(self) -> None:
        """Même message une nouvelle fois : compteur plutôt qu'un bandeau de plus."""
        self.count += 1
        self.text_label.setText(f"{self.text} (×{self.count})")
        if self._timeout:
            self._timer.start(self._timeout)

    def enterEvent(self, event: QEnterEvent) -> None:
        self._timer.stop()
        super().enterEvent(event)

    def leaveEvent(self, event: QEvent) -> None:
        if self._timeout:
            self._timer.start(self._timeout)
        super().leaveEvent(event)

    def _expire(self) -> None:
        focus = QGuiApplication.focusObject()
        if isinstance(focus, QWidget) and self.isAncestorOf(focus):
            self._timer.start(self._timeout or 5000)
            return
        self.dismiss()

    def dismiss(self) -> None:
        if self.isVisible() or self.parent() is not None:
            self.hide()
            self.closed.emit()
            self.deleteLater()


class BannerStack(QWidget):
    """Deux bandeaux visibles au plus ; les répétitions identiques sont regroupées (§4.1)."""

    MAX_BANNERS = 2
    INFO_TIMEOUT_MS = 5000

    def __init__(self) -> None:
        super().__init__()
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(6)
        self.hide()

    def banners(self) -> list[Banner]:
        found: list[Banner] = []
        for index in range(self._layout.count()):
            item = self._layout.itemAt(index)
            widget = item.widget() if item is not None else None
            if isinstance(widget, Banner) and not widget.isHidden():
                found.append(widget)
        return found

    def show_message(
        self,
        level: str,
        text: str,
        *,
        action: tuple[str, Callable[[], None]] | None = None,
        timeout_ms: int | None = None,
    ) -> Banner:
        for existing in self.banners():
            if existing.level == level and existing.text == text:
                existing.repeat()
                return existing
        if timeout_ms is None and level in ("info", "success"):
            timeout_ms = self.INFO_TIMEOUT_MS
        visible = self.banners()
        while len(visible) >= self.MAX_BANNERS:
            visible.pop(0).dismiss()
        banner = Banner(level, text, action=action, timeout_ms=timeout_ms)
        banner.closed.connect(self._update_visibility)
        self._layout.addWidget(banner)
        self.show()
        return banner

    def _update_visibility(self) -> None:
        QTimer.singleShot(0, lambda: self.setVisible(bool(self.banners())))


class EmptyState(QFrame):
    """État vide : titre explicite, une phrase et des actions ; pas de grand rectangle pointillé (§4.0)."""

    def __init__(
        self, icon_name: str, heading: str, text: str, actions: list[QPushButton] | None = None
    ) -> None:
        super().__init__()
        self.setObjectName("EmptyState")
        self.setProperty("role", "empty")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 32, 24, 32)
        layout.setSpacing(8)
        glyph = QLabel()
        set_glyph(glyph, icon_name, "muted", 32)
        glyph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(glyph)
        self.heading = title(heading, "SectionTitle")
        self.heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.heading)
        self.body = label(text, "muted", wrap=True)
        self.body.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.body)
        if actions:
            row = QHBoxLayout()
            row.addStretch()
            for action in actions:
                row.addWidget(action)
            row.addStretch()
            layout.addLayout(row)
        layout.addStretch()


class SecretField(QWidget):
    """Champ masqué, boutons « Afficher / Masquer » et « Copier ». Le secret revient masqué à chaque chargement."""

    changed = Signal()
    copied = Signal()

    def __init__(self, placeholder: str = "", *, subject: str = "") -> None:
        super().__init__()
        self._subject = subject
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit.setPlaceholderText(placeholder)
        self.edit.textEdited.connect(lambda _t: self.changed.emit())
        self.toggle = button(tr("Afficher"), "eye")
        self.toggle.setCheckable(True)
        self.toggle.toggled.connect(self._toggle)
        self.copy = button(tr("Copier"), "copy")
        self.copy.clicked.connect(self._copy)
        layout.addWidget(self.edit, 1)
        layout.addWidget(self.toggle)
        layout.addWidget(self.copy)
        self.set_subject(subject)

    def set_subject(self, subject: str) -> None:
        """Nom de l'objet protégé, pour des noms accessibles précis (« Afficher le secret de Production »)."""
        self._subject = subject
        self._update_names()

    def _update_names(self) -> None:
        shown = self.toggle.isChecked()
        if self._subject:
            name = (
                tr("Masquer le secret de {name}") if shown else tr("Afficher le secret de {name}")
            ).format(name=self._subject)
            copy_name = tr("Copier le secret de {name}").format(name=self._subject)
        else:
            name = tr("Masquer le secret") if shown else tr("Afficher le secret")
            copy_name = tr("Copier le secret")
        self.toggle.setAccessibleName(name)
        self.toggle.setToolTip(name)
        self.copy.setAccessibleName(copy_name)
        self.copy.setToolTip(copy_name)

    def _toggle(self, shown: bool) -> None:
        self.edit.setEchoMode(QLineEdit.EchoMode.Normal if shown else QLineEdit.EchoMode.Password)
        self.toggle.setText(tr("Masquer") if shown else tr("Afficher"))
        set_icon(self.toggle, "eye-off" if shown else "eye")
        self._update_names()

    def _copy(self) -> None:
        copy_to_clipboard(self.edit.text())
        self.copied.emit()

    def text(self) -> str:
        return self.edit.text()

    def set_text(self, value: str) -> None:
        self.edit.setText(value)
        self.toggle.setChecked(False)
        self._toggle(False)


class PortField(QWidget):
    """Port local avec vérification en direct (libre, occupé, réservé par Windows) et « Choisir un port libre »."""

    changed = Signal()

    def __init__(self, suggest: Callable[[int | None], int | None], host_provider: Callable[[], str]) -> None:
        super().__init__()
        self._suggest = suggest
        self._host_provider = host_provider
        self._ignore_port: int | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        row = QHBoxLayout()
        row.setSpacing(8)
        self.edit = QLineEdit()
        self.edit.setValidator(QIntValidator(1, 65535, self))
        self.edit.setMaximumWidth(120)
        self.edit.setPlaceholderText("2222")
        self.edit.textEdited.connect(self._on_edit)
        self.auto = button(tr("Choisir un port libre"), "refresh")
        self.auto.clicked.connect(self._auto)
        row.addWidget(self.edit)
        row.addWidget(self.auto)
        row.addStretch()
        layout.addLayout(row)
        self.status = label("", "muted", wrap=True)
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

    def _show(self, text: str, role: str) -> None:
        self.status.setText(text)
        set_role(self.status, role)
        self.edit.setAccessibleDescription(text)

    def check(self) -> None:
        port = self.value()
        if port is None:
            self._show(tr("Le port doit être compris entre 1 et 65535.") if self.edit.text() else "", "muted")
            return
        if port == self._ignore_port:
            self._show(tr("Ce port est utilisé par la session de ce profil."), "muted")
            return
        result = check_local_port(self._host_provider() or "127.0.0.1", port)
        if result.status == PortStatus.FREE:
            self._show("✓ " + tr("Le port {port} est libre.").format(port=port), "success")
        elif result.status == PortStatus.RESERVED:
            self._show("× " + result.message, "error")
        elif result.status == PortStatus.IN_USE:
            self._show(
                "! " + tr("Le port {port} est utilisé par un autre programme.").format(port=port), "warning"
            )
        else:
            self._show("! " + result.message, "warning")


class FieldError(QLabel):
    def __init__(self) -> None:
        super().__init__()
        self.setProperty("role", "error")
        self.setWordWrap(True)
        self.hide()

    def show_error(self, message: str | None) -> None:
        self.setText(("× " + message) if message else "")
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
    return separator()


def add_shortcut(
    parent: QWidget, sequence: QKeySequence | QKeySequence.StandardKey | str, callback: Callable[[], object]
) -> QShortcut:
    shortcut = QShortcut(sequence if isinstance(sequence, QKeySequence) else QKeySequence(sequence), parent)
    shortcut.activated.connect(callback)
    return shortcut


class FocusWithinWatcher(QObject):
    """Marque un conteneur `focusWithin=true` tant qu'un de ses enfants a le focus (repère de focus, §6.3)."""

    def __init__(self, shell: QWidget) -> None:
        super().__init__(shell)
        self.shell = shell
        app = QGuiApplication.instance()
        if isinstance(app, QGuiApplication):
            app.focusObjectChanged.connect(self._changed)

    def _changed(self, focus: QObject | None) -> None:
        inside = isinstance(focus, QWidget) and self.shell.isAncestorOf(focus)
        set_flag(self.shell, "focusWithin", inside)
