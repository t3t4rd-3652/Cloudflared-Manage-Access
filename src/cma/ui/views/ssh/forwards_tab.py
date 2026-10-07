"""Onglet « Redirections » : redirections enregistrées du serveur, chacune avec son propre état."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import (
    QPoint,
    Qt,
)
from PySide6.QtGui import QColor, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QMenu,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from cma.core.models import Config, SavedForward
from cma.core.sessions import SessionState
from cma.i18n import tr
from cma.ui.actions import quick_actions, run_action
from cma.ui.icons import set_icon
from cma.ui.state import remember_header
from cma.ui.theme import current_tokens, state_colors
from cma.ui.views.common import confirm
from cma.ui.widgets import (
    add_shortcut,
    button,
    clear_items,
    label,
    primary_button,
)

if TYPE_CHECKING:
    from cma.ui.views.ssh.view import SshProfilePanel


def forward_type_label(forward: SavedForward) -> str:
    """Colonne « Type » : SOCKS, inverse, ou le protocole web d'une redirection locale."""
    if forward.kind == "socks":
        return "SOCKS"
    if forward.kind == "remote":
        return tr("Inverse")
    return (forward.scheme or "tcp").upper()


class ForwardsTab(QWidget):
    def __init__(self, panel: SshProfilePanel) -> None:
        super().__init__()
        headers = [tr("Libellé"), tr("Côté serveur"), tr("Côté poste"), tr("Type"), tr("État")]
        self.panel = panel
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 12, 0, 0)
        layout.setSpacing(8)
        toolbar = QHBoxLayout()
        self.start_all = button(tr("Tout démarrer"), "player-play-filled")
        self.start_all.clicked.connect(self._start_all)
        self.stop_all = button(tr("Tout arrêter"), "player-stop-filled")
        self.stop_all.clicked.connect(self._stop_all)
        add = primary_button(tr("Ajouter…"), "plus")
        add.clicked.connect(lambda: self.panel.add_forward(None))
        toolbar.addWidget(self.start_all)
        toolbar.addWidget(self.stop_all)
        toolbar.addStretch()
        toolbar.addWidget(add)
        layout.addLayout(toolbar)
        self.scope = label("", "muted")
        layout.addWidget(self.scope)
        self.table = QTableWidget(0, len(headers))
        self.table.setAccessibleName(tr("Redirections enregistrées"))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(36)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        remember_header(self.table.horizontalHeader(), "ssh-forwards")
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self.table.doubleClicked.connect(lambda _i: self._edit())
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self.table, 1)
        row = QHBoxLayout()
        self.toggle_button = button(tr("Démarrer"), "player-play-filled")
        self.toggle_button.clicked.connect(self._toggle)
        self.open_button = QToolButton()
        self.open_button.setText(tr("Ouvrir"))
        self.open_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        set_icon(self.open_button, "external-link")
        self.open_button.clicked.connect(self._open)
        self.edit_button = button(tr("Modifier…"), "pencil")
        self.edit_button.clicked.connect(self._edit)
        self.remove_button = button(tr("Supprimer…"), "trash", danger=True)
        self.remove_button.clicked.connect(self._remove)
        for widget in (self.toggle_button, self.open_button, self.edit_button, self.remove_button):
            row.addWidget(widget)
        row.addStretch()
        layout.addLayout(row)
        self.empty_hint = label(
            tr(
                "Aucune redirection enregistrée. Listez les ports du serveur, puis choisissez « Rediriger… »."
            ),
            "muted",
            wrap=True,
        )
        layout.addWidget(self.empty_hint)
        toggle = add_shortcut(self.table, QKeySequence("Ctrl+Return"), self._toggle)
        toggle.setContext(Qt.ShortcutContext.WidgetShortcut)

    def reload(self) -> None:
        profile = self.panel.profile
        forwards = profile.saved_forwards if profile else []
        selected = self._selected_id()
        clear_items(self.table, len(forwards))
        tokens = current_tokens()
        if profile is not None:
            self.scope.setText(tr("Actions appliquées aux redirections de {name}.").format(name=profile.name))
        for row, forward in enumerate(forwards):
            session = self.panel.forward_session(forward.id)
            state = session.state if session is not None else SessionState.STOPPED
            values = [
                forward.label or "—",
                forward.server_side,
                forward.local_side,
                forward_type_label(forward),
                state.label + (f" : {session.message}" if session is not None and session.message else ""),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, forward.id)
                if column == 4:
                    item.setForeground(QColor(state_colors(state, tokens)[0]))
                self.table.setItem(row, column, item)
            if forward.id == selected:
                self.table.selectRow(row)
        self.empty_hint.setVisible(not forwards)
        self._update_buttons()

    def _selected_id(self) -> str | None:
        items = self.table.selectedItems()
        return str(items[0].data(Qt.ItemDataRole.UserRole)) if items else None

    def _selected(self) -> SavedForward | None:
        forward_id = self._selected_id()
        profile = self.panel.profile
        if profile is None or forward_id is None:
            return None
        return next((f for f in profile.saved_forwards if f.id == forward_id), None)

    def _update_buttons(self) -> None:
        forward = self._selected()
        session = self.panel.forward_session(forward.id) if forward else None
        active = session is not None and session.state.active
        for widget in (self.toggle_button, self.edit_button, self.remove_button):
            widget.setEnabled(forward is not None)
        self.toggle_button.setText(tr("Arrêter") if active else tr("Démarrer"))
        set_icon(self.toggle_button, "player-stop-filled" if active else "player-play-filled")
        usable = session is not None and session.state in (SessionState.LISTENING, SessionState.DEGRADED)
        self.open_button.setEnabled(usable)
        self.open_button.setToolTip(
            "" if usable or forward is None else tr("Le port local n'est pas encore ouvert.")
        )
        profile = self.panel.profile
        forwards = profile.saved_forwards if profile else []
        running = [
            f for f in forwards if (s := self.panel.forward_session(f.id)) is not None and s.state.active
        ]
        self.start_all.setEnabled(len(running) < len(forwards))
        self.stop_all.setEnabled(bool(running))

    def _toggle(self) -> None:
        forward = self._selected()
        profile = self.panel.profile
        if forward is None or profile is None:
            return
        session = self.panel.forward_session(forward.id)
        ctx = self.panel.ctx
        if session is not None and session.state.active:
            ctx.run(ctx.manager.stop(session.id))
        else:
            ctx.run(
                ctx.manager.start_forward(profile.id, forward), on_error=lambda e: ctx.notify("error", str(e))
            )

    def _open(self) -> None:
        forward = self._selected()
        session = self.panel.forward_session(forward.id) if forward else None
        if session is not None:
            run_action(quick_actions(session)[0], self.panel.ctx.notify)

    def _edit(self) -> None:
        forward = self._selected()
        if forward is not None:
            self.panel.edit_forward(forward)

    def _remove(self) -> None:
        forward = self._selected()
        profile = self.panel.profile
        if forward is None or profile is None:
            return
        session = self.panel.forward_session(forward.id)
        active = session is not None and session.state.active
        name = forward.label or forward.describe()
        if active:
            text = tr("La redirection active sera arrêtée, puis retirée de {server}.")
        else:
            text = tr("Elle sera retirée de {server}.")
        if not confirm(
            self,
            tr("Supprimer la redirection « {name} » ?").format(name=name),
            text.format(server=profile.name),
            tr("Arrêter et supprimer") if active else tr("Supprimer"),
        ):
            return
        if session is not None:
            self.panel.ctx.run(self.panel.ctx.manager.stop(session.id))

        def remove(config: Config) -> None:
            target = config.ssh_profile(profile.id)
            if target is not None:
                target.saved_forwards = [f for f in target.saved_forwards if f.id != forward.id]

        self.panel.ctx.update_config(remove)

    def _context_menu(self, pos: QPoint) -> None:
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        self.table.selectRow(index.row())
        menu = QMenu(self)
        menu.addAction(self.toggle_button.text(), self._toggle)
        open_action = menu.addAction(tr("Ouvrir"), self._open)
        open_action.setEnabled(self.open_button.isEnabled())
        forward = self._selected()
        session = self.panel.forward_session(forward.id) if forward else None
        if session is not None and self.open_button.isEnabled():
            for action in quick_actions(session)[1:]:
                menu.addAction(action.label, lambda a=action: run_action(a, self.panel.ctx.notify))
        menu.addSeparator()
        menu.addAction(tr("Modifier…"), self._edit)
        menu.addAction(tr("Supprimer…"), self._remove)
        menu.exec(self.table.viewport().mapToGlobal(pos))
        menu.deleteLater()

    def _start_all(self) -> None:
        profile = self.panel.profile
        if profile is not None:
            self.panel.ctx.run(
                self.panel.ctx.manager.start_saved_forwards(profile.id),
                on_error=lambda e: self.panel.ctx.notify("error", str(e)),
            )

    def _stop_all(self) -> None:
        for forward in self.panel.profile.saved_forwards if self.panel.profile else []:
            session = self.panel.forward_session(forward.id)
            if session is not None and session.state.active:
                self.panel.ctx.run(self.panel.ctx.manager.stop(session.id))
