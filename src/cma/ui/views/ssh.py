"""Serveurs SSH : ports distants découverts, redirections enregistrées, configuration (spécification §4.5).

- La liaison SSH du serveur et l'état des redirections sont deux choses distinctes : l'en-tête ne parle que
  de la liaison, chaque redirection garde son propre état.
- « Ports distants » est l'onglet initial ; les résultats restent visibles avec la date de leur lecture.
- La destination d'une redirection est toujours dite « vue depuis le serveur SSH ».
"""

from __future__ import annotations

import contextlib
from datetime import datetime
from typing import Any

from pydantic import ValidationError
from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QPoint,
    QSortFilterProxyModel,
    Qt,
)
from PySide6.QtGui import QColor, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSplitter,
    QStackedWidget,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from cma.core.events import SshConnectionChanged
from cma.core.models import Config, SavedForward, SshAuthMode, SshProfile, new_id, unique_name
from cma.core.sessions import SessionInfo, SessionKind, SessionState
from cma.core.ssh.discovery import DiscoveryResult, RemotePort
from cma.core.ssh.keys import KeySource, list_keys
from cma.i18n import tr
from cma.ui.actions import quick_actions, run_action
from cma.ui.context import GuiContext
from cma.ui.dialogs.misc import KeysDialog, KnownHostsDialog
from cma.ui.dialogs.redirect import RedirectDialog
from cma.ui.dialogs.transfer import run_export, run_import
from cma.ui.format import last_read
from cma.ui.icons import set_icon
from cma.ui.theme import current_tokens, state_colors
from cma.ui.views.common import Action, ListEntry, ProfileList, ask_unsaved, confirm
from cma.ui.widgets import (
    EmptyState,
    FieldError,
    StatusPill,
    add_shortcut,
    button,
    copy_to_clipboard,
    label,
    primary_button,
    set_flag,
    set_role,
    title,
    with_error,
)

TABS = ("ports", "forwards", "config")


def port_columns() -> list[str]:
    return [tr("Port"), tr("Écoute"), tr("Service ou conteneur"), tr("Web")]


class RemotePortsModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self.ports: list[RemotePort] = []

    def set_ports(self, ports: list[RemotePort]) -> None:
        self.beginResetModel()
        self.ports = ports
        self.endResetModel()

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.ports)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 4

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return port_columns()[section]
        return None

    def data(
        self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if not index.isValid():
            return None
        port = self.ports[index.row()]
        column = index.column()
        web = "—" if port.web_label in ("", "-") else port.web_label
        if role == Qt.ItemDataRole.DisplayRole:
            return [str(port.port), ", ".join(port.bind), port.display_name, web][column]
        if role == Qt.ItemDataRole.UserRole:
            return [port.port, ", ".join(port.bind), port.display_name.lower(), port.web_label][column]
        if role == Qt.ItemDataRole.AccessibleTextRole:
            return tr("Port {port}, écoute {bind}, {service}, web : {web}").format(
                port=port.port, bind=", ".join(port.bind) or "?", service=port.display_name, web=web
            )
        if role == Qt.ItemDataRole.ToolTipRole:
            details = [f"{port.port}/tcp", tr("écoute : {bind}").format(bind=", ".join(port.bind) or "?")]
            if port.final_url:
                details.append(port.final_url)
            if port.local_only:
                details.append(
                    tr(
                        "n'écoute que localement sur le serveur : une redirection SSH est le bon moyen d'y accéder"
                    )
                )
            return "\n".join(details)
        if role == Qt.ItemDataRole.ForegroundRole and column == 3 and port.http_code:
            tokens = current_tokens()
            return QColor(tokens.success if 200 <= port.http_code < 400 else tokens.warning)
        return None


class PortsTab(QWidget):
    def __init__(self, panel: SshProfilePanel) -> None:
        super().__init__()
        self.panel = panel
        self._last_when: datetime | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 12, 0, 0)
        layout.setSpacing(8)
        toolbar = QHBoxLayout()
        self.refresh_button = primary_button(tr("Lister les ports"), "list-details")
        self.refresh_button.setToolTip(tr("Interroger le serveur (F5)"))
        self.refresh_button.clicked.connect(self.refresh)
        self.probe = QCheckBox(tr("Sonder HTTP/HTTPS"))
        self.probe.setChecked(True)
        toolbar.addWidget(self.refresh_button)
        toolbar.addWidget(self.probe)
        toolbar.addStretch()
        layout.addLayout(toolbar)
        filters = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText(tr("Filtrer : port, service, conteneur…"))
        self.filter.setAccessibleName(tr("Filtrer les ports"))
        self.filter.setClearButtonEnabled(True)
        filters.addWidget(self.filter, 1)
        meta = QVBoxLayout()
        meta.setSpacing(0)
        self.status = label("", "meta")
        self.status.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.read_at = label("", "meta")
        self.read_at.setAlignment(Qt.AlignmentFlag.AlignRight)
        meta.addWidget(self.status)
        meta.addWidget(self.read_at)
        filters.addLayout(meta)
        layout.addLayout(filters)
        self.warnings = label("", "warning", wrap=True)
        self.warnings.hide()
        layout.addWidget(self.warnings)
        self.error_host = QWidget()
        error_row = QHBoxLayout(self.error_host)
        error_row.setContentsMargins(0, 0, 0, 0)
        self.error = label("", "error", wrap=True)
        self.retry = button(tr("Réessayer"), "refresh")
        self.retry.clicked.connect(self.refresh)
        error_row.addWidget(self.error, 1)
        error_row.addWidget(self.retry)
        self.error_host.hide()
        layout.addWidget(self.error_host)
        self.model = RemotePortsModel()
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(Qt.ItemDataRole.UserRole)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.filter.textChanged.connect(self.proxy.setFilterFixedString)
        self.filter.textChanged.connect(lambda _t: self._update_empty())
        self.table = QTableView()
        self.table.setAccessibleName(tr("Ports distants"))
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(40)
        header = self.table.horizontalHeader()
        header.resizeSection(0, 80)
        header.resizeSection(1, 150)
        header.resizeSection(3, 110)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.doubleClicked.connect(lambda _i: self.redirect_selected())
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.selectionModel().selectionChanged.connect(lambda *_a: self._update_redirect_button())
        layout.addWidget(self.table, 1)
        self.empty_hint = label("", "muted", wrap=True)
        layout.addWidget(self.empty_hint)
        bottom = QHBoxLayout()
        bottom.addWidget(label(tr("La destination est vue depuis le serveur SSH."), "muted"), 1)
        self.redirect_button = primary_button(tr("Rediriger…"), "arrows-right-left")
        self.redirect_button.clicked.connect(self.redirect_selected)
        bottom.addWidget(self.redirect_button)
        layout.addLayout(bottom)
        add_shortcut(self, QKeySequence.StandardKey.Refresh, self.refresh)
        self._update_empty()

    def _selected_port(self) -> RemotePort | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        return self.model.ports[self.proxy.mapToSource(rows[0]).row()]

    def _update_redirect_button(self) -> None:
        port = self._selected_port()
        self.redirect_button.setText(
            tr("Rediriger le port {port}…").format(port=port.port) if port else tr("Rediriger…")
        )

    def _update_empty(self) -> None:
        if self._last_when is None:
            text = tr("Le script de découverte est envoyé au serveur. Rien n'y est installé.")
        elif self.model.rowCount() == 0:
            text = tr("Aucun port découvert.")
        elif self.proxy.rowCount() == 0:
            text = tr("Aucun port ne correspond au filtre.")
        else:
            text = ""
        self.empty_hint.setText(text)
        self.empty_hint.setVisible(bool(text))

    def show_result(self, result: DiscoveryResult | None, when: datetime | None) -> None:
        self.model.set_ports(result.ports if result else [])
        self._last_when = when if result is not None else None
        self.error_host.hide()
        self._update_empty()
        self._update_redirect_button()
        if result is None:
            self.status.setText("")
            self.read_at.setText("")
            self.warnings.hide()
            return
        system = "Windows" if result.os == "windows" else "Linux"
        script = (
            tr("ports-report {version}").format(version=result.script_version or "?")
            if result.mode == "script"
            else "ss"
        )
        count = len(result.ports)
        ports = tr("1 port") if count == 1 else tr("{n} ports").format(n=count)
        self.status.setText(f"{ports} · {system} · {script}")
        self.read_at.setText(last_read(when))
        self.warnings.setText("\n".join("! " + w for w in result.warnings))
        self.warnings.setVisible(bool(result.warnings))

    def mark_disconnected(self, disconnected: bool) -> None:
        if self._last_when is None:
            return
        suffix = " · " + tr("Résultats conservés — serveur déconnecté.") if disconnected else ""
        self.read_at.setText(last_read(self._last_when) + suffix)

    def refresh(self) -> None:
        profile = self.panel.profile
        if profile is None:
            return
        self.refresh_button.setEnabled(False)
        self.error_host.hide()
        self.status.setText(
            tr("Recherche des ports…")
            if self.panel.is_connected()
            else tr("Connexion à {name}…").format(name=profile.name)
        )

        def done(result: DiscoveryResult) -> None:
            self.refresh_button.setEnabled(True)
            when = datetime.now()
            self.panel.view.discoveries[profile.id] = (result, when)
            if self.panel.profile is not None and self.panel.profile.id == profile.id:
                self.show_result(result, when)
                self.panel.update_connection_state()

        def failed(error: BaseException) -> None:
            self.refresh_button.setEnabled(True)
            if self.panel.profile is None or self.panel.profile.id != profile.id:
                return
            previous = self.panel.view.discoveries.get(profile.id)
            self.show_result(*(previous if previous else (None, None)))
            self.error.setText(tr("Impossible de lister les ports.") + f" {error}")
            self.error_host.show()

        self.panel.ctx.run(
            self.panel.ctx.manager.discover_ports(profile.id, probe_web=self.probe.isChecked()), done, failed
        )

    def redirect_selected(self) -> None:
        self.panel.add_forward(self._selected_port())

    def _context_menu(self, pos: QPoint) -> None:
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        self.table.selectRow(index.row())
        port = self._selected_port()
        if port is None:
            return
        menu = QMenu(self)
        menu.addAction(tr("Rediriger…"), self.redirect_selected)
        line = "\t".join((str(port.port), ", ".join(port.bind), port.display_name, port.web_label))
        menu.addAction(tr("Copier la ligne"), lambda: copy_to_clipboard(line))
        menu.exec(self.table.viewport().mapToGlobal(pos))
        menu.deleteLater()


class ForwardsTab(QWidget):
    def __init__(self, panel: SshProfilePanel) -> None:
        super().__init__()
        headers = [tr("Libellé"), tr("Vers (vu du serveur)"), tr("Local"), tr("Protocole"), tr("État")]
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
        self.table.setRowCount(len(forwards))
        tokens = current_tokens()
        if profile is not None:
            self.scope.setText(tr("Actions appliquées aux redirections de {name}.").format(name=profile.name))
        for row, forward in enumerate(forwards):
            session = self.panel.forward_session(forward.id)
            state = session.state if session is not None else SessionState.STOPPED
            values = [
                forward.label or "—",
                f"{forward.remote_host}:{forward.remote_port}",
                f"127.0.0.1:{forward.local_port}",
                (forward.scheme or "tcp").upper(),
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
        name = forward.label or f"{forward.remote_host}:{forward.remote_port}"
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


class SettingsTab(QWidget):
    """Onglet « Configuration » du serveur (le nom historique est conservé)."""

    def __init__(self, panel: SshProfilePanel) -> None:
        super().__init__()
        self.panel = panel
        self._loading = False
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setObjectName("PageScroll")
        scroll.setWidgetResizable(True)
        host = QWidget()
        host_layout = QHBoxLayout(host)
        host_layout.setContentsMargins(0, 12, 16, 12)
        column = QWidget()
        column.setMaximumWidth(720)
        layout = QVBoxLayout(column)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self.errors = {name: FieldError() for name in ("name", "host", "port", "user", "key_path", "via")}
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.name = QLineEdit()
        self.group = QComboBox()
        self.group.setEditable(True)
        group_line = self.group.lineEdit()
        if group_line is not None:
            group_line.setPlaceholderText(tr("Sans groupe"))
        self.favorite = QCheckBox(tr("Afficher dans les favoris"))
        self.host = QLineEdit()
        self.host.setPlaceholderText("serveur.exemple.lan")
        self.port = QLineEdit()
        self.port.setMaximumWidth(120)
        self.user = QLineEdit()
        form.addRow(tr("Nom"), with_error(self.name, self.errors["name"]))
        form.addRow(tr("Groupe"), self.group)
        form.addRow(self.favorite)
        form.addRow(tr("Hôte"), with_error(self.host, self.errors["host"]))
        form.addRow(tr("Port SSH"), with_error(self.port, self.errors["port"]))
        form.addRow(tr("Utilisateur"), with_error(self.user, self.errors["user"]))
        layout.addLayout(form)

        layout.addWidget(title(tr("Authentification"), "SectionTitle"))
        auth_form = QFormLayout()
        auth_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        auth_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.auth_password = QRadioButton(tr("Mot de passe"))
        self.auth_key = QRadioButton(tr("Clé SSH"))
        self.auth_agent = QRadioButton(tr("Agent SSH"))
        self.auth_agent.setToolTip(tr("Agent SSH et clés de ~/.ssh"))
        group = QButtonGroup(self)
        radios = QHBoxLayout()
        radios.setSpacing(16)
        for radio in (self.auth_password, self.auth_key, self.auth_agent):
            group.addButton(radio)
            radios.addWidget(radio)
        radios.addStretch()
        auth_form.addRow(tr("Méthode"), radios)
        self.remember = QCheckBox(tr("Mémoriser le mot de passe dans le coffre"))
        auth_form.addRow(self.remember)
        key_host = QWidget()
        key_row = QHBoxLayout(key_host)
        key_row.setContentsMargins(0, 0, 0, 0)
        self.key = QComboBox()
        self.key.setAccessibleName(tr("Clé SSH"))
        manage = QPushButton(tr("Clés…"))
        manage.clicked.connect(self._manage_keys)
        self.deploy = button(tr("Déployer sur le serveur…"), "upload")
        self.deploy.clicked.connect(self._deploy)
        key_row.addWidget(self.key, 1)
        key_row.addWidget(manage)
        key_row.addWidget(self.deploy)
        auth_form.addRow(tr("Clé"), with_error(key_host, self.errors["key_path"]))
        layout.addLayout(auth_form)

        layout.addWidget(title(tr("Passage par Cloudflare"), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Pour un serveur SSH publié par Cloudflare Access : le tunnel du profil choisi est ouvert d'abord, puis le SSH passe par lui."
                ),
                "muted",
                wrap=True,
            )
        )
        via_form = QFormLayout()
        via_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        via_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.via = QComboBox()
        via_form.addRow(tr("Profil Cloudflare"), with_error(self.via, self.errors["via"]))
        layout.addLayout(via_form)
        layout.addWidget(title(tr("Notes"), "SectionTitle"))
        self.notes = QPlainTextEdit()
        self.notes.setAccessibleName(tr("Notes"))
        self.notes.setMinimumHeight(80)
        self.notes.setMaximumHeight(120)
        layout.addWidget(self.notes)
        known = button(tr("Empreintes des serveurs…"), "fingerprint")
        known.clicked.connect(lambda: KnownHostsDialog(self, self.panel.ctx).exec())
        layout.addWidget(known, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addStretch()
        host_layout.addWidget(column, 1)
        scroll.setWidget(host)
        outer.addWidget(scroll, 1)
        footer = QHBoxLayout()
        footer.setContentsMargins(0, 8, 16, 0)
        self.dirty_label = label("", "muted")
        footer.addWidget(self.dirty_label, 1)
        self.revert_button = QPushButton(tr("Annuler"))
        self.revert_button.setToolTip(tr("Revenir aux valeurs enregistrées"))
        self.revert_button.clicked.connect(self._revert)
        self.save_button = primary_button(tr("Enregistrer"), "circle-check")
        self.save_button.clicked.connect(self.save)
        footer.addWidget(self.revert_button)
        footer.addWidget(self.save_button)
        outer.addLayout(footer)
        add_shortcut(self, QKeySequence.StandardKey.Save, self.save)
        for widget in (self.name, self.host, self.port, self.user):
            widget.textEdited.connect(self._changed)
        self.group.editTextChanged.connect(self._changed)
        for combo in (self.key, self.via):
            combo.currentIndexChanged.connect(self._changed)
        for check in (self.favorite, self.remember, self.auth_password, self.auth_key, self.auth_agent):
            check.toggled.connect(self._changed)
        self.notes.textChanged.connect(self._changed)

    def refresh_choices(self) -> None:
        self._loading = True
        ctx = self.panel.ctx
        config = ctx.config()
        current_key = self.key.currentData()
        self.key.clear()
        self.key.addItem(tr("— choisir une clé —"), None)
        for key in list_keys(ctx.paths.keys_dir):
            stored = key.path.name if key.source == KeySource.APP else str(key.path)
            suffix = f" · {key.fingerprint[:20]}…" if key.fingerprint else ""
            self.key.addItem(
                f"{key.name} ({'app' if key.source == KeySource.APP else '~/.ssh'}){suffix}", stored
            )
        self.key.setCurrentIndex(max(0, self.key.findData(current_key)))
        current_via = self.via.currentData()
        self.via.clear()
        self.via.addItem(tr("Aucun — connexion directe"), None)
        for profile in config.cloudflare_profiles:
            self.via.addItem(f"{profile.name} ({profile.hostname or '?'})", profile.id)
        self.via.setCurrentIndex(max(0, self.via.findData(current_via)))
        groups = sorted({p.group for p in config.ssh_profiles if p.group}, key=str.lower)
        text = self.group.currentText()
        self.group.clear()
        self.group.addItems(["", *groups])
        self.group.setEditText(text)
        self._loading = False

    def load(self, profile: SshProfile) -> None:
        self.refresh_choices()
        self._loading = True
        self.name.setText(profile.name)
        self.group.setEditText(profile.group)
        self.favorite.setChecked(profile.favorite)
        self.host.setText(profile.host)
        self.port.setText(str(profile.port))
        self.user.setText(profile.user)
        {
            SshAuthMode.PASSWORD: self.auth_password,
            SshAuthMode.KEY: self.auth_key,
            SshAuthMode.AGENT: self.auth_agent,
        }[profile.auth].setChecked(True)
        self.remember.setChecked(profile.remember_password)
        index = self.key.findData(profile.key_path)
        if index < 0 and profile.key_path:
            self.key.addItem(profile.key_path, profile.key_path)
            index = self.key.count() - 1
        self.key.setCurrentIndex(max(0, index))
        self.via.setCurrentIndex(max(0, self.via.findData(profile.via_cloudflare_profile)))
        self.notes.setPlainText(profile.notes)
        self._clear_errors()
        self._loading = False
        self._changed()

    def _revert(self) -> None:
        if self.panel.profile is not None:
            self.load(self.panel.profile)

    def form_values(self) -> dict[str, Any]:
        profile = self.panel.profile
        assert profile is not None
        auth = (
            SshAuthMode.KEY
            if self.auth_key.isChecked()
            else SshAuthMode.AGENT
            if self.auth_agent.isChecked()
            else SshAuthMode.PASSWORD
        )
        port_text = self.port.text().strip()
        return {
            **profile.model_dump(),
            "name": self.name.text().strip(),
            "group": self.group.currentText().strip(),
            "favorite": self.favorite.isChecked(),
            "host": self.host.text().strip(),
            "port": int(port_text) if port_text.isdigit() else port_text,
            "user": self.user.text().strip(),
            "auth": auth,
            "remember_password": self.remember.isChecked() and auth == SshAuthMode.PASSWORD,
            "key_path": self.key.currentData(),
            "via_cloudflare_profile": self.via.currentData(),
            "notes": self.notes.toPlainText(),
        }

    def is_dirty(self) -> bool:
        profile = self.panel.profile
        if profile is None:
            return False
        reference = profile.model_dump(mode="json")
        current = self.form_values()
        current["auth"] = str(current["auth"])
        keys = (
            "name",
            "group",
            "favorite",
            "host",
            "port",
            "user",
            "auth",
            "remember_password",
            "key_path",
            "via_cloudflare_profile",
            "notes",
        )
        return any(reference.get(k) != current.get(k) for k in keys)

    def _changed(self, *_args: object) -> None:
        if self._loading:
            return
        key_mode = self.auth_key.isChecked()
        has_key = self.key.currentData() is not None
        self.key.setEnabled(key_mode)
        self.deploy.setEnabled(key_mode and has_key)
        self.deploy.setToolTip(
            tr("Ajoute la clé publique aux clés autorisées du compte (connexion par mot de passe)")
            if has_key
            else tr("Sélectionnez une clé publique à déployer.")
        )
        self.remember.setEnabled(self.auth_password.isChecked())
        dirty = self.is_dirty()
        self.save_button.setEnabled(dirty)
        self.revert_button.setEnabled(dirty)
        self.dirty_label.setText(tr("Modifications non enregistrées") if dirty else "")

    def _clear_errors(self) -> None:
        for error in self.errors.values():
            error.show_error(None)
        for widget in (self.name, self.host, self.port, self.user):
            set_flag(widget, "invalid", False)

    def _show_error(self, field: str, message: str) -> None:
        if field in self.errors:
            self.errors[field].show_error(message)
        widget = {"name": self.name, "host": self.host, "port": self.port, "user": self.user}.get(field)
        if widget is not None:
            set_flag(widget, "invalid", True)

    def save(self) -> bool:
        profile = self.panel.profile
        if profile is None or not self.is_dirty():
            return True
        self._clear_errors()
        values = self.form_values()
        # Messages de la spécification avant la validation du modèle, plus technique.
        port = values["port"]
        checks = {
            "name": None if values["name"] else tr("Saisissez un nom."),
            "host": None if values["host"] else tr("Saisissez un nom d'hôte ou une adresse IP."),
            "port": None
            if isinstance(port, int) and 1 <= port <= 65535
            else tr("Saisissez un port entre 1 et 65535."),
        }
        others = {p.name.lower() for p in self.panel.ctx.config().ssh_profiles if p.id != profile.id}
        if values["name"] and values["name"].lower() in others:
            checks["name"] = tr("Un serveur nommé « {name} » existe déjà.").format(name=values["name"])
        if values["auth"] == SshAuthMode.KEY and not values["key_path"]:
            checks["key_path"] = tr("Sélectionnez une clé SSH, ou créez-en une avec « Clés… ».")
        failed = {field: message for field, message in checks.items() if message}
        candidate: SshProfile | None = None
        try:
            candidate = SshProfile.model_validate(values)
        except ValidationError as exc:
            for err in exc.errors():
                field = str(err["loc"][0]) if err.get("loc") else "name"
                failed.setdefault(field, str(err.get("msg", "")).removeprefix("Value error, "))
        if failed or candidate is None:
            for field, message in failed.items():
                self._show_error(field, message)
            return False
        if not candidate.remember_password and profile.remember_password:
            with contextlib.suppress(Exception):
                self.panel.ctx.core.secrets.delete(candidate.password_key)

        def replace(config: Config) -> None:
            config.ssh_profiles = [candidate if p.id == candidate.id else p for p in config.ssh_profiles]

        if not self.panel.ctx.update_config(replace):
            return False
        self.panel.profile = candidate
        self.load(candidate)
        self.panel.ctx.notify("success", tr("Serveur « {name} » enregistré.").format(name=candidate.name))
        return True

    def _manage_keys(self) -> None:
        KeysDialog(self, self.panel.ctx).exec()
        self.refresh_choices()
        self._changed()

    def _deploy(self) -> None:
        profile = self.panel.profile
        key_path = self.key.currentData()
        if profile is None or key_path is None:
            return
        if self.is_dirty() and not self.save():
            return
        key_name = self.key.currentText().split(" (")[0]
        if not confirm(
            self,
            tr("Déployer la clé « {key} » ?").format(key=key_name),
            tr(
                "La clé publique sera ajoutée à ~/.ssh/authorized_keys de {user}@{host}. "
                "La connexion se fait une fois par mot de passe."
            ).format(user=profile.user or "?", host=profile.host or "?"),
            tr("Déployer"),
        ):
            return
        ctx = self.panel.ctx

        def done(result: Any) -> None:
            if str(result) == "already_present":
                ctx.notify("info", tr("La clé était déjà autorisée sur le serveur."))
            else:
                ctx.notify("success", tr("Clé ajoutée à ~/.ssh/authorized_keys sur le serveur."))

        ctx.notify("info", tr("Connexion par mot de passe pour déposer la clé…"))
        ctx.run(ctx.manager.deploy_key(profile.id, key_path), done, lambda e: ctx.notify("error", str(e)))


class SshProfilePanel(QWidget):
    def __init__(self, ctx: GuiContext, view: SshView) -> None:
        super().__init__()
        self.ctx = ctx
        self.view = view
        self.profile: SshProfile | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 0, 0, 0)
        layout.setSpacing(8)
        header = QHBoxLayout()
        header.setSpacing(12)
        names = QVBoxLayout()
        names.setSpacing(2)
        first = QHBoxLayout()
        first.setSpacing(8)
        self.heading = title("", "ObjectTitle")
        self.pill = StatusPill()
        first.addWidget(self.heading)
        first.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignVCenter)
        first.addStretch()
        names.addLayout(first)
        self.target = label("", "mono", selectable=True)
        self.route = label("", "muted")
        names.addWidget(self.target)
        names.addWidget(self.route)
        header.addLayout(names, 1)
        self.connect_button = primary_button(tr("Connecter"), "plug-connected")
        self.connect_button.clicked.connect(self._toggle_connection)
        header.addWidget(self.connect_button, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setProperty("role", "plain")
        self.ports_tab = PortsTab(self)
        self.forwards_tab = ForwardsTab(self)
        self.settings_tab = SettingsTab(self)
        self.tabs.addTab(self.ports_tab, tr("Ports distants"))
        self.tabs.addTab(self.forwards_tab, tr("Redirections"))
        self.tabs.addTab(self.settings_tab, tr("Configuration"))
        layout.addWidget(self.tabs, 1)

    def show_tab(self, key: str) -> None:
        """Affiche un onglet : « ports », « forwards » ou « config »."""
        self.tabs.setCurrentIndex(TABS.index(key) if key in TABS else 0)

    def load(self, profile: SshProfile) -> None:
        changed = self.profile is None or self.profile.id != profile.id
        self.profile = profile
        self.heading.setText(profile.name)
        via = self.ctx.config().cloudflare_profile(profile.via_cloudflare_profile)
        self.target.setText(f"{profile.user or '?'}@{profile.host or '?'}:{profile.port}")
        self.route.setText(
            tr("Via Cloudflare : {name}").format(name=via.name) if via else tr("Connexion directe")
        )
        discovery = self.view.discoveries.get(profile.id)
        self.ports_tab.show_result(*(discovery if discovery else (None, None)))
        self.forwards_tab.reload()
        self.settings_tab.load(profile)
        if changed:
            self.show_tab("ports")
        self.update_connection_state()

    def forward_session(self, forward_id: str) -> SessionInfo | None:
        matches = [s for s in self.view.sessions.values() if s.forward_id == forward_id]
        active = [s for s in matches if s.state.active]
        return (active or matches or [None])[0]

    def is_connected(self) -> bool:
        state = self.view.ssh_states.get(self.profile.id) if self.profile else None
        return state is not None and state.state == "connected"

    def update_connection_state(self) -> None:
        if self.profile is None:
            return
        state = self.view.ssh_states.get(self.profile.id)
        labels = {
            "connected": (tr("Connecté"), "success", "✓"),
            "connecting": (tr("Connexion…"), "info", "↻"),
            "error": (tr("Erreur"), "danger", "×"),
        }
        text, status, symbol = labels.get(state.state if state else "", (tr("Déconnecté"), "neutral", "■"))
        self.pill.set_status(text, status, symbol)
        self.pill.setToolTip(state.message if state and state.message else "")
        connected = state is not None and state.state in ("connected", "connecting")
        self.connect_button.setText(tr("Déconnecter") if connected else tr("Connecter"))
        set_role(self.connect_button, "secondary" if connected else "primary")
        set_icon(
            self.connect_button,
            "plug-connected-x" if connected else "plug-connected",
            "text" if connected else "on_accent",
        )
        self.ports_tab.mark_disconnected(not connected)

    def _toggle_connection(self) -> None:
        if self.profile is None:
            return
        state = self.view.ssh_states.get(self.profile.id)
        if state is not None and state.state in ("connected", "connecting"):
            self.ctx.run(self.ctx.manager.ssh_disconnect(self.profile.id))
            return
        if self.settings_tab.is_dirty() and not self.settings_tab.save():
            self.show_tab("config")
            return
        self.ctx.run(
            self.ctx.manager.ssh_connect(self.profile.id), on_error=lambda e: self.ctx.notify("error", str(e))
        )

    def add_forward(self, remote: RemotePort | None) -> None:
        if self.profile is None:
            return
        dialog = RedirectDialog(self, self.ctx, remote=remote, server=self.profile.name)
        if dialog.exec() != RedirectDialog.DialogCode.Accepted or dialog.choice is None:
            return
        choice = dialog.choice
        profile_id = self.profile.id
        if choice.save:

            def add(config: Config) -> None:
                target = config.ssh_profile(profile_id)
                if target is not None:
                    target.saved_forwards.append(choice.forward)

            if not self.ctx.update_config(add):
                return
        if choice.start:
            self.ctx.run(
                self.ctx.manager.start_forward(profile_id, choice.forward),
                on_error=lambda e: self.ctx.notify("error", str(e)),
            )
        self.show_tab("forwards")

    def edit_forward(self, forward: SavedForward) -> None:
        if self.profile is None:
            return
        session = self.forward_session(forward.id)
        active = session is not None and session.state.active
        dialog = RedirectDialog(self, self.ctx, existing=forward, server=self.profile.name, active=active)
        if dialog.exec() != RedirectDialog.DialogCode.Accepted or dialog.choice is None:
            return
        updated = dialog.choice.forward
        profile_id = self.profile.id

        def replace(config: Config) -> None:
            target = config.ssh_profile(profile_id)
            if target is not None:
                target.saved_forwards = [updated if f.id == updated.id else f for f in target.saved_forwards]

        if self.ctx.update_config(replace) and active:
            self.ctx.notify(
                "info", tr("Les changements prendront effet au prochain démarrage de la redirection.")
            )


class SshView(QWidget):
    def __init__(self, ctx: GuiContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.sessions: dict[str, SessionInfo] = {}
        self.ssh_states: dict[str, SshConnectionChanged] = {}
        self.discoveries: dict[str, tuple[DiscoveryResult, datetime]] = {}
        self._current: str | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 16)
        layout.setSpacing(4)
        layout.addWidget(title(tr("Serveurs SSH")))
        layout.addWidget(
            label(
                tr("Découvrez les ports d'un serveur et ouvrez-les sur ce poste par des redirections."),
                "muted",
            )
        )
        layout.addSpacing(12)
        splitter = QSplitter()
        splitter.setChildrenCollapsible(False)
        self.list = ProfileList(
            tr("Rechercher un serveur (Ctrl+F)"),
            [
                ("copy", tr("Dupliquer"), self.duplicate),
                ("file-import", tr("Importer…"), lambda: run_import(ctx, self)),
                (
                    "file-export",
                    tr("Exporter…"),
                    lambda: run_export(ctx, self, {self._current} if self._current else None),
                ),
                ("key", tr("Clés SSH…"), self._manage_keys),
                ("trash", tr("Supprimer le serveur…"), self.delete),
            ],
            new_action=(tr("Nouveau serveur"), self.new_profile),
            item_actions=self._item_actions,
            name=tr("Serveurs SSH"),
        )
        self.list.more_button.setAccessibleName(tr("Actions sur les serveurs"))
        self.list.more_button.setToolTip(tr("Actions sur les serveurs"))
        self.list.selected.connect(self._on_select)
        splitter.addWidget(self.list)
        self.stack = QStackedWidget()
        new_button = primary_button(tr("Nouveau serveur"), "plus")
        new_button.clicked.connect(self.new_profile)
        import_button = button(tr("Importer…"), "file-import")
        import_button.clicked.connect(lambda: run_import(ctx, self))
        self.empty = EmptyState(
            "server",
            tr("Aucun serveur sélectionné"),
            tr(
                "Un serveur SSH permet de lister ses ports ouverts et d'y accéder depuis ce poste par des redirections."
            ),
            [new_button, import_button],
        )
        self.panel = SshProfilePanel(ctx, self)
        self.stack.addWidget(self.empty)
        self.stack.addWidget(self.panel)
        splitter.addWidget(self.stack)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([248, 760])
        layout.addWidget(splitter, 1)
        add_shortcut(self, QKeySequence.StandardKey.New, self.new_profile)
        add_shortcut(self, QKeySequence.StandardKey.Find, self.list.focus_search)
        ctx.bridge.config_changed.connect(self.reload)
        ctx.bridge.session_changed.connect(self._on_session)
        ctx.bridge.session_removed.connect(self._on_session_removed)
        ctx.bridge.ssh_state.connect(self._on_ssh_state)
        self.reload()

    def _entries(self) -> list[ListEntry]:
        tokens = current_tokens()
        texts = {
            "connected": tr("connecté"),
            "connecting": tr("connexion en cours"),
            "error": tr("en erreur"),
        }
        entries = []
        for profile in self.ctx.config().ssh_profiles:
            state = self.ssh_states.get(profile.id)
            key = state.state if state else ""
            color = {"connected": tokens.success, "connecting": tokens.info, "error": tokens.danger}.get(key)
            entries.append(
                ListEntry(
                    profile.id,
                    profile.name,
                    profile.group,
                    profile.favorite,
                    color,
                    f"{profile.user}@{profile.host}",
                    texts.get(key, ""),
                )
            )
        return entries

    def reload(self) -> None:
        self.list.set_entries(self._entries())
        if self._current is None:
            return
        profile = self.ctx.config().ssh_profile(self._current)
        if profile is None:
            self._show(None)
        elif not self.panel.settings_tab.is_dirty():
            self.panel.load(profile)
        elif self.panel.profile is not None:
            # Formulaire en cours d'édition : on ne met à jour que les redirections.
            self.panel.profile = self.panel.profile.model_copy(
                update={"saved_forwards": profile.saved_forwards}
            )
            self.panel.forwards_tab.reload()

    def _show(self, profile_id: str | None) -> None:
        profile = self.ctx.config().ssh_profile(profile_id) if profile_id else None
        self._current = profile.id if profile else None
        if profile is None:
            self.stack.setCurrentWidget(self.empty)
            return
        self.panel.load(profile)
        self.stack.setCurrentWidget(self.panel)

    def _on_select(self, profile_id: str) -> None:
        if profile_id == (self._current or ""):
            return
        if self.panel.settings_tab.is_dirty() and self.panel.profile is not None:
            choice = ask_unsaved(self, self.panel.profile.name)
            if choice == "cancel" or (choice == "save" and not self.panel.settings_tab.save()):
                self.list.select(self._current)
                return
        self._show(profile_id or None)

    def select_profile(self, profile_id: str, section: str | None = None) -> None:
        self.list.select(profile_id)
        if section is not None and self._current == profile_id:
            self.panel.show_tab(section)

    def _on_session(self, info: SessionInfo) -> None:
        if info.kind != SessionKind.SSH_FORWARD:
            return
        self.sessions[info.id] = info
        if info.profile_id == self._current:
            self.panel.forwards_tab.reload()

    def _on_session_removed(self, session_id: str) -> None:
        info = self.sessions.pop(session_id, None)
        if info is not None and info.profile_id == self._current:
            self.panel.forwards_tab.reload()

    def _on_ssh_state(self, event: SshConnectionChanged) -> None:
        self.ssh_states[event.profile_id] = event
        self.list.set_entries(self._entries())
        if event.profile_id == self._current:
            self.panel.update_connection_state()

    def new_profile(self) -> None:
        config = self.ctx.config()
        profile = SshProfile(name=unique_name(tr("Nouveau serveur"), [p.name for p in config.ssh_profiles]))
        if self.ctx.update_config(lambda c: c.ssh_profiles.append(profile)):
            self.list.search.clear()
            self.list.select(profile.id)
            self._show(profile.id)
            self.panel.show_tab("config")
            self.panel.settings_tab.name.setFocus()
            self.panel.settings_tab.name.selectAll()

    def duplicate(self) -> None:
        config = self.ctx.config()
        source = config.ssh_profile(self._current)
        if source is None:
            return
        copy = source.model_copy(
            update={
                "id": new_id(),
                "name": unique_name(
                    tr("{name} (copie)").format(name=source.name), [p.name for p in config.ssh_profiles]
                ),
                "remember_password": False,
                "saved_forwards": [],
            }
        )
        if self.ctx.update_config(lambda c: c.ssh_profiles.append(copy)):
            self.list.select(copy.id)

    def delete(self) -> None:
        profile = self.ctx.config().ssh_profile(self._current)
        if profile is None:
            return
        active = sum(1 for s in self.sessions.values() if s.profile_id == profile.id and s.state.active)
        count = len(profile.saved_forwards)
        details = []
        if count:
            details.append(tr("Ses {n} redirection(s) enregistrée(s) seront supprimées.").format(n=count))
        if active:
            details.append(tr("{n} redirection(s) active(s) seront arrêtées.").format(n=active))
        if not confirm(
            self,
            tr("Supprimer le serveur « {name} » ?").format(name=profile.name),
            " ".join(details) or tr("Le serveur sera retiré de la liste."),
            tr("Arrêter et supprimer") if active else tr("Supprimer"),
        ):
            return
        for session in list(self.sessions.values()):
            if session.profile_id == profile.id and session.state.active:
                self.ctx.run(self.ctx.manager.stop(session.id))
        self.ctx.run(self.ctx.manager.ssh_disconnect(profile.id))
        with contextlib.suppress(Exception):
            self.ctx.core.secrets.delete(profile.password_key)
        self.panel.profile = None
        if self.ctx.update_config(
            lambda c: setattr(c, "ssh_profiles", [p for p in c.ssh_profiles if p.id != profile.id])
        ):
            self._show(None)
            self.ctx.notify("success", tr("Serveur « {name} » supprimé.").format(name=profile.name))

    def _manage_keys(self) -> None:
        KeysDialog(self, self.ctx).exec()

    def _item_actions(self, profile_id: str) -> list[Action]:
        state = self.ssh_states.get(profile_id)
        connected = state is not None and state.state in ("connected", "connecting")

        def toggle() -> None:
            manager = self.ctx.manager
            coro = manager.ssh_disconnect(profile_id) if connected else manager.ssh_connect(profile_id)
            self.ctx.run(coro, on_error=lambda e: self.ctx.notify("error", str(e)))

        return [
            (
                "plug-connected-x" if connected else "plug-connected",
                tr("Déconnecter") if connected else tr("Connecter"),
                toggle,
            ),
            ("copy", tr("Dupliquer"), self.duplicate),
            ("file-export", tr("Exporter…"), lambda: run_export(self.ctx, self, {profile_id})),
            ("trash", tr("Supprimer…"), self.delete),
        ]

    def has_unsaved_changes(self) -> bool:
        return self.panel.settings_tab.is_dirty()
