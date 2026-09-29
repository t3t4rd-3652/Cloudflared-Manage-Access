"""Redirections SSH : profils, ports distants découverts, redirections enregistrées, paramètres et clés."""

from __future__ import annotations

import contextlib
from datetime import datetime
from typing import Any

from pydantic import ValidationError
from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPersistentModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
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
from cma.ui.format import since
from cma.ui.theme import current_tokens, state_colors
from cma.ui.views.common import ListEntry, ProfileList, ask_unsaved, confirm
from cma.ui.widgets import (
    EmptyState,
    FieldError,
    StatusPill,
    add_shortcut,
    button,
    label,
    primary_button,
    set_flag,
    title,
    with_error,
)


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
        if role == Qt.ItemDataRole.DisplayRole:
            return [str(port.port), ", ".join(port.bind), port.display_name, port.web_label][column]
        if role == Qt.ItemDataRole.UserRole:
            return [port.port, ", ".join(port.bind), port.display_name.lower(), port.web_label][column]
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
            from PySide6.QtGui import QColor

            return QColor(tokens.success if 200 <= port.http_code < 400 else tokens.warning)
        return None


class PortsTab(QWidget):
    def __init__(self, panel: SshProfilePanel) -> None:
        super().__init__()
        self.panel = panel
        layout = QVBoxLayout(self)
        toolbar = QHBoxLayout()
        self.refresh_button = primary_button(tr("Lister les ports"), "refresh")
        self.refresh_button.setToolTip(tr("Interroger le serveur (F5)"))
        self.refresh_button.clicked.connect(self.refresh)
        self.probe = QCheckBox(tr("Sonder HTTP/HTTPS"))
        self.probe.setChecked(True)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText(tr("Filtrer (port, service, conteneur…)"))
        self.filter.setClearButtonEnabled(True)
        self.redirect_button = button(tr("Rediriger…"), "arrows-right-left")
        self.redirect_button.clicked.connect(self.redirect_selected)
        toolbar.addWidget(self.refresh_button)
        toolbar.addWidget(self.probe)
        toolbar.addWidget(self.filter, 1)
        toolbar.addWidget(self.redirect_button)
        layout.addLayout(toolbar)
        self.status = label("", "muted", wrap=True)
        layout.addWidget(self.status)
        self.warnings = label("", "warning", wrap=True)
        self.warnings.hide()
        layout.addWidget(self.warnings)
        self.model = RemotePortsModel()
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(Qt.ItemDataRole.UserRole)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.filter.textChanged.connect(self.proxy.setFilterFixedString)
        self.table = QTableView()
        self.table.setAccessibleName(tr("Ports distants"))
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.doubleClicked.connect(lambda _i: self.redirect_selected())
        layout.addWidget(self.table, 1)
        add_shortcut(self, QKeySequence.StandardKey.Refresh, self.refresh)
        self.empty_hint = label(
            tr(
                "Cliquez sur « Lister les ports » : le script de découverte est envoyé au serveur, rien n'y est installé."
            ),
            "muted",
            wrap=True,
        )
        layout.addWidget(self.empty_hint)

    def show_result(self, result: DiscoveryResult | None, when: datetime | None) -> None:
        self.model.set_ports(result.ports if result else [])
        self.empty_hint.setVisible(result is None)
        if result is None:
            self.status.setText("")
            self.warnings.hide()
            return
        mode = (
            tr("ports-report {version}").format(version=result.script_version or "?")
            if result.mode == "script"
            else "ss"
        )
        if result.os == "windows":
            mode += " · Windows"
        self.status.setText(
            tr("{n} port(s) · {mode} · il y a {ago}").format(n=len(result.ports), mode=mode, ago=since(when))
        )
        self.warnings.setText("\n".join(result.warnings))
        self.warnings.setVisible(bool(result.warnings))

    def refresh(self) -> None:
        profile = self.panel.profile
        if profile is None:
            return
        self.refresh_button.setEnabled(False)
        self.status.setText(tr("Découverte en cours sur {host}…").format(host=profile.host or profile.name))

        def done(result: DiscoveryResult) -> None:
            self.refresh_button.setEnabled(True)
            self.panel.view.discoveries[profile.id] = (result, datetime.now())
            if self.panel.profile is not None and self.panel.profile.id == profile.id:
                self.show_result(result, datetime.now())

        def failed(error: BaseException) -> None:
            self.refresh_button.setEnabled(True)
            self.status.setText("")
            self.panel.ctx.notify("error", str(error))

        self.panel.ctx.run(
            self.panel.ctx.manager.discover_ports(profile.id, probe_web=self.probe.isChecked()), done, failed
        )

    def redirect_selected(self) -> None:
        index = self.table.currentIndex()
        remote = self.model.ports[self.proxy.mapToSource(index).row()] if index.isValid() else None
        self.panel.add_forward(remote)


class ForwardsTab(QWidget):
    def __init__(self, panel: SshProfilePanel) -> None:
        super().__init__()
        headers = [tr("Libellé"), tr("Vers (vu du serveur)"), tr("Local"), tr("Protocole"), tr("État")]
        self.panel = panel
        layout = QVBoxLayout(self)
        toolbar = QHBoxLayout()
        self.start_all = primary_button(tr("Tout démarrer"), "player-play-filled")
        self.start_all.clicked.connect(self._start_all)
        self.stop_all = button(tr("Tout arrêter"), "player-stop-filled")
        self.stop_all.clicked.connect(self._stop_all)
        add = button(tr("Ajouter…"), "plus")
        add.clicked.connect(lambda: self.panel.add_forward(None))
        for widget in (self.start_all, self.stop_all, add):
            toolbar.addWidget(widget)
        toolbar.addStretch()
        layout.addLayout(toolbar)
        self.table = QTableWidget(0, len(headers))
        self.table.setAccessibleName(tr("Redirections enregistrées"))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.verticalHeader().hide()
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        self.table.doubleClicked.connect(lambda _i: self._toggle())
        layout.addWidget(self.table, 1)
        row = QHBoxLayout()
        self.toggle_button = button(tr("Démarrer"), "player-play-filled")
        self.toggle_button.clicked.connect(self._toggle)
        self.open_button = button(tr("Ouvrir"), "external-link")
        self.open_button.clicked.connect(self._open)
        self.edit_button = button(tr("Modifier…"), "pencil")
        self.edit_button.clicked.connect(self._edit)
        self.remove_button = button(tr("Supprimer"), "trash", danger=True)
        self.remove_button.clicked.connect(self._remove)
        for widget in (self.toggle_button, self.open_button, self.edit_button, self.remove_button):
            row.addWidget(widget)
        row.addStretch()
        layout.addLayout(row)
        self.empty_hint = label(
            tr("Aucune redirection enregistrée. Listez les ports du serveur puis choisissez « Rediriger… »."),
            "muted",
            wrap=True,
        )
        layout.addWidget(self.empty_hint)

    def reload(self) -> None:
        profile = self.panel.profile
        forwards = profile.saved_forwards if profile else []
        selected = self._selected_id()
        self.table.setRowCount(len(forwards))
        tokens = current_tokens()
        for row, forward in enumerate(forwards):
            session = self.panel.forward_session(forward.id)
            state = session.state if session is not None else SessionState.STOPPED
            values = [
                forward.label or "-",
                f"{forward.remote_host}:{forward.remote_port}",
                f"127.0.0.1:{forward.local_port}",
                (forward.scheme or "tcp").upper(),
                state.label + (f" : {session.message}" if session is not None and session.message else ""),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, forward.id)
                if column == 4:
                    from PySide6.QtGui import QColor

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
        self.open_button.setEnabled(
            session is not None and session.state in (SessionState.LISTENING, SessionState.DEGRADED)
        )
        profile = self.panel.profile
        self.start_all.setEnabled(bool(profile and profile.saved_forwards))

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
        if not confirm(
            self,
            tr("Supprimer la redirection"),
            tr("Supprimer la redirection vers {target} ?").format(
                target=f"{forward.remote_host}:{forward.remote_port}"
            ),
        ):
            return
        session = self.panel.forward_session(forward.id)
        if session is not None:
            self.panel.ctx.run(self.panel.ctx.manager.stop(session.id))

        def remove(config: Config) -> None:
            target = config.ssh_profile(profile.id)
            if target is not None:
                target.saved_forwards = [f for f in target.saved_forwards if f.id != forward.id]

        self.panel.ctx.update_config(remove)

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
    def __init__(self, panel: SshProfilePanel) -> None:
        super().__init__()
        self.panel = panel
        self._loading = False
        outer = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setObjectName("PageScroll")
        scroll.setWidgetResizable(True)
        body = QWidget()
        layout = QVBoxLayout(body)
        self.errors = {name: FieldError() for name in ("name", "host", "port", "user", "key_path", "via")}
        form = QFormLayout()
        self.name = QLineEdit()
        self.group = QComboBox()
        self.group.setEditable(True)
        self.favorite = QCheckBox(tr("Afficher dans les favoris du tableau de bord"))
        self.host = QLineEdit()
        self.host.setPlaceholderText("serveur.exemple.lan")
        self.port = QLineEdit()
        self.port.setMaximumWidth(100)
        self.user = QLineEdit()
        form.addRow(tr("Nom :"), with_error(self.name, self.errors["name"]))
        form.addRow(tr("Groupe :"), self.group)
        form.addRow("", self.favorite)
        form.addRow(tr("Hôte :"), with_error(self.host, self.errors["host"]))
        form.addRow(tr("Port SSH :"), with_error(self.port, self.errors["port"]))
        form.addRow(tr("Utilisateur :"), with_error(self.user, self.errors["user"]))
        layout.addLayout(form)

        layout.addWidget(title(tr("Authentification"), "SectionTitle"))
        auth_form = QFormLayout()
        self.auth_password = QRadioButton(tr("Mot de passe"))
        self.auth_key = QRadioButton(tr("Clé SSH"))
        self.auth_agent = QRadioButton(tr("Agent SSH et clés de ~/.ssh"))
        group = QButtonGroup(self)
        for radio in (self.auth_password, self.auth_key, self.auth_agent):
            group.addButton(radio)
        radios = QVBoxLayout()
        for radio in (self.auth_password, self.auth_key, self.auth_agent):
            radios.addWidget(radio)
        auth_form.addRow(tr("Méthode :"), radios)
        self.remember = QCheckBox(tr("Mémoriser le mot de passe dans le coffre"))
        auth_form.addRow("", self.remember)
        key_row = QHBoxLayout()
        key_row.setContentsMargins(0, 0, 0, 0)
        self.key = QComboBox()
        manage = QPushButton(tr("Clés…"))
        manage.clicked.connect(self._manage_keys)
        self.deploy = button(
            tr("Déployer sur le serveur"),
            "upload",
            tooltip=tr("Ajoute la clé publique à ~/.ssh/authorized_keys (connexion par mot de passe)"),
        )
        self.deploy.clicked.connect(self._deploy)
        key_row.addWidget(self.key, 1)
        key_row.addWidget(manage)
        key_row.addWidget(self.deploy)
        key_host = QWidget()
        key_host.setLayout(key_row)
        auth_form.addRow(tr("Clé :"), with_error(key_host, self.errors["key_path"]))
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
        self.via = QComboBox()
        via_form.addRow(tr("Profil Cloudflare :"), with_error(self.via, self.errors["via"]))
        layout.addLayout(via_form)
        layout.addWidget(title(tr("Notes"), "SectionTitle"))
        self.notes = QPlainTextEdit()
        self.notes.setAccessibleName(tr("Notes"))
        self.notes.setMaximumHeight(80)
        layout.addWidget(self.notes)
        known = button(tr("Empreintes des serveurs…"), "fingerprint")
        known.clicked.connect(lambda: KnownHostsDialog(self, self.panel.ctx).exec())
        layout.addWidget(known)
        layout.addStretch()
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)
        footer = QHBoxLayout()
        self.dirty_label = label("", "muted")
        footer.addWidget(self.dirty_label)
        footer.addStretch()
        self.save_button = primary_button(tr("Enregistrer"), "circle-check")
        self.save_button.clicked.connect(self.save)
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
        self.via.addItem(tr("Aucun (connexion directe)"), None)
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
        for error in self.errors.values():
            error.show_error(None)
        self._loading = False
        self._changed()

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
        self.key.setEnabled(key_mode)
        self.deploy.setEnabled(key_mode and self.key.currentData() is not None)
        self.remember.setEnabled(self.auth_password.isChecked())
        dirty = self.is_dirty()
        self.save_button.setEnabled(dirty)
        self.dirty_label.setText(tr("Modifications non enregistrées") if dirty else "")

    def save(self) -> bool:
        profile = self.panel.profile
        if profile is None or not self.is_dirty():
            return True
        for error in self.errors.values():
            error.show_error(None)
        for widget in (self.name, self.host, self.port, self.user):
            set_flag(widget, "invalid", False)
        values = self.form_values()
        try:
            candidate = SshProfile.model_validate(values)
        except ValidationError as exc:
            for err in exc.errors():
                field = str(err["loc"][0]) if err.get("loc") else "name"
                message = str(err.get("msg", "")).removeprefix("Value error, ")
                if field in self.errors:
                    self.errors[field].show_error(message)
                widget = {"name": self.name, "host": self.host, "port": self.port, "user": self.user}.get(
                    field
                )
                if widget is not None:
                    set_flag(widget, "invalid", True)
            return False
        if candidate.name.lower() in {
            p.name.lower() for p in self.panel.ctx.config().ssh_profiles if p.id != candidate.id
        }:
            self.errors["name"].show_error(tr("Un autre profil SSH porte déjà ce nom."))
            return False
        if candidate.auth == SshAuthMode.KEY and not candidate.key_path:
            self.errors["key_path"].show_error(tr("Choisissez une clé, ou générez-en une avec « Clés… »."))
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
        self.panel.ctx.notify("success", tr("Profil SSH « {name} » enregistré.").format(name=candidate.name))
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
        layout.setContentsMargins(0, 0, 0, 0)
        header = QHBoxLayout()
        self.heading = title("")
        self.pill = StatusPill()
        self.target = label("", "muted")
        header.addWidget(self.heading)
        header.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignVCenter)
        header.addWidget(self.target)
        header.addStretch()
        self.connect_button = primary_button(tr("Connecter"), "plug-connected")
        self.connect_button.clicked.connect(self._toggle_connection)
        header.addWidget(self.connect_button)
        layout.addLayout(header)
        self.tabs = QTabWidget()
        self.ports_tab = PortsTab(self)
        self.forwards_tab = ForwardsTab(self)
        self.settings_tab = SettingsTab(self)
        self.tabs.addTab(self.ports_tab, tr("Ports distants"))
        self.tabs.addTab(self.forwards_tab, tr("Redirections"))
        self.tabs.addTab(self.settings_tab, tr("Paramètres"))
        layout.addWidget(self.tabs, 1)

    def load(self, profile: SshProfile) -> None:
        self.profile = profile
        self.heading.setText(profile.name)
        via = self.ctx.config().cloudflare_profile(profile.via_cloudflare_profile)
        target = f"{profile.user or '?'}@{profile.host or '?'}:{profile.port}"
        self.target.setText(target + (tr(" via Cloudflare « {name} »").format(name=via.name) if via else ""))
        discovery = self.view.discoveries.get(profile.id)
        self.ports_tab.show_result(*(discovery if discovery else (None, None)))
        self.forwards_tab.reload()
        self.settings_tab.load(profile)
        self.update_connection_state()

    def forward_session(self, forward_id: str) -> SessionInfo | None:
        matches = [s for s in self.view.sessions.values() if s.forward_id == forward_id]
        active = [s for s in matches if s.state.active]
        return (active or matches or [None])[0]

    def update_connection_state(self) -> None:
        if self.profile is None:
            return
        state = self.view.ssh_states.get(self.profile.id)
        tokens = current_tokens()
        labels = {
            "connected": (tr("Connecté"), tokens.success, tokens.success_bg),
            "connecting": (tr("Connexion…"), tokens.warning, tokens.warning_bg),
            "error": (tr("Erreur"), tokens.danger, tokens.danger_bg),
        }
        text, fg, bg = labels.get(
            state.state if state else "", (tr("Déconnecté"), tokens.neutral, tokens.neutral_bg)
        )
        self.pill.set_colors("● " + text, fg, bg)
        self.pill.setToolTip(state.message if state and state.message else "")
        connected = state is not None and state.state in ("connected", "connecting")
        self.connect_button.setText(tr("Déconnecter") if connected else tr("Connecter"))

    def _toggle_connection(self) -> None:
        if self.profile is None:
            return
        state = self.view.ssh_states.get(self.profile.id)
        if state is not None and state.state in ("connected", "connecting"):
            self.ctx.run(self.ctx.manager.ssh_disconnect(self.profile.id))
            return
        if self.settings_tab.is_dirty() and not self.settings_tab.save():
            return
        self.ctx.run(
            self.ctx.manager.ssh_connect(self.profile.id), on_error=lambda e: self.ctx.notify("error", str(e))
        )

    def add_forward(self, remote: RemotePort | None) -> None:
        if self.profile is None:
            return
        dialog = RedirectDialog(self, self.ctx, remote=remote)
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
        self.tabs.setCurrentWidget(self.forwards_tab)

    def edit_forward(self, forward: SavedForward) -> None:
        if self.profile is None:
            return
        dialog = RedirectDialog(self, self.ctx, existing=forward)
        if dialog.exec() != RedirectDialog.DialogCode.Accepted or dialog.choice is None:
            return
        updated = dialog.choice.forward
        profile_id = self.profile.id

        def replace(config: Config) -> None:
            target = config.ssh_profile(profile_id)
            if target is not None:
                target.saved_forwards = [updated if f.id == updated.id else f for f in target.saved_forwards]

        if self.ctx.update_config(replace):
            session = self.forward_session(updated.id)
            if session is not None and session.state.active:
                self.ctx.notify("info", tr("Redémarrez la redirection pour appliquer les modifications."))


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
        layout.addWidget(title(tr("Redirections SSH")))
        splitter = QSplitter()
        self.list = ProfileList(
            tr("Rechercher un serveur (Ctrl+F)"),
            [
                ("plus", tr("Nouveau profil SSH (Ctrl+N)"), self.new_profile),
                ("copy", tr("Dupliquer"), self.duplicate),
                ("file-import", tr("Importer…"), lambda: run_import(ctx, self)),
                (
                    "file-export",
                    tr("Exporter…"),
                    lambda: run_export(ctx, self, {self._current} if self._current else None),
                ),
                ("key", tr("Clés SSH…"), self._manage_keys),
                ("trash", tr("Supprimer (Suppr)"), self.delete),
            ],
            name=tr("Serveurs SSH"),
        )
        self.list.selected.connect(self._on_select)
        splitter.addWidget(self.list)
        self.stack = QStackedWidget()
        new_button = primary_button(tr("Créer un profil SSH"), "plus")
        new_button.clicked.connect(self.new_profile)
        self.empty = EmptyState(
            "server",
            tr("Aucun serveur sélectionné"),
            tr(
                "Un profil SSH permet de lister les ports ouverts d'un serveur et d'y accéder depuis ce poste par des redirections."
            ),
            [new_button],
        )
        self.panel = SshProfilePanel(ctx, self)
        self.stack.addWidget(self.empty)
        self.stack.addWidget(self.panel)
        splitter.addWidget(self.stack)
        splitter.setStretchFactor(1, 1)
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
        entries = []
        for profile in self.ctx.config().ssh_profiles:
            state = self.ssh_states.get(profile.id)
            color = {"connected": tokens.success, "connecting": tokens.warning, "error": tokens.danger}.get(
                state.state if state else ""
            )
            entries.append(
                ListEntry(
                    profile.id,
                    profile.name,
                    profile.group,
                    profile.favorite,
                    color,
                    f"{profile.user}@{profile.host}",
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

    def select_profile(self, profile_id: str) -> None:
        self.list.select(profile_id)

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
            self.panel.tabs.setCurrentWidget(self.panel.settings_tab)
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
        if not confirm(
            self,
            tr("Supprimer le profil SSH"),
            tr("Supprimer le profil « {name} » et ses redirections enregistrées ?").format(name=profile.name),
        ):
            return
        self.ctx.run(self.ctx.manager.ssh_disconnect(profile.id))
        with contextlib.suppress(Exception):
            self.ctx.core.secrets.delete(profile.password_key)
        self.panel.profile = None
        if self.ctx.update_config(
            lambda c: setattr(c, "ssh_profiles", [p for p in c.ssh_profiles if p.id != profile.id])
        ):
            self._show(None)
            self.ctx.notify("success", tr("Profil SSH « {name} » supprimé.").format(name=profile.name))

    def _manage_keys(self) -> None:
        KeysDialog(self, self.ctx).exec()

    def has_unsaved_changes(self) -> bool:
        return self.panel.settings_tab.is_dirty()
