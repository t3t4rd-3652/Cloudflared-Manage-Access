"""Serveurs SSH : ports distants découverts, redirections enregistrées, configuration (spécification §4.5).

- La liaison SSH du serveur et l'état des redirections sont deux choses distinctes : l'en-tête ne parle que
  de la liaison, chaque redirection garde son propre état.
- « Ports distants » est l'onglet initial ; les résultats restent visibles avec la date de leur lecture.
- La destination d'une redirection est toujours dite « vue depuis le serveur SSH ».
"""

from __future__ import annotations

import contextlib
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import (
    QHBoxLayout,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from cma.core.events import SshConnectionChanged
from cma.core.models import Config, SavedForward, SshProfile, new_id, unique_name
from cma.core.sessions import SessionInfo, SessionKind
from cma.core.ssh.discovery import DiscoveryResult, RemotePort
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.dialogs.misc import KeysDialog
from cma.ui.dialogs.redirect import RedirectDialog
from cma.ui.dialogs.transfer import run_export, run_import
from cma.ui.icons import set_icon
from cma.ui.theme import current_tokens
from cma.ui.views.common import Action, ListEntry, ProfileList, ask_unsaved, confirm
from cma.ui.views.ssh.files_tab import FilesTab
from cma.ui.views.ssh.forwards_tab import ForwardsTab
from cma.ui.views.ssh.ports_tab import PortsTab
from cma.ui.views.ssh.settings_tab import SettingsTab
from cma.ui.widgets import (
    EmptyState,
    StatusPill,
    add_shortcut,
    button,
    label,
    primary_button,
    set_role,
    title,
)

TABS = ("ports", "forwards", "files", "config")


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
        self.files_tab = FilesTab(self)
        self.settings_tab = SettingsTab(self)
        self.tabs.addTab(self.ports_tab, tr("Ports distants"))
        self.tabs.addTab(self.forwards_tab, tr("Redirections"))
        self.tabs.addTab(self.files_tab, tr("Fichiers"))
        self.tabs.addTab(self.settings_tab, tr("Configuration"))
        layout.addWidget(self.tabs, 1)

    def show_tab(self, key: str) -> None:
        """Affiche un onglet : « ports », « forwards », « files » ou « config »."""
        self.tabs.setCurrentIndex(TABS.index(key) if key in TABS else 0)

    def load(self, profile: SshProfile) -> None:
        changed = self.profile is None or self.profile.id != profile.id
        self.profile = profile
        self.heading.setText(profile.name)
        via = self.ctx.config().cloudflare_profile(profile.via_cloudflare_profile)
        self.target.setText(f"{profile.user or '?'}@{profile.host or '?'}:{profile.port}")
        jump = self.ctx.config().ssh_profile(profile.jump_profile)
        if via:
            route = tr("Via Cloudflare : {name}").format(name=via.name)
        elif jump:
            route = tr("Rebond par : {name}").format(name=jump.name)
        else:
            route = tr("Connexion directe")
        self.route.setText(route)
        discovery = self.view.discoveries.get(profile.id)
        self.ports_tab.show_result(*(discovery if discovery else (None, None)))
        self.forwards_tab.reload()
        self.settings_tab.load(profile)
        if changed:
            self.files_tab.reset(profile)
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
