"""Accès Cloudflare : liste groupée à gauche, éditeur en trois sections à droite (spécification §4.3) ; l'éditeur
est dans `profile_editor.py`.

- Sections « Connexion », « Authentification » et « Avancé » ; libellés au-dessus des champs, formulaire
  limité à 720 px ; seul le corps défile, l'en-tête et le pied d'enregistrement restent fixes.
- Un onglet signale ses erreurs (« Avancé · 1 erreur ») ; un enregistrement refusé place le focus sur le
  premier champ invalide.
- Modifier un profil n'interrompt pas sa session : un bandeau propose de redémarrer pour appliquer.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import (
    QSplitter,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from cma.core.models import CloudflareProfile, Config, new_id, unique_name
from cma.core.sessions import SessionInfo, SessionKind
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.dialogs.diagnose import open_diagnosis
from cma.ui.dialogs.links import show_share
from cma.ui.dialogs.transfer import run_export, run_import
from cma.ui.theme import STATUS_OF_STATE
from cma.ui.views.common import (
    SERVICE_ICONS,
    Action,
    ListEntry,
    ProfileList,
    ask_unsaved,
    confirm,
    page_header,
)
from cma.ui.views.profile_editor import CloudflareEditor
from cma.ui.widgets import (
    EmptyState,
    add_shortcut,
    button,
    primary_button,
)


class CloudflareProfilesView(QWidget):
    def __init__(self, ctx: GuiContext, open_tokens: Callable[[], None]) -> None:
        super().__init__()
        self.ctx = ctx
        self.open_tokens = open_tokens
        self.sessions: dict[str, SessionInfo] = {}
        self._current: str | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 16)
        layout.setSpacing(4)
        page_header(
            layout,
            tr("Accès Cloudflare"),
            tr("Applications protégées par Cloudflare Access, ouvertes sur un port de ce poste."),
        )
        splitter = QSplitter()
        splitter.setHandleWidth(8)
        splitter.setChildrenCollapsible(False)
        self.list = ProfileList(
            tr("Rechercher un profil (Ctrl+F)"),
            [
                ("file-import", tr("Importer…"), lambda: run_import(ctx, self)),
                ("file-export", tr("Exporter…"), lambda: run_export(ctx, self)),
                ("copy", tr("Dupliquer le profil"), self.duplicate),
                ("trash", tr("Supprimer le profil…"), self.delete),
            ],
            new_action=(tr("Nouveau profil"), self.new_profile),
            group_actions=self._group_actions,
            item_actions=self._item_actions,
            name=tr("Profils Cloudflare"),
        )
        self.list.more_button.setAccessibleName(tr("Actions sur les profils"))
        self.list.more_button.setToolTip(tr("Actions sur les profils"))
        self.list.selected.connect(self._on_select)
        self.list.tree.itemDoubleClicked.connect(lambda *_a: self.editor.name.setFocus())
        splitter.addWidget(self.list)
        self.stack = QStackedWidget()
        new_button = primary_button(tr("Créer un profil"), "plus")
        new_button.clicked.connect(self.new_profile)
        import_button = button(tr("Importer…"), "file-import")
        import_button.clicked.connect(lambda: run_import(ctx, self))
        self.empty = EmptyState(
            "cloud",
            tr("Aucun profil sélectionné"),
            tr(
                "Un profil décrit une application protégée par Cloudflare Access et le port local qui y mène."
            ),
            [new_button, import_button],
        )
        self.editor = CloudflareEditor(ctx, self)
        self.stack.addWidget(self.empty)
        self.stack.addWidget(self.editor)
        splitter.addWidget(self.stack)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([280, 760])
        layout.addWidget(splitter, 1)
        add_shortcut(self, QKeySequence.StandardKey.New, self.new_profile)
        add_shortcut(self, QKeySequence.StandardKey.Find, self.list.focus_search)
        ctx.bridge.config_changed.connect(self.reload)
        ctx.bridge.session_changed.connect(self._on_session)
        ctx.bridge.session_removed.connect(self._on_session_removed)
        self.reload()

    # --- Menus -----------------------------------------------------------------------------

    def _group_actions(self, group: str) -> list[Action]:
        return [
            ("player-play-filled", tr("Connecter le groupe"), lambda: self.connect_group(group)),
            ("player-stop-filled", tr("Déconnecter le groupe"), lambda: self.disconnect_group(group)),
        ]

    def _item_actions(self, profile_id: str) -> list[Action]:
        session = self._session_for(profile_id)
        active = session is not None and session.state.active

        def toggle() -> None:
            if active:
                self.ctx.run(self.ctx.manager.stop_profile(profile_id))
            else:
                self.ctx.run(
                    self.ctx.manager.start_cloudflare(profile_id),
                    on_error=lambda e: self.ctx.notify("error", str(e)),
                )

        def rename() -> None:
            self.editor.tabs.setCurrentIndex(0)
            self.editor.name.setFocus()
            self.editor.name.selectAll()

        return [
            (
                "player-stop-filled" if active else "player-play-filled",
                tr("Déconnecter") if active else tr("Connecter"),
                toggle,
            ),
            ("bug", tr("Diagnostiquer…"), lambda: open_diagnosis(self, self.ctx, profile_id)),
            ("copy", tr("Dupliquer"), self.duplicate),
            ("pencil", tr("Renommer"), rename),
            ("file-export", tr("Exporter…"), lambda: run_export(self.ctx, self, {profile_id})),
            ("link", tr("Partager…"), lambda: self.share(profile_id)),
            ("trash", tr("Supprimer…"), self.delete),
        ]

    def share(self, profile_id: str) -> None:
        profile = self.ctx.config().cloudflare_profile(profile_id)
        if profile is not None:
            show_share(self, self.ctx, profile)

    def connect_group(self, group: str) -> None:
        self.ctx.run(self.ctx.manager.start_group(group), None, lambda e: self.ctx.notify("error", str(e)))

    def disconnect_group(self, group: str) -> None:
        self.ctx.run(self.ctx.manager.stop_group(group), None, lambda e: self.ctx.notify("error", str(e)))

    # --- Données ---------------------------------------------------------------------------

    def _entries(self) -> list[ListEntry]:
        config = self.ctx.config()
        entries: list[ListEntry] = []
        for profile in config.cloudflare_profiles:
            session = self._session_for(profile.id)
            active = session is not None and session.state.active
            entries.append(
                ListEntry(
                    profile.id,
                    profile.name,
                    profile.group,
                    profile.favorite,
                    STATUS_OF_STATE[session.state] if session is not None and active else None,
                    profile.hostname or "—",
                    session.state.label if session is not None and active else "",
                    SERVICE_ICONS.get(profile.service_type, "cloud"),
                )
            )
        return entries

    def reload(self) -> None:
        config = self.ctx.config()
        self.list.set_entries(self._entries())
        self.editor.refresh_choices(config)
        if self._current is not None:
            profile = config.cloudflare_profile(self._current)
            if profile is None:
                self._show(None)
            elif not self.editor.is_dirty():
                self.editor.load(profile)

    def _session_for(self, profile_id: str) -> SessionInfo | None:
        matches = [
            s
            for s in self.sessions.values()
            if s.profile_id == profile_id and s.kind == SessionKind.CLOUDFLARE
        ]
        active = [s for s in matches if s.state.active]
        return (active or matches or [None])[0]

    def _on_session(self, info: SessionInfo) -> None:
        if info.kind != SessionKind.CLOUDFLARE:
            return
        self.sessions[info.id] = info
        if info.profile_id == self._current:
            self.editor.set_session(self._session_for(info.profile_id))
        self.reload_statuses()

    def _on_session_removed(self, session_id: str) -> None:
        info = self.sessions.pop(session_id, None)
        if info is not None and info.profile_id == self._current:
            self.editor.set_session(self._session_for(info.profile_id))
        self.reload_statuses()

    def reload_statuses(self) -> None:
        self.list.set_entries(self._entries())

    def _show(self, profile_id: str | None) -> None:
        self._current = profile_id
        profile = self.ctx.config().cloudflare_profile(profile_id) if profile_id else None
        if profile is None:
            self._current = None
            self.stack.setCurrentWidget(self.empty)
            return
        self.editor.session = self._session_for(profile.id)
        self.editor._saved_while_active = False
        self.editor.load(profile)
        self.stack.setCurrentWidget(self.editor)

    def _on_select(self, profile_id: str) -> None:
        if profile_id == (self._current or ""):
            return
        if self.editor.is_dirty() and self.editor.profile is not None:
            choice = ask_unsaved(self, self.editor.profile.name)
            if choice == "cancel" or (choice == "save" and not self.editor.save()):
                self.list.select(self._current)
                return
        self._show(profile_id or None)

    def select_profile(self, profile_id: str) -> None:
        self.list.select(profile_id)

    # --- Actions ----------------------------------------------------------------------------

    def new_profile(self) -> None:
        config = self.ctx.config()
        profile = CloudflareProfile(
            name=unique_name(tr("Nouveau profil"), [p.name for p in config.cloudflare_profiles]),
            local_port=self.ctx.manager.suggest_local_port(),
        )
        if self.ctx.update_config(lambda c: c.cloudflare_profiles.append(profile)):
            self.list.search.clear()
            self.list.select(profile.id)
            self._show(profile.id)
            self.editor.tabs.setCurrentIndex(0)
            self.editor.name.setFocus()
            self.editor.name.selectAll()

    def duplicate(self) -> None:
        source = self.ctx.config().cloudflare_profile(self._current)
        if source is None:
            return
        config = self.ctx.config()
        copy = source.model_copy(
            update={
                "id": new_id(),
                "name": unique_name(
                    tr("{name} (copie)").format(name=source.name),
                    [p.name for p in config.cloudflare_profiles],
                ),
                "local_port": self.ctx.manager.suggest_local_port(),
                "auto_start": False,
            }
        )
        if self.ctx.update_config(lambda c: c.cloudflare_profiles.append(copy)):
            self.list.select(copy.id)

    def delete(self) -> None:
        config = self.ctx.config()
        profile = config.cloudflare_profile(self._current)
        if profile is None:
            return
        dependents = config.ssh_profiles_via(profile.id)
        session = self._session_for(profile.id)
        active = session is not None and session.state.active
        lines: list[str] = []
        if dependents:
            lines.append(
                tr("Ces profils SSH passent par lui : {names}.").format(
                    names=", ".join(p.name for p in dependents)
                )
            )
            lines.append(tr("Leur passage par Cloudflare devra être reconfiguré."))
        if active:
            lines.append(tr("La connexion sera arrêtée."))
        heading = tr("Supprimer le profil « {name} » ?").format(name=profile.name)
        action = tr("Arrêter et supprimer") if active else tr("Supprimer le profil")
        if not confirm(self, heading, "\n".join(lines) or heading, action):
            return
        self.ctx.run(self.ctx.manager.stop_profile(profile.id))

        def remove(c: Config) -> None:
            c.cloudflare_profiles = [p for p in c.cloudflare_profiles if p.id != profile.id]
            for ssh in c.ssh_profiles:
                if ssh.via_cloudflare_profile == profile.id:
                    ssh.via_cloudflare_profile = None

        self.editor.profile = None
        if self.ctx.update_config(remove):
            self._show(None)
            self.ctx.notify("success", tr("Profil « {name} » supprimé.").format(name=profile.name))

    def has_unsaved_changes(self) -> bool:
        return self.editor.is_dirty()
