"""Zone de notification : état global (couleur et symbole), favoris avec leur état en mots, ouverture, sortie.

L'icône est neutre sans session, verte avec un ✓ si tout est à l'écoute, orange avec « ! » pour une session
dégradée ou en reconnexion, rouge avec « × » en cas d'erreur (§4.26) : la couleur ne porte jamais seule l'état.
"""

from __future__ import annotations

from PySide6.QtCore import QObject
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from cma.core.events import SshConnectionChanged
from cma.core.models import CloudflareProfile, SshProfile
from cma.core.sessions import SessionInfo, SessionState
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.icons import app_icon_with_status, token_icon
from cma.ui.main_window import MainWindow
from cma.ui.theme import LIGHT
from cma.ui.views.dashboard import RUNNING, sessions_summary


class Tray(QObject):
    def __init__(self, ctx: GuiContext, window: MainWindow) -> None:
        super().__init__(window)
        self.ctx = ctx
        self.window = window
        self.sessions: dict[str, SessionInfo] = {}
        self.ssh_states: dict[str, SshConnectionChanged] = {}
        self.icon = QSystemTrayIcon(app_icon_with_status(None), self)
        self.icon.setToolTip(tr("CMA : {summary}").format(summary=sessions_summary([])))
        self.menu = QMenu()
        self.icon.setContextMenu(self.menu)
        self.icon.activated.connect(self._activated)
        ctx.bridge.session_changed.connect(self._on_session)
        ctx.bridge.session_removed.connect(self._on_removed)
        ctx.bridge.ssh_state.connect(self._on_ssh_state)
        ctx.bridge.config_changed.connect(self._rebuild_menu)
        self._rebuild_menu()

    def show(self) -> None:
        self.icon.show()

    def notify(self, level: str, title: str, message: str) -> None:
        kind = {
            "error": QSystemTrayIcon.MessageIcon.Critical,
            "warning": QSystemTrayIcon.MessageIcon.Warning,
        }.get(level, QSystemTrayIcon.MessageIcon.Information)
        self.icon.showMessage(title, message, kind, 6000)

    def _activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.window.bring_to_front()
        elif reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.window.isVisible() and not self.window.isMinimized():
                self.window.save_window_state()
                self.window.hide()
            else:
                self.window.bring_to_front()

    def _on_session(self, info: SessionInfo) -> None:
        self.sessions[info.id] = info
        self._refresh_state()

    def _on_removed(self, session_id: str) -> None:
        self.sessions.pop(session_id, None)
        self._refresh_state()

    def _on_ssh_state(self, event: SshConnectionChanged) -> None:
        self.ssh_states[event.profile_id] = event
        self._rebuild_menu()

    def global_state(self) -> tuple[str | None, str | None]:
        """(couleur, symbole) de l'icône : erreur, puis vigilance, puis tout va bien, sinon neutre."""
        # La barre des tâches ne suit pas le thème de CMA : teintes du thème clair, lisibles sur les deux fonds.
        states = {s.state for s in self.sessions.values()}
        if SessionState.ERROR in states:
            return LIGHT.danger, "error"
        if states & {SessionState.DEGRADED, SessionState.RECONNECTING}:
            return LIGHT.warning, "warn"
        if states & {SessionState.LISTENING, SessionState.STARTING}:
            return LIGHT.success, "ok"
        return None, None

    def _refresh_state(self) -> None:
        color, symbol = self.global_state()
        self.icon.setIcon(app_icon_with_status(color, symbol))
        summary = sessions_summary(list(self.sessions.values()))
        self.icon.setToolTip(tr("CMA : {summary}").format(summary=summary))
        self._rebuild_menu()

    def _favorite_state(self, profile: CloudflareProfile | SshProfile) -> tuple[str, bool]:
        if isinstance(profile, CloudflareProfile):
            infos = [s for s in self.sessions.values() if s.profile_id == profile.id]
            running = [s for s in infos if s.state in RUNNING]
            if running:
                return running[0].state.label, True
            return (infos[0].state.label if infos else tr("Arrêté")), False
        state = self.ssh_states.get(profile.id)
        forwards_running = any(
            s.profile_id == profile.id and s.state in RUNNING for s in self.sessions.values()
        )
        if state is not None and state.state == "connected":
            return tr("Connecté"), True
        if forwards_running:
            return tr("En cours"), True
        return tr("Déconnecté"), False

    def _rebuild_menu(self) -> None:
        self.menu.clear()
        summary = sessions_summary(list(self.sessions.values()))
        header = self.menu.addAction(tr("CMA — {summary}").format(summary=summary))
        header.setEnabled(False)
        config = self.ctx.config()
        favorites: list[CloudflareProfile | SshProfile] = [
            p for p in config.cloudflare_profiles if p.favorite
        ]
        favorites += [p for p in config.ssh_profiles if p.favorite]
        submenu = self.menu.addMenu(token_icon("star"), tr("Favoris"))
        if not favorites:
            empty = submenu.addAction(tr("Aucun favori"))
            empty.setEnabled(False)
        for profile in favorites:
            state, running = self._favorite_state(profile)
            if isinstance(profile, CloudflareProfile):
                verb = tr("Arrêter") if running else tr("Connecter")
            else:
                verb = tr("Déconnecter") if running else tr("Connecter")
            action = submenu.addAction(
                token_icon("player-stop-filled" if running else "player-play-filled"),
                f"{profile.name} — {state} · {verb}",
            )
            action.triggered.connect(lambda _c=False, p=profile, r=running: self._toggle(p, r))
        self.menu.addSeparator()
        self.menu.addAction(token_icon("layout-dashboard"), tr("Ouvrir"), self.window.bring_to_front)
        stop = self.menu.addAction(
            token_icon("player-stop-filled"),
            tr("Tout arrêter"),
            lambda: self.ctx.run(self.ctx.manager.stop_all()),
        )
        stop.setEnabled(any(s.state in RUNNING for s in self.sessions.values()))
        self.menu.addSeparator()
        self.menu.addAction(token_icon("x"), tr("Quitter"), self.window.request_quit)

    def _toggle(self, profile: CloudflareProfile | SshProfile, running: bool) -> None:
        manager = self.ctx.manager

        def notify_error(error: BaseException) -> None:
            self.ctx.notify("error", str(error))

        if isinstance(profile, CloudflareProfile):
            coro = manager.stop_profile(profile.id) if running else manager.start_cloudflare(profile.id)
        else:
            coro = manager.ssh_disconnect(profile.id) if running else manager.start_saved_forwards(profile.id)
        self.ctx.run(coro, on_error=notify_error)
