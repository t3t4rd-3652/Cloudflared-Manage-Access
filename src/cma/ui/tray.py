"""Icône de la zone de notification : état global en couleur, favoris, ouverture, arrêt, sortie."""

from __future__ import annotations

from PySide6.QtCore import QObject
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from cma import APP_NAME
from cma.core.models import CloudflareProfile
from cma.core.sessions import SessionInfo, SessionState
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.icons import app_icon_with_status, icon
from cma.ui.main_window import MainWindow
from cma.ui.theme import current_tokens


class Tray(QObject):
    def __init__(self, ctx: GuiContext, window: MainWindow) -> None:
        super().__init__(window)
        self.ctx = ctx
        self.window = window
        self.sessions: dict[str, SessionInfo] = {}
        self.icon = QSystemTrayIcon(app_icon_with_status(None), self)
        self.icon.setToolTip(APP_NAME)
        self.menu = QMenu()
        self.icon.setContextMenu(self.menu)
        self.icon.activated.connect(self._activated)
        ctx.bridge.session_changed.connect(self._on_session)
        ctx.bridge.session_removed.connect(self._on_removed)
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
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
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

    def _refresh_state(self) -> None:
        tokens = current_tokens()
        states = {s.state for s in self.sessions.values()}
        if states & {SessionState.ERROR}:
            color = tokens.danger
        elif states & {SessionState.DEGRADED, SessionState.RECONNECTING, SessionState.STARTING}:
            color = tokens.warning
        elif SessionState.LISTENING in states:
            color = tokens.success
        else:
            color = None
        self.icon.setIcon(app_icon_with_status(color))
        active = sum(1 for s in self.sessions.values() if s.state.active)
        self.icon.setToolTip(f"{APP_NAME}\n" + tr("{n} session(s) active(s)").format(n=active))
        self._rebuild_menu()

    def _rebuild_menu(self) -> None:
        self.menu.clear()
        active = sum(1 for s in self.sessions.values() if s.state.active)
        header = self.menu.addAction(tr("{n} session(s) active(s)").format(n=active))
        header.setEnabled(False)
        config = self.ctx.config()
        favorites = [p for p in config.cloudflare_profiles if p.favorite] + [
            p for p in config.ssh_profiles if p.favorite
        ]
        if favorites:
            self.menu.addSection(tr("Favoris"))
            running = {s.profile_id for s in self.sessions.values() if s.state.active}
            for profile in favorites:
                is_running = profile.id in running
                action = QAction(
                    icon("player-stop-filled" if is_running else "player-play-filled"),
                    profile.name,
                    self.menu,
                )
                action.triggered.connect(lambda _c=False, p=profile, r=is_running: self._toggle(p, r))
                self.menu.addAction(action)
        self.menu.addSeparator()
        self.menu.addAction(icon("layout-dashboard"), tr("Ouvrir"), self.window.bring_to_front)
        stop = self.menu.addAction(
            icon("player-stop-filled"), tr("Tout arrêter"), lambda: self.ctx.run(self.ctx.manager.stop_all())
        )
        stop.setEnabled(active > 0)
        self.menu.addSeparator()
        self.menu.addAction(icon("x"), tr("Quitter"), self.window.request_quit)

    def _toggle(self, profile: object, running: bool) -> None:
        manager = self.ctx.manager
        notify_error = lambda e: self.ctx.notify("error", str(e))  # noqa: E731
        if isinstance(profile, CloudflareProfile):
            coro = manager.stop_profile(profile.id) if running else manager.start_cloudflare(profile.id)
        else:
            coro = manager.ssh_disconnect(profile.id) if running else manager.start_saved_forwards(profile.id)  # type: ignore[attr-defined]
        self.ctx.run(coro, on_error=notify_error)
