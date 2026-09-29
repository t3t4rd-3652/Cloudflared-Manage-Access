"""Fenêtre principale : barre latérale, vues, bandeaux d'information, barre d'état."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QByteArray, QSize, Qt, Signal
from PySide6.QtGui import QCloseEvent, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from cma import APP_NAME, __version__
from cma.core.events import Notification
from cma.core.sessions import SessionInfo, SessionState
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.icons import app_icon, icon
from cma.ui.views.dashboard import DashboardView
from cma.ui.views.logs import LogsView
from cma.ui.views.profiles import CloudflareProfilesView
from cma.ui.views.settings import SettingsView
from cma.ui.views.ssh import SshView
from cma.ui.views.tokens import TokensView
from cma.ui.widgets import BannerStack, add_shortcut, label


class MainWindow(QMainWindow):
    quit_requested = Signal()

    def __init__(self, ctx: GuiContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.tray_notify: Callable[[str, str, str], None] | None = None
        self.tray_available = False
        self.quitting = False
        self._told_about_tray = False
        self._sessions: dict[str, SessionInfo] = {}
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(app_icon())
        self.setMinimumSize(QSize(980, 640))

        root = QWidget()
        root.setObjectName("AppRoot")
        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(220)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(0, 0, 0, 8)
        brand = QHBoxLayout()
        brand.setContentsMargins(16, 14, 12, 8)
        logo = QLabel()
        logo.setPixmap(app_icon().pixmap(32, 32))
        heading = label(APP_NAME)
        heading.setObjectName("AppTitle")
        heading.setWordWrap(True)
        brand.addWidget(logo, 0, Qt.AlignmentFlag.AlignTop)
        brand.addWidget(heading, 1)
        side.addLayout(brand)
        self.nav = QListWidget()
        self.nav.setObjectName("SidebarList")
        self.nav.setIconSize(QSize(20, 20))
        self.nav.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        side.addWidget(self.nav, 1)
        side.addWidget(label(f"v{__version__}", "muted"), 0, Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(sidebar)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        self.banners = BannerStack()
        banner_host = QWidget()
        banner_layout = QVBoxLayout(banner_host)
        banner_layout.setContentsMargins(24, 12, 24, 0)
        banner_layout.addWidget(self.banners)
        content_layout.addWidget(banner_host)
        self.stack = QStackedWidget()
        content_layout.addWidget(self.stack, 1)
        layout.addWidget(content, 1)
        self.setCentralWidget(root)

        self.dashboard = DashboardView(ctx, self.open_logs_for)
        self.profiles = CloudflareProfilesView(ctx, lambda: self.show_view("tokens"))
        self.tokens = TokensView(ctx, self.open_profile)
        self.ssh = SshView(ctx)
        self.logs = LogsView(ctx)
        self.settings = SettingsView(ctx)
        self.views: dict[str, QWidget] = {}
        for key, text, icon_name, view in (
            ("dashboard", tr("Tableau de bord"), "layout-dashboard", self.dashboard),
            ("profiles", tr("Profils Cloudflare"), "cloud", self.profiles),
            ("tokens", tr("Service tokens"), "key", self.tokens),
            ("ssh", tr("Redirections SSH"), "server", self.ssh),
            ("logs", tr("Journaux"), "list-details", self.logs),
            ("settings", tr("Paramètres"), "settings", self.settings),
        ):
            item = QListWidgetItem(icon(icon_name), text)
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setSizeHint(QSize(0, 40))
            self.nav.addItem(item)
            self.stack.addWidget(view)
            self.views[key] = view
        self.nav.currentRowChanged.connect(self._on_nav)
        for index in range(self.nav.count()):
            add_shortcut(self, QKeySequence(f"Ctrl+{index + 1}"), lambda i=index: self.nav.setCurrentRow(i))
        add_shortcut(self, QKeySequence("Ctrl+Q"), self.request_quit)

        status = self.statusBar()
        self.status_cloudflared = label("")
        self.status_sessions = label("")
        self.status_errors = QPushButton()
        self.status_errors.setFlat(True)
        self.status_errors.setCursor(Qt.CursorShape.PointingHandCursor)
        self.status_errors.clicked.connect(lambda: self.show_view("logs"))
        status.addWidget(self.status_cloudflared, 1)
        status.addPermanentWidget(self.status_sessions)
        status.addPermanentWidget(self.status_errors)

        ctx.set_notifier(self.notify)
        ctx.runner.error.connect(self._on_task_error)
        ctx.bridge.notification.connect(self._on_notification)
        ctx.bridge.session_changed.connect(self._on_session)
        ctx.bridge.session_removed.connect(self._on_session_removed)
        ctx.bridge.log_line.connect(self._on_log_line)
        ctx.bridge.fatal_error.connect(
            lambda text: self.notify("error", tr("Erreur inattendue : {error}").format(error=text))
        )

        settings = ctx.config().settings
        if settings.window_geometry:
            self.restoreGeometry(QByteArray.fromBase64(settings.window_geometry.encode("ascii")))
        else:
            self.resize(1180, 760)
        start = next(
            (
                i
                for i in range(self.nav.count())
                if self.nav.item(i).data(Qt.ItemDataRole.UserRole) == settings.last_view
            ),
            0,
        )
        self.nav.setCurrentRow(start)
        self._update_status()

    # --- Navigation ----------------------------------------------------------------------------

    def _on_nav(self, row: int) -> None:
        if row < 0:
            return
        key = self.nav.item(row).data(Qt.ItemDataRole.UserRole)
        self.stack.setCurrentWidget(self.views[key])

    def show_view(self, key: str) -> None:
        for row in range(self.nav.count()):
            if self.nav.item(row).data(Qt.ItemDataRole.UserRole) == key:
                self.nav.setCurrentRow(row)
                return

    def current_view_key(self) -> str:
        item = self.nav.currentItem()
        return str(item.data(Qt.ItemDataRole.UserRole)) if item else "dashboard"

    def open_logs_for(self, session_id: str) -> None:
        self.logs.show_source(session_id)
        self.show_view("logs")

    def open_profile(self, profile_id: str) -> None:
        self.show_view("profiles")
        self.profiles.select_profile(profile_id)

    def bring_to_front(self) -> None:
        self.showNormal() if self.isMinimized() else self.show()
        self.raise_()
        self.activateWindow()

    # --- Notifications -------------------------------------------------------------------------------

    def notify(
        self,
        level: str,
        text: str,
        *,
        action: tuple[str, Callable[[], None]] | None = None,
        timeout_ms: int | None = None,
    ) -> None:
        visible = self.isVisible() and not self.isMinimized()
        if visible or level in ("warning", "error"):
            self.banners.show_message(level, text, action=action, timeout_ms=timeout_ms)
        if not visible and self.tray_notify is not None and self.ctx.config().settings.notifications:
            self.tray_notify(level, APP_NAME, text)

    def _on_task_error(self, error: object) -> None:
        self.notify("error", str(error))

    def _on_log_line(self, _line: object) -> None:
        self._update_status()

    def _on_notification(self, event: Notification) -> None:
        self.notify(event.level, f"{event.title} : {event.message}")

    def _on_session(self, info: SessionInfo) -> None:
        previous = self._sessions.get(info.id)
        self._sessions[info.id] = info
        if (
            info.state == SessionState.ERROR
            and (previous is None or previous.state != SessionState.ERROR)
            and info.message
        ):
            self.notify(
                "error",
                f"{info.name} : {info.message}",
                action=(tr("Journal"), lambda: self.open_logs_for(info.id)),
            )
        self._update_status()

    def _on_session_removed(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        self._update_status()

    def _update_status(self) -> None:
        active = [s for s in self._sessions.values() if s.state.active]
        self.status_sessions.setText(tr("{n} session(s) active(s)").format(n=len(active)))
        errors = self.logs.error_count()
        self.status_errors.setText(
            tr("Journal : {n} erreur(s)").format(n=errors) if errors else tr("Journal")
        )
        self.status_errors.setIcon(icon("alert-triangle") if errors else icon("list-details"))

    def set_cloudflared_status(self, text: str) -> None:
        self.status_cloudflared.setText(text)

    # --- Fermeture ------------------------------------------------------------------------------------

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.quitting:
            event.accept()
            return
        settings = self.ctx.config().settings
        if settings.close_to_tray and self.tray_available:
            event.ignore()
            self.save_window_state()
            self.hide()
            if not self._told_about_tray and self.tray_notify is not None:
                self._told_about_tray = True
                self.tray_notify(
                    "info",
                    APP_NAME,
                    tr("CMA continue dans la zone de notification. Clic droit sur l'icône pour quitter."),
                )
            return
        event.ignore()
        self.request_quit()

    def has_unsaved_changes(self) -> bool:
        return any(view.has_unsaved_changes() for view in (self.profiles, self.tokens, self.ssh))  # type: ignore[attr-defined]

    def request_quit(self) -> None:
        if self.has_unsaved_changes():
            self.bring_to_front()
            answer = QMessageBox.question(
                self, tr("Quitter"), tr("Des modifications ne sont pas enregistrées. Quitter quand même ?")
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        active = [s for s in self._sessions.values() if s.state.active]
        if active and self.ctx.config().settings.confirm_exit:
            self.bring_to_front()
            answer = QMessageBox.question(
                self,
                tr("Quitter"),
                tr("{n} session(s) sont ouvertes et seront fermées. Quitter ?").format(n=len(active)),
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.quitting = True
        self.save_window_state()
        self.quit_requested.emit()
        QApplication.instance().quit()  # type: ignore[union-attr]

    def save_window_state(self) -> None:
        geometry = bytes(self.saveGeometry().toBase64().data()).decode("ascii")
        view = self.current_view_key()

        def mutate(config: object) -> None:
            config.settings.window_geometry = geometry  # type: ignore[attr-defined]
            config.settings.last_view = view  # type: ignore[attr-defined]

        self.ctx.update_config(mutate)
