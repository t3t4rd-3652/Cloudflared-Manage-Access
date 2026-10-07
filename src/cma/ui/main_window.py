"""Fenêtre principale : navigation groupée, pages, bandeaux d'information, barre d'état (§3.1 et §4.1)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from PySide6.QtCore import QByteArray, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QCloseEvent, QKeySequence, QResizeEvent, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
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
from cma.core.expiry import TokenExpiry, expiring_tokens
from cma.core.secrets import EncryptedFileSecretStore
from cma.core.sessions import SessionInfo, SessionKind, SessionState
from cma.i18n import tr
from cma.ui.a11y import apply_accessible_names
from cma.ui.context import GuiContext
from cma.ui.dialogs.diagnose import open_diagnosis
from cma.ui.dialogs.history import show_history
from cma.ui.dialogs.palette import CommandPalette, PaletteEntry
from cma.ui.dialogs.workspaces import launch_workspace
from cma.ui.format import expiry_alert
from cma.ui.icons import app_icon, set_icon, token_icon
from cma.ui.lock import IdleWatcher, LockPanel
from cma.ui.views.cloud import CloudView
from cma.ui.views.dashboard import RUNNING, TO_CHECK, DashboardView, sessions_summary
from cma.ui.views.logs import LogsView
from cma.ui.views.profiles import CloudflareProfilesView
from cma.ui.views.settings import SettingsView
from cma.ui.views.ssh import SshView
from cma.ui.views.tokens import TokensView
from cma.ui.widgets import BannerStack, add_shortcut, label

# Clés internes inchangées (vue mémorisée dans la configuration) ; libellés de la refonte.
DESTINATIONS = ("dashboard", "profiles", "tokens", "ssh", "cloud", "logs", "settings")
KEY_ROLE = Qt.ItemDataRole.UserRole


def confirm_quit(parent: QWidget, count: int) -> bool:
    """« Quitter CMA ? » : Annuler par défaut, « Arrêter et quitter » jamais bouton par défaut (§4.21)."""
    box = QMessageBox(parent)
    box.setWindowTitle(tr("Quitter CMA ?"))
    box.setIcon(QMessageBox.Icon.Question)
    box.setText(tr("Quitter CMA ?"))
    box.setInformativeText(
        tr("1 session est en cours. Elle sera arrêtée.")
        if count == 1
        else tr("{n} sessions sont en cours. Elles seront arrêtées.").format(n=count)
    )
    cancel = box.addButton(tr("Annuler"), QMessageBox.ButtonRole.RejectRole)
    stop = box.addButton(tr("Arrêter et quitter"), QMessageBox.ButtonRole.DestructiveRole)
    box.setDefaultButton(cancel)
    box.setEscapeButton(cancel)
    box.exec()
    return box.clickedButton() is stop


def explain_tray(parent: QWidget, text: str) -> None:
    """Boîte d'information « Compris » (fonction de module pour que les tests puissent la remplacer)."""
    box = QMessageBox(parent)
    box.setWindowTitle(APP_NAME)
    box.setIcon(QMessageBox.Icon.Information)
    box.setText(text)
    box.addButton(tr("Compris"), QMessageBox.ButtonRole.AcceptRole)
    box.exec()


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

        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(208)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(0, 0, 0, 12)
        side.setSpacing(0)
        brand = QHBoxLayout()
        brand.setContentsMargins(18, 18, 12, 10)
        brand.setSpacing(10)
        logo = QLabel()
        logo.setPixmap(app_icon().pixmap(32, 32))
        heading = label("CMA")
        heading.setObjectName("AppTitle")
        heading.setAccessibleName(APP_NAME)
        heading.setAccessibleDescription(APP_NAME)
        heading.setToolTip(APP_NAME)
        brand.addWidget(logo, 0, Qt.AlignmentFlag.AlignVCenter)
        brand.addWidget(heading, 1)
        side.addLayout(brand)
        self.nav = QListWidget()
        self.nav.setAccessibleName(tr("Navigation"))
        self.nav.setObjectName("Navigation")
        self.nav.setIconSize(QSize(20, 20))
        self.nav.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        side.addWidget(self.nav, 1)
        version = label(f"CMA {__version__}", "meta")
        version.setContentsMargins(20, 0, 0, 0)
        side.addWidget(version)
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
        self.cloud = CloudView(ctx, open_profile=self.open_profile)
        self.logs = LogsView(ctx)
        self.settings = SettingsView(ctx)
        self.dashboard.open_view = self.show_view
        self.dashboard.open_source = self.open_session_source
        self.views: dict[str, QWidget] = {}
        self._nav_items: dict[str, QListWidgetItem] = {}
        entries: tuple[tuple[str | None, str, str, QWidget | None], ...] = (
            (None, tr("Utiliser"), "", None),
            ("dashboard", tr("Sessions"), "layout-dashboard", self.dashboard),
            (None, tr("Configurer"), "", None),
            ("profiles", tr("Accès Cloudflare"), "cloud", self.profiles),
            ("tokens", tr("Service tokens"), "key", self.tokens),
            ("ssh", tr("Serveurs SSH"), "server", self.ssh),
            (None, tr("Administrer"), "", None),
            ("cloud", tr("Cloudflare"), "cloud-cog", self.cloud),
            (None, "", "", None),
            ("logs", tr("Journaux"), "list-details", self.logs),
            ("settings", tr("Paramètres"), "settings", self.settings),
        )
        for key, text, icon_name, view in entries:
            if key is None or view is None:
                header = QListWidgetItem(text.upper())
                header.setFlags(Qt.ItemFlag.NoItemFlags)
                header.setSizeHint(QSize(0, 34 if text else 12))
                self.nav.addItem(header)
                continue
            item = QListWidgetItem(token_icon(icon_name), text)
            item.setData(KEY_ROLE, key)
            item.setData(Qt.ItemDataRole.UserRole + 1, (text, icon_name))
            item.setSizeHint(QSize(0, 40))
            self.nav.addItem(item)
            self.stack.addWidget(view)
            self.views[key] = view
            self._nav_items[key] = item
        self.nav.currentRowChanged.connect(self._on_nav)
        for index, key in enumerate(DESTINATIONS):
            add_shortcut(self, QKeySequence(f"Ctrl+{index + 1}"), lambda k=key: self.show_view(k))
        add_shortcut(self, QKeySequence("Ctrl+Q"), self.request_quit)
        add_shortcut(self, QKeySequence("Ctrl+K"), self.open_palette)
        add_shortcut(self, QKeySequence("Ctrl+L"), self.lock_now)
        # Verrouillage après inactivité (coffre chiffré seulement) : vérifié toutes les 30 s.
        self._lock_panel: LockPanel | None = None
        self._disabled_shortcuts: list[QShortcut] = []
        self.idle = IdleWatcher(self)
        self._lock_timer = QTimer(self)
        self._lock_timer.setInterval(30_000)
        self._lock_timer.timeout.connect(self.check_idle)
        self._lock_timer.start()
        # Échéance des service tokens : vérifiée peu après l'affichage, puis toutes les 12 heures.
        self._expiry_alerted: set[str] = set()
        self._expiry_timer = QTimer(self)
        self._expiry_timer.setInterval(12 * 3600 * 1000)
        self._expiry_timer.timeout.connect(self.check_token_expiry)
        self._expiry_timer.start()
        QTimer.singleShot(5_000, self.check_token_expiry)
        ctx.theme.changed.connect(self._refresh_nav_icons)

        status = self.statusBar()
        status.setSizeGripEnabled(False)
        self.status_cloudflared = label("")
        self.status_sessions = label("")
        self.status_errors = QPushButton()
        self.status_errors.setFlat(True)
        self.status_errors.setProperty("role", "link")
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
        self.show_view(settings.last_view if settings.last_view in self.views else "dashboard")
        self._update_status()
        apply_accessible_names(self)

    # --- Navigation ----------------------------------------------------------------------------

    def _on_nav(self, row: int) -> None:
        if row < 0:
            return
        item = self.nav.item(row)
        key = item.data(KEY_ROLE) if item is not None else None
        if key in self.views:
            self.stack.setCurrentWidget(self.views[key])

    def show_view(self, key: str) -> None:
        item = self._nav_items.get(key)
        if item is not None:
            self.nav.setCurrentItem(item)

    def open_ssh_server(self, profile_id: str) -> None:
        self.show_view("ssh")
        self.ssh.select_profile(profile_id)

    def new_cloudflare_profile(self) -> None:
        self.show_view("profiles")
        self.profiles.new_profile()

    def new_ssh_server(self) -> None:
        self.show_view("ssh")
        self.ssh.new_profile()

    def open_palette(self) -> None:
        CommandPalette(self, self.palette_entries()).exec()

    def palette_entries(self) -> list[PaletteEntry]:
        """Toutes les commandes de la palette Ctrl+K, le verbe suivant l'état réel de chaque accès."""
        config = self.ctx.config()
        dashboard = self.dashboard
        running = {r.info.profile_id for r in dashboard.cards.values() if r.info.state in RUNNING}
        entries: list[PaletteEntry] = []
        section = tr("Accès Cloudflare")
        for profile in sorted(config.cloudflare_profiles, key=lambda p: (not p.favorite, p.name.lower())):
            if profile.id in running:
                entries.append(
                    PaletteEntry(
                        section,
                        tr("Arrêter « {name} »").format(name=profile.name),
                        lambda p=profile: self.ctx.run(self.ctx.manager.stop_profile(p.id)),
                        profile.hostname,
                        "player-stop-filled",
                        profile.group,
                    )
                )
            else:
                entries.append(
                    PaletteEntry(
                        section,
                        tr("Connecter « {name} »").format(name=profile.name),
                        lambda p=profile: dashboard.start_cloudflare(p.id),
                        profile.hostname,
                        "player-play-filled",
                        profile.group,
                    )
                )
            entries.append(
                PaletteEntry(
                    section,
                    tr("Diagnostiquer « {name} »").format(name=profile.name),
                    lambda p=profile: open_diagnosis(self, self.ctx, p.id),
                    profile.hostname,
                    "bug",
                    profile.group,
                )
            )
            entries.append(
                PaletteEntry(
                    section,
                    tr("Modifier « {name} »").format(name=profile.name),
                    lambda p=profile: self.open_profile(p.id),
                    profile.hostname,
                    "pencil",
                    profile.group,
                )
            )
        section = tr("Serveurs SSH")
        for server in sorted(config.ssh_profiles, key=lambda p: (not p.favorite, p.name.lower())):
            target = f"{server.user}@{server.host}" if server.host else server.user
            entries.append(
                PaletteEntry(
                    section,
                    tr("Ouvrir le serveur « {name} »").format(name=server.name),
                    lambda s=server: self.open_ssh_server(s.id),
                    target,
                    "server",
                    server.group,
                )
            )
            for forward in server.saved_forwards:
                name = f"{server.name} › {forward.short_label}"
                entries.append(
                    PaletteEntry(
                        section,
                        tr("Connecter « {name} »").format(name=name),
                        lambda s=server, f=forward: dashboard.start_forward(s.id, f),
                        forward.describe(),
                        "arrows-right-left",
                        server.group,
                    )
                )
        section = tr("Groupes et espaces de travail")
        if config.favorite_items():
            entries.append(
                PaletteEntry(
                    section, tr("Connecter tous les favoris"), dashboard.launch_favorites, icon="star"
                )
            )
        for workspace in sorted(config.workspaces, key=lambda w: w.name.lower()):
            entries.append(
                PaletteEntry(
                    section,
                    tr("Connecter l'espace « {name} »").format(name=workspace.name),
                    lambda w=workspace: launch_workspace(self.ctx, w),
                    tr("{n} élément(s)").format(n=len(workspace.items)),
                    "layout-dashboard",
                )
            )
        for group in sorted({p.group for p in config.cloudflare_profiles if p.group}, key=str.lower):
            entries.append(
                PaletteEntry(
                    section,
                    tr("Connecter le groupe « {name} »").format(name=group),
                    lambda g=group: dashboard.start_group(g),
                    icon="player-play-filled",
                )
            )
        section = tr("Actions")
        entries += [
            PaletteEntry(
                section,
                tr("Nouvel accès Cloudflare"),
                self.new_cloudflare_profile,
                icon="plus",
            ),
            PaletteEntry(
                section,
                tr("Nouveau serveur SSH"),
                self.new_ssh_server,
                icon="plus",
            ),
            PaletteEntry(
                section,
                tr("Gérer les espaces de travail…"),
                dashboard.manage_workspaces,
                icon="layout-dashboard",
            ),
            PaletteEntry(
                section,
                tr("Historique des sessions…"),
                lambda: show_history(self, self.ctx),
                icon="history",
            ),
        ]
        if self.can_lock():
            entries.append(PaletteEntry(section, tr("Verrouiller CMA"), self.lock_now, "Ctrl+L", "lock"))
        if running:
            entries.append(
                PaletteEntry(
                    section,
                    tr("Tout arrêter"),
                    lambda: self.ctx.run(self.ctx.manager.stop_all()),
                    icon="player-stop-filled",
                )
            )
        section = tr("Aller à")
        for key, item in self._nav_items.items():
            entries.append(
                PaletteEntry(
                    section, item.text(), lambda k=key: self.show_view(k), icon="arrow-right", keywords=key
                )
            )
        return entries

    def current_view_key(self) -> str:
        item = self.nav.currentItem()
        key = item.data(KEY_ROLE) if item is not None else None
        return str(key) if key else "dashboard"

    def _refresh_nav_icons(self) -> None:
        for item in self._nav_items.values():
            _text, icon_name = item.data(Qt.ItemDataRole.UserRole + 1)
            item.setIcon(token_icon(icon_name))

    def open_logs_for(self, session_id: str) -> None:
        self.logs.show_source(session_id)
        self.show_view("logs")

    def open_profile(self, profile_id: str) -> None:
        self.show_view("profiles")
        self.profiles.select_profile(profile_id)

    def open_session_source(self, info: SessionInfo, section: str) -> None:
        """Depuis un incident de session : ouvrir l'objet configuré, sur la section concernée."""
        if info.kind == SessionKind.CLOUDFLARE:
            self.open_profile(info.profile_id)
            show_section = getattr(self.profiles.editor, "show_section", None)
            if callable(show_section):
                show_section(section)
            return
        self.show_view("ssh")
        self.ssh.select_profile(info.profile_id)
        show_tab = getattr(self.ssh.panel, "show_tab", None)
        if callable(show_tab):
            show_tab(section)

    # --- Verrouillage ------------------------------------------------------------------------------

    @property
    def locked(self) -> bool:
        return self._lock_panel is not None

    def can_lock(self) -> bool:
        return isinstance(self.ctx.core.secrets, EncryptedFileSecretStore)

    def check_token_expiry(self) -> list[TokenExpiry]:
        """Prévient une fois par session pour chaque service token expiré ou proche de son échéance."""
        fresh = [
            item
            for item in expiring_tokens(self.ctx.config(), datetime.now(UTC))
            if item.token.id not in self._expiry_alerted
        ]
        for item in fresh:
            self._expiry_alerted.add(item.token.id)
            self.notify(
                "error" if item.expired else "warning",
                expiry_alert(item),
                action=(tr("Renouveler"), self.open_cloud_tokens),
            )
        return fresh

    def open_cloud_tokens(self) -> None:
        """Onglet « Service tokens » de la vue Cloudflare, où se prolonge un token."""
        self.show_view("cloud")
        self.cloud.tabs.setCurrentIndex(2)

    def check_idle(self) -> None:
        minutes = self.ctx.config().settings.lock_after_minutes
        if minutes and self.can_lock() and not self.locked and self.idle.idle_seconds() >= minutes * 60:
            self.lock_now()

    def lock_now(self) -> None:
        store = self.ctx.core.secrets
        if not isinstance(store, EncryptedFileSecretStore):
            self.notify("info", tr("Le verrouillage existe avec un coffre chiffré (version portable)."))
            return
        if self.locked:
            return
        panel = LockPanel(self, store.matches)
        panel.unlocked.connect(self.unlock)
        panel.setGeometry(self.rect())
        panel.show()
        panel.raise_()
        self._lock_panel = panel
        self._disabled_shortcuts = [s for s in self.findChildren(QShortcut) if s.isEnabled()]
        for shortcut in self._disabled_shortcuts:
            shortcut.setEnabled(False)
        panel.passphrase.setFocus()

    def unlock(self) -> None:
        panel, self._lock_panel = self._lock_panel, None
        if panel is not None:
            panel.hide()
            panel.deleteLater()
        for shortcut in self._disabled_shortcuts:
            shortcut.setEnabled(True)
        self._disabled_shortcuts = []
        self.idle.reset()

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        if self._lock_panel is not None:
            self._lock_panel.setGeometry(self.rect())

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

    def _tray(self, level: str, title: str, text: str) -> None:
        """Notification Windows seule, quand la fenêtre est cachée (transitions persistantes, §4.26)."""
        visible = self.isVisible() and not self.isMinimized()
        if not visible and self.tray_notify is not None and self.ctx.config().settings.notifications:
            self.tray_notify(level, title, text)

    def _on_task_error(self, error: object) -> None:
        self.notify("error", str(error))

    def _on_log_line(self, _line: object) -> None:
        self._update_status()

    def _on_notification(self, event: Notification) -> None:
        self.notify(event.level, f"{event.title} : {event.message}")

    def _on_session(self, info: SessionInfo) -> None:
        previous = self._sessions.get(info.id)
        self._sessions[info.id] = info
        before = previous.state if previous is not None else None
        if info.state == SessionState.ERROR and before != SessionState.ERROR and info.message:
            self.notify(
                "error",
                f"{info.name} : {info.message}",
                action=(tr("Journal"), lambda: self.open_logs_for(info.id)),
            )
        elif info.state == SessionState.RECONNECTING and before in (
            SessionState.LISTENING,
            SessionState.DEGRADED,
        ):
            delay = round(info.reconnect_in or 0)
            self._tray(
                "warning",
                tr("CMA — Connexion interrompue"),
                tr("{name} : nouvelle tentative dans {s} s.").format(name=info.name, s=delay),
            )
        elif info.state == SessionState.LISTENING and before == SessionState.RECONNECTING:
            self._tray(
                "info", tr("CMA — Connexion rétablie"), tr("{name} : à l'écoute.").format(name=info.name)
            )
        self._update_status()

    def _on_session_removed(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        self._update_status()

    def _update_status(self) -> None:
        infos = list(self._sessions.values())
        summary = sessions_summary(infos)
        self.status_sessions.setText(summary)
        to_check = sum(1 for s in infos if s.state in TO_CHECK)
        item = self._nav_items.get("dashboard")
        if item is not None:
            item.setText(f"{tr('Sessions')} · {to_check} !" if to_check else tr("Sessions"))
            item.setToolTip(
                tr("{n} connexion(s) à vérifier").format(n=to_check) if to_check else tr("Sessions")
            )
        errors = self.logs.error_count()
        self.status_errors.setText(
            tr("Journaux · {n} erreur(s)").format(n=errors) if errors else tr("Journaux")
        )
        set_icon(
            self.status_errors,
            "alert-triangle" if errors else "list-details",
            "warning" if errors else "text",
        )

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
            if not settings.tray_hint_shown and not self._told_about_tray:
                self._told_about_tray = True
                self._explain_tray()
            self.save_window_state()
            self.hide()
            return
        event.ignore()
        self.request_quit()

    def _explain_tray(self) -> None:
        """Première fermeture : expliquer avant de masquer que CMA continue (§4.1)."""
        text = tr(
            "CMA continue dans la zone de notification. Pour arrêter les connexions, choisissez « Tout arrêter »."
        )
        if self.isVisible():
            explain_tray(self, text)
        elif self.tray_notify is not None:
            self.tray_notify("info", APP_NAME, text)
        self.ctx.update_config(lambda c: setattr(c.settings, "tray_hint_shown", True))

    def has_unsaved_changes(self) -> bool:
        return any(view.has_unsaved_changes() for view in (self.profiles, self.tokens, self.ssh))  # type: ignore[attr-defined]

    def request_quit(self) -> None:
        if self.has_unsaved_changes():
            self.bring_to_front()
            answer = QMessageBox.question(
                self,
                tr("Quitter CMA ?"),
                tr("Des modifications ne sont pas enregistrées. Quitter quand même ?"),
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        active = [s for s in self._sessions.values() if s.state.active]
        if active and self.ctx.config().settings.confirm_exit:
            self.bring_to_front()
            if not confirm_quit(self, len(active)):
                return
        self.quit_now()

    def quit_now(self) -> None:
        """Ferme l'application sans question (sessions arrêtées par l'arrêt du moteur)."""
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
