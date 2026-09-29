"""Tableau de bord : toutes les sessions (Cloudflare et SSH), leur état réel, et les favoris."""

from __future__ import annotations

import time
from collections.abc import Callable

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QMenu,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from cma.core.models import CloudflareProfile, SshProfile
from cma.core.sessions import SessionInfo, SessionKind, SessionState
from cma.i18n import tr
from cma.ui.actions import QuickAction, quick_actions, run_action
from cma.ui.context import GuiContext
from cma.ui.format import human_bytes, since
from cma.ui.icons import icon
from cma.ui.theme import current_tokens
from cma.ui.widgets import (
    EmptyState,
    StatusPill,
    copy_to_clipboard,
    label,
    primary_button,
    set_role,
    title,
    tool_button,
)


class SessionCard(QFrame):
    def __init__(self, ctx: GuiContext, info: SessionInfo, open_logs: Callable[[str], None]) -> None:
        super().__init__()
        self.ctx = ctx
        self.info = info
        self.setObjectName("Card")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        outer = QHBoxLayout(self)
        outer.setContentsMargins(14, 12, 12, 12)
        outer.setSpacing(12)

        body = QVBoxLayout()
        body.setSpacing(4)
        row1 = QHBoxLayout()
        self.pill = StatusPill()
        self.name = label()
        self.name.setStyleSheet("font-weight: 600; font-size: 11pt;")
        self.kind = label()
        self.kind.setObjectName("Badge")
        self.clock = label("", "muted")
        row1.addWidget(self.pill)
        row1.addWidget(self.name)
        row1.addWidget(self.kind)
        row1.addStretch()
        row1.addWidget(self.clock)
        body.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setSpacing(4)
        self.address = label("", "mono", selectable=True)
        self.copy = tool_button("copy", tr("Copier l'adresse locale"), lambda: self._copy_address())
        self.subtitle = label("", "muted")
        row2.addWidget(self.address)
        row2.addWidget(self.copy)
        row2.addSpacing(8)
        row2.addWidget(self.subtitle, 1)
        body.addLayout(row2)
        self.stats = label("", "muted")
        body.addWidget(self.stats)
        self.message = label("", "warning", wrap=True, selectable=True)
        body.addWidget(self.message)
        outer.addLayout(body, 1)

        actions = QHBoxLayout()
        actions.setSpacing(6)
        self.open_button = QToolButton()
        self.open_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.open_button.setPopupMode(QToolButton.ToolButtonPopupMode.MenuButtonPopup)
        self.open_button.setIconSize(QSize(18, 18))
        self._primary_action: QuickAction | None = None
        self.open_button.clicked.connect(self._run_primary)
        self.logs_button = tool_button("list-details", tr("Voir le journal"), lambda: open_logs(self.info.id))
        self.restart_button = tool_button("rotate-clockwise", tr("Redémarrer"), self._restart)
        self.stop_button = tool_button("player-stop-filled", tr("Arrêter"), self._stop)
        for widget in (self.open_button, self.logs_button, self.restart_button, self.stop_button):
            actions.addWidget(widget, 0, Qt.AlignmentFlag.AlignTop)
        outer.addLayout(actions)
        self.update_info(info)

    def _copy_address(self) -> None:
        copy_to_clipboard(self.info.local_address)
        self.ctx.notify("success", tr("Adresse copiée : {address}").format(address=self.info.local_address))

    def update_info(self, info: SessionInfo) -> None:
        self.info = info
        self._received_at = time.monotonic()
        self.pill.set_state(info.state)
        self.name.setText(info.name)
        self.kind.setText("Cloudflare" if info.kind == SessionKind.CLOUDFLARE else "SSH")
        self.address.setText(info.local_address)
        self.subtitle.setText(f"→ {info.subtitle}")
        if info.kind == SessionKind.SSH_FORWARD:
            self.stats.setText(
                tr("{n} connexion(s) · envoyé {up} · reçu {down}").format(
                    n=info.connections, up=human_bytes(info.bytes_up), down=human_bytes(info.bytes_down)
                )
            )
            self.stats.show()
        else:
            self.stats.hide()
        self.message.setText(info.message)
        self.message.setVisible(bool(info.message))
        set_role(self.message, "error" if info.state == SessionState.ERROR else "warning")
        active = info.state.active
        self.stop_button.setIcon(icon("player-stop-filled", current_tokens().danger) if active else icon("x"))
        self.stop_button.setToolTip(tr("Arrêter") if active else tr("Retirer de la liste"))
        self.restart_button.setToolTip(tr("Redémarrer") if active else tr("Relancer"))
        self._setup_open_button()
        self.tick()

    def _setup_open_button(self) -> None:
        actions = quick_actions(self.info)
        menu = QMenu(self.open_button)
        for action in actions[1:]:
            menu.addAction(icon(action.icon), action.label, lambda a=action: run_action(a, self.ctx.notify))
        self.open_button.setMenu(menu if actions[1:] else None)  # type: ignore[arg-type]
        self.open_button.setPopupMode(
            QToolButton.ToolButtonPopupMode.MenuButtonPopup
            if actions[1:]
            else QToolButton.ToolButtonPopupMode.DelayedPopup
        )
        first = actions[0]
        self.open_button.setText(first.label)
        self.open_button.setIcon(icon(first.icon))
        self._primary_action = first
        self.open_button.setEnabled(self.info.state in (SessionState.LISTENING, SessionState.DEGRADED))

    def _run_primary(self) -> None:
        if self._primary_action is not None:
            run_action(self._primary_action, self.ctx.notify)

    def tick(self) -> None:
        info = self.info
        if info.state in (SessionState.LISTENING, SessionState.DEGRADED):
            self.clock.setText(tr("depuis {d}").format(d=since(info.listening_since)))
        elif info.state == SessionState.RECONNECTING and info.reconnect_in is not None:
            remaining = max(0, round(info.reconnect_in - (time.monotonic() - self._received_at)))
            self.clock.setText(tr("nouvel essai dans {s} s").format(s=remaining))
        elif info.state == SessionState.STARTING:
            self.clock.setText(tr("démarrage…"))
        else:
            self.clock.setText("")

    def _stop(self) -> None:
        self.ctx.run(self.ctx.manager.stop(self.info.id), on_error=lambda e: self.ctx.notify("error", str(e)))

    def _restart(self) -> None:
        self.ctx.run(
            self.ctx.manager.restart(self.info.id), on_error=lambda e: self.ctx.notify("error", str(e))
        )


class DashboardView(QWidget):
    def __init__(self, ctx: GuiContext, open_logs: Callable[[str], None]) -> None:
        super().__init__()
        self.ctx = ctx
        self.open_logs = open_logs
        self.cards: dict[str, SessionCard] = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 16)
        layout.setSpacing(12)

        header = QHBoxLayout()
        heading = QVBoxLayout()
        heading.addWidget(title(tr("Tableau de bord")))
        self.summary = label("", "muted")
        heading.addWidget(self.summary)
        header.addLayout(heading)
        header.addStretch()
        self.connect_button = primary_button(tr("Connecter"), "player-play-filled")
        self.connect_menu = QMenu(self.connect_button)
        self.connect_button.setMenu(self.connect_menu)
        self.stop_all_button = QPushButton(icon("player-stop-filled", "#C4232D"), tr("Tout arrêter"))
        self.stop_all_button.clicked.connect(self._stop_all)
        header.addWidget(self.connect_button, 0, Qt.AlignmentFlag.AlignTop)
        header.addWidget(self.stop_all_button, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)

        self.favorites_title = title(tr("Favoris"), "SectionTitle")
        layout.addWidget(self.favorites_title)
        self.favorites = QHBoxLayout()
        self.favorites.setSpacing(8)
        favorites_host = QWidget()
        favorites_host.setLayout(self.favorites)
        layout.addWidget(favorites_host)

        layout.addWidget(title(tr("Sessions"), "SectionTitle"))
        self.scroll_area = QScrollArea()
        self.scroll_area.setObjectName("PageScroll")
        self.scroll_area.setWidgetResizable(True)
        container = QWidget()
        self.cards_layout = QVBoxLayout(container)
        self.cards_layout.setContentsMargins(0, 0, 4, 0)
        self.cards_layout.setSpacing(10)
        self.empty = EmptyState(
            "plug-connected",
            tr("Aucune session ouverte"),
            tr(
                "Lancez un profil avec le bouton « Connecter », un favori, ou depuis les vues Profils et SSH."
            ),
        )
        self.cards_layout.addWidget(self.empty)
        self.cards_layout.addStretch()
        self.scroll_area.setWidget(container)
        layout.addWidget(self.scroll_area, 1)

        ctx.bridge.session_changed.connect(self._on_session)
        ctx.bridge.session_removed.connect(self._on_removed)
        ctx.bridge.config_changed.connect(self.refresh_profiles)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)
        self.refresh_profiles()
        self._update_summary()

    # --- Sessions ---------------------------------------------------------------------

    def load_sessions(self, infos: list[SessionInfo]) -> None:
        for info in infos:
            self._on_session(info)

    def _on_session(self, info: SessionInfo) -> None:
        card = self.cards.get(info.id)
        if card is None:
            card = SessionCard(self.ctx, info, self.open_logs)
            self.cards[info.id] = card
            self.cards_layout.insertWidget(self.cards_layout.count() - 1, card)
        else:
            card.update_info(info)
        self._update_summary()
        self._refresh_favorite_states()

    def _on_removed(self, session_id: str) -> None:
        card = self.cards.pop(session_id, None)
        if card is not None:
            card.deleteLater()
        self._update_summary()
        self._refresh_favorite_states()

    def _tick(self) -> None:
        for card in self.cards.values():
            if card.isVisible():
                card.tick()

    def _update_summary(self) -> None:
        infos = [c.info for c in self.cards.values()]
        active = sum(1 for i in infos if i.state.active)
        problems = sum(1 for i in infos if i.state in (SessionState.ERROR, SessionState.DEGRADED))
        self.empty.setVisible(not self.cards)
        self.stop_all_button.setEnabled(active > 0)
        if not infos:
            self.summary.setText(tr("Aucune session."))
        else:
            text = tr("{n} session(s) active(s)").format(n=active)
            if problems:
                text += " · " + tr("{n} en difficulté").format(n=problems)
            self.summary.setText(text)

    def _stop_all(self) -> None:
        self.ctx.run(self.ctx.manager.stop_all())

    # --- Profils : menu « Connecter » et favoris ------------------------------------------------

    def refresh_profiles(self) -> None:
        config = self.ctx.config()
        self.connect_menu.clear()
        if config.cloudflare_profiles:
            self.connect_menu.addSection(tr("Cloudflare"))
            for profile in sorted(
                config.cloudflare_profiles, key=lambda p: (not p.favorite, p.group.lower(), p.name.lower())
            ):
                text = f"{profile.group} › {profile.name}" if profile.group else profile.name
                self.connect_menu.addAction(
                    icon("cloud"), text, lambda pid=profile.id: self.start_cloudflare(pid)
                )
        groups: dict[str, tuple[str, int]] = {}
        for profile in config.cloudflare_profiles:
            name = profile.group.strip()
            if name:
                label_text, count = groups.get(name.lower(), (name, 0))
                groups[name.lower()] = (label_text, count + 1)
        multi = sorted((g for g in groups.values() if g[1] > 1), key=lambda g: g[0].lower())
        if multi:
            self.connect_menu.addSection(tr("Groupes"))
            for name, count in multi:
                self.connect_menu.addAction(
                    icon("folder-open"),
                    tr("Tout le groupe {name} ({n})").format(name=name, n=count),
                    lambda g=name: self.start_group(g),
                )
        forwards = [p for p in config.ssh_profiles if p.saved_forwards]
        if forwards:
            self.connect_menu.addSection(tr("Redirections SSH enregistrées"))
            for profile in sorted(forwards, key=lambda p: (not p.favorite, p.name.lower())):
                self.connect_menu.addAction(
                    icon("server"), profile.name, lambda pid=profile.id: self.start_ssh(pid)
                )
        if self.connect_menu.isEmpty():
            action = self.connect_menu.addAction(tr("Aucun profil : créez-en un dans la vue Profils"))
            action.setEnabled(False)

        while self.favorites.count():
            item = self.favorites.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.deleteLater()
        favorites: list[CloudflareProfile | SshProfile] = [
            p for p in config.cloudflare_profiles if p.favorite
        ]
        favorites += [p for p in config.ssh_profiles if p.favorite]
        self.favorites_title.setVisible(bool(favorites))
        self._favorite_buttons: dict[str, QToolButton] = {}
        for profile in favorites:
            chip = QToolButton()
            chip.setObjectName("Chip")
            chip.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
            chip.setText(profile.name)
            chip.setCheckable(True)
            chip.setCursor(Qt.CursorShape.PointingHandCursor)
            chip.clicked.connect(lambda checked, p=profile: self._toggle_favorite(p, checked))
            self.favorites.addWidget(chip)
            self._favorite_buttons[profile.id] = chip
        self.favorites.addStretch()
        self._refresh_favorite_states()

    def _refresh_favorite_states(self) -> None:
        active_profiles = {c.info.profile_id for c in self.cards.values() if c.info.state.active}
        for profile_id, chip in getattr(self, "_favorite_buttons", {}).items():
            running = profile_id in active_profiles
            chip.setChecked(running)
            tokens = current_tokens()
            chip.setIcon(
                icon("player-stop-filled", tokens.danger)
                if running
                else icon("player-play-filled", tokens.success)
            )
            chip.setToolTip(tr("Arrêter") if running else tr("Démarrer"))

    def _toggle_favorite(self, profile: CloudflareProfile | SshProfile, checked: bool) -> None:
        if isinstance(profile, CloudflareProfile):
            if checked:
                self.start_cloudflare(profile.id)
            else:
                self.ctx.run(self.ctx.manager.stop_profile(profile.id))
        elif checked:
            self.start_ssh(profile.id)
        else:
            self.ctx.run(self.ctx.manager.ssh_disconnect(profile.id))

    def _start_failed(self, error: BaseException) -> None:
        self.ctx.notify("error", str(error))
        self._refresh_favorite_states()

    def start_cloudflare(self, profile_id: str) -> None:
        self.ctx.run(self.ctx.manager.start_cloudflare(profile_id), on_error=self._start_failed)

    def start_group(self, group: str) -> None:
        self.ctx.run(self.ctx.manager.start_group(group), on_error=self._start_failed)

    def start_ssh(self, profile_id: str) -> None:
        self.ctx.run(self.ctx.manager.start_saved_forwards(profile_id), on_error=self._start_failed)
