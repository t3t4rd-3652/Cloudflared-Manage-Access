"""Page « Sessions » : favoris, connexions en cours et incidents (spécification de refonte §4.2).

- Les sessions qui demandent une intervention (dégradée, reconnexion, erreur) passent avant celles qui
  fonctionnent ; les sessions arrêtées sont regroupées dans « Terminées », replié par défaut.
- Chaque état associe un libellé, un symbole, une explication et les seules actions possibles.
- Une ligne survolée ou focalisée ne change pas de groupe sous le pointeur : le déplacement est différé.
- Un favori se lance d'un clic sur son corps ; l'arrêt est un bouton séparé, jamais le nom lui-même.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QResizeEvent
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from cma.core.events import SshConnectionChanged
from cma.core.models import CloudflareProfile, Config, SavedForward, SshProfile
from cma.core.sessions import SessionInfo, SessionKind, SessionState
from cma.i18n import tr
from cma.ui.actions import QuickAction, quick_actions, run_action
from cma.ui.context import GuiContext
from cma.ui.dialogs.diagnose import open_diagnosis
from cma.ui.dialogs.history import show_history
from cma.ui.dialogs.workspaces import WorkspacesDialog, launch_favorites, launch_workspace
from cma.ui.format import human_bytes, since
from cma.ui.icons import set_glyph, set_icon
from cma.ui.states import (  # noqa: F401 (RUNNING, TO_CHECK, sessions_summary : réexportés)
    MAX_ATTEMPTS,
    RUNNING,
    TO_CHECK,
    cloudflare_favorite,
    fix_for,
    group_of,
    plural,
    profile_session,
    row_actions,
    session_cause,
    sessions_summary,
    ssh_favorite,
)
from cma.ui.theme import ICON_OF_STATE, STATUS_OF_STATE
from cma.ui.views.common import SERVICE_ICONS
from cma.ui.widgets import (
    EmptyState,
    StatusPill,
    button,
    copy_to_clipboard,
    group_label,
    label,
    primary_button,
    repolish,
    set_role,
    set_status,
    title,
    tool_button,
)


class SessionRow(QFrame):
    """Une connexion : état, adresse locale et cible, cause d'un incident, actions possibles."""

    def __init__(
        self,
        ctx: GuiContext,
        info: SessionInfo,
        open_logs: Callable[[str], None],
        open_source: Callable[[SessionInfo, str], None],
    ) -> None:
        super().__init__()
        self.ctx = ctx
        self.info = info
        self._open_logs = open_logs
        self._open_source = open_source
        self._received_at = time.monotonic()
        self._stopped_at: datetime | None = None
        self._fix_section = "connection"
        self.setProperty("role", "session")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 12, 0)
        outer.setSpacing(12)
        self.marker = QFrame()
        self.marker.setProperty("role", "marker")
        self.marker.setFixedWidth(4)
        outer.addWidget(self.marker)

        self.glyph = QLabel()
        self.glyph.setFixedSize(QSize(24, 24))
        glyph_host = QVBoxLayout()
        glyph_host.setContentsMargins(0, 14, 0, 0)
        glyph_host.addWidget(self.glyph)
        glyph_host.addStretch()
        outer.addLayout(glyph_host)

        body = QVBoxLayout()
        body.setContentsMargins(0, 12, 0, 12)
        body.setSpacing(6)
        row1 = QHBoxLayout()
        row1.setSpacing(8)
        self.pill = StatusPill()
        self.name = label()
        self.name.setObjectName("SessionName")
        self.name.setStyleSheet("font-weight: 600; font-size: 11pt;")
        self.kind = label("", "kind")
        self.clock = label("", "meta")
        self.clock.setMinimumWidth(150)
        self.clock.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        row1.addWidget(self.pill)
        row1.addWidget(self.name)
        row1.addWidget(self.kind)
        row1.addStretch()
        row1.addWidget(self.clock)
        body.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setSpacing(6)
        self.address = label("", "mono", selectable=True)
        self.copy = tool_button("copy", tr("Copier l'adresse locale"), self._copy_address)
        self.arrow = label("→", "muted")
        self.subtitle = label("", "muted", wrap=True, selectable=True)
        row2.addWidget(self.address)
        row2.addWidget(self.copy)
        row2.addWidget(self.arrow)
        row2.addWidget(self.subtitle, 1)
        body.addLayout(row2)
        self.stats = label("", "meta")
        body.addWidget(self.stats)
        self.probe = label("", "muted", wrap=True, selectable=True)
        self.probe.hide()
        body.addWidget(self.probe)

        cause = QHBoxLayout()
        cause.setContentsMargins(0, 0, 0, 0)
        cause.setSpacing(8)
        self.message = label("", "warning", wrap=True, selectable=True)
        self.fix_button = button("", "pencil", link=True)
        self.fix_button.clicked.connect(self._fix)
        cause.addWidget(self.message, 1)
        cause.addWidget(self.fix_button, 0, Qt.AlignmentFlag.AlignTop)
        self.cause_host = QWidget()
        self.cause_host.setLayout(cause)
        body.addWidget(self.cause_host)

        actions = QHBoxLayout()
        actions.setSpacing(6)
        self.open_button = QToolButton()
        self.open_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.open_button.setIconSize(QSize(18, 18))
        self.open_button.setMinimumHeight(36)
        self._primary_action: QuickAction | None = None
        self.open_button.clicked.connect(self._run_primary)
        self.logs_button = button(tr("Voir le journal"), "list-details")
        self.logs_button.clicked.connect(lambda: self._open_logs(self.info.id))
        self.restart_button = button(tr("Redémarrer"), "refresh")
        self.restart_button.clicked.connect(self._restart)
        self.stop_button = button(tr("Arrêter"), "player-stop-filled")
        self.stop_button.clicked.connect(self._stop)
        self.remove_button = button(tr("Retirer de la liste"), "x")
        self.remove_button.clicked.connect(self._stop)
        self.more_button = tool_button("dots", tr("Actions de la session"), flat=False)
        self.more_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.more_menu = QMenu(self.more_button)
        self.more_menu.addAction(tr("Tester le service"), self.test_service)
        self.diagnose_action = self.more_menu.addAction(tr("Diagnostiquer…"), self._diagnose)
        self.more_menu.addSeparator()
        self.more_menu.addAction(tr("Voir le journal"), lambda: self._open_logs(self.info.id))
        self.more_menu.addAction(
            tr("Historique de cet accès"),
            lambda: show_history(self.window(), self.ctx, (self.info.profile_id, self.info.forward_id)),
        )
        self.more_menu.addAction(tr("Redémarrer"), self._restart)
        self.more_menu.addAction(tr("Arrêter"), self._stop)
        self.more_button.setMenu(self.more_menu)
        actions.addStretch()
        for widget in (
            self.open_button,
            self.logs_button,
            self.restart_button,
            self.stop_button,
            self.remove_button,
            self.more_button,
        ):
            actions.addWidget(widget)
        body.addLayout(actions)
        outer.addLayout(body, 1)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)
        self.update_info(info)

    # --- Présentation -----------------------------------------------------------------------------------

    def update_info(self, info: SessionInfo) -> None:
        previous = self.info.state
        self.info = info
        self._received_at = time.monotonic()
        if info.state == SessionState.STOPPED and (
            previous != SessionState.STOPPED or self._stopped_at is None
        ):
            self._stopped_at = datetime.now()
        state = info.state
        status = STATUS_OF_STATE[state]
        set_status(self, status if state in TO_CHECK else "neutral")
        self.marker.setVisible(state in TO_CHECK)
        set_glyph(self.glyph, ICON_OF_STATE[state], status, 24)
        self.pill.set_state(state)
        self.name.setText(info.name)
        self.kind.setText("Cloudflare" if info.kind == SessionKind.CLOUDFLARE else "SSH")
        self.address.setText(info.local_address)
        self.subtitle.setText(info.subtitle)
        name = tr("Copier l'adresse locale de {name} : {address}").format(
            name=info.name, address=info.local_address
        )
        self.copy.setAccessibleName(name)
        self.copy.setToolTip(name)
        more = tr("Actions de la session {name}").format(name=info.name)
        self.more_button.setAccessibleName(more)
        self.more_button.setToolTip(more)
        if info.kind == SessionKind.SSH_FORWARD:
            self.stats.setText(
                tr("{n} connexion(s) · envoyé {up} · reçu {down}").format(
                    n=info.connections, up=human_bytes(info.bytes_up), down=human_bytes(info.bytes_down)
                )
            )
            self.stats.show()
        else:
            self.stats.hide()
        self._update_probe()
        self.diagnose_action.setVisible(info.kind == SessionKind.CLOUDFLARE)
        self._update_cause()
        self._update_actions()
        self._setup_open_button()
        description = tr("{name}, {kind}, {state}.").format(
            name=info.name, kind=self.kind.text(), state=state.label.lower()
        )
        self.setAccessibleName(description + (f" {info.message}" if info.message else ""))
        self.pill.setToolTip(
            tr("Le port local est ouvert. La disponibilité du service distant dépend de sa réponse.")
            if state == SessionState.LISTENING
            else ""
        )
        self.tick()

    def _update_probe(self) -> None:
        info = self.info
        if not info.probe_message:
            self.probe.hide()
            return
        symbol, role = {True: ("✓", "success"), False: ("×", "error")}.get(info.probe_ok, ("?", "muted"))  # type: ignore[arg-type]
        self.probe.setText(f"{symbol} {info.probe_message}")
        set_role(self.probe, role)
        self.probe.show()

    def test_service(self) -> None:
        """Test explicite et borné du service distant, à travers le port local."""
        self.probe.setText(tr("Test du service…"))
        set_role(self.probe, "muted")
        self.probe.show()
        self.ctx.run(self.ctx.manager.probe_session(self.info.id), on_error=self._probe_failed)

    def _diagnose(self) -> None:
        open_diagnosis(self.window(), self.ctx, self.info.profile_id)

    def _probe_failed(self, error: BaseException) -> None:
        self.probe.hide()
        self.ctx.notify("error", str(error))

    def _update_cause(self) -> None:
        info = self.info
        cause = session_cause(info)
        self.message.setText(cause[0] if cause else "")
        self.message.setProperty("role", cause[1] if cause else "warning")
        repolish(self.message)
        fix = fix_for(info) if info.state in (SessionState.DEGRADED, SessionState.ERROR) else None
        self.fix_button.setVisible(fix is not None)
        if fix is not None:
            self.fix_button.setText(fix[0])
            self._fix_section = fix[1]
        self.cause_host.setVisible(cause is not None or fix is not None)

    def _update_actions(self) -> None:
        actions = row_actions(self.info.state)
        self.logs_button.setVisible(actions.logs)
        self.restart_button.setVisible(actions.restart)
        self.restart_button.setText(actions.restart_label)
        self.stop_button.setVisible(actions.stop)
        self.remove_button.setVisible(actions.remove)
        self.more_button.setVisible(actions.more)

    def _setup_open_button(self) -> None:
        state = self.info.state
        actions = quick_actions(self.info)
        first = actions[0]
        others = actions[1:]
        menu = QMenu(self.open_button)
        for action in others:
            menu.addAction(action.label, lambda a=action: run_action(a, self.ctx.notify))
        self.open_button.setMenu(menu if others else None)  # type: ignore[arg-type]
        self.open_button.setPopupMode(
            QToolButton.ToolButtonPopupMode.MenuButtonPopup
            if others
            else QToolButton.ToolButtonPopupMode.DelayedPopup
        )
        self.open_button.setText(first.label)
        set_icon(self.open_button, first.icon)
        self._primary_action = first
        usable = state in (SessionState.LISTENING, SessionState.DEGRADED)
        self.open_button.setEnabled(usable)
        self.open_button.setVisible(state not in (SessionState.ERROR, SessionState.STOPPED))
        if state == SessionState.DEGRADED:
            tip = tr("La connexion distante peut échouer.")
        elif not usable:
            tip = tr("Le port local n'est pas encore ouvert.")
        else:
            tip = tr("Autres actions pour {name}").format(name=self.info.name) if others else first.label
        self.open_button.setToolTip(tip)
        self.open_button.setAccessibleName(f"{first.label} — {self.info.name}")
        self.open_button.setAccessibleDescription(tip)

    def tick(self) -> None:
        info = self.info
        if info.state in (SessionState.LISTENING, SessionState.DEGRADED):
            self.clock.setText(tr("Depuis {d}").format(d=since(info.listening_since)))
        elif info.state == SessionState.RECONNECTING and info.reconnect_in is not None:
            remaining = max(0, round(info.reconnect_in - (time.monotonic() - self._received_at)))
            self.clock.setText(
                tr("Tentative {n}/{max} · nouvel essai dans {s} s").format(
                    n=max(1, info.attempts), max=MAX_ATTEMPTS, s=remaining
                )
            )
        elif info.state == SessionState.STARTING:
            self.clock.setText(tr("Ouverture du port local…"))
        elif info.state == SessionState.STOPPED and self._stopped_at is not None:
            self.clock.setText(tr("Arrêtée à {time}").format(time=self._stopped_at.strftime("%H:%M")))
        else:
            self.clock.setText("")

    # --- Actions -----------------------------------------------------------------------------------------

    def _context_menu(self, pos: object) -> None:
        if self.info.state in RUNNING:
            self.more_menu.exec(self.mapToGlobal(pos))  # type: ignore[arg-type]

    def _copy_address(self) -> None:
        copy_to_clipboard(self.info.local_address)
        self.ctx.notify("success", tr("Adresse copiée : {address}").format(address=self.info.local_address))

    def _run_primary(self) -> None:
        if self._primary_action is not None:
            run_action(self._primary_action, self.ctx.notify)

    def _fix(self) -> None:
        self._open_source(self.info, self._fix_section)

    def _stop(self) -> None:
        self.ctx.run(self.ctx.manager.stop(self.info.id), on_error=lambda e: self.ctx.notify("error", str(e)))

    def _restart(self) -> None:
        self.ctx.run(
            self.ctx.manager.restart(self.info.id), on_error=lambda e: self.ctx.notify("error", str(e))
        )

    def is_engaged(self) -> bool:
        """Survolée ou focalisée : ne pas la déplacer sous le pointeur de l'utilisateur."""
        focus = self.focusWidget()
        return self.underMouse() or (focus is not None and self.isAncestorOf(focus))


# Nom historique, conservé pour les scripts et les tests.
SessionCard = SessionRow


class FavoriteTile(QFrame):
    """Favori : le corps lance ou ouvre la session ; l'arrêt est un bouton séparé de 32 × 32 px."""

    def __init__(self, view: DashboardView, profile: CloudflareProfile | SshProfile) -> None:
        super().__init__()
        self.view = view
        self.profile = profile
        self.active = False
        self.setProperty("role", "tile")
        self.setMinimumSize(QSize(220, 64))
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 6, 8, 6)
        layout.setSpacing(6)
        # Corps cliquable : un bouton qui contient deux libellés (nom en gras, état dans sa teinte).
        self.body = QPushButton()
        self.body.setProperty("role", "tileBody")
        self.body.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.body.setMinimumHeight(52)
        self.body.setCursor(Qt.CursorShape.PointingHandCursor)
        self.body.clicked.connect(self._activate)
        inner = QHBoxLayout(self.body)
        inner.setContentsMargins(10, 6, 10, 6)
        inner.setSpacing(10)
        kind = (
            SERVICE_ICONS.get(profile.service_type, "cloud")
            if isinstance(profile, CloudflareProfile)
            else "server"
        )
        glyph = QLabel()
        set_glyph(glyph, kind, "muted", 24)
        texts = QVBoxLayout()
        texts.setSpacing(2)
        self.name_label = label("★ " + profile.name)
        self.name_label.setStyleSheet("font-weight: 600;")
        self.state_label = label("", "stateText")
        texts.addWidget(self.name_label)
        texts.addWidget(self.state_label)
        inner.addWidget(glyph, 0, Qt.AlignmentFlag.AlignVCenter)
        inner.addLayout(texts, 1)
        for child in (glyph, self.name_label, self.state_label):
            child.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.stop = tool_button("player-stop-filled", "", self._stop, flat=False)
        layout.addWidget(self.body, 1)
        layout.addWidget(self.stop, 0, Qt.AlignmentFlag.AlignVCenter)
        self.refresh()

    def state_text(self) -> tuple[str, bool, str, str]:
        """(libellé, actif ?, teinte, symbole) : session Cloudflare, ou liaison SSH du serveur."""
        view = self.view
        if isinstance(self.profile, CloudflareProfile):
            state = cloudflare_favorite(view.profile_session(self.profile.id))
        else:
            link = view.ssh_states.get(self.profile.id)
            forwards = [r.info for r in view.cards.values() if r.info.profile_id == self.profile.id]
            state = ssh_favorite(link.state if link is not None else None, forwards)
        return state.label, state.active, state.tone, state.symbol

    def refresh(self) -> None:
        text, active, status, symbol = self.state_text()
        name = self.profile.name
        self.state_label.setText(f"{symbol} {text}")
        set_status(self.state_label, status)
        self.body.setAccessibleName(
            (tr("Afficher la session de {name}") if active else tr("Connecter {name}")).format(name=name)
        )
        self.body.setAccessibleDescription(text)
        self.body.setToolTip(f"{name} — {text}")
        stop_name = (
            tr("Arrêter {name}").format(name=name)
            if isinstance(self.profile, CloudflareProfile)
            else tr("Déconnecter le serveur {name}").format(name=name)
        )
        self.stop.setAccessibleName(stop_name)
        self.stop.setToolTip(stop_name)
        self.stop.setEnabled(active)
        self.active = active

    def _activate(self) -> None:
        if self.active:
            self.view.reveal_profile(self.profile)
        elif isinstance(self.profile, CloudflareProfile):
            self.view.start_cloudflare(self.profile.id)
        else:
            self.view.start_ssh(self.profile.id)

    def _stop(self) -> None:
        ctx = self.view.ctx
        if isinstance(self.profile, CloudflareProfile):
            ctx.run(ctx.manager.stop_profile(self.profile.id))
            return
        ctx.run(ctx.manager.ssh_disconnect(self.profile.id))
        for row in self.view.cards.values():
            if row.info.profile_id == self.profile.id and row.info.state in RUNNING:
                ctx.run(ctx.manager.stop(row.info.id))


class DashboardView(QWidget):
    """Page Sessions (clé interne « dashboard », conservée pour la vue mémorisée et les raccourcis)."""

    def __init__(self, ctx: GuiContext, open_logs: Callable[[str], None]) -> None:
        super().__init__()
        self.ctx = ctx
        self.open_logs = open_logs
        self.open_source: Callable[[SessionInfo, str], None] = lambda _info, _section: None
        self.open_view: Callable[[str], None] = lambda _key: None
        self.cards: dict[str, SessionRow] = {}
        self.ssh_states: dict[str, SshConnectionChanged] = {}
        self._pending_moves: set[str] = set()
        self._tiles: list[FavoriteTile] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 16)
        layout.setSpacing(12)

        header = QHBoxLayout()
        heading = QVBoxLayout()
        heading.setSpacing(2)
        heading.addWidget(title(tr("Sessions")))
        self.summary = label("", "muted")
        heading.addWidget(self.summary)
        header.addLayout(heading)
        header.addStretch()
        self.connect_button = primary_button(tr("Connecter…"), "plus")
        self.connect_menu = QMenu(self.connect_button)
        self.connect_button.setMenu(self.connect_menu)
        self.stop_all_button = button(tr("Tout arrêter"), "player-stop")
        self.stop_all_button.clicked.connect(self._stop_all)
        header.addWidget(self.connect_button, 0, Qt.AlignmentFlag.AlignTop)
        header.addWidget(self.stop_all_button, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)

        self.scroll_area = QScrollArea()
        self.scroll_area.setObjectName("PageScroll")
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        container = QWidget()
        self.content = QVBoxLayout(container)
        self.content.setContentsMargins(0, 0, 4, 0)
        self.content.setSpacing(10)

        self.favorites_title = QWidget()
        favorites_row = QHBoxLayout(self.favorites_title)
        favorites_row.setContentsMargins(0, 0, 0, 0)
        favorites_row.addWidget(group_label(tr("Favoris")))
        self.launch_favorites_button = button(tr("Tout connecter"), "player-play-filled", link=True)
        self.launch_favorites_button.setToolTip(tr("Connecter tous les favoris"))
        self.launch_favorites_button.clicked.connect(self.launch_favorites)
        favorites_row.addWidget(self.launch_favorites_button)
        favorites_row.addStretch()
        self.content.addWidget(self.favorites_title)
        self.favorites_host = QWidget()
        self.favorites_grid = QGridLayout(self.favorites_host)
        self.favorites_grid.setContentsMargins(0, 0, 0, 0)
        self.favorites_grid.setSpacing(8)
        self.content.addWidget(self.favorites_host)

        self.groups: dict[str, tuple[QLabel, QVBoxLayout, QWidget, QWidget]] = {}
        for key in ("check", "listening", "done"):
            heading_row = QHBoxLayout()
            heading_row.setContentsMargins(0, 8, 0, 0)
            head = group_label("")
            heading_row.addWidget(head)
            heading_row.addStretch()
            if key == "done":
                self.done_toggle = button(tr("Afficher"), None, link=True)
                self.done_toggle.setCheckable(True)
                self.done_toggle.toggled.connect(self._toggle_done)
                heading_row.addWidget(self.done_toggle)
            head_host = QWidget()
            head_host.setLayout(heading_row)
            rows_host = QWidget()
            rows_host.setProperty("group", key)
            rows = QVBoxLayout(rows_host)
            rows.setContentsMargins(0, 0, 0, 0)
            rows.setSpacing(8)
            self.content.addWidget(head_host)
            self.content.addWidget(rows_host)
            self.groups[key] = (head, rows, head_host, rows_host)

        new_button = primary_button(tr("Créer un profil"), "plus")
        new_button.clicked.connect(lambda: self.open_view("profiles"))
        import_button = button(tr("Importer…"), "file-import")
        import_button.clicked.connect(self._import)
        self.first_use = EmptyState(
            "cloud",
            tr("Votre premier accès"),
            tr("Créez un profil ou importez ceux de votre équipe."),
            [new_button, import_button],
        )
        self.content.addWidget(self.first_use)
        connect_again = primary_button(tr("Connecter…"), "plus")
        connect_again.clicked.connect(self._show_connect_menu)
        self.empty = EmptyState(
            "plug-connected",
            tr("Aucune session ouverte"),
            tr("Connectez un favori ou choisissez un accès enregistré."),
            [connect_again],
        )
        self.content.addWidget(self.empty)
        self.content.addStretch()
        self.scroll_area.setWidget(container)
        layout.addWidget(self.scroll_area, 1)

        ctx.bridge.session_changed.connect(self._on_session)
        ctx.bridge.session_removed.connect(self._on_removed)
        ctx.bridge.config_changed.connect(self.refresh_profiles)
        ctx.bridge.ssh_state.connect(self._on_ssh_state)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(1000)
        self._toggle_done(False)
        self.refresh_profiles()
        self._update_groups()
        self._update_summary()

    # --- Sessions ---------------------------------------------------------------------------------------

    def load_sessions(self, infos: list[SessionInfo]) -> None:
        for info in infos:
            self._on_session(info)

    def profile_session(self, profile_id: str) -> SessionInfo | None:
        return profile_session([r.info for r in self.cards.values()], profile_id)

    def _on_session(self, info: SessionInfo) -> None:
        row = self.cards.get(info.id)
        if row is None:
            row = SessionRow(self.ctx, info, self.open_logs, self.open_source)
            self.cards[info.id] = row
            self._place(row)
        else:
            before = group_of(row.info)
            row.update_info(info)
            if group_of(info) != before:
                if row.is_engaged():
                    self._pending_moves.add(info.id)
                else:
                    self._place(row)
        self._update_summary()
        self._refresh_tiles()

    def _place(self, row: SessionRow) -> None:
        rows = self.groups[group_of(row.info)][1]
        rows.addWidget(row)
        row.show()
        self._update_groups()

    def _on_removed(self, session_id: str) -> None:
        row = self.cards.pop(session_id, None)
        self._pending_moves.discard(session_id)
        if row is not None:
            row.hide()
            row.setParent(None)
            row.deleteLater()
        self._update_summary()
        self._update_groups()
        self._refresh_tiles()

    def _on_ssh_state(self, event: SshConnectionChanged) -> None:
        self.ssh_states[event.profile_id] = event
        self._refresh_tiles()

    def _tick(self) -> None:
        for row in self.cards.values():
            if row.isVisible():
                row.tick()
        for session_id in list(self._pending_moves):
            row = self.cards.get(session_id)
            if row is None or not row.is_engaged():
                self._pending_moves.discard(session_id)
                if row is not None:
                    self._place(row)

    def _update_groups(self) -> None:
        counts = {"check": 0, "listening": 0, "done": 0}
        for row in self.cards.values():
            parent = row.parentWidget()
            key = parent.property("group") if parent is not None else None
            if isinstance(key, str) and key in counts:
                counts[key] += 1
        titles = {"check": tr("À vérifier"), "listening": tr("À l'écoute"), "done": tr("Terminées")}
        for key, (head, _rows, head_host, rows_host) in self.groups.items():
            head.setText(f"{titles[key].upper()} · {counts[key]}")
            visible = bool(counts[key])
            head_host.setVisible(visible)
            if key != "done":
                rows_host.setVisible(visible)
        if not counts["done"]:
            self.groups["done"][3].setVisible(False)
        else:
            self.groups["done"][3].setVisible(self.done_toggle.isChecked())

    def _toggle_done(self, shown: bool) -> None:
        self.groups["done"][3].setVisible(shown and self.groups["done"][2].isVisibleTo(self))
        self.done_toggle.setText(tr("Masquer") if shown else tr("Afficher"))
        self.done_toggle.setAccessibleName(
            tr("Masquer les sessions terminées") if shown else tr("Afficher les sessions terminées")
        )

    def _update_summary(self) -> None:
        infos = [r.info for r in self.cards.values()]
        config = self.ctx.config()
        has_profiles = bool(config.cloudflare_profiles or config.ssh_profiles)
        self.first_use.setVisible(not self.cards and not has_profiles)
        self.empty.setVisible(not self.cards and has_profiles)
        running = sum(1 for i in infos if i.state in RUNNING)
        self.stop_all_button.setEnabled(running > 0)
        self.summary.setText(sessions_summary(infos))

    def _stop_all(self) -> None:
        self.ctx.run(self.ctx.manager.stop_all())

    def reveal_profile(self, profile: CloudflareProfile | SshProfile) -> None:
        """Corps d'un favori actif : montrer sa session (ou le serveur SSH connecté)."""
        rows = [r for r in self.cards.values() if r.info.profile_id == profile.id]
        if not rows:
            self.open_view("ssh" if isinstance(profile, SshProfile) else "profiles")
            return
        self.scroll_area.ensureWidgetVisible(rows[0])
        rows[0].setFocus()

    # --- Profils : menu « Connecter… » et favoris -----------------------------------------------------------

    def _show_connect_menu(self) -> None:
        self.connect_menu.exec(self.connect_button.mapToGlobal(self.connect_button.rect().bottomLeft()))

    def _import(self) -> None:
        from cma.ui.dialogs.transfer import run_import

        run_import(self.ctx, self)

    def refresh_profiles(self) -> None:
        config = self.ctx.config()
        self.connect_menu.clear()
        active = {r.info.profile_id for r in self.cards.values() if r.info.state in RUNNING}
        self.connect_menu.addSection(tr("Favoris et espaces de travail"))
        favorites = config.favorite_items()
        launch_all = self.connect_menu.addAction(
            tr("Connecter tous les favoris ({n})").format(n=len(favorites)), self.launch_favorites
        )
        launch_all.setEnabled(bool(favorites))
        for workspace in sorted(config.workspaces, key=lambda w: w.name.lower()):
            self.connect_menu.addAction(
                tr("Connecter « {name} » ({n})").format(name=workspace.name, n=len(workspace.items)),
                lambda w=workspace: launch_workspace(self.ctx, w),
            )
        self.connect_menu.addAction(tr("Gérer les espaces de travail…"), self.manage_workspaces)
        if config.cloudflare_profiles:
            self.connect_menu.addSection(tr("Accès Cloudflare"))
            for profile in sorted(
                config.cloudflare_profiles, key=lambda p: (not p.favorite, p.group.lower(), p.name.lower())
            ):
                text = f"{profile.group} › {profile.name}" if profile.group else profile.name
                action = self.connect_menu.addAction(text)
                action.setCheckable(True)
                action.setChecked(profile.id in active)
                action.setData(profile.id)
                action.triggered.connect(lambda _c=False, p=profile: self._connect_or_reveal(p))
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
                    tr("Connecter {name} ({n})").format(name=name, n=count),
                    lambda g=name: self.start_group(g),
                )
        forwards = [(p, f) for p in config.ssh_profiles for f in p.saved_forwards]
        if forwards:
            self.connect_menu.addSection(tr("Redirections SSH enregistrées"))
            for profile, forward in sorted(forwards, key=lambda pf: (not pf[0].favorite, pf[0].name.lower())):
                text = f"{profile.name} › {forward.short_label}"
                self.connect_menu.addAction(
                    text, lambda pid=profile.id, fw=forward: self.start_forward(pid, fw)
                )
        if self.connect_menu.isEmpty():
            action = self.connect_menu.addAction(tr("Aucun profil : créez-en un dans Accès Cloudflare"))
            action.setEnabled(False)
        self._rebuild_tiles(config)
        self._update_summary()

    def _connect_or_reveal(self, profile: CloudflareProfile) -> None:
        if self.profile_session(profile.id) is not None and any(
            r.info.profile_id == profile.id and r.info.state in RUNNING for r in self.cards.values()
        ):
            self.reveal_profile(profile)
        else:
            self.start_cloudflare(profile.id)

    def _rebuild_tiles(self, config: Config) -> None:
        for tile in self._tiles:
            tile.hide()
            tile.setParent(None)
            tile.deleteLater()
        favorites: list[CloudflareProfile | SshProfile] = [
            p for p in config.cloudflare_profiles if p.favorite
        ]
        favorites += [p for p in config.ssh_profiles if p.favorite]
        self.favorites_title.setVisible(bool(favorites))
        self.favorites_host.setVisible(bool(favorites))
        self._tiles = [FavoriteTile(self, profile) for profile in favorites]
        self._layout_tiles()

    def _layout_tiles(self) -> None:
        # Largeur de la page (marges et barre de défilement déduites) : la zone défilante n'a pas encore
        # sa taille définitive lors de la première construction.
        width = max(self.width() - 48 - 20, 240)
        columns = max(1, min(len(self._tiles) or 1, width // 232))
        while self.favorites_grid.count():
            self.favorites_grid.takeAt(0)
        for index, tile in enumerate(self._tiles):
            self.favorites_grid.addWidget(tile, index // columns, index % columns)
        for column in range(4):
            self.favorites_grid.setColumnStretch(column, 1 if column < columns else 0)

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._layout_tiles()

    def _refresh_tiles(self) -> None:
        for tile in self._tiles:
            tile.refresh()
        active = {r.info.profile_id for r in self.cards.values() if r.info.state in RUNNING}
        for action in self.connect_menu.actions():
            if action.isCheckable():
                action.setChecked(action.data() in active)

    def _start_failed(self, error: BaseException) -> None:
        self.ctx.notify("error", str(error))
        self._refresh_tiles()

    def launch_favorites(self) -> None:
        launch_favorites(self.ctx)

    def manage_workspaces(self) -> None:
        WorkspacesDialog(self, self.ctx).exec()
        self.refresh_profiles()

    def start_cloudflare(self, profile_id: str) -> None:
        self.ctx.run(self.ctx.manager.start_cloudflare(profile_id), on_error=self._start_failed)

    def start_group(self, group: str) -> None:
        manager = self.ctx.manager
        active = {r.info.profile_id for r in self.cards.values() if r.info.state in RUNNING}
        pending = [p for p in manager.group_profiles(group) if p.id not in active]

        def done(infos: list[SessionInfo]) -> None:
            failed = len(pending) - len(infos)
            if failed > 0:
                self.ctx.notify(
                    "warning",
                    tr("{group} : {ok} connexion(s) ouverte(s), {ko} en erreur.").format(
                        group=group, ok=len(infos), ko=failed
                    ),
                )

        self.ctx.run(manager.start_group(group), done, self._start_failed)

    def start_ssh(self, profile_id: str) -> None:
        self.ctx.run(self.ctx.manager.start_saved_forwards(profile_id), on_error=self._start_failed)

    def start_forward(self, profile_id: str, forward: SavedForward) -> None:
        self.ctx.run(self.ctx.manager.start_forward(profile_id, forward), on_error=self._start_failed)
