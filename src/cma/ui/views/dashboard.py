"""Page « Sessions » : favoris, connexions en cours et incidents (spécification de refonte §4.2). La ligne d'une
session et la tuile d'un favori sont dans `session_cards.py`.

- Les sessions qui demandent une intervention (dégradée, reconnexion, erreur) passent avant celles qui
  fonctionnent ; les sessions arrêtées sont regroupées dans « Terminées », replié par défaut.
- Chaque état associe un libellé, un symbole, une explication et les seules actions possibles.
- Une ligne survolée ou focalisée ne change pas de groupe sous le pointeur : le déplacement est différé.
- Un favori se lance d'un clic sur son corps ; l'arrêt est un bouton séparé, jamais le nom lui-même.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QResizeEvent
from PySide6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMenu,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from cma.core.events import SshConnectionChanged
from cma.core.models import CloudflareProfile, Config, SavedForward, SshProfile
from cma.core.sessions import SessionInfo
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.dialogs.workspaces import WorkspacesDialog, launch_favorites, launch_workspace
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
from cma.ui.views.health import HealthCard
from cma.ui.views.session_cards import FavoriteTile, SessionRow
from cma.ui.widgets import (
    EmptyState,
    button,
    group_label,
    label,
    primary_button,
    title,
)


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
        # Santé du compte Cloudflare (pannes, tokens à renouveler) : la fenêtre principale la tient à jour.
        self.health = HealthCard(lambda: None, lambda: None)
        layout.addWidget(self.health)

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
