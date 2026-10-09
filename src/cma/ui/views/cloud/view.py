"""Administration Cloudflare : tunnels et noms d'hôte publiés, applications Access, service tokens (§4.6).

Tout passe par l'API Cloudflare avec un jeton d'API gardé dans le coffre. Les actions typiques :
importer les noms d'hôte d'un tunnel comme profils, publier un nouveau service protégé par Access,
créer un service token directement rangé dans le coffre de CMA (D14 à D17).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from PySide6.QtCore import (
    QSignalBlocker,
    Qt,
    QUrl,
    Signal,
)
from PySide6.QtGui import (
    QDesktopServices,
    QKeySequence,
    QShowEvent,
)
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QStackedWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from cma.core.cfadmin import CloudflareAdmin, Overview
from cma.core.cfapi import (
    TOKENS_PAGE,
    Account,
)
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.format import last_read
from cma.ui.icons import set_glyph, token_icon
from cma.ui.theme import current_tokens
from cma.ui.views.cloud.account_tools import AccountTools
from cma.ui.views.cloud.apps_tab import AppsTab
from cma.ui.views.cloud.cards import (
    StatTile,
)
from cma.ui.views.cloud.helpers import (
    describe_api_error,
    plural,
)
from cma.ui.views.cloud.summary import account_stats
from cma.ui.views.cloud.tokens_tab import TokensTab
from cma.ui.views.cloud.tunnels_tab import TunnelsTab
from cma.ui.views.common import confirm
from cma.ui.widgets import (
    SecretField,
    add_shortcut,
    button,
    clear_items,
    hline,
    label,
    primary_button,
    title,
)

ADD_TOKEN = "__add__"  # noqa: S105 (entrée « Ajouter un jeton… » du choix du jeton, pas un secret)

PERMISSION_GROUPS = (
    (
        "Compte",
        (
            "Account Settings : Read",
            "Cloudflare Tunnel : Edit",
            "Access: Apps and Policies : Edit",
            "Access: Service Tokens : Edit",
            "Access: Audit Logs : Read",
        ),
    ),
    ("Zone", ("DNS : Edit", "Zone : Read", "Analytics : Read")),
)


class CloudView(QWidget):
    publish_progress = Signal(str)

    def __init__(self, ctx: GuiContext, open_profile: Callable[[str], None] | None = None) -> None:
        super().__init__()
        self.publish_progress.connect(lambda text: self.status.setText(text))
        self.ctx = ctx
        self.open_profile = open_profile
        self.overview: Overview | None = None
        self.read_at: datetime | None = None
        self._auto_done = False
        self._loading = False
        self._refresh_again = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 16)
        layout.setSpacing(4)
        layout.addWidget(title(tr("Cloudflare")))
        layout.addWidget(label(tr("Services publiés dans votre compte"), "muted"))
        layout.addSpacing(12)
        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_login())
        self.stack.addWidget(self._build_account())
        layout.addWidget(self.stack, 1)
        add_shortcut(self, QKeySequence.StandardKey.Refresh, self.refresh)
        self._show_state()

    # --- Construction -------------------------------------------------------------------------------

    def _build_login(self) -> QWidget:
        card = QFrame()
        card.setObjectName("Card")
        card.setMaximumWidth(720)
        box = QVBoxLayout(card)
        box.setContentsMargins(28, 24, 28, 24)
        box.setSpacing(14)
        header = QHBoxLayout()
        header.setSpacing(14)
        glyph = QLabel()
        set_glyph(glyph, "cloud-cog", "accent", 40)
        header.addWidget(glyph, 0, Qt.AlignmentFlag.AlignTop)
        heading = QVBoxLayout()
        heading.setSpacing(2)
        heading.addWidget(title(tr("Connecter votre compte Cloudflare"), "SectionTitle"))
        heading.addWidget(
            label(
                tr("Tunnels, noms d'hôte publiés, applications Access et service tokens, gérés depuis CMA."),
                "muted",
                wrap=True,
            )
        )
        header.addLayout(heading, 1)
        box.addLayout(header)
        box.addWidget(hline())

        def step(number: int, text: str) -> QHBoxLayout:
            row = QHBoxLayout()
            row.setSpacing(10)
            badge = QLabel(str(number))
            badge.setFixedSize(24, 24)
            badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            tokens = current_tokens()
            badge.setStyleSheet(
                f"background: {tokens.accent}; color: {tokens.on_accent}; border-radius: 12px; font-weight: 600;"
            )
            row.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)
            row.addWidget(label(text, wrap=True), 1)
            return row

        first = step(1, tr("Créez un jeton d'API personnalisé dans votre profil Cloudflare."))
        create = button(tr("Créer un jeton d'API ↗"), link=True)
        create.setToolTip(TOKENS_PAGE)
        create.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(TOKENS_PAGE)))
        first.addWidget(create, 0, Qt.AlignmentFlag.AlignTop)
        box.addLayout(first)
        box.addLayout(step(2, tr("Donnez-lui ces permissions, limitées à votre compte et à vos zones :")))
        permissions = QGridLayout()
        permissions.setContentsMargins(34, 0, 0, 0)
        permissions.setHorizontalSpacing(24)
        permissions.setVerticalSpacing(4)
        for column, (scope, items) in enumerate(PERMISSION_GROUPS):
            permissions.addWidget(label(tr("Compte") if scope == "Compte" else scope, "meta"), 0, column)
            for row, item in enumerate(items, start=1):
                line = QHBoxLayout()
                line.setSpacing(6)
                check = QLabel()
                set_glyph(check, "circle-check", "success", 16)
                line.addWidget(check)
                line.addWidget(label(item, selectable=True))
                line.addStretch()
                holder = QWidget()
                holder.setLayout(line)
                line.setContentsMargins(0, 0, 0, 0)
                permissions.addWidget(holder, row, column)
        box.addLayout(permissions)
        box.addLayout(step(3, tr("Collez-le ici :")))
        token_row = QHBoxLayout()
        token_row.setContentsMargins(34, 0, 0, 0)
        self.token_field = SecretField(tr("jeton d'API Cloudflare"), subject=tr("jeton d'API"))
        self.token_field.setAccessibleName(tr("Jeton d'API"))
        token_row.addWidget(self.token_field, 1)
        self.connect_button = primary_button(tr("Se connecter"), "plug-connected")
        self.connect_button.clicked.connect(lambda: self.connect_account())
        token_row.addWidget(self.connect_button)
        box.addLayout(token_row)
        name_row = QHBoxLayout()
        name_row.setContentsMargins(34, 0, 0, 0)
        self.token_name = QLineEdit()
        self.token_name.setPlaceholderText(
            tr("Nom du jeton (facultatif) : « Perso », « Client X »… Par défaut, le nom du compte.")
        )
        self.token_name.setAccessibleName(tr("Nom du jeton"))
        self.token_name.setMaxLength(80)
        name_row.addWidget(self.token_name, 1)
        self.cancel_add = button(tr("Revenir au compte"), "arrow-back-up")
        self.cancel_add.clicked.connect(self._cancel_add_token)
        self.cancel_add.hide()
        name_row.addWidget(self.cancel_add)
        box.addLayout(name_row)
        self.login_error = label("", "error", wrap=True)
        self.login_error.hide()
        box.addWidget(self.login_error)
        box.addWidget(hline())
        footer = QHBoxLayout()
        lock = QLabel()
        set_glyph(lock, "lock", "muted", 16)
        footer.addWidget(lock)
        footer.addWidget(
            label(
                tr(
                    "Le jeton est vérifié puis conservé dans le coffre de cet ordinateur ; il n'est jamais affiché."
                ),
                "muted",
                wrap=True,
            ),
            1,
        )
        box.addLayout(footer)
        self.token_field.edit.returnPressed.connect(lambda: self.connect_account())
        host = QWidget()
        outer = QHBoxLayout(host)
        outer.setContentsMargins(0, 0, 0, 0)
        column = QVBoxLayout()
        column.addWidget(card)
        column.addStretch()
        outer.addStretch()
        outer.addLayout(column, 10)
        outer.addStretch()
        return host

    def _build_account(self) -> QWidget:
        host = QWidget()
        outer = QVBoxLayout(host)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(12)
        header = QFrame()
        header.setObjectName("Card")
        bar = QHBoxLayout(header)
        bar.setContentsMargins(18, 14, 18, 14)
        bar.setSpacing(14)
        avatar = QLabel()
        set_glyph(avatar, "cloud", "accent", 32)
        bar.addWidget(avatar, 0, Qt.AlignmentFlag.AlignVCenter)
        names = QVBoxLayout()
        names.setSpacing(2)
        self.account_name = title("", "ObjectTitle")
        names.addWidget(self.account_name)
        self.status = label("", "meta")
        names.addWidget(self.status)
        self.read_label = label("", "meta")
        names.addWidget(self.read_label)
        self.permission_hint = label(
            tr(
                "Compte retrouvé par ses zones : le jeton n'a pas la permission « Account Settings : Read ». "
                "Ajoutez-la pour voir tous vos comptes, y compris ceux sans domaine."
            ),
            "warning",
            wrap=True,
        )
        self.permission_hint.hide()
        names.addWidget(self.permission_hint)
        bar.addLayout(names, 1)
        self.token_choice = QComboBox()
        self.token_choice.setAccessibleName(tr("Jeton d'API"))
        self.token_choice.setToolTip(
            tr("Changer de jeton d'API (autre compte ou autre connexion Cloudflare)")
        )
        self.token_choice.activated.connect(self._token_chosen)
        bar.addWidget(self.token_choice, 0, Qt.AlignmentFlag.AlignVCenter)
        self.account = QComboBox()
        self.account.setAccessibleName(tr("Compte Cloudflare"))
        self.account.setMinimumWidth(220)
        self.account.setToolTip(tr("Changer de compte"))
        self.account.activated.connect(self._account_chosen)
        bar.addWidget(self.account, 0, Qt.AlignmentFlag.AlignVCenter)
        self.refresh_button = button(tr("Actualiser"), "refresh", tooltip=tr("Relire le compte (F5)"))
        self.refresh_button.clicked.connect(self.refresh)
        bar.addWidget(self.refresh_button, 0, Qt.AlignmentFlag.AlignVCenter)
        self.tools = AccountTools(self)
        bar.addWidget(self.tools.button, 0, Qt.AlignmentFlag.AlignVCenter)
        forget = button(tr("Oublier le jeton…"), "key-off")
        forget.clicked.connect(self.forget)
        bar.addWidget(forget, 0, Qt.AlignmentFlag.AlignVCenter)
        outer.addWidget(header)
        tiles = QHBoxLayout()
        tiles.setSpacing(10)
        self.stat_tunnels = StatTile("cloud", tr("Tunnels"))
        self.stat_hostnames = StatTile("world-www", tr("Noms d'hôte publiés"))
        self.stat_apps = StatTile("shield-check", tr("Applications Access"))
        self.stat_tokens = StatTile("key", tr("Service tokens"))
        for index, tile in enumerate(
            (self.stat_tunnels, self.stat_hostnames, self.stat_apps, self.stat_tokens)
        ):
            tab = max(0, index - 1)
            tile.clicked.connect(lambda t=tab: self.tabs.setCurrentIndex(t))
            tiles.addWidget(tile, 1)
        outer.addLayout(tiles)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setProperty("role", "plain")
        self.tunnels_tab = TunnelsTab(self)
        self.tabs.addTab(self.tunnels_tab, token_icon("cloud"), tr("Tunnels"))
        # Noms d'avant le découpage, gardés pour la palette, les menus, la fenêtre principale et les tests.
        tab = self.tunnels_tab
        self.tree = tab.tree
        self.tunnels_stack = tab.tunnels_stack
        self.tunnels_empty = tab.tunnels_empty
        self.tunnel_hint = tab.tunnel_hint
        self.publish_button = tab.publish_button
        self.import_button = tab.import_button
        self.unpublish_button = tab.unpublish_button
        self.test_all_button = tab.test_all_button
        self.tree_menu = tab.tree_menu
        self.selected_rules = tab.selected_rules
        self.import_selected = tab.import_selected
        self.publish = tab.publish
        self.unpublish_selected = tab.unpublish_selected
        self.check_connectors = tab.check_connectors
        self.show_service_results = tab.show_service_results
        self.test_all_hostnames = tab.test_all_hostnames
        self.test_from_internet = tab.test_from_internet
        self.add_path_rule = tab.add_path_rule
        self.fix_dns = tab.fix_dns
        self.move_rule = tab.move_rule
        self.edit_catch_all = tab.edit_catch_all
        self.edit_service = tab.edit_service
        self.create_tunnel = tab.create_tunnel
        self.rename_tunnel = tab.rename_tunnel
        self.delete_tunnel = tab.delete_tunnel
        self.apps_tab = AppsTab(self)
        self.tabs.addTab(self.apps_tab, token_icon("shield-check"), tr("Applications Access"))
        # Noms d'avant le découpage, gardés pour la palette, les menus et les tests.
        self.apps = self.apps_tab.table
        self.apps_hint = self.apps_tab.apps_hint
        self.allow_button = self.apps_tab.allow_button
        self.policies_button = self.apps_tab.policies_button
        self.delete_app_button = self.apps_tab.delete_app_button
        self.app_settings_button = self.apps_tab.app_settings_button
        self.access_log_button = self.apps_tab.access_log_button
        self.protect_hostname = self.apps_tab.protect_hostname
        self.allow_token = self.apps_tab.allow_token
        self.manage_policies = self.apps_tab.manage_policies
        self.manage_account_policies = self.apps_tab.manage_account_policies
        self.open_access_log = self.apps_tab.open_access_log
        self.edit_app_settings = self.apps_tab.edit_app_settings
        self.delete_selected_app = self.apps_tab.delete_selected_app
        self._selected_app = self.apps_tab.selected_app
        self.tokens_tab = TokensTab(self)
        self.tabs.addTab(self.tokens_tab, token_icon("key"), tr("Service tokens"))
        # Noms d'avant le découpage, gardés pour la palette, les menus et les tests.
        self.remote_tokens = self.tokens_tab.table
        self.extend_button = self.tokens_tab.extend_button
        self.rotate_button = self.tokens_tab.rotate_button
        self.delete_token_button = self.tokens_tab.delete_button
        self.create_token = self.tokens_tab.create_token
        self.extend_selected_token = self.tokens_tab.extend_selected_token
        self.rotate_selected_token = self.tokens_tab.rotate_selected_token
        self.delete_selected_token = self.tokens_tab.delete_selected_token
        self.selected_remote_token = self.tokens_tab.selected_remote_token
        outer.addWidget(self.tabs, 1)
        return host

    # --- État ----------------------------------------------------------------------------------------

    @property
    def admin(self) -> CloudflareAdmin:
        return self.ctx.manager.cloudflare

    def _show_state(self) -> None:
        self.stack.setCurrentIndex(1 if self.admin.has_token() else 0)
        self.cancel_add.hide()
        self._fill_tokens()

    def _fill_tokens(self) -> None:
        active = self.admin.active_token()
        with QSignalBlocker(self.token_choice):
            self.token_choice.clear()
            for token in self.admin.tokens():
                self.token_choice.addItem(token.name, token.id)
                if active is not None and token.id == active.id:
                    self.token_choice.setCurrentIndex(self.token_choice.count() - 1)
            self.token_choice.addItem(tr("Ajouter un jeton…"), ADD_TOKEN)
        # Un seul jeton : pas de choix à faire (« Ajouter un jeton d'API… » est dans le menu Outils).
        self.token_choice.setVisible(len(self.admin.tokens()) >= 2)

    def _token_chosen(self, _index: int) -> None:
        chosen = self.token_choice.currentData()
        active = self.admin.active_token()
        if chosen == ADD_TOKEN:
            self._fill_tokens()  # le choix revient sur le jeton actif
            self.start_add_token()
            return
        if active is not None and chosen == active.id:
            return
        self.admin.switch_token(str(chosen))
        self.overview = None
        self.read_at = None
        self.account.clear()
        self._fill(None)
        self.connect_account(use_saved=True)

    def start_add_token(self) -> None:
        """Page de connexion pour un jeton de plus, avec retour au compte en cours."""
        self.login_error.hide()
        self.stack.setCurrentIndex(0)
        self.cancel_add.show()
        self.token_field.setFocus()

    def _cancel_add_token(self) -> None:
        self.token_field.set_text("")
        self.token_name.clear()
        self._show_state()

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        if not self._auto_done and self.admin.has_token():
            self._auto_done = True
            self.connect_account(use_saved=True)

    def _error(self, error: BaseException) -> None:
        self._loading = False
        self.connect_button.setEnabled(True)
        self.refresh_button.setEnabled(True)
        self.tabs.setEnabled(True)
        self._show_summary()
        message = describe_api_error(error)
        if self.stack.currentIndex() == 0:
            self.login_error.setText(message)
            self.login_error.show()
        self.ctx.notify("error", message)

    # --- Connexion ---------------------------------------------------------------------------------------

    def connect_account(self, use_saved: bool = False) -> None:
        token = None if use_saved else self.token_field.text().strip()
        if token == "":
            self.ctx.notify("error", tr("Collez d'abord un jeton d'API Cloudflare."))
            return
        self.connect_button.setEnabled(False)
        self.login_error.hide()
        self.status.setText(tr("Connexion…"))

        def done(accounts: list[Account]) -> None:
            self.connect_button.setEnabled(True)
            self.token_field.set_text("")
            self.token_name.clear()
            self._show_state()
            current = self.ctx.config().settings.cloudflare_account_id
            self.account.clear()
            for account in sorted(accounts, key=lambda a: a.name.lower()):
                self.account.addItem(account.name, account)
                if account.id == current:
                    self.account.setCurrentIndex(self.account.count() - 1)
            self.permission_hint.setVisible(any(a.inferred for a in accounts))
            self.refresh()

        self.ctx.run(self.admin.connect(token, self.token_name.text()), done, self._error)

    def forget(self) -> None:
        if not confirm(
            self,
            tr("Oublier le jeton d'API ?"),
            tr(
                "Le jeton est retiré du coffre de cet ordinateur. Les sessions en cours et les ressources "
                "Cloudflare ne sont pas modifiées."
            ),
            tr("Oublier le jeton"),
        ):
            return
        self.admin.forget()
        self.overview = None
        self.read_at = None
        self.account.clear()
        self.permission_hint.hide()
        self._fill(None)
        self._show_state()
        self.ctx.notify("info", tr("Jeton d'API oublié."))
        if self.admin.has_token():  # un autre jeton enregistré prend le relais
            self.connect_account(use_saved=True)

    def _account_chosen(self, _index: int) -> None:
        account = self.account.currentData()
        if isinstance(account, Account):
            self.admin.select_account(account.id)
            # Les lignes affichées appartiennent à l'ancien compte : aucune action jusqu'au nouveau résultat.
            self.tabs.setEnabled(False)
            self.refresh()

    def refresh(self) -> None:
        account = self.account.currentData()
        if not isinstance(account, Account):
            return
        if self._loading:
            # Une lecture est en cours, peut-être d'avant la dernière modification : relire juste après elle.
            self._refresh_again = True
            return
        self._loading = True
        self._refresh_again = False
        self.refresh_button.setEnabled(False)
        self.status.setText(tr("Lecture du compte…"))

        def done(overview: Overview) -> None:
            self._loading = False
            self.refresh_button.setEnabled(True)
            self.tabs.setEnabled(True)
            self.read_at = datetime.now()
            self._fill(overview)
            if self._refresh_again:
                self.refresh()

        self.ctx.run(self.admin.overview(account), done, self._error)

    def _show_summary(self) -> None:
        overview = self.overview
        account = self.account.currentData()
        self.account_name.setText(account.name if isinstance(account, Account) else tr("Compte Cloudflare"))
        self.account.setVisible(self.account.count() > 1)
        if overview is None:
            self.status.setText("")
            self.read_label.setText("")
            for tile in (self.stat_tunnels, self.stat_hostnames, self.stat_apps, self.stat_tokens):
                tile.set_values(None)
            return
        stats = account_stats(overview, {t.client_id for t in self.ctx.config().tokens})
        self.status.setText(
            " · ".join(
                (
                    plural(stats.tunnels, tr("{n} tunnel"), tr("{n} tunnels")),
                    plural(stats.hostnames, tr("{n} nom d'hôte"), tr("{n} noms d'hôte")),
                    plural(stats.apps, tr("{n} application"), tr("{n} applications")),
                )
            )
        )
        self.read_label.setText(last_read(self.read_at))
        if not stats.tunnels:
            self.stat_tunnels.set_values(0)
        elif stats.troubled:
            self.stat_tunnels.set_values(
                stats.tunnels, tr("{n} à vérifier").format(n=stats.troubled), "warning"
            )
        else:
            self.stat_tunnels.set_values(stats.tunnels, tr("tous en ligne"), "success")
        if stats.dns_problems:
            self.stat_hostnames.set_values(
                stats.hostnames, tr("{n} DNS à corriger").format(n=stats.dns_problems), "warning"
            )
        else:
            self.stat_hostnames.set_values(
                stats.hostnames, plural(stats.zones, tr("{n} domaine"), tr("{n} domaines"))
            )
        self.stat_apps.set_values(
            stats.apps,
            tr("{n} sans protection").format(n=stats.unprotected) if stats.unprotected else "",
            "warning" if stats.unprotected else None,
        )
        self.stat_tokens.set_values(
            stats.tokens, tr("{n} dans CMA").format(n=stats.tokens_in_cma) if stats.tokens else ""
        )

    def _fill(self, overview: Overview | None) -> None:
        self.overview = overview
        # Vider d'abord les sélections (leurs éléments existent encore), sans signaux ; les actions sont recalculées
        # à la fin.
        self.tunnels_tab.clear()
        for table in (self.apps, self.remote_tokens):
            table.clearSelection()
            with QSignalBlocker(table):
                clear_items(table)
        self._show_summary()
        if overview is None:
            self.tunnels_tab.update_actions()
            self.apps_tab.update_actions()
            return
        self.tunnels_tab.fill(overview)
        self.apps_tab.fill(overview)
        self.tokens_tab.fill(overview)
        self.tunnels_tab.update_actions()
        self.apps_tab.update_actions()
        self.tokens_tab.update_actions()
