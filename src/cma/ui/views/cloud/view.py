"""Administration Cloudflare : tunnels et noms d'hôte publiés, applications Access, service tokens (§4.6).

Tout passe par l'API Cloudflare avec un jeton d'API gardé dans le coffre. Les actions typiques :
importer les noms d'hôte d'un tunnel comme profils, publier un nouveau service protégé par Access,
créer un service token directement rangé dans le coffre de CMA (D14 à D17).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from PySide6.QtCore import (
    QPoint,
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
    QAbstractItemView,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMenu,
    QStackedWidget,
    QTabWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.cfadmin import CloudflareAdmin, NewTunnel, Overview, PublishRequest, PublishResult
from cma.core.cfapi import (
    TOKENS_PAGE,
    Account,
    Connector,
    IngressRule,
    Tunnel,
)
from cma.core.dnscheck import DnsCheck
from cma.core.hostprobe import HostProbe, probe_hostname_async
from cma.core.models import CloudflareProfile
from cma.core.servicewatch import ServiceResult, ServiceTarget, probe_token, targets_of
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.format import last_read
from cma.ui.icons import set_glyph, token_icon
from cma.ui.theme import current_tokens, mono_font
from cma.ui.views.cloud.apps_tab import AppsTab
from cma.ui.views.cloud.cards import (
    DNS_ROLE,
    PROFILE_ROLE,
    PROTECTED_ROLE,
    RULE_ROLE,
    SERVICE_ROLE,
    TUNNEL_ROLE,
    StatTile,
    TunnelTree,
    service_icon,
)
from cma.ui.views.cloud.connectors import show_connectors
from cma.ui.views.cloud.dialogs import (
    PublishDialog,
    ask_catch_all,
    ask_path_rule,
    ask_service,
    publish_summary,
)
from cma.ui.views.cloud.helpers import (
    describe_api_error,
    plural,
    tunnel_state,
)
from cma.ui.views.cloud.services import service_tooltip, show_service_tests
from cma.ui.views.cloud.summary import account_stats, protected_hosts
from cma.ui.views.cloud.tokens_tab import TokensTab
from cma.ui.views.cloud.tunnel_create import ask_tunnel_name, show_new_tunnel
from cma.ui.views.common import confirm
from cma.ui.widgets import (
    EmptyState,
    SecretField,
    add_shortcut,
    button,
    clear_items,
    copy_to_clipboard,
    hline,
    label,
    primary_button,
    title,
)

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
    ("Zone", ("DNS : Edit", "Zone : Read")),
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
        self._preferred_tunnel: Tunnel | None = None
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
        self.account = QComboBox()
        self.account.setAccessibleName(tr("Compte Cloudflare"))
        self.account.setMinimumWidth(220)
        self.account.setToolTip(tr("Changer de compte"))
        self.account.activated.connect(self._account_chosen)
        bar.addWidget(self.account, 0, Qt.AlignmentFlag.AlignVCenter)
        self.refresh_button = button(tr("Actualiser"), "refresh", tooltip=tr("Relire le compte (F5)"))
        self.refresh_button.clicked.connect(self.refresh)
        bar.addWidget(self.refresh_button, 0, Qt.AlignmentFlag.AlignVCenter)
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
        self.tabs.addTab(self._build_tunnels(), token_icon("cloud"), tr("Tunnels"))
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

    def _build_tunnels(self) -> QWidget:
        page = QWidget()
        box = QVBoxLayout(page)
        box.setContentsMargins(0, 12, 0, 0)
        box.setSpacing(8)
        row = QHBoxLayout()
        self.publish_button = primary_button(tr("Publier un service…"), "world-www")
        self.publish_button.clicked.connect(self.publish)
        self.import_button = button(tr("Importer comme profils"), "file-import")
        self.import_button.clicked.connect(self.import_selected)
        self.unpublish_button = button(tr("Retirer…"), "trash", danger=True)
        self.unpublish_button.clicked.connect(self.unpublish_selected)
        for widget in (self.publish_button, self.import_button, self.unpublish_button):
            row.addWidget(widget)
        row.addStretch()
        self.test_all_button = button(
            tr("Tester tous les noms d'hôte"),
            "world",
            tooltip=tr("Demander chaque nom d'hôte publié depuis Internet, comme un visiteur"),
        )
        self.test_all_button.clicked.connect(self.test_all_hostnames)
        row.addWidget(self.test_all_button)
        create = button(tr("Créer un tunnel…"), "plus")
        create.clicked.connect(self.create_tunnel)
        row.addWidget(create)
        box.addLayout(row)
        self.tunnel_hint = label("", "meta", wrap=True)
        box.addWidget(self.tunnel_hint)
        self.tree = TunnelTree()
        self.tree.setAccessibleName(tr("Tunnels et noms d'hôte publiés"))
        self.tree.setHeaderLabels([tr("Tunnel ou nom d'hôte"), tr("Service"), tr("État")])
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.itemSelectionChanged.connect(self._update_tunnel_actions)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_menu)
        refresh = button(tr("Actualiser"), "refresh")
        refresh.clicked.connect(self.refresh)
        create_empty = primary_button(tr("Créer un tunnel…"), "plus")
        create_empty.clicked.connect(self.create_tunnel)
        self.tunnels_empty = EmptyState(
            "cloud",
            tr("Aucun tunnel disponible dans ce compte."),
            tr("Créez un tunnel, puis installez son connecteur sur un serveur de votre réseau."),
            [create_empty, refresh],
        )
        self.tunnels_stack = QStackedWidget()
        self.tunnels_stack.addWidget(self.tree)
        self.tunnels_stack.addWidget(self.tunnels_empty)
        box.addWidget(self.tunnels_stack, 1)
        return page

    # --- État ----------------------------------------------------------------------------------------

    @property
    def admin(self) -> CloudflareAdmin:
        return self.ctx.manager.cloudflare

    def _show_state(self) -> None:
        self.stack.setCurrentIndex(1 if self.admin.has_token() else 0)

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
            self._show_state()
            current = self.ctx.config().settings.cloudflare_account_id
            self.account.clear()
            for account in sorted(accounts, key=lambda a: a.name.lower()):
                self.account.addItem(account.name, account)
                if account.id == current:
                    self.account.setCurrentIndex(self.account.count() - 1)
            self.permission_hint.setVisible(any(a.inferred for a in accounts))
            self.refresh()

        self.ctx.run(self.admin.connect(token), done, self._error)

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
        # Vider d'abord les sélections (leurs éléments existent encore), puis reconstruire sans signaux :
        # un `itemSelectionChanged` émis pendant `clear()` ferait relire un élément en cours de destruction
        # (abandon de Qt sous Linux). Les actions sont recalculées à la fin.
        self.tree.clearSelection()
        with QSignalBlocker(self.tree):
            clear_items(self.tree)
        for table in (self.apps, self.remote_tokens):
            table.clearSelection()
            with QSignalBlocker(table):
                clear_items(table)
        self._show_summary()
        if overview is None:
            self._update_tunnel_actions()
            self.apps_tab.update_actions()
            return
        mono = mono_font(9.5)
        protected = protected_hosts(overview.apps)
        imported = {p.hostname.lower() for p in self.ctx.config().cloudflare_profiles if p.hostname}
        for view in sorted(overview.tunnels, key=lambda v: v.tunnel.name.lower()):
            text, _tone, symbol = tunnel_state(view.tunnel.status)
            count = plural(len(view.hostnames), tr("{n} nom d'hôte"), tr("{n} noms d'hôte"))
            guarded = sum(1 for r in view.hostnames if r.hostname.lower() in protected)
            summary = count
            if view.hostnames:
                summary += " · " + tr("{n}/{total} protégés par Access").format(
                    n=guarded, total=len(view.hostnames)
                )
            parent = QTreeWidgetItem([view.tunnel.name, summary, f"{symbol} {text}"])
            parent.setToolTip(
                0,
                tr("Tunnel {name} ({id})").format(name=view.tunnel.name, id=view.tunnel.id)
                + "\n"
                + tr("Règle finale : {service}").format(service=view.catch_all),
            )
            parent.setData(0, TUNNEL_ROLE, view.tunnel)
            parent.setData(0, Qt.ItemDataRole.AccessibleTextRole, f"{view.tunnel.name}, {text}, {summary}")
            for rule in view.hostnames:
                child = QTreeWidgetItem([rule.hostname + rule.path, rule.service, "—"])
                child.setIcon(0, token_icon(service_icon(rule.service), "muted"))
                child.setFont(1, mono)
                is_protected = rule.hostname.lower() in protected
                in_cma = rule.hostname.lower() in imported
                notes = [tr("protégé par Access") if is_protected else tr("non protégé")]
                if in_cma:
                    notes.append(tr("profil présent dans CMA"))
                child.setToolTip(0, f"{rule.hostname}{rule.path}  →  {rule.service}")
                self._set_service_result(child, self.ctx.services.result(rule.hostname, rule.path))
                child.setToolTip(1, rule.service)
                child.setData(0, TUNNEL_ROLE, view.tunnel)
                child.setData(0, RULE_ROLE, rule)
                child.setData(0, PROTECTED_ROLE, is_protected)
                child.setData(0, PROFILE_ROLE, in_cma)
                dns = overview.dns.get(rule.hostname.lower())
                child.setData(0, DNS_ROLE, dns)
                if dns is not None and not dns.ok:
                    notes.append(dns.label())
                child.setData(
                    0,
                    Qt.ItemDataRole.AccessibleTextRole,
                    ", ".join([rule.hostname, rule.service, *notes]),
                )
                parent.addChild(child)
            self.tree.addTopLevelItem(parent)
            parent.setExpanded(True)
        self.tunnels_stack.setCurrentWidget(self.tree if overview.tunnels else self.tunnels_empty)
        self.apps_tab.fill(overview)
        self.tokens_tab.fill(overview)
        self._update_tunnel_actions()
        self.apps_tab.update_actions()
        self.tokens_tab.update_actions()

    # --- Tunnels -----------------------------------------------------------------------------------------

    def _selected_item(self) -> QTreeWidgetItem | None:
        items = self.tree.selectedItems()
        return items[0] if items else None

    def _update_tunnel_actions(self) -> None:
        item = self._selected_item()
        rule = item.data(0, RULE_ROLE) if item is not None else None
        tunnel = item.data(0, TUNNEL_ROLE) if item is not None else None
        usable = self.overview is not None and bool(self.overview.tunnels) and bool(self.overview.zones)
        self.publish_button.setEnabled(usable)
        self.test_all_button.setEnabled(
            self.overview is not None and any(v.hostnames for v in self.overview.tunnels)
        )
        self.unpublish_button.setEnabled(isinstance(rule, IngressRule))
        if isinstance(rule, IngressRule):
            scope = tr("Importer {host} comme profil").format(host=rule.hostname)
        elif isinstance(tunnel, Tunnel):
            scope = tr("Importer les noms d'hôte du tunnel {name}").format(name=tunnel.name)
        else:
            scope = tr("Importer tous les noms d'hôte du compte")
        self.import_button.setToolTip(scope)
        self.import_button.setAccessibleDescription(scope)
        if self.overview is not None and not usable:
            hint = tr("Aucun tunnel ou domaine utilisable dans ce compte.")
        elif not isinstance(rule, IngressRule):
            hint = tr(
                "Sélectionnez un nom d'hôte pour le retirer ; sans sélection, l'import couvre tout le compte."
            )
        else:
            hint = ""
        self.tunnel_hint.setText(hint)
        self.tunnel_hint.setVisible(bool(hint))

    def selected_rules(self) -> list[tuple[Tunnel, IngressRule]]:
        """Noms d'hôte sélectionnés ; un tunnel sélectionné vaut tous ses noms ; rien de sélectionné vaut tout."""
        items = self.tree.selectedItems() or [
            self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount())
        ]
        chosen: list[tuple[Tunnel, IngressRule]] = []
        for item in items:
            if item is None:
                continue
            rule = item.data(0, RULE_ROLE)
            tunnel = item.data(0, TUNNEL_ROLE)
            if isinstance(rule, IngressRule):
                chosen.append((tunnel, rule))
            else:
                for index in range(item.childCount()):
                    child = item.child(index)
                    if child is not None:
                        chosen.append((tunnel, child.data(0, RULE_ROLE)))
        unique: dict[str, tuple[Tunnel, IngressRule]] = {}
        for tunnel, rule in chosen:
            unique.setdefault(rule.hostname, (tunnel, rule))
        return list(unique.values())

    def import_selected(self) -> None:
        rules = self.selected_rules()
        if not rules:
            self.ctx.notify("info", tr("Aucun nom d'hôte publié à importer."))
            return
        created: list[CloudflareProfile] = self.admin.import_profiles(rules)
        if len(created) == 1:
            profile = created[0]
            self.ctx.notify(
                "success",
                tr("Profil créé : {name}.").format(name=profile.name),
                action=self._open_action(profile),
            )
        elif created:
            self.ctx.notify("success", tr("{n} profils importés.").format(n=len(created)))
        else:
            self.ctx.notify("info", tr("Ces noms d'hôte ont déjà un profil dans CMA."))

    def _open_action(self, profile: CloudflareProfile | None) -> tuple[str, Callable[[], None]] | None:
        opener = self.open_profile
        if profile is None or opener is None:
            return None
        return (tr("Ouvrir le profil"), lambda: opener(profile.id))

    def _tree_menu(self, pos: QPoint) -> None:
        item = self.tree.itemAt(pos)
        if item is None:
            return
        self.tree.setCurrentItem(item)
        menu = self.tree_menu(item)
        menu.exec(self.tree.viewport().mapToGlobal(pos))
        menu.deleteLater()

    def tree_menu(self, item: QTreeWidgetItem) -> QMenu:
        """Menu d'un tunnel ou d'une règle (construit à part de son `exec`, pour les tests)."""
        rule = item.data(0, RULE_ROLE)
        tunnel = item.data(0, TUNNEL_ROLE)
        menu = QMenu(self)
        if isinstance(rule, IngressRule):
            menu.addAction(tr("Importer comme profil"), self.import_selected)
            menu.addAction(tr("Copier le nom d'hôte"), lambda: copy_to_clipboard(rule.hostname))
            menu.addAction(tr("Tester depuis Internet"), lambda: self.test_from_internet(rule))
            if rule.service.lower().startswith(("http://", "https://")):
                menu.addAction(
                    tr("Ouvrir dans le navigateur"),
                    lambda: QDesktopServices.openUrl(QUrl(f"https://{rule.hostname}{rule.path}")),
                )
            parent = item.parent()
            owner = parent.data(0, TUNNEL_ROLE) if parent is not None else None
            if isinstance(owner, Tunnel) and parent is not None:
                menu.addAction(tr("Modifier le service…"), lambda: self.edit_service(owner, rule))
                menu.addAction(tr("Ajouter une règle avec chemin…"), lambda: self.add_path_rule(owner, rule))
                dns = item.data(0, DNS_ROLE)
                if isinstance(dns, DnsCheck) and dns.fixable:
                    menu.addAction(tr("Corriger le DNS…"), lambda: self.fix_dns(owner, rule, dns))
                menu.addSeparator()
                position, count = parent.indexOfChild(item), parent.childCount()
                up = menu.addAction(tr("Monter"), lambda: self.move_rule(owner, rule, -1))
                up.setEnabled(position > 0)
                down = menu.addAction(tr("Descendre"), lambda: self.move_rule(owner, rule, 1))
                down.setEnabled(position < count - 1)
            menu.addSeparator()
            menu.addAction(
                tr("Retirer cette règle…") if rule.path else tr("Retirer ce nom d'hôte…"),
                self.unpublish_selected,
            )
        elif isinstance(tunnel, Tunnel):
            menu.addAction(tr("Importer ses noms d'hôte"), self.import_selected)
            publish = menu.addAction(tr("Publier un service sur ce tunnel…"), lambda: self.publish(tunnel))
            publish.setEnabled(self.publish_button.isEnabled())
            menu.addAction(tr("Règle finale…"), lambda: self.edit_catch_all(tunnel))
            menu.addAction(tr("État des connecteurs…"), lambda: self.check_connectors(tunnel))
            menu.addSeparator()
            menu.addAction(tr("Renommer…"), lambda: self.rename_tunnel(tunnel))
            menu.addAction(tr("Supprimer le tunnel…"), lambda: self.delete_tunnel(tunnel))
        return menu

    def add_path_rule(self, tunnel: Tunnel, rule: IngressRule) -> None:
        """Nouvelle règle avec chemin sur le nom d'hôte de `rule` (même DNS, même protection Access)."""
        answer = ask_path_rule(self, tunnel, rule.hostname)
        if not answer:
            return
        path, service = answer

        def done(added: IngressRule) -> None:
            self.ctx.notify(
                "success",
                tr("{host} pointe désormais vers {service}.").format(
                    host=added.hostname + added.path, service=added.service
                ),
            )
            self.refresh()

        self.ctx.run(self.admin.add_path_rule(tunnel, rule.hostname, path, service), done, self._error)

    def fix_dns(self, tunnel: Tunnel, rule: IngressRule, check: DnsCheck) -> None:
        """CNAME du nom d'hôte vers ce tunnel, proxifié ; la confirmation dit ce qui est faux et ce qui change."""
        host = rule.hostname
        text = (
            check.explanation(host)
            + "\n\n"
            + tr("Le CNAME de {host} visera ce tunnel ({tunnel}), proxifié par Cloudflare.").format(
                host=host, tunnel=tunnel.name
            )
        )
        if not confirm(self, tr("Corriger le DNS de {host} ?").format(host=host), text, tr("Corriger")):
            return

        def done(_result: object) -> None:
            self.ctx.notify("success", tr("DNS de {host} corrigé.").format(host=host))
            self.refresh()

        self.ctx.run(self.admin.fix_dns(tunnel, host), done, self._error)

    def _probe_token(self, hostname: str) -> tuple[str, str] | None:
        return probe_token(self.ctx.config(), self.ctx.core.secrets, hostname)

    def _set_service_result(self, item: QTreeWidgetItem, result: ServiceResult | None) -> None:
        item.setData(0, SERVICE_ROLE, result)
        rule = item.data(0, RULE_ROLE)
        if isinstance(rule, IngressRule):
            base = f"{rule.hostname}{rule.path}  →  {rule.service}"
            item.setToolTip(0, base + ("\n\n" + service_tooltip(result) if result is not None else ""))

    def show_service_results(self) -> None:
        """Reporte les derniers tests (surveillance ou test manuel) sur les cartes, sans relire le compte."""
        for row in range(self.tree.topLevelItemCount()):
            parent = self.tree.topLevelItem(row)
            for index in range(parent.childCount() if parent is not None else 0):
                child = parent.child(index) if parent is not None else None
                rule = child.data(0, RULE_ROLE) if child is not None else None
                if child is not None and isinstance(rule, IngressRule):
                    self._set_service_result(child, self.ctx.services.result(rule.hostname, rule.path))
        self.tree.viewport().update()

    def _target(self, rule: IngressRule) -> ServiceTarget:
        owner = next(
            (v.tunnel for v in (self.overview.tunnels if self.overview else []) if rule in v.hostnames), None
        )
        return ServiceTarget(
            rule.hostname, rule.path, rule.service, owner.id if owner else "", owner.name if owner else ""
        )

    def test_all_hostnames(self) -> None:
        """Tous les noms d'hôte publiés, testés depuis Internet ; le tableau des résultats s'ouvre ensuite."""
        if self.overview is None:
            return
        targets = targets_of(
            ((v.tunnel, v.hostnames) for v in self.overview.tunnels), web_only=False, active_only=False
        )
        if not targets:
            return
        self.test_all_button.setEnabled(False)
        self.status.setText(
            plural(
                len(targets),
                tr("Test de {n} nom d'hôte depuis Internet…"),
                tr("Test de {n} noms d'hôte depuis Internet…"),
            )
        )

        def done(results: list[tuple[ServiceTarget, HostProbe]]) -> None:
            self._show_summary()
            self._update_tunnel_actions()
            self.ctx.services.record(results)
            self.show_service_results()
            show_service_tests(self, results)

        def failed(error: BaseException) -> None:
            self._update_tunnel_actions()
            self._error(error)

        self.ctx.run(self.admin.probe_services(targets), done, failed)

    def test_from_internet(self, rule: IngressRule) -> None:
        """Ce qu'obtient un visiteur : DNS public, Access, tunnel, service. Un service non HTTP (SSH, RDP, TCP)
        ne se teste ainsi que jusqu'à Access ; la connexion complète se teste avec une session."""
        target = self._target(rule)
        web = target.web
        token = self._probe_token(rule.hostname) if web else None
        self.status.setText(tr("Test de {host} depuis Internet…").format(host=rule.hostname + rule.path))

        def done(result: HostProbe) -> None:
            self._show_summary()
            self.ctx.services.record([(target, result)])
            self.show_service_results()
            text = result.summary(rule.hostname + rule.path)
            if not web:
                text += " " + tr(
                    "Service non HTTP : seuls le DNS et Access sont testés ; la connexion complète se teste avec "
                    "une session (« Tester le service »)."
                )
            elif token is not None:
                text += " " + tr("Test fait avec le service token du profil CMA.")
            self.ctx.notify(result.tone, text)

        self.ctx.run(
            probe_hostname_async(rule.hostname, token=token, path=target.probe_path), done, self._error
        )

    def move_rule(self, tunnel: Tunnel, rule: IngressRule, offset: int) -> None:
        self.ctx.run(self.admin.move_rule(tunnel, rule, offset), lambda _p: self.refresh(), self._error)

    def edit_catch_all(self, tunnel: Tunnel) -> None:
        current = next(
            (
                v.catch_all
                for v in (self.overview.tunnels if self.overview else [])
                if v.tunnel.id == tunnel.id
            ),
            "http_status:404",
        )
        service = ask_catch_all(self, tunnel, current)
        if not service or service == current:
            return

        def done(_result: object) -> None:
            self.ctx.notify(
                "success",
                tr("Règle finale du tunnel {name} : {service}.").format(name=tunnel.name, service=service),
            )
            self.refresh()

        self.ctx.run(self.admin.set_catch_all(tunnel, service), done, self._error)

    def edit_service(self, tunnel: Tunnel, rule: IngressRule) -> None:
        """Change la cible d'un nom d'hôte publié (même nom, même DNS, même protection Access)."""
        answer = ask_service(self, tunnel, rule)
        if not answer:
            return
        service, origin = answer
        self.status.setText(tr("Modification du service…"))

        def done(updated: IngressRule) -> None:
            self.ctx.notify(
                "success",
                tr("{host} pointe désormais vers {service}.").format(
                    host=updated.hostname, service=updated.service
                ),
            )
            self.refresh()

        self.ctx.run(
            self.admin.edit_hostname(tunnel, rule.hostname, service, origin, rule.path), done, self._error
        )

    def create_tunnel(self) -> None:
        """Crée un tunnel géré depuis Cloudflare, puis donne la commande d'installation de son connecteur."""
        existing = [v.tunnel.name for v in self.overview.tunnels] if self.overview else []
        name = ask_tunnel_name(self, existing)
        if not name:
            return
        self.status.setText(tr("Création du tunnel…"))

        def done(created: NewTunnel) -> None:
            self.refresh()
            show_new_tunnel(self, created)

        self.ctx.run(self.admin.create_tunnel(name), done, self._error)

    def check_connectors(self, tunnel: Tunnel) -> None:
        """Lit les connecteurs du tunnel puis affiche le diagnostic et les connexions vers Cloudflare."""
        self.status.setText(tr("Lecture des connecteurs…"))

        def done(connectors: list[Connector]) -> None:
            self._show_summary()
            show_connectors(self, tunnel, connectors)

        self.ctx.run(self.admin.connectors(tunnel), done, self._error)

    def ask_publish(self) -> PublishRequest | None:
        if self.overview is None:
            return None
        remote = {t.client_id for t in self.overview.tokens}
        tokens = [t for t in self.ctx.config().tokens if t.client_id in remote]
        dialog = PublishDialog(self, self.overview, tokens, self._preferred_tunnel)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        return dialog.request()

    def publish(self, tunnel: Tunnel | None = None) -> None:
        self._preferred_tunnel = tunnel if isinstance(tunnel, Tunnel) else None
        request = self.ask_publish()
        self._preferred_tunnel = None
        if request is None:
            return
        self.status.setText(tr("Publication de {host}…").format(host=request.hostname))

        def done(result: PublishResult) -> None:
            if result.complete:
                parts = [tr("Service publié : {host}.").format(host=result.rule.hostname)]
                if result.app is not None:
                    parts.append(tr("Protégé par Access."))
                if result.profile is not None:
                    parts.append(tr("Profil CMA créé."))
                self.ctx.notify("success", " ".join(parts), action=self._open_action(result.profile))
            else:
                self.ctx.notify("warning", publish_summary(result), action=self._open_action(result.profile))
            self.refresh()

        def failed(error: BaseException) -> None:
            self._error(
                RuntimeError(
                    tr("La publication n'a pas abouti. Contrôlez l'état dans Cloudflare avant de réessayer.")
                    + " "
                    + describe_api_error(error)
                )
            )
            self.refresh()

        self.ctx.run(self.admin.publish(request, self.publish_progress.emit), done, failed)

    def unpublish_selected(self) -> None:
        item = self._selected_item()
        rule = item.data(0, RULE_ROLE) if item is not None else None
        tunnel = item.data(0, TUNNEL_ROLE) if item is not None else None
        if not isinstance(rule, IngressRule) or not isinstance(tunnel, Tunnel):
            self.ctx.notify("info", tr("Sélectionnez un nom d'hôte à retirer."))
            return
        shared = self.overview is not None and any(
            r.hostname == rule.hostname and r.path != rule.path
            for v in self.overview.tunnels
            if v.tunnel.id == tunnel.id
            for r in v.hostnames
        )
        if not confirm(
            self,
            tr("Retirer {host} ?").format(host=rule.hostname + rule.path),
            (
                tr(
                    "La règle est retirée du tunnel {tunnel}. Le nom d'hôte reste publié par ses autres règles : "
                    "son enregistrement DNS est gardé."
                )
                if shared
                else tr(
                    "La règle est retirée du tunnel {tunnel} et l'enregistrement DNS est supprimé. "
                    "Le tunnel, l'application Access et les profils CMA sont conservés."
                )
            ).format(tunnel=tunnel.name),
            tr("Retirer"),
        ):
            return

        def done(_result: object) -> None:
            self.ctx.notify("success", tr("{host} retiré.").format(host=rule.hostname + rule.path))
            self.refresh()

        self.ctx.run(self.admin.unpublish(tunnel, rule.hostname, rule.path), done, self._error)

    # --- Ménage -----------------------------------------------------------------------------------------------

    def rename_tunnel(self, tunnel: Tunnel) -> None:
        existing = [v.tunnel.name for v in self.overview.tunnels] if self.overview else []
        name = ask_tunnel_name(self, existing, tunnel.name)
        if not name:
            return
        self.status.setText(tr("Renommage du tunnel…"))

        def done(renamed: Tunnel) -> None:
            self.ctx.notify("success", tr("Tunnel renommé : {name}.").format(name=renamed.name))
            self.refresh()

        self.ctx.run(self.admin.rename_tunnel(tunnel, name), done, self._error)

    def delete_tunnel(self, tunnel: Tunnel) -> None:
        view = (
            next((v for v in self.overview.tunnels if v.tunnel.id == tunnel.id), None)
            if self.overview
            else None
        )
        hostnames = [r.hostname for r in view.hostnames] if view else []
        text = tr(
            "Le tunnel doit être arrêté sur son serveur (aucun connecteur actif). Ses {n} nom(s) d'hôte publié(s) "
            "cessent de répondre et leurs enregistrements DNS qui le visent sont supprimés. Les applications Access "
            "et les profils CMA ne sont pas touchés."
        ).format(n=len(hostnames))
        if not confirm(
            self, tr("Supprimer le tunnel « {name} » ?").format(name=tunnel.name), text, tr("Supprimer")
        ):
            return
        self.status.setText(tr("Suppression du tunnel…"))

        def done(removed: int) -> None:
            self.ctx.notify(
                "success",
                tr("Tunnel « {name} » supprimé, {n} enregistrement(s) DNS retiré(s).").format(
                    name=tunnel.name, n=removed
                ),
            )
            self.refresh()

        self.ctx.run(self.admin.delete_tunnel(tunnel, hostnames), done, self._error)
