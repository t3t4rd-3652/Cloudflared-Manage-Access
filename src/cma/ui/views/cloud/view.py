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
    Qt,
    QUrl,
    Signal,
)
from PySide6.QtGui import (
    QBrush,
    QColor,
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
    QTableWidgetItem,
    QTabWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.cfadmin import CloudflareAdmin, Overview, PublishRequest, PublishResult
from cma.core.cfapi import (
    TOKENS_PAGE,
    AccessApp,
    Account,
    CloudflareApiError,
    Connector,
    IngressRule,
    RemoteServiceToken,
    Tunnel,
)
from cma.core.models import CloudflareProfile, ServiceToken
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.format import last_read
from cma.ui.icons import set_glyph, token_icon
from cma.ui.state import remember_header
from cma.ui.theme import current_tokens, mono_font, status_colors
from cma.ui.views.cloud.cards import (
    PROFILE_ROLE,
    PROTECTED_ROLE,
    RULE_ROLE,
    TOKEN_ROLE,
    TUNNEL_ROLE,
    StatTile,
    TunnelTree,
    service_icon,
)
from cma.ui.views.cloud.connectors import show_connectors
from cma.ui.views.cloud.dialogs import (
    PublishDialog,
    ask_allow,
    ask_create_token,
    ask_protect,
    publish_summary,
)
from cma.ui.views.cloud.helpers import (
    app_type_label,
    data_table,
    describe_api_error,
    expiry_label,
    expiry_status,
    plural,
    tunnel_state,
)
from cma.ui.views.common import confirm
from cma.ui.widgets import (
    EmptyState,
    SecretField,
    add_shortcut,
    button,
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
        self.tabs.addTab(self._build_apps(), token_icon("shield-check"), tr("Applications Access"))
        self.tabs.addTab(self._build_tokens(), token_icon("key"), tr("Service tokens"))
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
        self.tunnels_empty = EmptyState(
            "cloud",
            tr("Aucun tunnel disponible dans ce compte."),
            tr("Créez le connecteur côté serveur dans Cloudflare."),
            [refresh],
        )
        self.tunnels_stack = QStackedWidget()
        self.tunnels_stack.addWidget(self.tree)
        self.tunnels_stack.addWidget(self.tunnels_empty)
        box.addWidget(self.tunnels_stack, 1)
        return page

    def _build_apps(self) -> QWidget:
        page = QWidget()
        box = QVBoxLayout(page)
        box.setContentsMargins(0, 12, 0, 0)
        box.setSpacing(8)
        row = QHBoxLayout()
        protect = primary_button(tr("Protéger un nom d'hôte…"), "shield-check")
        protect.clicked.connect(self.protect_hostname)
        self.allow_button = button(tr("Autoriser un service token…"), "key")
        self.allow_button.clicked.connect(self.allow_token)
        row.addWidget(protect)
        row.addWidget(self.allow_button)
        row.addStretch()
        box.addLayout(row)
        self.apps_hint = label(tr("Sélectionnez une application pour y autoriser un service token."), "muted")
        box.addWidget(self.apps_hint)
        self.apps = data_table([tr("Nom"), tr("Domaine"), tr("Type")], tr("Applications Access"))
        self.apps.horizontalHeader().resizeSection(0, 220)
        self.apps.horizontalHeader().resizeSection(1, 280)
        remember_header(self.apps.horizontalHeader(), "cloud-apps")
        self.apps.itemSelectionChanged.connect(self._update_app_actions)
        protect_empty = primary_button(tr("Protéger un nom d'hôte…"), "shield-check")
        protect_empty.clicked.connect(self.protect_hostname)
        self.apps_empty = EmptyState(
            "shield-check",
            tr("Aucune application Access."),
            tr("Une application Access protège un nom d'hôte publié."),
            [protect_empty],
        )
        self.apps_stack = QStackedWidget()
        self.apps_stack.addWidget(self.apps)
        self.apps_stack.addWidget(self.apps_empty)
        box.addWidget(self.apps_stack, 1)
        return page

    def _build_tokens(self) -> QWidget:
        page = QWidget()
        box = QVBoxLayout(page)
        box.setContentsMargins(0, 12, 0, 0)
        box.setSpacing(8)
        row = QHBoxLayout()
        create = primary_button(tr("Créer un service token…"), "plus")
        create.clicked.connect(self.create_token)
        row.addWidget(create)
        self.extend_button = button(
            tr("Prolonger"), "hourglass", tooltip=tr("Repousser l'échéance, sans changer le secret")
        )
        self.extend_button.clicked.connect(self.extend_selected_token)
        row.addWidget(self.extend_button)
        self.rotate_button = button(tr("Changer le secret…"), "rotate-clockwise")
        self.rotate_button.clicked.connect(self.rotate_selected_token)
        row.addWidget(self.rotate_button)
        row.addStretch()
        box.addLayout(row)
        box.addWidget(
            label(
                tr(
                    "Service tokens du compte Cloudflare. « Dans CMA » indique si le token est aussi "
                    "enregistré sur ce poste, avec son secret. Seul un token enregistré dans CMA peut changer "
                    "de secret : le nouveau part directement dans le coffre."
                ),
                "muted",
                wrap=True,
            )
        )
        self.remote_tokens = data_table(
            [tr("Nom"), tr("ID client"), tr("Expiration"), tr("Dans CMA")], tr("Service tokens du compte")
        )
        header = self.remote_tokens.horizontalHeader()
        for column, width in enumerate((200, 280, 120)):
            header.resizeSection(column, width)
        remember_header(header, "cloud-tokens")
        self.remote_tokens.itemSelectionChanged.connect(self._update_token_actions)
        create_empty = primary_button(tr("Créer un service token…"), "plus")
        create_empty.clicked.connect(self.create_token)
        self.tokens_empty = EmptyState(
            "key",
            tr("Aucun service token dans ce compte."),
            tr("Le secret d'un token créé ici part directement dans le coffre de CMA."),
            [create_empty],
        )
        self.tokens_stack = QStackedWidget()
        self.tokens_stack.addWidget(self.remote_tokens)
        self.tokens_stack.addWidget(self.tokens_empty)
        box.addWidget(self.tokens_stack, 1)
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
        if not isinstance(account, Account) or self._loading:
            return
        self._loading = True
        self.refresh_button.setEnabled(False)
        self.status.setText(tr("Lecture du compte…"))

        def done(overview: Overview) -> None:
            self._loading = False
            self.refresh_button.setEnabled(True)
            self.tabs.setEnabled(True)
            self.read_at = datetime.now()
            self._fill(overview)

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
        hostnames = sum(len(v.hostnames) for v in overview.tunnels)
        self.status.setText(
            " · ".join(
                (
                    plural(len(overview.tunnels), tr("{n} tunnel"), tr("{n} tunnels")),
                    plural(hostnames, tr("{n} nom d'hôte"), tr("{n} noms d'hôte")),
                    plural(len(overview.apps), tr("{n} application"), tr("{n} applications")),
                )
            )
        )
        self.read_label.setText(last_read(self.read_at))
        healthy = sum(1 for v in overview.tunnels if v.tunnel.status == "healthy")
        troubled = len(overview.tunnels) - healthy
        if not overview.tunnels:
            self.stat_tunnels.set_values(0)
        elif troubled:
            self.stat_tunnels.set_values(
                len(overview.tunnels), tr("{n} à vérifier").format(n=troubled), "warning"
            )
        else:
            self.stat_tunnels.set_values(len(overview.tunnels), tr("tous en ligne"), "success")
        self.stat_hostnames.set_values(
            hostnames, plural(len(overview.zones), tr("{n} domaine"), tr("{n} domaines"))
        )
        protected = {a.domain.split("/")[0] for a in overview.apps}
        published = {r.hostname for v in overview.tunnels for r in v.hostnames}
        unprotected = len(published - protected)
        self.stat_apps.set_values(
            len(overview.apps),
            tr("{n} sans protection").format(n=unprotected) if unprotected else "",
            "warning" if unprotected else None,
        )
        local = {t.client_id for t in self.ctx.config().tokens}
        in_cma = sum(1 for t in overview.tokens if t.client_id in local)
        self.stat_tokens.set_values(
            len(overview.tokens), tr("{n} dans CMA").format(n=in_cma) if overview.tokens else ""
        )

    def _fill(self, overview: Overview | None) -> None:
        self.overview = overview
        self.tree.clear()
        self.apps.setRowCount(0)
        self.remote_tokens.setRowCount(0)
        self._show_summary()
        if overview is None:
            self._update_tunnel_actions()
            self._update_app_actions()
            return
        tokens = current_tokens()
        mono = mono_font(9.5)
        protected = {a.domain.split("/")[0].lower() for a in overview.apps}
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
            parent.setToolTip(0, tr("Tunnel {name} ({id})").format(name=view.tunnel.name, id=view.tunnel.id))
            parent.setData(0, TUNNEL_ROLE, view.tunnel)
            parent.setData(0, Qt.ItemDataRole.AccessibleTextRole, f"{view.tunnel.name}, {text}, {summary}")
            for rule in view.hostnames:
                child = QTreeWidgetItem([rule.hostname, rule.service, "—"])
                child.setIcon(0, token_icon(service_icon(rule.service), "muted"))
                child.setFont(1, mono)
                is_protected = rule.hostname.lower() in protected
                in_cma = rule.hostname.lower() in imported
                notes = [tr("protégé par Access") if is_protected else tr("non protégé")]
                if in_cma:
                    notes.append(tr("profil présent dans CMA"))
                child.setToolTip(0, f"{rule.hostname}{rule.path}  →  {rule.service}")
                child.setToolTip(1, rule.service)
                child.setData(0, TUNNEL_ROLE, view.tunnel)
                child.setData(0, RULE_ROLE, rule)
                child.setData(0, PROTECTED_ROLE, is_protected)
                child.setData(0, PROFILE_ROLE, in_cma)
                child.setData(
                    0,
                    Qt.ItemDataRole.AccessibleTextRole,
                    ", ".join([rule.hostname, rule.service, *notes]),
                )
                parent.addChild(child)
            self.tree.addTopLevelItem(parent)
            parent.setExpanded(True)
        self.tunnels_stack.setCurrentWidget(self.tree if overview.tunnels else self.tunnels_empty)
        for app in sorted(overview.apps, key=lambda a: a.name.lower()):
            row = self.apps.rowCount()
            self.apps.insertRow(row)
            for column, value in enumerate((app.name, app.domain, app_type_label(app.type))):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                item.setData(TUNNEL_ROLE, app)
                if column == 0:
                    item.setIcon(token_icon("shield-check", "accent"))
                elif column == 1:
                    item.setFont(mono)
                else:
                    item.setForeground(QBrush(QColor(tokens.muted)))
                self.apps.setItem(row, column, item)
        self.apps_stack.setCurrentWidget(self.apps if overview.apps else self.apps_empty)
        local = {t.client_id: t for t in self.ctx.config().tokens}
        for token in sorted(overview.tokens, key=lambda t: t.name.lower()):
            row = self.remote_tokens.rowCount()
            self.remote_tokens.insertRow(row)
            mine = local.get(token.client_id)
            if mine is None:
                in_cma, in_tone = tr("Non"), "neutral"
            elif self.ctx.core.secrets.get(mine.secret_key):
                in_cma, in_tone = tr("Oui"), "success"
            else:
                in_cma, in_tone = tr("Secret indisponible"), "warning"
            expiry_tone = expiry_status(token.expires_at)
            values = (token.name, token.client_id, expiry_label(token.expires_at), in_cma)
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 0:
                    item.setIcon(token_icon("key", "accent"))
                    item.setData(TOKEN_ROLE, token)
                elif column == 1:
                    item.setFont(mono)
                elif column == 2 and expiry_tone:
                    item.setForeground(QBrush(QColor(status_colors(expiry_tone, tokens)[0])))
                elif column == 3:
                    item.setForeground(QBrush(QColor(status_colors(in_tone, tokens)[0])))
                self.remote_tokens.setItem(row, column, item)
        self.tokens_stack.setCurrentWidget(self.remote_tokens if overview.tokens else self.tokens_empty)
        self._update_tunnel_actions()
        self._update_app_actions()
        self._update_token_actions()

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
        rule = item.data(0, RULE_ROLE)
        tunnel = item.data(0, TUNNEL_ROLE)
        menu = QMenu(self)
        if isinstance(rule, IngressRule):
            menu.addAction(tr("Importer comme profil"), self.import_selected)
            menu.addAction(tr("Copier le nom d'hôte"), lambda: copy_to_clipboard(rule.hostname))
            if rule.service.lower().startswith(("http://", "https://")):
                menu.addAction(
                    tr("Ouvrir dans le navigateur"),
                    lambda: QDesktopServices.openUrl(QUrl(f"https://{rule.hostname}{rule.path}")),
                )
            menu.addSeparator()
            menu.addAction(tr("Retirer ce nom d'hôte…"), self.unpublish_selected)
        elif isinstance(tunnel, Tunnel):
            menu.addAction(tr("Importer ses noms d'hôte"), self.import_selected)
            publish = menu.addAction(tr("Publier un service sur ce tunnel…"), lambda: self.publish(tunnel))
            publish.setEnabled(self.publish_button.isEnabled())
            menu.addAction(tr("État des connecteurs…"), lambda: self.check_connectors(tunnel))
        menu.exec(self.tree.viewport().mapToGlobal(pos))
        menu.deleteLater()

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
        if not confirm(
            self,
            tr("Retirer {host} ?").format(host=rule.hostname),
            tr(
                "La règle est retirée du tunnel {tunnel} et l'enregistrement DNS est supprimé. "
                "Le tunnel, l'application Access et les profils CMA sont conservés."
            ).format(tunnel=tunnel.name),
            tr("Retirer"),
        ):
            return

        def done(_result: object) -> None:
            self.ctx.notify("success", tr("{host} retiré.").format(host=rule.hostname))
            self.refresh()

        self.ctx.run(self.admin.unpublish(tunnel, rule.hostname), done, self._error)

    # --- Access et service tokens ------------------------------------------------------------------------------

    def _selected_app(self) -> AccessApp | None:
        row = self.apps.currentRow()
        item = self.apps.item(row, 0) if row >= 0 and self.apps.selectedItems() else None
        app = item.data(TUNNEL_ROLE) if item is not None else None
        return app if isinstance(app, AccessApp) else None

    def _update_app_actions(self) -> None:
        has_app = self._selected_app() is not None
        self.allow_button.setEnabled(has_app)
        self.apps_hint.setVisible(not has_app and bool(self.overview and self.overview.apps))

    def protect_hostname(self) -> None:
        hostnames = []
        if self.overview is not None:
            protected = {a.domain.split("/")[0] for a in self.overview.apps}
            hostnames = [
                r.hostname for v in self.overview.tunnels for r in v.hostnames if r.hostname not in protected
            ]
        hostname = ask_protect(self, hostnames)
        hostname = (hostname or "").strip().lower()
        if not hostname:
            return
        self.status.setText(tr("Création de l'application Access…"))

        def done(_app: AccessApp) -> None:
            self.ctx.notify("success", tr("Application Access créée."))
            self.refresh()

        def failed(error: BaseException) -> None:
            self._error(
                RuntimeError(
                    tr("Impossible de créer la protection Access.") + " " + describe_api_error(error)
                )
            )

        self.ctx.run(self.admin.protect_hostname(hostname), done, failed)

    def allow_token(self) -> None:
        app = self._selected_app()
        if app is None:
            self.ctx.notify("info", tr("Sélectionnez d'abord une application Access."))
            return
        remote = {t.client_id for t in self.overview.tokens} if self.overview else set()
        tokens = [t for t in self.ctx.config().tokens if t.client_id in remote]
        token = ask_allow(self, app, tokens)
        if token is None:
            return
        self.status.setText(tr("Ajout de l'autorisation…"))

        def done(_policy: object) -> None:
            self._show_summary()
            self.ctx.notify(
                "success",
                tr("Service token autorisé : {token} sur {app}.").format(token=token.name, app=app.domain),
            )

        def failed(error: BaseException) -> None:
            self._error(
                RuntimeError(
                    tr("L'autorisation n'a pas pu être enregistrée.") + " " + describe_api_error(error)
                )
            )

        self.ctx.run(self.admin.allow_token(app, token.id), done, failed)

    def create_token(self) -> None:
        account = self.account.currentText() or "—"
        answer = ask_create_token(self, account, self.ctx.core.secrets.persistent)
        name, duration = answer if answer is not None else ("", "")
        name = name.strip()
        if not name:
            return
        self.status.setText(tr("Création du service token…"))

        def done(_token: ServiceToken) -> None:
            self.ctx.notify("success", tr("Service token créé et enregistré dans CMA."))
            self.refresh()

        def failed(error: BaseException) -> None:
            if isinstance(error, CloudflareApiError):
                self._error(error)
                return
            self._error(
                RuntimeError(
                    tr("Le token a été créé dans Cloudflare, mais son secret n'a pas pu être enregistré.")
                    + f" ({error})"
                )
            )
            self.refresh()

        self.ctx.run(self.admin.create_service_token(name, duration=duration), done, failed)

    # --- Échéance et secret des service tokens --------------------------------------------------------------

    def selected_remote_token(self) -> RemoteServiceToken | None:
        rows = self.remote_tokens.selectionModel().selectedRows()
        item = self.remote_tokens.item(rows[0].row(), 0) if rows else None
        token = item.data(TOKEN_ROLE) if item is not None else None
        return token if isinstance(token, RemoteServiceToken) else None

    def _local_token(self, remote: RemoteServiceToken | None) -> ServiceToken | None:
        if remote is None:
            return None
        return next((t for t in self.ctx.config().tokens if t.client_id == remote.client_id), None)

    def _update_token_actions(self) -> None:
        remote = self.selected_remote_token()
        self.extend_button.setEnabled(remote is not None)
        self.rotate_button.setEnabled(self._local_token(remote) is not None)

    def extend_selected_token(self) -> None:
        remote = self.selected_remote_token()
        if remote is None:
            return
        self.status.setText(tr("Prolongation du service token…"))

        def done(expires_at: str) -> None:
            self.ctx.notify(
                "success",
                tr("« {name} » expire désormais le {date}.").format(
                    name=remote.name, date=expiry_label(expires_at)
                ),
            )
            self.refresh()

        self.ctx.run(self.admin.extend_token(remote), done, self._error)

    def rotate_selected_token(self) -> None:
        local = self._local_token(self.selected_remote_token())
        if local is None:
            return
        users = [p.name for p in self.ctx.config().profiles_using_token(local.id)]
        text = tr(
            "Cloudflare crée un nouveau secret et révoque aussitôt l'ancien. Le nouveau secret est rangé dans le "
            "coffre de CMA ; l'ID client ne change pas."
        )
        if users:
            text += "\n\n" + tr("Les accès en cours qui l'utilisent sont à relancer : {names}.").format(
                names=", ".join(users)
            )
        if not confirm(
            self,
            tr("Changer le secret de « {name} » ?").format(name=local.name),
            text,
            tr("Changer le secret"),
        ):
            return
        self.status.setText(tr("Changement du secret…"))

        def done(token: ServiceToken) -> None:
            self.ctx.notify(
                "success", tr("Nouveau secret de « {name} » enregistré dans CMA.").format(name=token.name)
            )
            self.refresh()

        self.ctx.run(self.admin.rotate_token(local.id), done, self._error)
