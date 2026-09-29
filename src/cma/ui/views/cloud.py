"""Compte Cloudflare : le côté serveur (tunnels, noms d'hôte publiés, applications Access, service tokens).

Tout passe par l'API Cloudflare avec un jeton d'API gardé dans le coffre. Les actions typiques :
importer les noms d'hôte d'un tunnel comme profils, publier un nouveau service protégé par Access,
créer un service token directement rangé dans le coffre de CMA.
"""

from __future__ import annotations

from PySide6.QtCore import QUrl
from PySide6.QtGui import QBrush, QColor, QDesktopServices, QShowEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLineEdit,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.cfadmin import CloudflareAdmin, Overview, PublishRequest, PublishResult
from cma.core.cfapi import TOKENS_PAGE, AccessApp, Account, IngressRule, Tunnel
from cma.core.models import CloudflareProfile, ServiceToken
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.theme import current_tokens
from cma.ui.views.common import confirm
from cma.ui.widgets import SecretField, button, label, primary_button, title

PERMISSIONS = (
    "Compte › Cloudflare Tunnel : Modifier",
    "Compte › Access: Apps and Policies : Modifier",
    "Compte › Access: Service Tokens : Modifier",
    "Zone › DNS : Modifier",
    "Zone › Zone : Lire",
)
TUNNEL_ROLE = 256
RULE_ROLE = 257


def tunnel_status_label(status: str) -> str:
    """État d'un tunnel tel que l'API le donne, traduit pour l'affichage."""
    return {
        "healthy": tr("en ligne"),
        "degraded": tr("dégradé"),
        "down": tr("hors ligne"),
        "inactive": tr("inactif"),
    }.get(status, status)


def _card() -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName("Card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(8)
    return frame, layout


def _table(headers: list[str], name: str) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setAccessibleName(name)
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().hide()
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    table.horizontalHeader().setStretchLastSection(True)
    return table


class PublishDialog(QDialog):
    """Publier un service : nom d'hôte → service du réseau privé, via un tunnel, protégé par Access."""

    def __init__(self, parent: QWidget | None, overview: Overview, tokens: list[ServiceToken]) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Publier un service"))
        self.setMinimumWidth(520)
        self.overview = overview
        layout = QVBoxLayout(self)
        layout.addWidget(
            label(
                tr(
                    "Cloudflare ajoute la règle au tunnel et crée l'enregistrement DNS. Le service doit être "
                    "joignable depuis la machine où tourne le tunnel."
                ),
                "muted",
                wrap=True,
            )
        )
        form = QFormLayout()
        self.tunnel = QComboBox()
        for view in overview.tunnels:
            self.tunnel.addItem(
                f"{view.tunnel.name} ({tunnel_status_label(view.tunnel.status)})", view.tunnel
            )
        form.addRow(tr("Tunnel :"), self.tunnel)
        self.hostname = QLineEdit()
        self.hostname.setPlaceholderText(tr("app.exemple.fr"))
        form.addRow(tr("Nom d'hôte :"), self.hostname)
        zones = ", ".join(z.name for z in overview.zones) or tr("aucune")
        form.addRow("", label(tr("Domaines du compte : {zones}").format(zones=zones), "muted", wrap=True))
        self.service = QLineEdit()
        self.service.setPlaceholderText(tr("tcp://localhost:22, rdp://10.0.0.5:3389, http://localhost:8080"))
        form.addRow(tr("Service :"), self.service)
        self.protect = QCheckBox(tr("Protéger par Cloudflare Access (application créée si besoin)"))
        self.protect.setChecked(True)
        form.addRow("", self.protect)
        self.token = QComboBox()
        self.token.addItem(tr("— aucun (connexion par navigateur) —"), None)
        for token in tokens:
            self.token.addItem(token.name, token.id)
        form.addRow(tr("Service token autorisé :"), self.token)
        self.create_profile = QCheckBox(tr("Créer le profil CMA correspondant"))
        self.create_profile.setChecked(True)
        form.addRow("", self.create_profile)
        layout.addLayout(form)
        self.error = label("", "error", wrap=True)
        self.error.hide()
        layout.addWidget(self.error)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.protect.toggled.connect(self.token.setEnabled)

    def request(self) -> PublishRequest | None:
        tunnel = self.tunnel.currentData()
        hostname = self.hostname.text().strip().lower()
        service = self.service.text().strip()
        if not isinstance(tunnel, Tunnel):
            return self._fail(
                tr("Ce compte n'a aucun tunnel : créez-en un dans le tableau de bord Cloudflare.")
            )
        if "." not in hostname or " " in hostname:
            return self._fail(tr("Nom d'hôte invalide : utilisez un nom comme app.exemple.fr"))
        if "://" not in service and not service.startswith("http_status:"):
            return self._fail(tr("Service invalide : indiquez un schéma, par exemple tcp://localhost:22"))
        return PublishRequest(
            tunnel=tunnel,
            hostname=hostname,
            service=service,
            protect=self.protect.isChecked(),
            token_id=self.token.currentData() if self.protect.isChecked() else None,
            create_profile=self.create_profile.isChecked(),
        )

    def _fail(self, message: str) -> None:
        self.error.setText(message)
        self.error.show()
        return

    def _accept(self) -> None:
        if self.request() is not None:
            self.accept()


class CloudView(QWidget):
    def __init__(self, ctx: GuiContext, open_profile: object = None) -> None:
        super().__init__()
        self.ctx = ctx
        self.open_profile = open_profile
        self.overview: Overview | None = None
        self._auto_done = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 16)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Compte Cloudflare")))
        layout.addWidget(
            label(
                tr(
                    "Gérez le côté serveur par l'API Cloudflare : tunnels et noms d'hôte publiés, applications "
                    "Access, service tokens. Les noms d'hôte d'un tunnel deviennent des profils en un clic."
                ),
                "muted",
                wrap=True,
            )
        )
        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_login())
        self.stack.addWidget(self._build_account())
        layout.addWidget(self.stack, 1)
        self._show_state()

    # --- Construction -------------------------------------------------------------------------------

    def _build_login(self) -> QWidget:
        card, box = _card()
        box.addWidget(title(tr("Connexion à l'API"), "SectionTitle"))
        form = QFormLayout()
        self.token_field = SecretField(tr("jeton d'API Cloudflare"))
        form.addRow(tr("Jeton d'API :"), self.token_field)
        box.addLayout(form)
        box.addWidget(
            label(
                tr("Créez un jeton personnalisé avec ces permissions :") + "\n• " + "\n• ".join(PERMISSIONS),
                "muted",
                wrap=True,
                selectable=True,
            )
        )
        box.addWidget(
            label(
                tr(
                    "Le jeton est vérifié puis rangé dans le coffre du système. Il n'est jamais écrit dans un fichier."
                ),
                "muted",
                wrap=True,
            )
        )
        row = QHBoxLayout()
        self.connect_button = primary_button(tr("Se connecter"), "plug-connected")
        self.connect_button.clicked.connect(self.connect_account)
        create = button(tr("Créer un jeton d'API"), "external-link")
        create.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(TOKENS_PAGE)))
        row.addWidget(self.connect_button)
        row.addWidget(create)
        row.addStretch()
        box.addLayout(row)
        host = QWidget()
        outer = QVBoxLayout(host)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(card)
        outer.addStretch()
        return host

    def _build_account(self) -> QWidget:
        host = QWidget()
        outer = QVBoxLayout(host)
        outer.setContentsMargins(0, 0, 0, 0)
        bar = QHBoxLayout()
        bar.addWidget(label(tr("Compte :")))
        self.account = QComboBox()
        self.account.setAccessibleName(tr("Compte Cloudflare"))
        self.account.setMinimumWidth(260)
        self.account.activated.connect(self._account_chosen)
        bar.addWidget(self.account)
        self.refresh_button = button(tr("Actualiser"), "refresh")
        self.refresh_button.clicked.connect(self.refresh)
        bar.addWidget(self.refresh_button)
        bar.addStretch()
        self.status = label("", "muted")
        bar.addWidget(self.status)
        forget = button(tr("Oublier le jeton"), "key-off")
        forget.clicked.connect(self.forget)
        bar.addWidget(forget)
        outer.addLayout(bar)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_tunnels(), tr("Tunnels"))
        self.tabs.addTab(self._build_apps(), tr("Applications Access"))
        self.tabs.addTab(self._build_tokens(), tr("Service tokens"))
        outer.addWidget(self.tabs, 1)
        return host

    def _build_tunnels(self) -> QWidget:
        page = QWidget()
        box = QVBoxLayout(page)
        row = QHBoxLayout()
        publish = primary_button(tr("Publier un service…"), "world-www")
        publish.clicked.connect(self.publish)
        self.import_button = button(tr("Importer comme profils"), "file-import")
        self.import_button.setToolTip(
            tr("Crée un profil CMA par nom d'hôte sélectionné (ou pour tout le tunnel, ou tout le compte)")
        )
        self.import_button.clicked.connect(self.import_selected)
        self.unpublish_button = button(tr("Retirer"), "trash")
        self.unpublish_button.clicked.connect(self.unpublish_selected)
        for widget in (publish, self.import_button, self.unpublish_button):
            row.addWidget(widget)
        row.addStretch()
        box.addLayout(row)
        self.tree = QTreeWidget()
        self.tree.setAccessibleName(tr("Tunnels et noms d'hôte publiés"))
        self.tree.setHeaderLabels([tr("Tunnel ou nom d'hôte"), tr("Service"), tr("État")])
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        box.addWidget(self.tree, 1)
        return page

    def _build_apps(self) -> QWidget:
        page = QWidget()
        box = QVBoxLayout(page)
        row = QHBoxLayout()
        protect = button(tr("Protéger un nom d'hôte…"), "shield-check")
        protect.clicked.connect(self.protect_hostname)
        allow = button(tr("Autoriser un service token…"), "key")
        allow.clicked.connect(self.allow_token)
        row.addWidget(protect)
        row.addWidget(allow)
        row.addStretch()
        box.addLayout(row)
        self.apps = _table([tr("Nom"), tr("Domaine"), tr("Type")], tr("Applications Access"))
        box.addWidget(self.apps, 1)
        return page

    def _build_tokens(self) -> QWidget:
        page = QWidget()
        box = QVBoxLayout(page)
        row = QHBoxLayout()
        create = primary_button(tr("Créer un service token…"), "plus")
        create.clicked.connect(self.create_token)
        row.addWidget(create)
        row.addWidget(
            label(tr("Le secret part directement dans le coffre de CMA : il n'est jamais affiché."), "muted")
        )
        row.addStretch()
        box.addLayout(row)
        self.remote_tokens = _table(
            [tr("Nom"), tr("ID client"), tr("Expiration"), tr("Dans CMA")], tr("Service tokens du compte")
        )
        box.addWidget(self.remote_tokens, 1)
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
        self.connect_button.setEnabled(True)
        self.refresh_button.setEnabled(True)
        self.status.setText("")
        self.ctx.notify("error", str(error))

    # --- Connexion ---------------------------------------------------------------------------------------

    def connect_account(self, use_saved: bool = False) -> None:
        token = None if use_saved else self.token_field.text().strip()
        if token == "":
            self.ctx.notify("error", tr("Collez d'abord un jeton d'API Cloudflare."))
            return
        self.connect_button.setEnabled(False)
        self.status.setText(tr("Connexion…"))

        def done(accounts: list[Account]) -> None:
            self.connect_button.setEnabled(True)
            self.token_field.set_text("")
            self._show_state()
            current = self.ctx.config().settings.cloudflare_account_id
            self.account.clear()
            for account in accounts:
                self.account.addItem(account.name, account)
                if account.id == current:
                    self.account.setCurrentIndex(self.account.count() - 1)
            self.refresh()

        self.ctx.run(self.admin.connect(token), done, self._error)

    def forget(self) -> None:
        if not confirm(self, tr("Oublier le jeton"), tr("Retirer le jeton d'API Cloudflare du coffre ?")):
            return
        self.admin.forget()
        self.overview = None
        self.account.clear()
        self._fill(None)
        self._show_state()

    def _account_chosen(self, _index: int) -> None:
        account = self.account.currentData()
        if isinstance(account, Account):
            self.admin.select_account(account.id)
            self.refresh()

    def refresh(self) -> None:
        account = self.account.currentData()
        if not isinstance(account, Account):
            return
        self.refresh_button.setEnabled(False)
        self.status.setText(tr("Chargement…"))

        def done(overview: Overview) -> None:
            self.refresh_button.setEnabled(True)
            self._fill(overview)

        self.ctx.run(self.admin.overview(account), done, self._error)

    def _fill(self, overview: Overview | None) -> None:
        self.overview = overview
        self.tree.clear()
        self.apps.setRowCount(0)
        self.remote_tokens.setRowCount(0)
        if overview is None:
            self.status.setText("")
            return
        tokens = current_tokens()
        for view in overview.tunnels:
            parent = QTreeWidgetItem([view.tunnel.name, "", tunnel_status_label(view.tunnel.status)])
            parent.setToolTip(2, view.tunnel.status)
            parent.setData(0, TUNNEL_ROLE, view.tunnel)
            healthy = view.tunnel.status == "healthy"
            parent.setForeground(2, QBrush(QColor(tokens.success if healthy else tokens.warning)))
            for rule in view.hostnames:
                child = QTreeWidgetItem([rule.hostname, rule.service, ""])
                child.setData(0, TUNNEL_ROLE, view.tunnel)
                child.setData(0, RULE_ROLE, rule)
                parent.addChild(child)
            self.tree.addTopLevelItem(parent)
            parent.setExpanded(True)
        for app in overview.apps:
            row = self.apps.rowCount()
            self.apps.insertRow(row)
            for column, value in enumerate((app.name, app.domain, app.type)):
                item = QTableWidgetItem(value)
                item.setData(TUNNEL_ROLE, app)
                self.apps.setItem(row, column, item)
        local = {t.client_id for t in self.ctx.config().tokens}
        for token in overview.tokens:
            row = self.remote_tokens.rowCount()
            self.remote_tokens.insertRow(row)
            values = (
                token.name,
                token.client_id,
                token.expires_at[:10],
                tr("oui") if token.client_id in local else "",
            )
            for column, value in enumerate(values):
                self.remote_tokens.setItem(row, column, QTableWidgetItem(value))
        hostnames = sum(len(v.hostnames) for v in overview.tunnels)
        self.status.setText(
            tr("{t} tunnel(s), {h} nom(s) d'hôte, {a} application(s)").format(
                t=len(overview.tunnels), h=hostnames, a=len(overview.apps)
            )
        )

    # --- Tunnels -----------------------------------------------------------------------------------------

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
        if created:
            self.ctx.notify(
                "success",
                tr("{n} profil(s) créé(s) : {names}.").format(
                    n=len(created), names=", ".join(p.name for p in created)
                ),
            )
        else:
            self.ctx.notify("info", tr("Ces noms d'hôte ont déjà un profil dans CMA."))

    def ask_publish(self) -> PublishRequest | None:
        if self.overview is None:
            return None
        dialog = PublishDialog(self, self.overview, self.ctx.config().tokens)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        return dialog.request()

    def publish(self) -> None:
        request = self.ask_publish()
        if request is None:
            return

        def done(result: PublishResult) -> None:
            text = tr("{host} publié sur le tunnel {tunnel}.").format(
                host=result.rule.hostname, tunnel=request.tunnel.name
            )
            if result.app is not None:
                text += " " + tr("Protégé par Access.")
            if result.profile is not None:
                text += " " + tr("Profil « {name} » créé.").format(name=result.profile.name)
            self.ctx.notify("success", text)
            self.refresh()

        self.ctx.run(self.admin.publish(request), done, self._error)

    def unpublish_selected(self) -> None:
        rules = self.selected_rules() if self.tree.selectedItems() else []
        if len(rules) != 1:
            self.ctx.notify("info", tr("Sélectionnez un seul nom d'hôte à retirer."))
            return
        tunnel, rule = rules[0]
        if not confirm(
            self,
            tr("Retirer le nom d'hôte"),
            tr("Retirer {host} du tunnel {tunnel} et supprimer son enregistrement DNS ?").format(
                host=rule.hostname, tunnel=tunnel.name
            ),
        ):
            return

        def done(_result: object) -> None:
            self.ctx.notify("success", tr("{host} retiré.").format(host=rule.hostname))
            self.refresh()

        self.ctx.run(self.admin.unpublish(tunnel, rule.hostname), done, self._error)

    # --- Access et service tokens ------------------------------------------------------------------------------

    def _selected_app(self) -> AccessApp | None:
        row = self.apps.currentRow()
        item = self.apps.item(row, 0) if row >= 0 else None
        app = item.data(TUNNEL_ROLE) if item is not None else None
        return app if isinstance(app, AccessApp) else None

    def protect_hostname(self) -> None:
        hostname, ok = QInputDialog.getText(
            self, tr("Protéger un nom d'hôte"), tr("Nom d'hôte à protéger par Cloudflare Access :")
        )
        hostname = hostname.strip().lower()
        if not ok or not hostname:
            return

        def done(app: AccessApp) -> None:
            self.ctx.notify("success", tr("Application Access « {name} » prête.").format(name=app.name))
            self.refresh()

        self.ctx.run(self.admin.protect_hostname(hostname), done, self._error)

    def allow_token(self) -> None:
        app = self._selected_app()
        if app is None:
            self.ctx.notify("info", tr("Sélectionnez d'abord une application Access."))
            return
        tokens = self.ctx.config().tokens
        if not tokens:
            self.ctx.notify(
                "info", tr("Aucun service token dans CMA : créez-en un dans l'onglet Service tokens.")
            )
            return
        name, ok = QInputDialog.getItem(
            self,
            tr("Autoriser un service token"),
            tr("Service token autorisé sur {app} :").format(app=app.domain),
            [t.name for t in tokens],
            0,
            False,
        )
        token = next((t for t in tokens if t.name == name), None)
        if not ok or token is None:
            return
        self.ctx.run(
            self.admin.allow_token(app, token.id),
            lambda _policy: self.ctx.notify(
                "success",
                tr("« {token} » peut maintenant joindre {app}.").format(token=token.name, app=app.domain),
            ),
            self._error,
        )

    def create_token(self) -> None:
        name, ok = QInputDialog.getText(self, tr("Créer un service token"), tr("Nom du service token :"))
        name = name.strip()
        if not ok or not name:
            return

        def done(token: ServiceToken) -> None:
            self.ctx.notify(
                "success",
                tr("Service token « {name} » créé et rangé dans le coffre.").format(name=token.name),
            )
            self.refresh()

        self.ctx.run(self.admin.create_service_token(name), done, self._error)
