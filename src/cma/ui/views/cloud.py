"""Administration Cloudflare : tunnels et noms d'hôte publiés, applications Access, service tokens (§4.6).

Tout passe par l'API Cloudflare avec un jeton d'API gardé dans le coffre. Les actions typiques :
importer les noms d'hôte d'un tunnel comme profils, publier un nouveau service protégé par Access,
créer un service token directement rangé dans le coffre de CMA (D14 à D17).
"""

from __future__ import annotations

import urllib.error
from collections.abc import Callable
from datetime import datetime

from PySide6.QtCore import QPoint, Qt, QUrl
from PySide6.QtGui import QBrush, QColor, QDesktopServices, QKeySequence, QShowEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QCompleter,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QMenu,
    QPushButton,
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
from cma.core.cfapi import TOKENS_PAGE, AccessApp, Account, CloudflareApiError, IngressRule, Tunnel
from cma.core.models import CloudflareProfile, ServiceToken
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.format import last_read
from cma.ui.icons import app_icon
from cma.ui.theme import current_tokens, status_colors
from cma.ui.views.common import confirm
from cma.ui.widgets import (
    EmptyState,
    SecretField,
    add_shortcut,
    button,
    copy_to_clipboard,
    label,
    primary_button,
    title,
)

PERMISSIONS = (
    "Compte › Cloudflare Tunnel : Modifier",
    "Compte › Access: Apps and Policies : Modifier",
    "Compte › Access: Service Tokens : Modifier",
    "Zone › DNS : Modifier",
    "Zone › Zone : Lire",
)
TUNNEL_ROLE = 256
RULE_ROLE = 257


def plural(n: int, one: str, many: str) -> str:
    return (one if n <= 1 else many).format(n=n)


def tunnel_state(status: str) -> tuple[str, str, str]:
    """(libellé, ton, symbole) de l'état d'un tunnel donné par l'API."""
    return {
        "healthy": (tr("En ligne"), "success", "✓"),
        "degraded": (tr("Dégradé"), "warning", "!"),
        "down": (tr("Hors ligne"), "danger", "×"),
        "inactive": (tr("Inactif"), "neutral", "■"),
    }.get(status, (status, "neutral", "■"))


def tunnel_status_label(status: str) -> str:
    return tunnel_state(status)[0]


def app_type_label(kind: str) -> str:
    known = {"self_hosted": "Self-hosted", "ssh": "SSH", "vnc": "VNC", "rdp": "RDP", "saas": "SaaS"}
    return known.get(kind, kind.replace("_", " ").capitalize())


def expiry_label(value: str) -> str:
    try:
        return datetime.fromisoformat(value[:10]).strftime("%d/%m/%Y")
    except ValueError:
        return value or "—"


def describe_api_error(error: BaseException) -> str:
    """Refus de l'API, réseau injoignable ou autre erreur : jamais tout confondre avec un 401 (§4.6)."""
    if isinstance(error, CloudflareApiError):
        if error.status in (401, 403):
            return tr("L'API a refusé la demande. Vérifiez le jeton et ses permissions.") + f" ({error})"
        if error.status is None and isinstance(error.__cause__, (urllib.error.URLError, OSError)):
            return tr("Impossible de joindre l'API Cloudflare.") + f" ({error})"
    return str(error)


def _dialog_buttons(dialog: QDialog, action: str) -> tuple[QDialogButtonBox, QPushButton]:
    buttons = QDialogButtonBox()
    buttons.addButton(tr("Annuler"), QDialogButtonBox.ButtonRole.RejectRole)
    ok = buttons.addButton(action, QDialogButtonBox.ButtonRole.AcceptRole)
    ok.setProperty("role", "primary")
    buttons.rejected.connect(dialog.reject)
    return buttons, ok


def _table(headers: list[str], name: str) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setAccessibleName(name)
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().hide()
    table.verticalHeader().setDefaultSectionSize(36)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    table.horizontalHeader().setStretchLastSection(True)
    return table


# --- D14 — Publier un service ------------------------------------------------------------------------------


class PublishDialog(QDialog):
    """Nom d'hôte → service du réseau privé, via un tunnel, protégé par Access (§4.22)."""

    def __init__(
        self,
        parent: QWidget | None,
        overview: Overview,
        tokens: list[ServiceToken],
        tunnel: Tunnel | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Publier un service"))
        self.setWindowIcon(app_icon())
        self.setMinimumWidth(560)
        self.resize(760, 560)
        self.overview = overview
        self.zone_names = sorted((z.name for z in overview.zones), key=lambda n: (-len(n), n))
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Publier un service"), "SectionTitle"))
        layout.addWidget(
            label(tr("Le service doit être joignable depuis le connecteur du tunnel."), "muted", wrap=True)
        )
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.tunnel = QComboBox()
        self.tunnel.setAccessibleName(tr("Tunnel"))
        for view in sorted(overview.tunnels, key=lambda v: v.tunnel.name.lower()):
            self.tunnel.addItem(
                f"{view.tunnel.name} — {tunnel_status_label(view.tunnel.status)}", view.tunnel
            )
            if tunnel is not None and view.tunnel.id == tunnel.id:
                self.tunnel.setCurrentIndex(self.tunnel.count() - 1)
        form.addRow(tr("Tunnel"), self.tunnel)
        host_row = QHBoxLayout()
        self.hostname = QLineEdit()
        self.hostname.setPlaceholderText("mongodb")
        self.hostname.setAccessibleName(tr("Nom d'hôte"))
        self.zone = QComboBox()
        self.zone.setAccessibleName(tr("Domaine"))
        for name in sorted(self.zone_names):
            self.zone.addItem(name, name)
        host_row.addWidget(self.hostname, 3)
        host_row.addWidget(label("."))
        host_row.addWidget(self.zone, 2)
        form.addRow(tr("Nom d'hôte · Domaine"), host_row)
        self.service = QLineEdit()
        self.service.setPlaceholderText("tcp://localhost:27017")
        self.service.setAccessibleName(tr("Service"))
        form.addRow(tr("Service"), self.service)
        form.addRow(
            label(
                tr("Exemples : tcp://localhost:22, rdp://10.0.0.5:3389, http://localhost:8080"),
                "muted",
                wrap=True,
            )
        )
        self.protect = QCheckBox(tr("Protéger par Cloudflare Access"))
        self.protect.setChecked(True)
        form.addRow(self.protect)
        self.token = QComboBox()
        self.token.setAccessibleName(tr("Service token autorisé"))
        self.token.addItem(tr("Aucun service token"), None)
        for token in sorted(tokens, key=lambda t: t.name.lower()):
            self.token.addItem(token.name, token.id)
        form.addRow(tr("Service token autorisé"), self.token)
        if not tokens:
            form.addRow(
                label(
                    tr(
                        "Créez un service token dans l'onglet Service tokens, puis revenez publier ce service."
                    ),
                    "muted",
                    wrap=True,
                )
            )
        self.create_profile = QCheckBox(tr("Créer le profil CMA correspondant"))
        self.create_profile.setChecked(True)
        form.addRow(self.create_profile)
        layout.addLayout(form)
        layout.addStretch()
        self.summary = label("", "mono", wrap=True, selectable=True)
        layout.addWidget(self.summary)
        self.error = label("", "error", wrap=True)
        self.error.hide()
        layout.addWidget(self.error)
        buttons, self.ok_button = _dialog_buttons(self, tr("Publier"))
        self.ok_button.setAutoDefault(False)
        self.ok_button.clicked.connect(self._accept)
        layout.addWidget(buttons)
        self.protect.toggled.connect(self.token.setEnabled)
        self.hostname.textEdited.connect(self._split_fqdn)
        for signal in (self.hostname.textChanged, self.service.textChanged):
            signal.connect(self._refresh)
        for combo in (self.tunnel, self.zone):
            combo.currentIndexChanged.connect(self._refresh)
        if not overview.tunnels or not overview.zones:
            self._fail(tr("Aucun tunnel ou domaine utilisable dans ce compte."))
        self._refresh()

    def _split_fqdn(self, text: str) -> None:
        """Nom complet collé : répartition seulement si le suffixe correspond à un domaine du compte."""
        value = text.strip().lower().rstrip(".")
        for zone in self.zone_names:  # le plus long d'abord : lab.exemple.fr avant exemple.fr
            if value.endswith("." + zone):
                self.zone.setCurrentIndex(self.zone.findData(zone))
                self.hostname.setText(value.removesuffix("." + zone))
                return

    def full_hostname(self) -> str:
        text = self.hostname.text().strip().lower().rstrip(".")
        if not text:
            return ""
        if any(text == zone or text.endswith("." + zone) for zone in self.zone_names):
            return text
        zone = self.zone.currentData()
        return f"{text}.{zone}" if zone else text

    def _refresh(self, *_args: object) -> None:
        tunnel = self.tunnel.currentData()
        host = self.full_hostname() or "?"
        service = self.service.text().strip() or "?"
        via = tunnel.name if isinstance(tunnel, Tunnel) else "?"
        self.summary.setText(
            tr("Résumé : {host} → {service} via {tunnel}").format(host=host, service=service, tunnel=via)
        )
        self.ok_button.setEnabled(
            isinstance(tunnel, Tunnel)
            and bool(self.hostname.text().strip())
            and bool(self.service.text().strip())
        )

    def request(self) -> PublishRequest | None:
        tunnel = self.tunnel.currentData()
        hostname = self.full_hostname()
        service = self.service.text().strip()
        if not isinstance(tunnel, Tunnel):
            return self._fail(tr("Aucun tunnel ou domaine utilisable dans ce compte."))
        if "." not in hostname or " " in hostname:
            return self._fail(tr("Nom d'hôte invalide : utilisez un nom comme app.exemple.fr"))
        if "://" not in service and not service.startswith("http_status:"):
            return self._fail(tr("Service invalide : indiquez un schéma, par exemple tcp://localhost:22"))
        self.error.hide()
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

    def _accept(self) -> None:
        if self.request() is not None:
            self.accept()


# --- D15 — Protéger un nom d'hôte ------------------------------------------------------------------------


class ProtectDialog(QDialog):
    """Application Access « self-hosted » pour un nom d'hôte ; aucune règle d'accès n'est ajoutée (§4.23)."""

    def __init__(self, parent: QWidget | None, hostnames: list[str]) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Protéger un nom d'hôte"))
        self.setWindowIcon(app_icon())
        self.resize(600, 340)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Protéger un nom d'hôte"), "SectionTitle"))
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.hostname = QLineEdit()
        self.hostname.setPlaceholderText("mongodb.exemple.fr")
        self.hostname.setAccessibleName(tr("Nom d'hôte"))
        completer = QCompleter(sorted(hostnames), self)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.hostname.setCompleter(completer)
        form.addRow(tr("Nom d'hôte"), self.hostname)
        layout.addLayout(form)
        layout.addWidget(
            label(
                tr(
                    "Une application Cloudflare Access sera créée pour ce nom d'hôte ; si elle existe déjà, "
                    "elle est réutilisée. Aucune règle d'accès n'est ajoutée : autorisez ensuite un service token."
                ),
                "muted",
                wrap=True,
            )
        )
        self.app_name = label("", wrap=True, selectable=True)
        layout.addWidget(self.app_name)
        layout.addStretch()
        buttons, self.ok_button = _dialog_buttons(self, tr("Protéger"))
        self.ok_button.clicked.connect(self.accept)
        layout.addWidget(buttons)
        self.hostname.textChanged.connect(self._refresh)
        self._refresh()

    def value(self) -> str:
        return self.hostname.text().strip().lower().rstrip(".")

    def _refresh(self, *_args: object) -> None:
        value = self.value()
        self.app_name.setText(tr("Nom de l'application : {name}").format(name=value or "—"))
        self.ok_button.setEnabled("." in value and " " not in value)


# --- D16 — Autoriser un service token --------------------------------------------------------------------


class AllowDialog(QDialog):
    """Autoriser un service token de CMA, présent dans le compte, sur une application Access (§4.24)."""

    def __init__(self, parent: QWidget | None, app: AccessApp, tokens: list[ServiceToken]) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Autoriser un service token"))
        self.setWindowIcon(app_icon())
        self.resize(640, 400)
        self.tokens = sorted(tokens, key=lambda t: t.name.lower())
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Autoriser un service token"), "SectionTitle"))
        layout.addWidget(label(tr("Application Access : {name}").format(name=app.name), selectable=True))
        layout.addWidget(label(tr("Domaine : {domain}").format(domain=app.domain), "mono", selectable=True))
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.token = QComboBox()
        self.token.setAccessibleName(tr("Service token"))
        for token in self.tokens:
            self.token.addItem(f"{token.name} · {token.client_id}", token.id)
        form.addRow(tr("Service token"), self.token)
        layout.addLayout(form)
        layout.addWidget(
            label(
                tr("Ce token pourra s'authentifier auprès de cette application.")
                if self.tokens
                else tr("Aucun service token disponible dans ce compte."),
                "muted",
                wrap=True,
            )
        )
        layout.addStretch()
        buttons, self.ok_button = _dialog_buttons(self, tr("Autoriser"))
        self.ok_button.setEnabled(bool(self.tokens))
        self.ok_button.clicked.connect(self.accept)
        layout.addWidget(buttons)

    def value(self) -> ServiceToken | None:
        token_id = self.token.currentData()
        return next((t for t in self.tokens if t.id == token_id), None)


# --- D17 — Créer un service token dans Cloudflare ----------------------------------------------------------


class CreateTokenDialog(QDialog):
    """Nom du token ; la durée est celle qu'utilise le moteur ; le secret n'est jamais affiché (§4.25)."""

    def __init__(self, parent: QWidget | None, account: str, persistent: bool) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Créer un service token"))
        self.setWindowIcon(app_icon())
        self.resize(640, 380)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Créer un service token"), "SectionTitle"))
        layout.addWidget(label(tr("Compte : {name}").format(name=account), selectable=True))
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.name = QLineEdit()
        self.name.setAccessibleName(tr("Nom"))
        self.name.setPlaceholderText("Production")
        form.addRow(tr("Nom"), self.name)
        form.addRow(tr("Durée de validité"), label(tr("1 an (8 760 h)")))
        layout.addLayout(form)
        layout.addWidget(
            label(
                tr("Le secret sera enregistré dans le coffre de CMA et ne sera pas affiché."),
                "muted",
                wrap=True,
            )
        )
        if not persistent:
            layout.addWidget(
                label(
                    tr("Coffre temporaire : le secret sera perdu à la fermeture de CMA."),
                    "warning",
                    wrap=True,
                )
            )
        layout.addStretch()
        buttons, self.ok_button = _dialog_buttons(self, tr("Créer"))
        self.ok_button.clicked.connect(self.accept)
        layout.addWidget(buttons)
        self.name.textChanged.connect(lambda text: self.ok_button.setEnabled(bool(text.strip())))
        self.ok_button.setEnabled(False)

    def value(self) -> str:
        return self.name.text().strip()


# Fonctions de module : les tests les remplacent pour ne pas ouvrir de boîte modale.


def ask_protect(parent: QWidget, hostnames: list[str]) -> str | None:
    dialog = ProtectDialog(parent, hostnames)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


def ask_allow(parent: QWidget, app: AccessApp, tokens: list[ServiceToken]) -> ServiceToken | None:
    dialog = AllowDialog(parent, app, tokens)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


def ask_create_token(parent: QWidget, account: str, persistent: bool) -> str | None:
    dialog = CreateTokenDialog(parent, account, persistent)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


# --- Vue ----------------------------------------------------------------------------------------------------


class CloudView(QWidget):
    def __init__(self, ctx: GuiContext, open_profile: Callable[[str], None] | None = None) -> None:
        super().__init__()
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
        card.setMaximumWidth(680)
        box = QVBoxLayout(card)
        box.setContentsMargins(24, 20, 24, 20)
        box.setSpacing(10)
        box.addWidget(title(tr("Connexion à l'API Cloudflare"), "SectionTitle"))
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.token_field = SecretField(tr("jeton d'API Cloudflare"), subject=tr("jeton d'API"))
        form.addRow(tr("Jeton d'API"), self.token_field)
        box.addLayout(form)
        box.addWidget(
            label(
                tr("Permissions nécessaires :") + "\n• " + "\n• ".join(PERMISSIONS),
                wrap=True,
                selectable=True,
            )
        )
        box.addWidget(
            label(tr("Limitez le jeton aux comptes et zones que vous souhaitez gérer."), "muted", wrap=True)
        )
        box.addWidget(label(tr("Secret conservé dans le coffre de cet ordinateur."), "muted", wrap=True))
        self.login_error = label("", "error", wrap=True)
        self.login_error.hide()
        box.addWidget(self.login_error)
        row = QHBoxLayout()
        create = button(tr("Créer un jeton d'API ↗"), link=True)
        create.setToolTip(TOKENS_PAGE)
        create.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(TOKENS_PAGE)))
        self.connect_button = primary_button(tr("Se connecter"), "plug-connected")
        self.connect_button.clicked.connect(lambda: self.connect_account())
        row.addWidget(create)
        row.addStretch()
        row.addWidget(self.connect_button)
        box.addLayout(row)
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
        outer.setSpacing(8)
        bar = QHBoxLayout()
        bar.addWidget(label(tr("Compte")))
        self.account = QComboBox()
        self.account.setAccessibleName(tr("Compte Cloudflare"))
        self.account.setMinimumWidth(240)
        self.account.activated.connect(self._account_chosen)
        bar.addWidget(self.account)
        self.refresh_button = button(tr("Actualiser"), "refresh", tooltip=tr("Relire le compte (F5)"))
        self.refresh_button.clicked.connect(self.refresh)
        bar.addWidget(self.refresh_button)
        bar.addStretch()
        forget = button(tr("Oublier le jeton…"), "key-off")
        forget.clicked.connect(self.forget)
        bar.addWidget(forget)
        outer.addLayout(bar)
        self.status = label("", "meta")
        outer.addWidget(self.status)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setProperty("role", "plain")
        self.tabs.addTab(self._build_tunnels(), tr("Tunnels"))
        self.tabs.addTab(self._build_apps(), tr("Applications Access"))
        self.tabs.addTab(self._build_tokens(), tr("Service tokens"))
        outer.addWidget(self.tabs, 1)
        self.read_label = label("", "meta")
        outer.addWidget(self.read_label)
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
        self.tunnel_hint = label("", "muted", wrap=True)
        box.addWidget(self.tunnel_hint)
        self.tree = QTreeWidget()
        self.tree.setAccessibleName(tr("Tunnels et noms d'hôte publiés"))
        self.tree.setHeaderLabels([tr("Tunnel ou nom d'hôte"), tr("Service"), tr("État")])
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.setUniformRowHeights(True)
        header = self.tree.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.resizeSection(1, 260)
        header.resizeSection(2, 120)
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
        self.apps = _table([tr("Nom"), tr("Domaine"), tr("Type")], tr("Applications Access"))
        self.apps.horizontalHeader().resizeSection(0, 220)
        self.apps.horizontalHeader().resizeSection(1, 280)
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
        row.addStretch()
        box.addLayout(row)
        box.addWidget(
            label(
                tr(
                    "Service tokens du compte Cloudflare. « Dans CMA » indique si le token est aussi "
                    "enregistré sur ce poste, avec son secret."
                ),
                "muted",
                wrap=True,
            )
        )
        self.remote_tokens = _table(
            [tr("Nom"), tr("ID client"), tr("Expiration"), tr("Dans CMA")], tr("Service tokens du compte")
        )
        header = self.remote_tokens.horizontalHeader()
        for column, width in enumerate((200, 280, 120)):
            header.resizeSection(column, width)
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
        if overview is None:
            self.status.setText("")
            self.read_label.setText("")
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
        for view in sorted(overview.tunnels, key=lambda v: v.tunnel.name.lower()):
            text, tone, symbol = tunnel_state(view.tunnel.status)
            parent = QTreeWidgetItem([view.tunnel.name, "", f"{symbol} {text}"])
            parent.setToolTip(2, view.tunnel.status)
            parent.setData(0, TUNNEL_ROLE, view.tunnel)
            parent.setForeground(2, QBrush(QColor(status_colors(tone, tokens)[0])))
            for rule in view.hostnames:
                child = QTreeWidgetItem([rule.hostname, rule.service, "—"])
                child.setToolTip(2, tr("État porté par le tunnel {name}").format(name=view.tunnel.name))
                child.setToolTip(1, rule.service)
                child.setData(0, TUNNEL_ROLE, view.tunnel)
                child.setData(0, RULE_ROLE, rule)
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
                self.apps.setItem(row, column, item)
        self.apps_stack.setCurrentWidget(self.apps if overview.apps else self.apps_empty)
        local = {t.client_id: t for t in self.ctx.config().tokens}
        for token in sorted(overview.tokens, key=lambda t: t.name.lower()):
            row = self.remote_tokens.rowCount()
            self.remote_tokens.insertRow(row)
            mine = local.get(token.client_id)
            if mine is None:
                in_cma = tr("Non")
            elif self.ctx.core.secrets.get(mine.secret_key):
                in_cma = tr("Oui")
            else:
                in_cma = tr("Secret indisponible")
            values = (token.name, token.client_id, expiry_label(token.expires_at), in_cma)
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.remote_tokens.setItem(row, column, item)
        self.tokens_stack.setCurrentWidget(self.remote_tokens if overview.tokens else self.tokens_empty)
        self._update_tunnel_actions()
        self._update_app_actions()

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
            menu.addSeparator()
            menu.addAction(tr("Retirer ce nom d'hôte…"), self.unpublish_selected)
        elif isinstance(tunnel, Tunnel):
            menu.addAction(tr("Importer ses noms d'hôte"), self.import_selected)
            publish = menu.addAction(tr("Publier un service sur ce tunnel…"), lambda: self.publish(tunnel))
            publish.setEnabled(self.publish_button.isEnabled())
        menu.exec(self.tree.viewport().mapToGlobal(pos))
        menu.deleteLater()

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
            parts = [tr("Service publié : {host}.").format(host=result.rule.hostname)]
            if result.app is not None:
                parts.append(tr("Protégé par Access."))
            if result.profile is not None:
                parts.append(tr("Profil CMA créé."))
            self.ctx.notify("success", " ".join(parts), action=self._open_action(result.profile))
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

        self.ctx.run(self.admin.publish(request), done, failed)

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
        name = ask_create_token(self, account, self.ctx.core.secrets.persistent)
        name = (name or "").strip()
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

        self.ctx.run(self.admin.create_service_token(name), done, failed)
