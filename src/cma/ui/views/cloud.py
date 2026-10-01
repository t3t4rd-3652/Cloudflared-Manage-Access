"""Administration Cloudflare : tunnels et noms d'hôte publiés, applications Access, service tokens (§4.6).

Tout passe par l'API Cloudflare avec un jeton d'API gardé dans le coffre. Les actions typiques :
importer les noms d'hôte d'un tunnel comme profils, publier un nouveau service protégé par Access,
créer un service token directement rangé dans le coffre de CMA (D14 à D17).
"""

from __future__ import annotations

import urllib.error
from collections.abc import Callable
from datetime import datetime

from PySide6.QtCore import (
    QModelIndex,
    QPersistentModelIndex,
    QPoint,
    QPointF,
    QRect,
    QRectF,
    QSize,
    Qt,
    QUrl,
    Signal,
)
from PySide6.QtGui import (
    QBrush,
    QColor,
    QDesktopServices,
    QFont,
    QFontMetrics,
    QKeySequence,
    QMouseEvent,
    QPainter,
    QPen,
    QShowEvent,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QCompleter,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QStackedWidget,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
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
from cma.ui.icons import app_icon, icon, set_glyph, token_icon
from cma.ui.state import remember_header
from cma.ui.theme import current_tokens, mono_font, status_colors
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

TUNNEL_ROLE = 256
RULE_ROLE = 257
PROTECTED_ROLE = 258
PROFILE_ROLE = 259

# Géométrie des cartes de tunnel.
CARD_GAP = 12
CARD_RADIUS = 10.0
CARD_PADDING = 8
HEADER_HEIGHT = 62
HOST_HEIGHT = 44
TEXT_LEFT = 88
CHEVRON_ZONE = 36


def token_durations() -> list[tuple[str, str]]:
    """Durées proposées, au format de l'API Cloudflare (« 8760h ») ; 1 an est la valeur par défaut de l'API."""
    return [(tr("1 an"), "8760h"), (tr("2 ans"), "17520h"), (tr("3 ans"), "26280h"), (tr("6 mois"), "4380h")]


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


def expiry_status(value: str) -> str | None:
    """Teinte de la date d'expiration : « danger » si dépassée, « warning » à moins de 30 jours."""
    try:
        expires = datetime.fromisoformat(value[:10])
    except ValueError:
        return None
    days = (expires - datetime.now()).days
    return "danger" if days < 0 else "warning" if days < 30 else None


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
    """Nom et durée de validité du token ; le secret n'est jamais affiché (§4.25)."""

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
        self.duration = QComboBox()
        self.duration.setAccessibleName(tr("Durée de validité"))
        for text, value in token_durations():
            self.duration.addItem(text, value)
        form.addRow(tr("Durée de validité"), self.duration)
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

    def value(self) -> tuple[str, str]:
        return self.name.text().strip(), str(self.duration.currentData())


# Fonctions de module : les tests les remplacent pour ne pas ouvrir de boîte modale.


def ask_protect(parent: QWidget, hostnames: list[str]) -> str | None:
    dialog = ProtectDialog(parent, hostnames)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


def ask_allow(parent: QWidget, app: AccessApp, tokens: list[ServiceToken]) -> ServiceToken | None:
    dialog = AllowDialog(parent, app, tokens)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


def ask_create_token(parent: QWidget, account: str, persistent: bool) -> tuple[str, str] | None:
    dialog = CreateTokenDialog(parent, account, persistent)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


def publish_summary(result: PublishResult) -> str:
    """« Nom d'hôte publié ; protection Access non créée ; profil CMA créé. » puis le détail des échecs."""
    labels = {
        "hostname": (tr("nom d'hôte publié"), tr("nom d'hôte non publié")),
        "access": (tr("protection Access créée"), tr("protection Access non créée")),
        "token": (tr("service token autorisé"), tr("service token non autorisé")),
        "profile": (tr("profil CMA créé"), tr("profil CMA non créé")),
    }
    parts = [labels[step.name][0 if step.ok else 1] for step in result.steps if step.name in labels]
    text = " ; ".join(parts)
    text = (text[:1].upper() + text[1:] + ".") if text else ""
    details = [step.detail for step in result.steps if not step.ok and step.detail]
    return "\n".join([text, *details])


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
DATABASE_PORTS = {"1433", "1521", "3306", "5432", "6379", "27017"}


def service_icon(service: str) -> str:
    """Icône d'un service publié, d'après son schéma (ssh://, rdp://, http://…) et son port."""
    scheme, _, rest = service.partition("://")
    scheme = scheme.lower()
    if scheme == "tcp" and rest.rsplit(":", 1)[-1].strip("/") in DATABASE_PORTS:
        return "database"
    return {
        "ssh": "terminal-2",
        "rdp": "device-desktop",
        "http": "world-www",
        "https": "world-www",
        "smb": "folder",
        "tcp": "plug-connected",
        "unix": "plug-connected",
    }.get(scheme, "link")


class StatTile(QFrame):
    """Chiffre clé du compte (tunnels, noms d'hôte…) ; un clic ouvre l'onglet correspondant."""

    clicked = Signal()

    def __init__(self, icon_name: str, caption: str) -> None:
        super().__init__()
        self.setProperty("role", "tile")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumWidth(150)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)
        self.glyph = QLabel()
        set_glyph(self.glyph, icon_name, "accent", 24)
        layout.addWidget(self.glyph, 0, Qt.AlignmentFlag.AlignTop)
        texts = QVBoxLayout()
        texts.setSpacing(0)
        self.value = QLabel("—")
        self.value.setStyleSheet("font-size: 18pt; font-weight: 600;")
        self.caption = label(caption, "muted")
        self.detail = label("", "meta")
        texts.addWidget(self.value)
        texts.addWidget(self.caption)
        texts.addWidget(self.detail)
        layout.addLayout(texts, 1)
        self._caption = caption

    def set_values(self, value: int | None, detail: str = "", tone: str | None = None) -> None:
        self.value.setText("—" if value is None else str(value))
        self.detail.setText(detail)
        self.detail.setVisible(bool(detail))
        if tone is not None:
            self.detail.setStyleSheet(f"color: {status_colors(tone, current_tokens())[0]};")
        else:
            self.detail.setStyleSheet("")
        self.setAccessibleName(f"{self._caption} : {self.value.text()}" + (f", {detail}" if detail else ""))

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class TunnelTree(QTreeWidget):
    """Arbre des tunnels présenté en cartes : un tunnel par carte, ses noms d'hôte en lignes."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("CardTree")
        self.setColumnCount(3)
        self.setHeaderHidden(True)
        self.setRootIsDecorated(False)
        self.setIndentation(0)
        self.setUniformRowHeights(False)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setMouseTracking(True)
        self.viewport().setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        # Le service et l'état restent des colonnes (lecture, tests) mais la carte les dessine elle-même.
        self.setColumnHidden(1, True)
        self.setColumnHidden(2, True)
        self.setItemDelegate(TunnelDelegate(self))

    def mousePressEvent(self, event: QMouseEvent) -> None:
        position = event.position().toPoint()
        item = self.itemAt(position)
        if (
            event.button() == Qt.MouseButton.LeftButton
            and item is not None
            and item.parent() is None
            and item.childCount()
            and position.x() < CHEVRON_ZONE
        ):
            item.setExpanded(not item.isExpanded())
        super().mousePressEvent(event)


def _is_last_child(index: QModelIndex | QPersistentModelIndex) -> bool:
    parent = index.parent()
    return parent.isValid() and index.row() == index.model().rowCount(parent) - 1


def _resized(font: QFont, delta: float, weight: QFont.Weight | None = None) -> QFont:
    result = QFont(font)
    result.setPointSizeF(max(7.5, font.pointSizeF() + delta))
    if weight is not None:
        result.setWeight(weight)
    return result


class TunnelDelegate(QStyledItemDelegate):
    """Dessine chaque tunnel comme une carte : en-tête (état, nom, résumé), puis une ligne par nom d'hôte.

    La carte s'étend sur plusieurs lignes de l'arbre : chaque ligne dessine sa part du même rectangle
    arrondi, prolongé au-delà de ses bords quand la carte continue, et rogné à la ligne.
    """

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> QSize:
        if not index.parent().isValid():
            return QSize(0, HEADER_HEIGHT + (CARD_GAP if index.row() else 0))
        return QSize(0, HOST_HEIGHT + (CARD_PADDING if _is_last_child(index) else 0))

    def paint(
        self, painter: QPainter, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex
    ) -> None:
        tokens = current_tokens()
        rect = QRect(option.rect)  # type: ignore[attr-defined]
        state = option.state  # type: ignore[attr-defined]
        font = QFont(option.font)  # type: ignore[attr-defined]
        top_level = not index.parent().isValid()
        view = self.parent()
        children = index.model().rowCount(index) if top_level else 0
        expanded = top_level and isinstance(view, QTreeWidget) and view.isExpanded(index)
        if top_level:
            band = QRect(
                rect.left(), rect.top() + (CARD_GAP if index.row() else 0), rect.width(), HEADER_HEIGHT
            )
            open_below = expanded and children > 0
        else:
            band = QRect(rect.left(), rect.top(), rect.width(), HOST_HEIGHT)
            open_below = not _is_last_child(index)
        reach = int(2 * CARD_RADIUS)
        top = band.top() if top_level else rect.top() - reach
        bottom = rect.bottom() + reach if open_below else rect.bottom()
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setClipRect(rect)
        painter.setPen(QPen(QColor(tokens.border), 1))
        painter.setBrush(QColor(tokens.surface))
        card = QRectF(rect.left() + 1.5, top + 0.5, rect.width() - 3, bottom - top)
        painter.drawRoundedRect(card, CARD_RADIUS, CARD_RADIUS)
        inner = QRectF(band).adjusted(6, 4 if top_level else 2, -6, -4 if top_level else -2)
        if state & QStyle.StateFlag.State_Selected:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(tokens.selected))
            painter.drawRoundedRect(inner, 6, 6)
            painter.setBrush(QColor(tokens.accent))
            painter.drawRoundedRect(QRectF(inner.left(), inner.top() + 7, 3, inner.height() - 14), 1.5, 1.5)
        elif state & QStyle.StateFlag.State_MouseOver:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(tokens.hover))
            painter.drawRoundedRect(inner, 6, 6)
        if state & QStyle.StateFlag.State_HasFocus:
            painter.setPen(QPen(QColor(tokens.focus), 1))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(inner.adjusted(0.5, 0.5, -0.5, -0.5), 6, 6)
        if top_level:
            self._paint_tunnel(painter, band, font, index, children, expanded)
        else:
            self._paint_host(painter, band, font, index)
        painter.restore()

    def _paint_tunnel(
        self,
        painter: QPainter,
        band: QRect,
        font: QFont,
        index: QModelIndex | QPersistentModelIndex,
        children: int,
        expanded: bool,
    ) -> None:
        tokens = current_tokens()
        tunnel = index.data(TUNNEL_ROLE)
        text, tone, symbol = tunnel_state(tunnel.status if isinstance(tunnel, Tunnel) else "")
        fg, bg = status_colors(tone, tokens)
        middle = band.center().y()
        if children:
            chevron = "chevron-down" if expanded else "chevron-right"
            icon(chevron, tokens.muted).paint(painter, QRect(band.left() + 14, middle - 8, 16, 16))
        tile = QRectF(band.left() + 38, middle - 18, 36, 36)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(bg))
        painter.drawRoundedRect(tile, 9, 9)
        icon("cloud", fg).paint(painter, tile.toRect().adjusted(8, 8, -8, -8))
        pill_font = _resized(font, -0.5, QFont.Weight.DemiBold)
        pill_text = f"{symbol} {text}"
        pill_width = QFontMetrics(pill_font).horizontalAdvance(pill_text) + 24
        pill = QRectF(band.right() - 16 - pill_width, middle - 12, pill_width, 24)
        painter.drawRoundedRect(pill, 12, 12)
        painter.setFont(pill_font)
        painter.setPen(QColor(fg))
        painter.drawText(pill, Qt.AlignmentFlag.AlignCenter, pill_text)
        left = band.left() + TEXT_LEFT
        width = max(0, int(pill.left()) - 12 - left)
        name_font = _resized(font, 1.5, QFont.Weight.DemiBold)
        meta_font = _resized(font, -0.5)
        name_metrics, meta_metrics = QFontMetrics(name_font), QFontMetrics(meta_font)
        y = middle - (name_metrics.height() + meta_metrics.height() + 2) // 2
        painter.setFont(name_font)
        painter.setPen(QColor(tokens.text))
        name = name_metrics.elidedText(str(index.data()), Qt.TextElideMode.ElideRight, width)
        painter.drawText(QRect(left, y, width, name_metrics.height()), Qt.AlignmentFlag.AlignVCenter, name)
        painter.setFont(meta_font)
        painter.setPen(QColor(tokens.muted))
        summary = meta_metrics.elidedText(
            str(index.model().index(index.row(), 1, index.parent()).data() or ""),
            Qt.TextElideMode.ElideRight,
            width,
        )
        y += name_metrics.height() + 2
        painter.drawText(QRect(left, y, width, meta_metrics.height()), Qt.AlignmentFlag.AlignVCenter, summary)
        if expanded and children:
            painter.setPen(QPen(QColor(tokens.border), 1))
            line = band.bottom() + 0.5
            painter.drawLine(QPointF(band.left() + 16, line), QPointF(band.right() - 16, line))

    def _paint_host(
        self, painter: QPainter, band: QRect, font: QFont, index: QModelIndex | QPersistentModelIndex
    ) -> None:
        tokens = current_tokens()
        rule = index.data(RULE_ROLE)
        service = rule.service if isinstance(rule, IngressRule) else ""
        middle = band.center().y()
        tile = QRectF(band.left() + 42, middle - 14, 28, 28)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(tokens.window))
        painter.drawRoundedRect(tile, 7, 7)
        icon(service_icon(service), tokens.muted).paint(painter, tile.toRect().adjusted(6, 6, -6, -6))
        badge_font = _resized(font, -1.0, QFont.Weight.DemiBold)
        badge_metrics = QFontMetrics(badge_font)
        badges: list[tuple[str, str, str]] = []
        if index.data(PROFILE_ROLE):
            badges.append((tr("Profil CMA"), "circle-check", "info"))
        if index.data(PROTECTED_ROLE):
            badges.append((tr("Access"), "shield-check", "success"))
        else:
            badges.append((tr("Non protégé"), "alert-triangle", "warning"))
        x = band.right() - 16
        painter.setFont(badge_font)
        for text, name, tone in reversed(badges):
            fg, bg = status_colors(tone, tokens)
            width = badge_metrics.horizontalAdvance(text) + 34
            badge = QRectF(x - width, middle - 11, width, 22)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(bg))
            painter.drawRoundedRect(badge, 11, 11)
            icon(name, fg).paint(painter, QRect(int(badge.left()) + 9, middle - 7, 14, 14))
            painter.setPen(QColor(fg))
            painter.drawText(badge.adjusted(27, 0, -8, 0), Qt.AlignmentFlag.AlignVCenter, text)
            x = int(badge.left()) - 6
        left = band.left() + TEXT_LEFT
        column = left + int((band.right() - 16 - left) * 0.42)
        host_width = max(0, column - 16 - left)
        painter.setFont(font)
        painter.setPen(QColor(tokens.text))
        host = QFontMetrics(font).elidedText(str(index.data()), Qt.TextElideMode.ElideMiddle, host_width)
        painter.drawText(
            QRect(left, band.top(), host_width, band.height()), Qt.AlignmentFlag.AlignVCenter, host
        )
        mono = mono_font(9.0)
        service_width = max(0, x - 12 - column)
        service = QFontMetrics(mono).elidedText(service, Qt.TextElideMode.ElideMiddle, service_width)
        painter.setFont(mono)
        painter.setPen(QColor(tokens.muted))
        painter.drawText(
            QRect(column, band.top(), service_width, band.height()), Qt.AlignmentFlag.AlignVCenter, service
        )


# --- Vue ----------------------------------------------------------------------------------------------------


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
        self.apps = _table([tr("Nom"), tr("Domaine"), tr("Type")], tr("Applications Access"))
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
        remember_header(header, "cloud-tokens")
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
