"""Boîtes de dialogue de la vue Cloudflare : publier, protéger, autoriser un token, créer un token."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QCompleter,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from cma.core.cfadmin import Overview, PublishRequest, PublishResult
from cma.core.cfapi import AccessApp, Tunnel
from cma.core.models import ServiceToken
from cma.i18n import tr
from cma.ui.icons import app_icon
from cma.ui.views.cloud.helpers import dialog_buttons, token_durations, tunnel_status_label
from cma.ui.widgets import (
    label,
    title,
)


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
        buttons, self.ok_button = dialog_buttons(self, tr("Publier"))
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
        buttons, self.ok_button = dialog_buttons(self, tr("Protéger"))
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
        buttons, self.ok_button = dialog_buttons(self, tr("Autoriser"))
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
        buttons, self.ok_button = dialog_buttons(self, tr("Créer"))
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
