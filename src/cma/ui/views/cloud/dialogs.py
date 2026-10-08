"""Boîtes de dialogue de la vue Cloudflare : publier, protéger, autoriser un token, créer un token."""

from __future__ import annotations

from typing import Any

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
from cma.core.cfapi import SESSION_DURATIONS, AccessApp, AppSettings, IngressRule, Tunnel
from cma.core.models import ServiceToken
from cma.i18n import tr
from cma.ui.icons import app_icon
from cma.ui.views.cloud.helpers import dialog_buttons, service_error, token_durations, tunnel_status_label
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
        if problem := service_error(service):
            return self._fail(problem)
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


# --- Modifier le service d'un nom d'hôte publié -------------------------------------------------------------


class EditServiceDialog(QDialog):
    """Changer la cible d'un nom d'hôte publié, sans le retirer puis le republier."""

    def __init__(self, parent: QWidget | None, tunnel: Tunnel, rule: IngressRule) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Modifier le service"))
        self.setWindowIcon(app_icon())
        self.resize(600, 300)
        self.rule = rule
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Modifier le service"), "SectionTitle"))
        layout.addWidget(label(rule.hostname + rule.path, "mono", selectable=True))
        layout.addWidget(label(tr("Tunnel : {name}").format(name=tunnel.name), "meta"))
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.service = QLineEdit(rule.service)
        self.service.setAccessibleName(tr("Service"))
        form.addRow(tr("Service"), self.service)
        self.no_tls_verify = QCheckBox(
            tr("Accepter le certificat de l'origine sans le vérifier (auto-signé)")
        )
        self.no_tls_verify.setChecked(bool(rule.origin.get("noTLSVerify")))
        form.addRow(self.no_tls_verify)
        self.host_header = QLineEdit(str(rule.origin.get("httpHostHeader") or ""))
        self.host_header.setAccessibleName(tr("En-tête Host envoyé à l'origine"))
        self.host_header.setPlaceholderText(tr("inchangé"))
        form.addRow(tr("En-tête Host envoyé à l'origine"), self.host_header)
        self.server_name = QLineEdit(str(rule.origin.get("originServerName") or ""))
        self.server_name.setAccessibleName(tr("Nom attendu dans le certificat de l'origine"))
        self.server_name.setPlaceholderText(tr("inchangé"))
        form.addRow(tr("Nom attendu dans le certificat de l'origine"), self.server_name)
        layout.addLayout(form)
        layout.addWidget(
            label(
                tr(
                    "Le service doit être joignable depuis le connecteur du tunnel. Le nom d'hôte, son "
                    "enregistrement DNS et sa protection Access ne changent pas."
                ),
                "muted",
                wrap=True,
            )
        )
        self.error = label("", "error", wrap=True)
        self.error.hide()
        layout.addWidget(self.error)
        layout.addStretch()
        buttons, self.ok_button = dialog_buttons(self, tr("Enregistrer"))
        self.ok_button.clicked.connect(self._accept)
        layout.addWidget(buttons)
        self.service.textChanged.connect(self._refresh)
        self.host_header.textChanged.connect(self._refresh)
        self.server_name.textChanged.connect(self._refresh)
        self.no_tls_verify.toggled.connect(self._refresh)
        self._refresh()

    def value(self) -> str:
        return self.service.text().strip()

    def origin(self) -> dict[str, Any]:
        """Options d'origine modifiables ici ; une valeur vide ou fausse retire l'option."""
        return {
            "noTLSVerify": self.no_tls_verify.isChecked(),
            "httpHostHeader": self.host_header.text().strip(),
            "originServerName": self.server_name.text().strip(),
        }

    def changed(self) -> bool:
        before = {
            key: self.rule.origin.get(key) or ("" if key != "noTLSVerify" else False) for key in self.origin()
        }
        return self.value() != self.rule.service or self.origin() != before

    def _refresh(self, *_args: object) -> None:
        self.ok_button.setEnabled(bool(self.value()) and self.changed())

    def _accept(self) -> None:
        problem = service_error(self.value())
        if problem:
            self.error.setText(problem)
            self.error.show()
            return
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


class PathRuleDialog(QDialog):
    """Règle avec chemin sur un nom d'hôte déjà publié : `/api` vers un autre service, même DNS et même Access."""

    def __init__(self, parent: QWidget | None, tunnel: Tunnel, hostname: str) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Ajouter une règle avec chemin"))
        self.setWindowIcon(app_icon())
        self.resize(560, 260)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Ajouter une règle avec chemin"), "SectionTitle"))
        layout.addWidget(label(hostname, "mono", selectable=True))
        layout.addWidget(label(tr("Tunnel : {name}").format(name=tunnel.name), "meta"))
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.path = QLineEdit()
        self.path.setPlaceholderText("/api")
        form.addRow(tr("Chemin"), self.path)
        self.service = QLineEdit()
        self.service.setPlaceholderText("http://localhost:8080")
        form.addRow(tr("Service"), self.service)
        layout.addLayout(form)
        layout.addWidget(
            label(
                tr(
                    "cloudflared essaie les règles dans l'ordre : placez la règle avec chemin avant celle du nom "
                    "d'hôte seul (« Monter »). Le chemin est une expression régulière : /api couvre aussi /api/v1."
                ),
                "muted",
                wrap=True,
            )
        )
        self.error = label("", "error", wrap=True)
        self.error.hide()
        layout.addWidget(self.error)
        layout.addStretch()
        buttons, self.ok_button = dialog_buttons(self, tr("Ajouter"))
        self.ok_button.clicked.connect(self.accept)
        layout.addWidget(buttons)
        self.path.textChanged.connect(self._refresh)
        self.service.textChanged.connect(self._refresh)
        self._refresh()

    def value(self) -> tuple[str, str]:
        return self.path.text().strip(), self.service.text().strip()

    def _refresh(self) -> None:
        path, service = self.value()
        problem = None
        if path and not path.startswith(("/", "^")):
            problem = tr("Le chemin commence par / (ou ^ pour une expression régulière).")
        elif service:
            problem = service_error(service)
        self.error.setText(problem or "")
        self.error.setVisible(bool(problem))
        self.ok_button.setEnabled(bool(path and service) and problem is None)


class CatchAllDialog(QDialog):
    """Règle finale du tunnel : ce que reçoit une requête qu'aucune règle nommée ne prend."""

    CHOICES = ("http_status:404", "http_status:503")

    def __init__(self, parent: QWidget | None, tunnel: Tunnel, current: str) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Règle finale"))
        self.setWindowIcon(app_icon())
        self.resize(520, 240)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Règle finale du tunnel {name}").format(name=tunnel.name), "SectionTitle"))
        layout.addWidget(
            label(
                tr("Ce que reçoit une requête qu'aucune règle du tunnel ne prend en charge."),
                "muted",
                wrap=True,
            )
        )
        self.choice = QComboBox()
        self.choice.setAccessibleName(tr("Règle finale"))
        self.choice.addItem(tr("Page « introuvable » (404, recommandé)"), "http_status:404")
        self.choice.addItem(tr("Service indisponible (503)"), "http_status:503")
        self.choice.addItem(tr("Un service…"), "")
        layout.addWidget(self.choice)
        self.service = QLineEdit()
        self.service.setAccessibleName(tr("Service"))
        self.service.setPlaceholderText("http://localhost:8080")
        layout.addWidget(self.service)
        self.error = label("", "error", wrap=True)
        self.error.hide()
        layout.addWidget(self.error)
        layout.addStretch()
        buttons, self.ok_button = dialog_buttons(self, tr("Enregistrer"))
        self.ok_button.clicked.connect(self.accept)
        layout.addWidget(buttons)
        index = self.choice.findData(current) if current in self.CHOICES else 2
        self.choice.setCurrentIndex(index)
        if current not in self.CHOICES:
            self.service.setText(current)
        self.choice.currentIndexChanged.connect(self._refresh)
        self.service.textChanged.connect(self._refresh)
        self._refresh()

    def value(self) -> str:
        return str(self.choice.currentData()) or self.service.text().strip()

    def _refresh(self) -> None:
        custom = not self.choice.currentData()
        self.service.setVisible(custom)
        problem = service_error(self.value()) if custom and self.value() else None
        self.error.setText(problem or "")
        self.error.setVisible(bool(problem))
        self.ok_button.setEnabled(bool(self.value()) and problem is None)


class AppSettingsDialog(QDialog):
    """Réglages d'une application Access : nom, durée de session, lanceur, redirection vers le fournisseur."""

    def __init__(self, parent: QWidget | None, app: AccessApp, settings: AppSettings) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Réglages de l'application"))
        self.setWindowIcon(app_icon())
        self.resize(560, 360)
        self.settings = settings
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Réglages de l'application"), "SectionTitle"))
        layout.addWidget(label(app.domain, "mono", selectable=True))
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.name = QLineEdit(settings.name)
        form.addRow(tr("Nom"), self.name)
        self.duration = QComboBox()
        for value in SESSION_DURATIONS:
            self.duration.addItem(session_duration_label(value), value)
        if self.duration.findData(settings.session_duration) < 0:
            self.duration.addItem(settings.session_duration, settings.session_duration)
        self.duration.setCurrentIndex(self.duration.findData(settings.session_duration))
        form.addRow(tr("Durée de session"), self.duration)
        self.launcher = QCheckBox(tr("Visible dans le lanceur d'applications Access"))
        self.launcher.setChecked(settings.app_launcher_visible)
        form.addRow(self.launcher)
        self.redirect = QCheckBox(tr("Rediriger directement vers le fournisseur d'identité"))
        self.redirect.setChecked(settings.auto_redirect_to_identity)
        # Cloudflare n'accepte la redirection automatique qu'avec un seul fournisseur d'identité choisi.
        single = len(settings.allowed_idps) == 1
        self.redirect.setEnabled(single or settings.auto_redirect_to_identity)
        if not single:
            self.redirect.setToolTip(
                tr("Possible seulement quand un seul fournisseur d'identité est choisi.")
            )
        form.addRow(self.redirect)
        layout.addLayout(form)
        idps = len(settings.allowed_idps)
        layout.addWidget(
            label(
                (
                    tr("Fournisseurs d'identité : tous ceux du compte.")
                    if not idps
                    else tr("Fournisseurs d'identité : {n} choisi(s), inchangés par CMA.").format(n=idps)
                ),
                "muted",
                wrap=True,
            )
        )
        layout.addStretch()
        buttons, self.ok_button = dialog_buttons(self, tr("Enregistrer"))
        self.ok_button.clicked.connect(self.accept)
        layout.addWidget(buttons)
        self.name.textChanged.connect(lambda text: self.ok_button.setEnabled(bool(text.strip())))

    def value(self) -> AppSettings:
        return AppSettings(
            self.name.text().strip(),
            str(self.duration.currentData()),
            self.launcher.isChecked(),
            self.redirect.isChecked(),
            self.settings.allowed_idps,
        )


def session_duration_label(value: str) -> str:
    """« Expire aussitôt », « 15 minutes », « 24 heures », « 1 semaine »… ; une valeur inconnue reste telle quelle."""
    return {
        "0s": tr("Expire aussitôt"),
        "15m": tr("15 minutes"),
        "30m": tr("30 minutes"),
        "6h": tr("6 heures"),
        "12h": tr("12 heures"),
        "24h": tr("24 heures"),
        "168h": tr("1 semaine"),
        "730h": tr("1 mois"),
    }.get(value, value)


# Fonctions de module : les tests les remplacent pour ne pas ouvrir de boîte modale.


def ask_service(parent: QWidget, tunnel: Tunnel, rule: IngressRule) -> tuple[str, dict[str, Any]] | None:
    dialog = EditServiceDialog(parent, tunnel, rule)
    return (dialog.value(), dialog.origin()) if dialog.exec() == QDialog.DialogCode.Accepted else None


def ask_protect(parent: QWidget, hostnames: list[str]) -> str | None:
    dialog = ProtectDialog(parent, hostnames)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


def ask_allow(parent: QWidget, app: AccessApp, tokens: list[ServiceToken]) -> ServiceToken | None:
    dialog = AllowDialog(parent, app, tokens)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


def ask_create_token(parent: QWidget, account: str, persistent: bool) -> tuple[str, str] | None:
    dialog = CreateTokenDialog(parent, account, persistent)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


def ask_path_rule(parent: QWidget, tunnel: Tunnel, hostname: str) -> tuple[str, str] | None:
    dialog = PathRuleDialog(parent, tunnel, hostname)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


def ask_catch_all(parent: QWidget, tunnel: Tunnel, current: str) -> str | None:
    dialog = CatchAllDialog(parent, tunnel, current)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


def ask_app_settings(parent: QWidget, app: AccessApp, settings: AppSettings) -> AppSettings | None:
    dialog = AppSettingsDialog(parent, app, settings)
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
