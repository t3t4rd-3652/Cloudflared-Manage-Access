"""Assistant de premier lancement : présentation, cloudflared, premier profil."""

from __future__ import annotations

from pydantic import ValidationError
from PySide6.QtWidgets import (
    QFormLayout,
    QLineEdit,
    QRadioButton,
    QVBoxLayout,
    QWidget,
    QWizard,
    QWizardPage,
)

from cma.core.models import AuthMode, CloudflareProfile, ServiceToken, guess_service_type, unique_name
from cma.i18n import tr
from cma.ui.context import GuiContext, describe_validation_error
from cma.ui.icons import app_icon
from cma.ui.widgets import PortField, SecretField, label


class OnboardingWizard(QWizard):
    def __init__(self, parent: QWidget | None, ctx: GuiContext, open_settings: object) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle(tr("Bienvenue dans Cloudflared Manage Access"))
        self.setWindowIcon(app_icon())
        self.setOption(QWizard.WizardOption.NoBackButtonOnStartPage, True)
        self.setButtonText(QWizard.WizardButton.NextButton, tr("Suivant"))
        self.setButtonText(QWizard.WizardButton.BackButton, tr("Précédent"))
        self.setButtonText(QWizard.WizardButton.FinishButton, tr("Terminer"))
        self.setButtonText(QWizard.WizardButton.CancelButton, tr("Plus tard"))

        welcome = QWizardPage()
        welcome.setTitle(tr("Bienvenue"))
        layout = QVBoxLayout(welcome)
        layout.addWidget(
            label(
                tr(
                    "CMA ouvre des accès locaux vers vos applications protégées par Cloudflare Access "
                    "(SSH, bases de données, Bureau à distance…) et des redirections de ports par SSH.\n\n"
                    "Chaque connexion a un état réel (à l'écoute, dégradée, en reconnexion), et les secrets restent dans le coffre du système."
                ),
                wrap=True,
            )
        )
        self.addPage(welcome)

        binary_page = QWizardPage()
        binary_page.setTitle(tr("cloudflared"))
        layout = QVBoxLayout(binary_page)
        binary = ctx.manager.cloudflared_path()
        if binary is not None:
            layout.addWidget(
                label(tr("cloudflared a été trouvé : {path}").format(path=binary), "success", wrap=True)
            )
        else:
            layout.addWidget(
                label(
                    tr(
                        "cloudflared est introuvable. Vous pourrez le télécharger (fichier vérifié) ou indiquer son chemin "
                        "dans les Paramètres, section cloudflared. Avec winget : winget install Cloudflare.cloudflared"
                    ),
                    "warning",
                    wrap=True,
                )
            )
        self.addPage(binary_page)

        profile_page = QWizardPage()
        profile_page.setTitle(tr("Premier profil (facultatif)"))
        profile_page.setSubTitle(tr("Laissez le hostname vide pour passer cette étape."))
        form = QFormLayout(profile_page)
        self.name = QLineEdit()
        self.name.setPlaceholderText(tr("ex. SSH production"))
        self.hostname = QLineEdit()
        self.hostname.setPlaceholderText("ssh.exemple.fr")
        self.port = PortField(lambda p: ctx.manager.suggest_local_port(p), lambda: "127.0.0.1")
        self.port.set_value(ctx.manager.suggest_local_port())
        self.browser = QRadioButton(tr("Navigateur (compte Cloudflare Access)"))
        self.browser.setChecked(True)
        self.token = QRadioButton(tr("Service token"))
        self.client_id = QLineEdit()
        self.client_id.setPlaceholderText("xxxxxxxx.access")
        self.secret = SecretField()
        self.error = label("", "error", wrap=True)
        form.addRow(tr("Nom :"), self.name)
        form.addRow(tr("Hostname :"), self.hostname)
        form.addRow(tr("Port local :"), self.port)
        form.addRow(tr("Authentification :"), self.browser)
        form.addRow("", self.token)
        form.addRow(tr("Client ID :"), self.client_id)
        form.addRow(tr("Secret :"), self.secret)
        form.addRow("", self.error)
        self.token.toggled.connect(self._toggle_token)
        self._toggle_token(False)
        self.addPage(profile_page)
        self.resize(620, 480)

    def _toggle_token(self, enabled: bool) -> None:
        self.client_id.setEnabled(enabled)
        self.secret.setEnabled(enabled)

    def validateCurrentPage(self) -> bool:
        if self.currentId() != 2 or not self.hostname.text().strip():
            return True
        config = self.ctx.config()
        name = self.name.text().strip() or self.hostname.text().strip()
        token: ServiceToken | None = None
        try:
            if self.token.isChecked():
                if not self.client_id.text().strip() or not self.secret.text().strip():
                    self.error.setText(tr("Client ID et secret sont requis pour un service token."))
                    return False
                token = ServiceToken(
                    name=unique_name(name, [t.name for t in config.tokens]),
                    client_id=self.client_id.text().strip(),
                )
            port = self.port.value()
            profile = CloudflareProfile(
                name=unique_name(name, [p.name for p in config.cloudflare_profiles]),
                hostname=self.hostname.text(),
                local_port=port,
                auth=AuthMode.SERVICE_TOKEN if token else AuthMode.BROWSER,
                token_id=token.id if token else None,
                service_type=guess_service_type(name, self.hostname.text(), port),
                favorite=True,
            )
        except ValidationError as exc:
            self.error.setText(describe_validation_error(exc))
            return False
        if token is not None:
            self.ctx.core.secrets.set(token.secret_key, self.secret.text().strip())

        def add(c: object) -> None:
            if token is not None:
                c.tokens.append(token)  # type: ignore[attr-defined]
            c.cloudflare_profiles.append(profile)  # type: ignore[attr-defined]

        return self.ctx.update_config(add)
