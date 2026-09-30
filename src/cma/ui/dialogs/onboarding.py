"""Assistant de premier lancement (D1) : bienvenue, cloudflared, premier profil facultatif.

Aucune connexion n'est lancée implicitement ; « Plus tard » termine sans rien créer.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from pydantic import ValidationError
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QRadioButton,
    QVBoxLayout,
    QWidget,
    QWizard,
    QWizardPage,
)

from cma.core.cloudflared.binary import download_release_binary, fetch_latest_release, read_version
from cma.core.models import AuthMode, CloudflareProfile, ServiceToken, guess_service_type, unique_name
from cma.i18n import tr
from cma.ui.context import GuiContext, describe_validation_error
from cma.ui.icons import app_icon
from cma.ui.widgets import (
    FieldError,
    PortField,
    SecretField,
    button,
    copy_to_clipboard,
    label,
    set_role,
    title,
    with_error,
)

WINGET_COMMAND = "winget install --id Cloudflare.cloudflared"
STEPS = 3


def _page(step: int, heading: str) -> tuple[QWizardPage, QVBoxLayout]:
    """Page avec « Étape n sur 3 » et son titre ; le pied (boutons) reste celui de l'assistant."""
    page = QWizardPage()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(8, 4, 8, 4)
    layout.setSpacing(10)
    layout.addWidget(label(tr("Étape {n} sur {total}").format(n=step, total=STEPS), "meta"))
    layout.addWidget(title(heading, "ObjectTitle"))
    return page, layout


class OnboardingWizard(QWizard):
    def __init__(self, parent: QWidget | None, ctx: GuiContext, open_settings: object = None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.created_profile: CloudflareProfile | None = None
        self.setWindowTitle(tr("Bienvenue dans Cloudflared Manage Access"))
        self.setWindowIcon(app_icon())
        self.setWizardStyle(QWizard.WizardStyle.ClassicStyle)
        self.setOption(QWizard.WizardOption.NoBackButtonOnStartPage, True)
        self.setOption(QWizard.WizardOption.NoDefaultButton, False)
        self.setButtonText(QWizard.WizardButton.NextButton, tr("Suivant"))
        self.setButtonText(QWizard.WizardButton.BackButton, tr("Précédent"))
        self.setButtonText(QWizard.WizardButton.FinishButton, tr("Terminer"))
        self.setButtonText(QWizard.WizardButton.CancelButton, tr("Plus tard"))
        for which in (QWizard.WizardButton.NextButton, QWizard.WizardButton.FinishButton):
            widget = self.button(which)
            if widget is not None:
                widget.setProperty("role", "primary")
        self.addPage(self._welcome_page())
        self.addPage(self._binary_page())
        self.addPage(self._profile_page())
        self.resize(720, 560)
        self.setMinimumSize(640, 520)

    # --- Pages ---------------------------------------------------------------------------------------

    def _welcome_page(self) -> QWizardPage:
        page, layout = _page(1, tr("Bienvenue dans CMA"))
        layout.addWidget(
            label(
                tr("Ouvrez vos accès Cloudflare et vos redirections SSH depuis une seule fenêtre."),
                wrap=True,
            )
        )
        layout.addWidget(
            label(tr("Les secrets sont conservés dans le coffre de cet ordinateur."), "muted", wrap=True)
        )
        layout.addStretch()
        return page

    def _binary_page(self) -> QWizardPage:
        page, layout = _page(2, tr("Préparer cloudflared"))
        self.binary_state = label("", wrap=True, selectable=True)
        layout.addWidget(self.binary_state)
        row = QHBoxLayout()
        self.detect_button = button(tr("Détecter"), "search")
        self.detect_button.clicked.connect(self.detect)
        choose = button(tr("Choisir un exécutable…"), "folder-open")
        choose.clicked.connect(self._choose)
        self.download_button = button(tr("Télécharger"), "download")
        self.download_button.setToolTip(tr("Fichier officiel vérifié par SHA-256 et signature"))
        self.download_button.clicked.connect(self._download)
        for widget in (self.detect_button, choose, self.download_button):
            row.addWidget(widget)
        row.addStretch()
        layout.addLayout(row)
        layout.addWidget(label(tr("Ou, dans un terminal :"), "muted"))
        command = QHBoxLayout()
        command.addWidget(label(WINGET_COMMAND, "code", selectable=True), 1)
        copy = button(tr("Copier la commande"), "copy")
        copy.clicked.connect(lambda: copy_to_clipboard(WINGET_COMMAND))
        command.addWidget(copy)
        layout.addLayout(command)
        self.binary_progress = label("", "muted", wrap=True)
        layout.addWidget(self.binary_progress)
        layout.addStretch()
        layout.addWidget(label(tr("Vous pourrez installer cloudflared plus tard."), "muted", wrap=True))
        self.detect()
        return page

    def _profile_page(self) -> QWizardPage:
        page, layout = _page(3, tr("Créer votre premier profil"))
        layout.addWidget(
            label(tr("Facultatif : « Plus tard » termine sans créer de profil."), "muted", wrap=True)
        )
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.name = QLineEdit()
        self.name.setPlaceholderText(tr("MongoDB production"))
        self.hostname = QLineEdit()
        self.hostname.setPlaceholderText("mongodb.exemple.fr")
        self.hostname_error = FieldError()
        names = QHBoxLayout()
        name_box = QFormLayout()
        name_box.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        name_box.addRow(tr("Nom"), self.name)
        host_box = QFormLayout()
        host_box.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        host_box.addRow(tr("Nom d'hôte"), with_error(self.hostname, self.hostname_error))
        names.addLayout(name_box, 1)
        names.addLayout(host_box, 1)
        form.addRow(names)
        self.port = PortField(lambda p: self.ctx.manager.suggest_local_port(p), lambda: "127.0.0.1")
        self.port.set_value(self.ctx.manager.suggest_local_port())
        form.addRow(tr("Port local"), self.port)
        self.browser = QRadioButton(tr("Navigateur"))
        self.browser.setChecked(True)
        self.token = QRadioButton(tr("Service token"))
        methods = QHBoxLayout()
        group = QButtonGroup(page)
        for radio in (self.browser, self.token):
            group.addButton(radio)
            methods.addWidget(radio)
        methods.addStretch()
        form.addRow(tr("Méthode"), methods)
        self.client_id = QLineEdit()
        self.client_id.setPlaceholderText("xxxxxxxx.access")
        self.secret = SecretField(tr("secret du service token"))
        self.token_row = QWidget()
        token_form = QFormLayout(self.token_row)
        token_form.setContentsMargins(0, 0, 0, 0)
        token_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        token_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        token_form.addRow(tr("Client ID"), self.client_id)
        token_form.addRow(tr("Secret"), self.secret)
        form.addRow(self.token_row)
        self.favorite = QCheckBox(tr("Afficher dans les favoris"))
        self.favorite.setChecked(True)
        form.addRow(self.favorite)
        layout.addLayout(form)
        self.error = label("", "error", wrap=True)
        layout.addWidget(self.error)
        layout.addStretch()
        self.token.toggled.connect(self._toggle_token)
        self._toggle_token(False)
        return page

    def _toggle_token(self, enabled: bool) -> None:
        self.token_row.setVisible(enabled)
        self.client_id.setEnabled(enabled)
        self.secret.setEnabled(enabled)

    # --- cloudflared ---------------------------------------------------------------------------------

    def detect(self) -> None:
        binary = self.ctx.manager.cloudflared_path()
        if binary is None:
            self.binary_state.setText(tr("État : cloudflared introuvable"))
            set_role(self.binary_state, "warning")
            return
        self.binary_state.setText(tr("Recherche de cloudflared…"))

        def done(version: str | None) -> None:
            self.binary_state.setText(
                tr("cloudflared {version} détecté.").format(version=version or "?") + f"\n{binary}"
            )
            set_role(self.binary_state, "success")

        self.ctx.run(read_version(binary), done, lambda e: self.binary_state.setText(str(e)))

    def _choose(self) -> None:
        pattern = tr("Exécutable (*.exe)") if sys.platform == "win32" else tr("Tous les fichiers (*)")
        path, _ = QFileDialog.getOpenFileName(self, tr("Choisir cloudflared"), str(Path.home()), pattern)
        if path:
            self.ctx.update_config(lambda c: setattr(c.settings, "cloudflared_path", path))
            self.detect()

    def _download(self) -> None:
        self.download_button.setEnabled(False)
        self.binary_progress.setText(tr("Téléchargement de cloudflared…"))
        cache = self.ctx.paths.cache_dir / "cloudflared-release.json"
        bin_dir = self.ctx.paths.bin_dir

        async def run() -> Path:
            release = await asyncio.to_thread(fetch_latest_release, cache)
            return await asyncio.to_thread(download_release_binary, release, bin_dir)

        def done(path: Path) -> None:
            self.download_button.setEnabled(True)
            self.binary_progress.setText("")
            self.ctx.update_config(lambda c: setattr(c.settings, "cloudflared_path", str(path)))
            self.detect()

        def failed(_error: BaseException) -> None:
            self.download_button.setEnabled(True)
            self.binary_progress.setText(
                tr("Le téléchargement a échoué. Réessayez ou choisissez un exécutable.")
            )

        self.ctx.run(run(), done, failed)

    # --- Premier profil ------------------------------------------------------------------------------

    def validateCurrentPage(self) -> bool:
        if self.currentId() != 2 or not self.hostname.text().strip():
            return True
        self.error.setText("")
        self.hostname_error.show_error(None)
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
                favorite=self.favorite.isChecked(),
            )
        except ValidationError as exc:
            message = describe_validation_error(exc)
            self.error.setText(message)
            if "hostname" in str(exc):
                self.hostname_error.show_error(message)
            return False
        if token is not None:
            self.ctx.core.secrets.set(token.secret_key, self.secret.text().strip())

        def add(c: object) -> None:
            if token is not None:
                c.tokens.append(token)  # type: ignore[attr-defined]
            c.cloudflare_profiles.append(profile)  # type: ignore[attr-defined]

        if not self.ctx.update_config(add):
            return False
        self.created_profile = profile
        return True
