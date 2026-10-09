"""Liens `cma://` et profils partagés : partager un profil, confirmer une connexion demandée par un lien, importer un
profil reçu."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from cma.core.fsutil import atomic_write_text
from cma.core.links import FILE_SUFFIX, SharedProfile, connect_link, share_file_text, share_link
from cma.core.models import AuthMode, CloudflareProfile, SshProfile
from cma.i18n import tr
from cma.platform import links as platform_links
from cma.ui.context import GuiContext
from cma.ui.icons import app_icon
from cma.ui.widgets import button, copy_to_clipboard, label, primary_button, title


def ask_share_path(parent: QWidget, name: str) -> Path | None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    path, _filter = QFileDialog.getSaveFileName(
        parent,
        tr("Enregistrer le profil partagé"),
        str(Path.home() / f"{name}{FILE_SUFFIX}"),
        f"CMA (*{FILE_SUFFIX})",
    )
    return Path(path) if path else None


class ShareDialog(QDialog):
    """Lien de connexion (pour soi : favori, document) et partage du profil (pour un collègue, sans secret)."""

    def __init__(self, parent: QWidget | None, ctx: GuiContext, profile: CloudflareProfile) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.profile = profile
        config = ctx.config()
        self.setWindowTitle(tr("Partager « {name} »").format(name=profile.name))
        self.setWindowIcon(app_icon())
        self.resize(720, 360)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Partager « {name} »").format(name=profile.name), "SectionTitle"))
        form = QFormLayout()
        self.connect_field = QLineEdit(connect_link(profile.name))
        self.connect_field.setReadOnly(True)
        copy_connect = button(tr("Copier"), "copy")
        copy_connect.clicked.connect(
            lambda: self._copy(self.connect_field.text(), tr("Lien de connexion copié."))
        )
        row = QHBoxLayout()
        row.addWidget(self.connect_field, 1)
        row.addWidget(copy_connect)
        form.addRow(tr("Lien de connexion"), row)
        form.addRow(
            "",
            label(
                tr("Ouvre la connexion sur ce poste : à mettre en favori ou dans une documentation."),
                "meta",
                wrap=True,
            ),
        )
        self.share_field = QLineEdit(share_link(profile, config))
        self.share_field.setReadOnly(True)
        for field in (self.connect_field, self.share_field):
            field.setCursorPosition(0)  # le début du lien, lisible, plutôt que sa fin
        copy_share = button(tr("Copier"), "copy")
        copy_share.clicked.connect(lambda: self._copy(self.share_field.text(), tr("Lien de partage copié.")))
        row = QHBoxLayout()
        row.addWidget(self.share_field, 1)
        row.addWidget(copy_share)
        form.addRow(tr("Lien de partage"), row)
        note = tr("Recrée ce profil chez un collègue qui a CMA. Aucun secret n'est inclus.")
        token = config.token(profile.token_id) if profile.auth == AuthMode.SERVICE_TOKEN else None
        if token is not None:
            note += " " + tr(
                "Le service token « {name} » n'y est désigné que par son Client ID : transmettez son secret à part, "
                "par un canal sûr."
            ).format(name=token.name)
        form.addRow("", label(note, "meta", wrap=True))
        layout.addLayout(form)
        layout.addStretch()
        self.status = label("", "meta", wrap=True)
        layout.addWidget(self.status)
        if platform_links.supported() and not platform_links.is_registered():
            self.register_box = QCheckBox(
                tr("Ouvrir les liens cma:// et les fichiers .cma avec cette copie de CMA")
            )
            self.register_box.toggled.connect(self.register_links)
            layout.addWidget(self.register_box)
        footer = QHBoxLayout()
        save = button(tr("Enregistrer en fichier .cma…"), "download")
        save.clicked.connect(self.save_file)
        footer.addWidget(save)
        footer.addStretch()
        close = primary_button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)

    def _copy(self, text: str, message: str) -> None:
        copy_to_clipboard(text)
        self.status.setText(message)

    def save_file(self) -> None:
        path = ask_share_path(self, self.profile.name)
        if path is None:
            return
        try:
            atomic_write_text(path, share_file_text(self.profile, self.ctx.config()))
        except OSError as exc:
            self.status.setText(tr("Enregistrement impossible : {error}").format(error=exc))
            return
        self.status.setText(tr("Profil enregistré : {file}").format(file=path.name))

    def register_links(self, checked: bool) -> None:
        if not checked:
            return
        try:
            platform_links.register()
        except (OSError, NotImplementedError) as exc:
            self.status.setText(tr("Association impossible : {error}").format(error=exc))
            return
        self.status.setText(tr("Les liens cma:// et les fichiers .cma s'ouvrent désormais avec CMA."))


def show_share(parent: QWidget, ctx: GuiContext, profile: CloudflareProfile) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    ShareDialog(parent, ctx, profile).exec()


def ask_link_connect(parent: QWidget, profile: CloudflareProfile | SshProfile) -> tuple[bool, bool]:
    """(ouvrir ?, ne plus demander pour ce profil ?) pour une connexion demandée par un lien `cma://`."""
    box = QMessageBox(parent)
    box.setWindowTitle(tr("Lien CMA"))
    box.setIcon(QMessageBox.Icon.Question)
    box.setText(tr("Ouvrir la connexion « {name} » ?").format(name=profile.name))
    box.setInformativeText(
        tr(
            "Un lien cma:// demande cette connexion (favori, document, page web). Ouvrez-la seulement si vous l'attendiez."
        )
    )
    trust = QCheckBox(tr("Ne plus demander pour ce profil"))
    box.setCheckBox(trust)
    open_button = box.addButton(tr("Ouvrir"), QMessageBox.ButtonRole.AcceptRole)
    box.addButton(tr("Annuler"), QMessageBox.ButtonRole.RejectRole)
    box.exec()
    accepted = box.clickedButton() is open_button
    return accepted, accepted and trust.isChecked()


def ask_import_shared(parent: QWidget, shared: SharedProfile) -> bool:
    """Aperçu d'un profil partagé avant de l'ajouter."""
    profile = shared.profile
    lines = [
        tr("Nom : {name}").format(name=profile.name),
        tr("Nom d'hôte : {host}").format(host=profile.hostname or "—"),
        tr("Port local : {port}").format(port=profile.local_port or tr("automatique")),
        tr("Connexion : {mode}").format(
            mode=tr("service token") if profile.auth == AuthMode.SERVICE_TOKEN else tr("navigateur")
        ),
    ]
    if shared.missing_token is not None:
        name, client_id = shared.missing_token
        lines.append(
            tr(
                "Service token à ajouter : « {name} » (Client ID {client_id}), avec son secret transmis à part."
            ).format(name=name or "—", client_id=client_id or "—")
        )
    box = QMessageBox(parent)
    box.setWindowTitle(tr("Profil partagé"))
    box.setIcon(QMessageBox.Icon.Question)
    box.setText(tr("Ajouter le profil « {name} » ?").format(name=profile.name))
    box.setInformativeText("\n".join(lines))
    add = box.addButton(tr("Ajouter"), QMessageBox.ButtonRole.AcceptRole)
    box.addButton(tr("Annuler"), QMessageBox.ButtonRole.RejectRole)
    box.exec()
    return box.clickedButton() is add
