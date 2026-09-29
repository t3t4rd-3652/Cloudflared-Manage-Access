"""Questions posées par le moteur : confiance dans une clé d'hôte, mot de passe, phrase de passe."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from cma.core.prompts import PassphraseRequest, PasswordAnswer, PasswordRequest
from cma.core.ssh.hostkeys import HostKeyPrompt
from cma.i18n import tr
from cma.ui.icons import app_icon, icon
from cma.ui.theme import current_tokens
from cma.ui.widgets import label


def _base(parent: QWidget | None, window_title: str) -> QDialog:
    dialog = QDialog(parent)
    dialog.setWindowTitle(window_title)
    dialog.setWindowIcon(app_icon())
    dialog.setModal(True)
    dialog.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, parent is None or not parent.isVisible())
    return dialog


def confirm_host_key(parent: QWidget | None, prompt: HostKeyPrompt) -> bool:
    tokens = current_tokens()
    dialog = _base(parent, tr("Clé d'hôte SSH"))
    layout = QVBoxLayout(dialog)
    header = QHBoxLayout()
    glyph = QLabel()
    glyph.setPixmap(
        icon(
            "alert-triangle" if prompt.changed else "fingerprint",
            tokens.danger if prompt.changed else tokens.accent,
        ).pixmap(36, 36)
    )
    header.addWidget(glyph, 0, Qt.AlignmentFlag.AlignTop)
    if prompt.changed:
        text = tr(
            "<b>La clé d'hôte de {host} a changé.</b><br>Cela arrive après une réinstallation du serveur, "
            "mais peut aussi signaler une interception. Ne continuez que si vous savez pourquoi elle a changé."
        ).format(host=prompt.identity)
    else:
        text = tr(
            "<b>Premier contact avec {host}.</b><br>Vérifiez que l'empreinte ci-dessous est bien celle du serveur "
            "(commande <code>ssh-keygen -lf /etc/ssh/ssh_host_{alg}_key.pub</code> sur le serveur)."
        ).format(host=prompt.identity, alg=prompt.algorithm.replace("ssh-", ""))
    message = label(text, wrap=True)
    message.setTextFormat(Qt.TextFormat.RichText)
    header.addWidget(message, 1)
    layout.addLayout(header)
    form = QFormLayout()
    form.addRow(tr("Type de clé :"), label(prompt.algorithm, "mono", selectable=True))
    form.addRow(tr("Empreinte :"), label(prompt.fingerprint, "mono", selectable=True))
    for previous in prompt.previous_fingerprints:
        form.addRow(tr("Ancienne empreinte :"), label(previous, "mono", selectable=True))
    if prompt.via:
        form.addRow(tr("Via Cloudflare :"), label(prompt.via))
    layout.addLayout(form)
    buttons = QDialogButtonBox()
    trust = buttons.addButton(
        tr("Remplacer et continuer") if prompt.changed else tr("Faire confiance et continuer"),
        QDialogButtonBox.ButtonRole.AcceptRole,
    )
    cancel = buttons.addButton(tr("Annuler"), QDialogButtonBox.ButtonRole.RejectRole)
    (cancel if prompt.changed else trust).setDefault(True)
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    dialog.resize(560, dialog.sizeHint().height())
    return dialog.exec() == QDialog.DialogCode.Accepted


def ask_password(parent: QWidget | None, request: PasswordRequest) -> PasswordAnswer | None:
    dialog = _base(parent, tr("Mot de passe SSH"))
    layout = QVBoxLayout(dialog)
    layout.addWidget(
        label(
            tr("Profil « {name} » : mot de passe pour {target}").format(
                name=request.profile_name, target=request.target
            ),
            wrap=True,
        )
    )
    if request.error:
        layout.addWidget(label(request.error, "error"))
    field = QLineEdit()
    field.setEchoMode(QLineEdit.EchoMode.Password)
    field.setAccessibleName(tr("Mot de passe"))
    layout.addWidget(field)
    remember = QCheckBox(tr("Mémoriser dans le coffre (Gestionnaire d'identifiants)"))
    remember.setVisible(request.can_remember)
    layout.addWidget(remember)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("Se connecter"))
    buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("Annuler"))
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    field.setFocus()
    dialog.resize(440, dialog.sizeHint().height())
    if dialog.exec() != QDialog.DialogCode.Accepted or not field.text():
        return None
    return PasswordAnswer(field.text(), remember.isChecked())


def ask_passphrase(parent: QWidget | None, request: PassphraseRequest) -> str | None:
    dialog = _base(parent, tr("Phrase de passe de la clé"))
    layout = QVBoxLayout(dialog)
    layout.addWidget(
        label(
            tr("La clé {key} est chiffrée. Saisissez sa phrase de passe.").format(key=request.key_path),
            wrap=True,
        )
    )
    if request.error:
        layout.addWidget(label(request.error, "error"))
    field = QLineEdit()
    field.setEchoMode(QLineEdit.EchoMode.Password)
    layout.addWidget(field)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("Annuler"))
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    field.setFocus()
    dialog.resize(440, dialog.sizeHint().height())
    if dialog.exec() != QDialog.DialogCode.Accepted or not field.text():
        return None
    return field.text()


def ask_new_passphrase(parent: QWidget | None, window_title: str, text: str) -> str | None:
    """Nouvelle phrase de passe, saisie deux fois."""
    dialog = _base(parent, window_title)
    layout = QVBoxLayout(dialog)
    layout.addWidget(label(text, wrap=True))
    form = QFormLayout()
    first = QLineEdit()
    first.setEchoMode(QLineEdit.EchoMode.Password)
    second = QLineEdit()
    second.setEchoMode(QLineEdit.EchoMode.Password)
    form.addRow(tr("Phrase de passe :"), first)
    form.addRow(tr("Confirmation :"), second)
    layout.addLayout(form)
    error = label("", "error")
    layout.addWidget(error)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
    buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("Annuler"))

    def validate() -> None:
        if len(first.text()) < 8:
            error.setText(tr("Au moins 8 caractères."))
        elif first.text() != second.text():
            error.setText(tr("Les deux saisies diffèrent."))
        else:
            dialog.accept()

    buttons.accepted.connect(validate)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    dialog.resize(440, dialog.sizeHint().height())
    return first.text() if dialog.exec() == QDialog.DialogCode.Accepted else None
