"""Questions posées par le moteur : identité d'un serveur SSH (D3), mot de passe (D4), phrase de passe (D5)."""

from __future__ import annotations

from pathlib import PureWindowsPath

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from cma.core.prompts import PassphraseRequest, PasswordAnswer, PasswordRequest
from cma.core.ssh.hostkeys import HostKeyPrompt
from cma.i18n import tr
from cma.ui.icons import app_icon, set_glyph
from cma.ui.widgets import copy_to_clipboard, label, title


def _base(parent: QWidget | None, window_title: str) -> QDialog:
    dialog = QDialog(parent)
    dialog.setWindowTitle(window_title)
    dialog.setWindowIcon(app_icon())
    dialog.setModal(True)
    dialog.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, parent is None or not parent.isVisible())
    return dialog


def _buttons(dialog: QDialog, action: str) -> tuple[QDialogButtonBox, QPushButton, QPushButton]:
    buttons = QDialogButtonBox()
    cancel = buttons.addButton(tr("Annuler"), QDialogButtonBox.ButtonRole.RejectRole)
    ok = buttons.addButton(action, QDialogButtonBox.ButtonRole.AcceptRole)
    ok.setProperty("role", "primary")
    buttons.rejected.connect(dialog.reject)
    return buttons, ok, cancel


def _secret_row(field: QLineEdit) -> QHBoxLayout:
    """Champ masqué suivi d'un bouton « Afficher » ; jamais de copie automatique."""
    field.setEchoMode(QLineEdit.EchoMode.Password)
    row = QHBoxLayout()
    row.addWidget(field, 1)
    toggle = QPushButton(tr("Afficher"))
    toggle.setCheckable(True)
    toggle.setAccessibleName(tr("Afficher la saisie"))

    def switch(shown: bool) -> None:
        field.setEchoMode(QLineEdit.EchoMode.Normal if shown else QLineEdit.EchoMode.Password)
        toggle.setText(tr("Masquer") if shown else tr("Afficher"))

    toggle.toggled.connect(switch)
    row.addWidget(toggle)
    return row


def _copy_row(text: str, name: str) -> QHBoxLayout:
    row = QHBoxLayout()
    value = label(text, "mono", wrap=True, selectable=True)
    value.setAccessibleName(name)
    row.addWidget(value, 1)
    copy = QPushButton(tr("Copier"))
    copy.setAccessibleName(tr("Copier : {what}").format(what=name))
    copy.clicked.connect(lambda: copy_to_clipboard(text))
    row.addWidget(copy, 0, Qt.AlignmentFlag.AlignTop)
    return row


# --- D3 — Vérifier l'identité d'un serveur SSH -----------------------------------------------------------


def key_type_label(algorithm: str) -> str:
    name = algorithm.lower()
    if "ed25519" in name:
        return "ED25519"
    if "ecdsa" in name:
        return "ECDSA"
    if "rsa" in name:
        return "RSA"
    return algorithm


def host_key_file(algorithm: str) -> str:
    """Nom du fichier de clé publique d'hôte correspondant à la clé réellement présentée."""
    kind = key_type_label(algorithm).lower()
    return f"ssh_host_{kind if kind in ('ed25519', 'ecdsa', 'rsa') else 'ed25519'}_key.pub"


def keygen_commands(algorithm: str) -> list[tuple[str, str]]:
    """Commandes à lancer sur le serveur : les deux emplacements usuels, sans deviner le système."""
    name = host_key_file(algorithm)
    windows = PureWindowsPath("C:/ProgramData/ssh") / name
    return [
        ("Linux", f"ssh-keygen -lf /etc/ssh/{name} -E sha256"),
        ("Windows", f"ssh-keygen -lf {windows} -E sha256"),
    ]


def confirm_host_key(parent: QWidget | None, prompt: HostKeyPrompt) -> bool:
    heading = (
        tr("L'identité du serveur a changé")
        if prompt.changed
        else tr("Vérifier l'identité de {host}").format(host=prompt.host)
    )
    dialog = _base(parent, heading)
    dialog.setMinimumWidth(560)
    layout = QVBoxLayout(dialog)
    layout.setSpacing(10)
    header = QHBoxLayout()
    glyph = QLabel()
    set_glyph(
        glyph,
        "alert-triangle" if prompt.changed else "fingerprint",
        "danger" if prompt.changed else "accent",
        32,
    )
    header.addWidget(glyph, 0, Qt.AlignmentFlag.AlignTop)
    header.addWidget(title(heading, "SectionTitle"), 1)
    layout.addLayout(header)
    layout.addWidget(
        label(
            tr("{target} · Type de clé : {kind}").format(
                target=prompt.identity, kind=key_type_label(prompt.algorithm)
            ),
            "mono",
            wrap=True,
            selectable=True,
        )
    )
    if prompt.via:
        layout.addWidget(label(tr("Via Cloudflare : {host}").format(host=prompt.via), "muted", wrap=True))
    readable = bool(prompt.fingerprint.strip())
    if not readable:
        layout.addWidget(label(tr("L'identité du serveur n'a pas pu être lue."), "error", wrap=True))
    elif prompt.changed:
        for previous in prompt.previous_fingerprints:
            layout.addWidget(label(tr("Ancienne empreinte"), "muted"))
            layout.addLayout(_copy_row(previous, tr("ancienne empreinte")))
        layout.addWidget(label(tr("Nouvelle empreinte"), "muted"))
        layout.addLayout(_copy_row(prompt.fingerprint, tr("nouvelle empreinte")))
        layout.addWidget(
            label(
                tr(
                    "Ce changement peut signaler un remplacement du serveur ou une interception. "
                    "Vérifiez la nouvelle empreinte par un autre canal avant de continuer."
                ),
                "warning",
                wrap=True,
            )
        )
    else:
        layout.addWidget(label(tr("Empreinte SHA-256"), "muted"))
        layout.addLayout(_copy_row(prompt.fingerprint, tr("empreinte")))
    if readable:
        layout.addWidget(label(tr("Vérifiez cette empreinte sur le serveur avec :"), wrap=True))
        for system, command in keygen_commands(prompt.algorithm):
            layout.addWidget(label(system, "muted"))
            layout.addLayout(_copy_row(command, tr("commande {system}").format(system=system)))
        if not prompt.changed:
            layout.addWidget(
                label(
                    tr("Ne continuez que si elle correspond à celle fournie par votre administrateur."),
                    "muted",
                    wrap=True,
                )
            )
    layout.addStretch()
    buttons, trust, cancel = _buttons(
        dialog, tr("Remplacer et continuer") if prompt.changed else tr("Faire confiance et continuer")
    )
    trust.setEnabled(readable)
    trust.setAutoDefault(False)
    trust.clicked.connect(dialog.accept)
    # Entrée n'accorde jamais la confiance : c'est « Annuler » qui a le focus et le rôle par défaut.
    cancel.setDefault(True)
    layout.addWidget(buttons)
    dialog.resize(680, 540 if prompt.changed else 480)
    cancel.setFocus()
    return dialog.exec() == QDialog.DialogCode.Accepted


# --- D4 — Mot de passe SSH ---------------------------------------------------------------------------------


def ask_password(parent: QWidget | None, request: PasswordRequest) -> PasswordAnswer | None:
    heading = tr("Connexion SSH à {name}").format(name=request.profile_name)
    dialog = _base(parent, heading)
    layout = QVBoxLayout(dialog)
    layout.setSpacing(10)
    layout.addWidget(title(heading, "SectionTitle"))
    layout.addWidget(
        label(
            tr("Mot de passe pour {target}").format(target=request.target), "mono", wrap=True, selectable=True
        )
    )
    if request.error:
        layout.addWidget(label(request.error, "error", wrap=True))
    field = QLineEdit()
    field.setAccessibleName(tr("Mot de passe"))
    form = QFormLayout()
    form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
    form.addRow(tr("Mot de passe"), _secret_row(field))
    layout.addLayout(form)
    remember = QCheckBox(tr("Mémoriser dans le coffre"))
    remember.setEnabled(request.can_remember)
    layout.addWidget(remember)
    if not request.can_remember:
        layout.addWidget(
            label(tr("Le mot de passe sera utilisé pour cette connexion uniquement."), "muted", wrap=True)
        )
    layout.addStretch()
    buttons, connect, _cancel = _buttons(dialog, tr("Se connecter"))
    connect.setDefault(True)
    connect.clicked.connect(dialog.accept)
    connect.setEnabled(False)
    field.textChanged.connect(lambda text: connect.setEnabled(bool(text)))
    layout.addWidget(buttons)
    dialog.resize(520, 300)
    field.setFocus()
    if dialog.exec() != QDialog.DialogCode.Accepted or not field.text():
        return None
    return PasswordAnswer(field.text(), remember.isChecked() and request.can_remember)


# --- D5 — Phrase de passe ----------------------------------------------------------------------------------


def ask_passphrase(parent: QWidget | None, request: PassphraseRequest) -> str | None:
    name = PureWindowsPath(request.key_path).name or request.key_path
    heading = tr("Déverrouiller la clé « {name} »").format(name=name)
    dialog = _base(parent, heading)
    layout = QVBoxLayout(dialog)
    layout.setSpacing(10)
    layout.addWidget(title(heading, "SectionTitle"))
    layout.addWidget(
        label(tr("Cette clé SSH est protégée : {path}").format(path=request.key_path), "muted", wrap=True)
    )
    if request.error:
        layout.addWidget(label(request.error, "error", wrap=True))
    field = QLineEdit()
    field.setAccessibleName(tr("Phrase de passe"))
    form = QFormLayout()
    form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
    form.addRow(tr("Phrase de passe"), _secret_row(field))
    layout.addLayout(form)
    layout.addStretch()
    buttons, unlock, _cancel = _buttons(dialog, tr("Déverrouiller"))
    unlock.setDefault(True)
    unlock.clicked.connect(dialog.accept)
    unlock.setEnabled(False)
    field.textChanged.connect(lambda text: unlock.setEnabled(bool(text)))
    layout.addWidget(buttons)
    dialog.resize(560, 260)
    field.setFocus()
    if dialog.exec() != QDialog.DialogCode.Accepted or not field.text():
        return None
    return field.text()


def ask_new_passphrase(parent: QWidget | None, window_title: str, text: str) -> str | None:
    """Création d'une phrase de passe, saisie deux fois ; le minimum de 8 caractères ne vaut qu'ici."""
    dialog = _base(parent, window_title)
    layout = QVBoxLayout(dialog)
    layout.setSpacing(10)
    layout.addWidget(title(window_title, "SectionTitle"))
    layout.addWidget(label(text, "muted", wrap=True))
    form = QFormLayout()
    form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
    first = QLineEdit()
    first.setEchoMode(QLineEdit.EchoMode.Password)
    first.setAccessibleName(tr("Phrase de passe"))
    second = QLineEdit()
    second.setEchoMode(QLineEdit.EchoMode.Password)
    second.setAccessibleName(tr("Confirmation"))
    form.addRow(tr("Phrase de passe"), first)
    form.addRow(tr("Confirmation"), second)
    layout.addLayout(form)
    layout.addWidget(
        label(tr("Utilisez au moins 8 caractères. Conservez cette phrase en lieu sûr."), "muted", wrap=True)
    )
    error = label("", "error", wrap=True)
    layout.addWidget(error)
    layout.addStretch()
    buttons = QDialogButtonBox()
    buttons.addButton(tr("Annuler"), QDialogButtonBox.ButtonRole.RejectRole)
    proceed = buttons.addButton(tr("Continuer"), QDialogButtonBox.ButtonRole.AcceptRole)
    proceed.setProperty("role", "primary")

    def validate() -> None:
        if len(first.text()) < 8:
            error.setText(tr("Utilisez au moins 8 caractères."))
        elif first.text() != second.text():
            error.setText(tr("Les deux phrases de passe ne correspondent pas."))
        else:
            dialog.accept()

    buttons.accepted.connect(validate)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    dialog.resize(560, 360)
    first.setFocus()
    return first.text() if dialog.exec() == QDialog.DialogCode.Accepted else None
