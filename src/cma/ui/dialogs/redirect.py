"""Création ou modification d'une redirection SSH."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import ValidationError
from PySide6.QtGui import QIntValidator
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

from cma.core.models import SavedForward, new_id
from cma.core.ssh.discovery import RemotePort
from cma.i18n import tr
from cma.ui.context import GuiContext, describe_validation_error
from cma.ui.icons import app_icon
from cma.ui.widgets import PortField, label


@dataclass(frozen=True)
class RedirectChoice:
    forward: SavedForward
    save: bool
    start: bool


class RedirectDialog(QDialog):
    def __init__(
        self,
        parent: QWidget | None,
        ctx: GuiContext,
        *,
        remote: RemotePort | None = None,
        existing: SavedForward | None = None,
    ) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.existing = existing
        self.setWindowTitle(tr("Modifier la redirection") if existing else tr("Nouvelle redirection"))
        self.setWindowIcon(app_icon())
        layout = QVBoxLayout(self)
        layout.addWidget(
            label(
                tr(
                    "Le port local de ce poste mènera au service vu depuis le serveur SSH (hôte et port ci-dessous)."
                ),
                "muted",
                wrap=True,
            )
        )
        form = QFormLayout()
        self.remote_host = QLineEdit(
            existing.remote_host if existing else (remote.forward_host if remote else "127.0.0.1")
        )
        self.remote_port = QLineEdit(
            str(existing.remote_port if existing else (remote.port if remote else ""))
        )
        self.remote_port.setValidator(QIntValidator(1, 65535, self))
        preferred = existing.local_port if existing else (remote.port if remote else None)
        self.local_port = PortField(
            lambda p: ctx.manager.suggest_local_port(p or preferred), lambda: "127.0.0.1"
        )
        if existing:
            self.local_port.set_value(existing.local_port)
        else:
            self.local_port.set_value(ctx.manager.suggest_local_port(preferred))
        self.scheme = QComboBox()
        self.scheme.addItem(tr("Aucun (TCP)"), None)
        self.scheme.addItem("HTTP", "http")
        self.scheme.addItem("HTTPS", "https")
        scheme = existing.scheme if existing else (remote.scheme if remote else None)
        self.scheme.setCurrentIndex(max(0, self.scheme.findData(scheme)))
        self.label_edit = QLineEdit(existing.label if existing else (remote.display_name if remote else ""))
        form.addRow(tr("Hôte vu du serveur :"), self.remote_host)
        form.addRow(tr("Port distant :"), self.remote_port)
        form.addRow(tr("Port local :"), self.local_port)
        form.addRow(tr("Protocole web :"), self.scheme)
        form.addRow(tr("Libellé :"), self.label_edit)
        layout.addLayout(form)
        self.save = QCheckBox(tr("Enregistrer dans le profil"))
        self.save.setChecked(True)
        self.save.setVisible(existing is None)
        self.start = QCheckBox(tr("Démarrer maintenant"))
        self.start.setChecked(existing is None)
        layout.addWidget(self.save)
        layout.addWidget(self.start)
        self.error = label("", "error", wrap=True)
        layout.addWidget(self.error)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("Valider"))
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("Annuler"))
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.choice: RedirectChoice | None = None
        self.resize(480, self.sizeHint().height())

    def _accept(self) -> None:
        local = self.local_port.value()
        remote_port = self.remote_port.text().strip()
        if local is None or not remote_port.isdigit():
            self.error.setText(tr("Ports distant et local requis."))
            return
        try:
            forward = SavedForward(
                id=self.existing.id if self.existing else new_id(),
                remote_host=self.remote_host.text(),
                remote_port=int(remote_port),
                local_port=local,
                scheme=self.scheme.currentData(),
                label=self.label_edit.text().strip(),
            )
        except ValidationError as exc:
            self.error.setText(describe_validation_error(exc))
            return
        self.choice = RedirectChoice(
            forward, self.save.isChecked() or self.existing is not None, self.start.isChecked()
        )
        self.accept()
