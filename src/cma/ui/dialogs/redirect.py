"""Nouvelle redirection ou modification d'une redirection SSH (spécification §4.14, D6)."""

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
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from cma.core.models import SavedForward, new_id
from cma.core.netutil import format_host_port
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
    """La destination est vue depuis le serveur SSH ; le port local est vérifié en direct."""

    def __init__(
        self,
        parent: QWidget | None,
        ctx: GuiContext,
        *,
        remote: RemotePort | None = None,
        existing: SavedForward | None = None,
        server: str = "",
        active: bool = False,
    ) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.existing = existing
        self.server = server
        if existing:
            heading = tr("Modifier la redirection")
        elif remote is not None:
            heading = (
                tr("Rediriger le port {port} de {server}").format(port=remote.port, server=server)
                if server
                else tr("Rediriger le port {port}").format(port=remote.port)
            )
        else:
            heading = tr("Nouvelle redirection")
        self.setWindowTitle(heading)
        self.setWindowIcon(app_icon())
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(label(tr("La destination est vue depuis le serveur SSH."), "muted", wrap=True))
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        self.remote_host = QLineEdit(
            existing.remote_host if existing else (remote.forward_host if remote else "127.0.0.1")
        )
        self.remote_port = QLineEdit(
            str(existing.remote_port if existing else (remote.port if remote else ""))
        )
        self.remote_port.setValidator(QIntValidator(1, 65535, self))
        destination = QHBoxLayout()
        destination.addWidget(self.remote_host, 3)
        destination.addWidget(self.remote_port, 1)
        form.addRow(tr("Hôte vu du serveur · Port distant"), destination)
        self.remote_host.setAccessibleName(tr("Hôte vu du serveur"))
        self.remote_port.setAccessibleName(tr("Port distant"))
        if remote is not None and not existing and ("0.0.0.0" in remote.bind or "::" in remote.bind):
            form.addRow(
                label(
                    tr(
                        "Le service écoute sur toutes les interfaces ; l'accès depuis ce serveur utilisera {host}."
                    ).format(host=remote.forward_host),
                    "muted",
                    wrap=True,
                )
            )
        preferred = existing.local_port if existing else (remote.port if remote else None)
        self.local_port = PortField(
            lambda p: ctx.manager.suggest_local_port(p or preferred), lambda: "127.0.0.1"
        )
        if existing:
            self.local_port.set_value(existing.local_port)
        else:
            self.local_port.set_value(ctx.manager.suggest_local_port(preferred))
        form.addRow(tr("Port local"), self.local_port)
        self.scheme = QComboBox()
        self.scheme.addItem(tr("Aucun (TCP)"), None)
        self.scheme.addItem("HTTP", "http")
        self.scheme.addItem("HTTPS", "https")
        scheme = existing.scheme if existing else (remote.scheme if remote else None)
        self.scheme.setCurrentIndex(max(0, self.scheme.findData(scheme)))
        self.label_edit = QLineEdit(existing.label if existing else (remote.display_name if remote else ""))
        details = QHBoxLayout()
        details.addWidget(self.scheme, 1)
        details.addWidget(self.label_edit, 2)
        self.scheme.setAccessibleName(tr("Protocole web"))
        self.label_edit.setAccessibleName(tr("Libellé"))
        form.addRow(tr("Protocole web · Libellé"), details)
        layout.addLayout(form)
        checks = QHBoxLayout()
        self.save = QCheckBox(tr("Enregistrer dans le profil"))
        self.save.setChecked(True)
        self.save.setVisible(existing is None)
        self.start = QCheckBox(tr("Démarrer maintenant"))
        self.start.setChecked(existing is None)
        self.start.setVisible(existing is None)
        checks.addWidget(self.save)
        checks.addWidget(self.start)
        checks.addStretch()
        layout.addLayout(checks)
        self.summary = label("", "mono", wrap=True, selectable=True)
        layout.addWidget(self.summary)
        if existing is not None and active:
            layout.addWidget(
                label(
                    tr("Les changements prendront effet au prochain démarrage de la redirection."),
                    "muted",
                    wrap=True,
                )
            )
        self.error = label("", "error", wrap=True)
        layout.addWidget(self.error)
        buttons = QDialogButtonBox()
        self.cancel_button = buttons.addButton(tr("Annuler"), QDialogButtonBox.ButtonRole.RejectRole)
        self.ok_button: QPushButton = buttons.addButton(tr("Valider"), QDialogButtonBox.ButtonRole.AcceptRole)
        self.ok_button.setProperty("role", "primary")
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.choice: RedirectChoice | None = None
        for widget in (self.remote_host, self.remote_port):
            widget.textChanged.connect(self._refresh)
        self.local_port.changed.connect(self._refresh)
        self.local_port.edit.textChanged.connect(self._refresh)
        self.save.toggled.connect(self._refresh)
        self.start.toggled.connect(self._refresh)
        self._refresh()
        self.resize(640, self.sizeHint().height())

    def _refresh(self, *_args: object) -> None:
        local = self.local_port.value()
        remote_port = self.remote_port.text().strip()
        target = format_host_port(
            self.remote_host.text().strip() or "?", int(remote_port) if remote_port.isdigit() else 0
        )
        where = tr(" depuis {server}").format(server=self.server) if self.server else ""
        self.summary.setText(
            tr("Local : {local} → {target}{where}").format(
                local=f"127.0.0.1:{local if local is not None else '?'}",
                target=target if remote_port.isdigit() else "?",
                where=where,
            )
        )
        if self.existing is not None:
            self.ok_button.setText(tr("Enregistrer"))
            self.ok_button.setEnabled(True)
            return
        save, start = self.save.isChecked(), self.start.isChecked()
        if save and start:
            text = tr("Créer et démarrer")
        elif save:
            text = tr("Créer")
        elif start:
            text = tr("Démarrer")
        else:
            text = tr("Choisissez au moins une action.")
        self.ok_button.setText(text)
        self.ok_button.setEnabled(save or start)

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
