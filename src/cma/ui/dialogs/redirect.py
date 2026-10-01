"""Nouvelle redirection ou modification d'une redirection SSH (spécification §4.14, D6).

Trois types : locale (-L, vers une cible vue du serveur), proxy SOCKS (-D, cibles choisies par l'application
cliente) et inverse (-R, le serveur écoute et renvoie vers ce poste). Depuis un port découvert, le type est
forcément « locale ».
"""

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

from cma.core.models import ForwardKind, SavedForward, new_id
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


def kinds() -> list[tuple[str, ForwardKind]]:
    return [
        (tr("Locale : un port de ce poste vers une cible vue du serveur"), "local"),
        (tr("Proxy SOCKS : les applications choisissent leur cible, qui sort depuis le serveur"), "socks"),
        (tr("Inverse : le serveur écoute et renvoie vers ce poste"), "remote"),
    ]


def _int(text: str) -> int | None:
    text = text.strip()
    return int(text) if text.isdigit() else None


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
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        self.form = form
        self.kind = QComboBox()
        self.kind.setAccessibleName(tr("Type de redirection"))
        for text, value in kinds():
            self.kind.addItem(text, value)
        self.kind.setCurrentIndex(max(0, self.kind.findData(existing.kind if existing else "local")))
        self.kind.setEnabled(remote is None)
        form.addRow(tr("Type"), self.kind)
        self.help = label("", "muted", wrap=True)
        form.addRow(self.help)

        self.remote_host = QLineEdit(
            existing.remote_host if existing else (remote.forward_host if remote else "127.0.0.1")
        )
        initial_remote = existing.remote_port if existing else (remote.port if remote else None)
        self.remote_port = QLineEdit(str(initial_remote) if initial_remote else "")
        self.remote_port.setValidator(QIntValidator(1, 65535, self))
        self.destination = QWidget()
        destination = QHBoxLayout(self.destination)
        destination.setContentsMargins(0, 0, 0, 0)
        destination.addWidget(self.remote_host, 3)
        destination.addWidget(self.remote_port, 1)
        self.destination_label = label(tr("Hôte vu du serveur · Port distant"))
        form.addRow(self.destination_label, self.destination)
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
        # Inverse : la cible est un service joignable depuis ce poste, pas un port libre.
        is_remote = existing is not None and existing.kind == "remote"
        self.target_host = QLineEdit(existing.local_host if existing and is_remote else "127.0.0.1")
        self.target_host.setAccessibleName(tr("Hôte cible depuis ce poste"))
        self.target_port = QLineEdit(str(existing.local_port) if existing and is_remote else "")
        self.target_port.setValidator(QIntValidator(1, 65535, self))
        self.target_port.setAccessibleName(tr("Port cible"))
        self.target = QWidget()
        target_row = QHBoxLayout(self.target)
        target_row.setContentsMargins(0, 0, 0, 0)
        target_row.addWidget(self.target_host, 3)
        target_row.addWidget(self.target_port, 1)
        form.addRow(tr("Cible depuis ce poste · Port"), self.target)

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
        for widget in (self.remote_host, self.remote_port, self.target_host, self.target_port):
            widget.textChanged.connect(self._refresh)
        self.local_port.changed.connect(self._refresh)
        self.local_port.edit.textChanged.connect(self._refresh)
        self.save.toggled.connect(self._refresh)
        self.start.toggled.connect(self._refresh)
        self.kind.currentIndexChanged.connect(self._kind_changed)
        self._kind_changed()
        self.resize(640, self.sizeHint().height())

    def current_kind(self) -> ForwardKind:
        return self.kind.currentData() or "local"

    def _kind_changed(self, *_args: object) -> None:
        kind = self.current_kind()
        self.form.setRowVisible(self.destination, kind != "socks")
        self.form.setRowVisible(self.local_port, kind != "remote")
        self.form.setRowVisible(self.target, kind == "remote")
        if kind == "remote":
            self.destination_label.setText(tr("Adresse d'écoute sur le serveur · Port"))
            if not self.existing and self.remote_host.text() == "127.0.0.1":
                self.remote_host.setText("localhost")
            self.help.setText(
                tr(
                    "Le serveur ouvre ce port ; chaque connexion qui y arrive est renvoyée vers la cible ci-dessous, "
                    "jointe depuis ce poste. « localhost » le limite au serveur lui-même."
                )
            )
        elif kind == "socks":
            self.help.setText(
                tr(
                    "Réglez le navigateur ou l'application sur le proxy SOCKS 127.0.0.1 et ce port : les connexions "
                    "sortiront depuis le serveur."
                )
            )
        else:
            self.destination_label.setText(tr("Hôte vu du serveur · Port distant"))
            if not self.existing and self.remote_host.text() == "localhost":
                self.remote_host.setText("127.0.0.1")
            self.help.setText(tr("La destination est vue depuis le serveur SSH."))
        self._refresh()

    def _ports(self) -> tuple[int | None, int | None]:
        """(port local, ou port cible pour une redirection inverse ; port distant) selon le type."""
        kind = self.current_kind()
        local = self.local_port.value() if kind != "remote" else _int(self.target_port.text())
        remote = _int(self.remote_port.text()) if kind != "socks" else None
        return local, remote

    def _refresh(self, *_args: object) -> None:
        kind = self.current_kind()
        local, remote_port = self._ports()
        where = tr(" depuis {server}").format(server=self.server) if self.server else ""
        local_text = f"127.0.0.1:{local if local is not None else '?'}"
        if kind == "socks":
            text = tr("SOCKS sur {local}, sorties{where}").format(local=local_text, where=where)
        elif kind == "remote":
            remote = (
                format_host_port(self.remote_host.text().strip() or "?", remote_port) if remote_port else "?"
            )
            target = format_host_port(self.target_host.text().strip() or "?", local) if local else "?"
            text = tr("Serveur : {remote} → {target} sur ce poste").format(remote=remote, target=target)
        else:
            target = (
                format_host_port(self.remote_host.text().strip() or "?", remote_port) if remote_port else "?"
            )
            text = tr("Local : {local} → {target}{where}").format(
                local=local_text, target=target, where=where
            )
        self.summary.setText(text)
        if self.existing is not None:
            self.ok_button.setText(tr("Enregistrer"))
            self.ok_button.setEnabled(True)
            return
        save, start = self.save.isChecked(), self.start.isChecked()
        if save and start:
            button_text = tr("Créer et démarrer")
        elif save:
            button_text = tr("Créer")
        elif start:
            button_text = tr("Démarrer")
        else:
            button_text = tr("Choisissez au moins une action.")
        self.ok_button.setText(button_text)
        self.ok_button.setEnabled(save or start)

    def _accept(self) -> None:
        kind = self.current_kind()
        local, remote_port = self._ports()
        if local is None or (kind != "socks" and remote_port is None):
            self.error.setText(tr("Ports distant et local requis."))
            return
        try:
            forward = SavedForward(
                id=self.existing.id if self.existing else new_id(),
                kind=kind,
                remote_host=self.remote_host.text() if kind != "socks" else "127.0.0.1",
                remote_port=remote_port,
                local_host=self.target_host.text() if kind == "remote" else "127.0.0.1",
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
