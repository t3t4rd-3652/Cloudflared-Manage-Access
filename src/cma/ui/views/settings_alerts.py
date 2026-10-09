"""Paramètres › Général › Alertes : canaux qui reçoivent les pannes et les retours des tunnels et des services publiés
(ntfy, Slack, Teams, Discord, webhook), avec un envoi de test. L'adresse d'un canal est rangée dans le coffre."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.alerts import KINDS, Alert, AlertError, kind_label, secret_key, send_alert
from cma.core.models import AlertChannel, Config
from cma.i18n import tr
from cma.ui.icons import app_icon
from cma.ui.views.cloud.helpers import data_table, dialog_buttons
from cma.ui.views.common import confirm
from cma.ui.widgets import SecretField, button, clear_items, label

if TYPE_CHECKING:
    from cma.ui.views.settings import SettingsView

URL_HINTS = {
    "ntfy": "https://ntfy.sh/mon-sujet-secret",
    "slack": "https://hooks.slack.com/services/…",
    "teams": "https://….logic.azure.com/workflows/…",
    "discord": "https://discord.com/api/webhooks/…",
    "webhook": "https://exemple.fr/alertes",
}


class ChannelDialog(QDialog):
    """Nouveau canal : nom, type, adresse (secrète), retours à la normale ou pannes seulement."""

    def __init__(self, parent: QWidget | None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Nouveau canal d'alerte"))
        self.setWindowIcon(app_icon())
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.name = QLineEdit()
        self.name.setPlaceholderText(tr("Téléphone, équipe infra…"))
        form.addRow(tr("Nom"), self.name)
        self.kind = QComboBox()
        for kind in KINDS:
            self.kind.addItem(kind_label(kind), kind)
        self.kind.currentIndexChanged.connect(self._hint)
        form.addRow(tr("Type"), self.kind)
        self.url = SecretField(tr("adresse du canal"), subject=tr("adresse du canal"))
        form.addRow(tr("Adresse"), self.url)
        self.hint = label("", "meta", wrap=True)
        form.addRow("", self.hint)
        self.recoveries = QCheckBox(tr("Prévenir aussi des retours à la normale"))
        self.recoveries.setChecked(True)
        form.addRow("", self.recoveries)
        layout.addLayout(form)
        self.error = label("", "error", wrap=True)
        layout.addWidget(self.error)
        buttons, ok = dialog_buttons(self, tr("Ajouter"))
        ok.clicked.connect(self._accept)
        layout.addWidget(buttons)
        self._hint()

    def _hint(self) -> None:
        kind = str(self.kind.currentData())
        text = tr("Exemple : {url}").format(url=URL_HINTS.get(kind, ""))
        if kind == "ntfy":
            text += " " + tr(
                "Choisissez un sujet difficile à deviner : quiconque le connaît lit vos alertes."
            )
        self.hint.setText(text)

    def _accept(self) -> None:
        if not self.name.text().strip():
            self.error.setText(tr("Donnez un nom au canal."))
        elif not self.url.text().strip().lower().startswith(("https://", "http://")):
            self.error.setText(tr("Adresse invalide : elle doit commencer par https://."))
        else:
            self.accept()

    def values(self) -> tuple[AlertChannel, str]:
        channel = AlertChannel(
            name=self.name.text().strip(),
            kind=self.kind.currentData(),
            recoveries=self.recoveries.isChecked(),
        )
        return channel, self.url.text().strip()


def ask_channel(parent: QWidget) -> tuple[AlertChannel, str] | None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    dialog = ChannelDialog(parent)
    return dialog.values() if dialog.exec() == QDialog.DialogCode.Accepted else None


class AlertsSection:
    def __init__(self, view: SettingsView, form: QFormLayout) -> None:
        self.view = view
        self.ctx = view.ctx
        self.channels: list[AlertChannel] = []
        self.table = data_table([tr("Nom"), tr("Type"), tr("Retours"), tr("Actif")], tr("Canaux d'alerte"))
        self.table.setMinimumHeight(140)
        self.table.itemSelectionChanged.connect(self._update_actions)
        self.table.itemDoubleClicked.connect(lambda _item: self.toggle_enabled())
        form.addRow(self.table)
        row = QHBoxLayout()
        add = button(tr("Ajouter un canal…"), "plus")
        add.clicked.connect(self.add)
        row.addWidget(add)
        self.test_button = button(tr("Envoyer un test"), "bell")
        self.test_button.clicked.connect(self.send_test)
        row.addWidget(self.test_button)
        self.toggle_button = button(tr("Activer ou suspendre"), "player-stop")
        self.toggle_button.clicked.connect(self.toggle_enabled)
        row.addWidget(self.toggle_button)
        self.remove_button = button(tr("Supprimer…"), "trash", danger=True)
        self.remove_button.clicked.connect(self.remove)
        row.addWidget(self.remove_button)
        row.addStretch()
        form.addRow(row)
        self.status = label("", "meta", wrap=True)
        form.addRow(self.status)

    def load(self, config: Config) -> None:
        self.channels = list(config.settings.alert_channels)
        selected = self.selected()
        clear_items(self.table, len(self.channels))
        for index, channel in enumerate(self.channels):
            values = (
                channel.name,
                kind_label(channel.kind),
                tr("Oui") if channel.recoveries else tr("Non"),
                tr("Oui") if channel.enabled else tr("Suspendu"),
            )
            for column, value in enumerate(values):
                self.table.setItem(index, column, QTableWidgetItem(value))
        if selected is not None:
            for index, channel in enumerate(self.channels):
                if channel.id == selected.id:
                    self.table.selectRow(index)
        self._update_actions()

    def selected(self) -> AlertChannel | None:
        index = self.table.currentRow()
        return (
            self.channels[index] if 0 <= index < len(self.channels) and self.table.selectedItems() else None
        )

    def _update_actions(self) -> None:
        chosen = self.selected() is not None
        for widget in (self.test_button, self.toggle_button, self.remove_button):
            widget.setEnabled(chosen)

    def add(self) -> None:
        answer = ask_channel(self.view)
        if answer is None:
            return
        channel, url = answer
        self.ctx.core.secrets.set(secret_key(channel.id), url)
        self.ctx.update_config(lambda c: c.settings.alert_channels.append(channel))
        self.status.setText(
            tr("Canal « {name} » ajouté : « Envoyer un test » pour le vérifier.").format(name=channel.name)
        )

    def toggle_enabled(self) -> None:
        channel = self.selected()
        if channel is None:
            return

        def apply(config: Config) -> None:
            for item in config.settings.alert_channels:
                if item.id == channel.id:
                    item.enabled = not item.enabled

        self.ctx.update_config(apply)

    def remove(self) -> None:
        channel = self.selected()
        if channel is None or not confirm(
            self.view,
            tr("Supprimer le canal « {name} » ?").format(name=channel.name),
            tr("Il ne recevra plus d'alertes ; son adresse est retirée du coffre."),
            tr("Supprimer"),
        ):
            return
        self.ctx.core.secrets.delete(secret_key(channel.id))
        self.ctx.update_config(
            lambda c: setattr(
                c.settings, "alert_channels", [i for i in c.settings.alert_channels if i.id != channel.id]
            )
        )
        self.status.setText(tr("Canal « {name} » supprimé.").format(name=channel.name))

    def send_test(self) -> None:
        channel = self.selected()
        url = self.ctx.core.secrets.get(secret_key(channel.id)) if channel is not None else None
        if channel is None or not url:
            self.status.setText(
                tr("Adresse du canal introuvable dans le coffre : supprimez-le puis ajoutez-le.")
            )
            return
        alert = Alert(
            tr("CMA — test d'alerte"),
            tr("Ce canal recevra les pannes et les retours de vos services."),
            "info",
        )
        self.test_button.setEnabled(False)
        self.status.setText(tr("Envoi du test à « {name} »…").format(name=channel.name))

        async def run() -> None:
            await asyncio.to_thread(send_alert, channel.kind, url, alert)

        def done(_result: object) -> None:
            self._update_actions()
            self.status.setText(tr("Test envoyé à « {name} ».").format(name=channel.name))

        def failed(error: BaseException) -> None:
            self._update_actions()
            message = str(error) if isinstance(error, AlertError) else repr(error)
            self.status.setText(tr("Échec du test : {error}").format(error=message))

        self.ctx.run(run(), done, failed)
