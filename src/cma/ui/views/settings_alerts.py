"""Paramètres › Général › Alertes : canaux qui reçoivent les pannes et les retours des tunnels et des services publiés
(ntfy, Slack, Teams, Discord, webhook), avec un envoi de test. L'adresse d'un canal est rangée dans le coffre."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QTime
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QSpinBox,
    QTableWidgetItem,
    QTimeEdit,
    QVBoxLayout,
    QWidget,
)

from cma.core.alerts import KINDS, Alert, AlertError, kind_label, secret_key, send_alert
from cma.core.models import AlertChannel, Config, MaintenanceWindow
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


def weekday_name(weekday: int) -> str:
    return (
        tr("Lundi"),
        tr("Mardi"),
        tr("Mercredi"),
        tr("Jeudi"),
        tr("Vendredi"),
        tr("Samedi"),
        tr("Dimanche"),
    )[weekday % 7]


def target_text(target: str, objects: list[tuple[str, str]]) -> str:
    """Objet visé par une maintenance : « Tout le compte », le libellé connu, sinon ce que la clé permet de dire."""
    if not target:
        return tr("Tout le compte")
    known = dict(objects)
    name = known[target] if target in known else target.split(":", 1)[-1]
    return tr("Tunnel « {name} »").format(name=name) if target.startswith("tunnel:") else name


class MaintenanceDialog(QDialog):
    """Nouvelle maintenance hebdomadaire : jour, heures (locales), objet visé, libellé."""

    def __init__(self, parent: QWidget | None, objects: list[tuple[str, str]]) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Nouvelle maintenance"))
        self.setWindowIcon(app_icon())
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.day = QComboBox()
        self.day.setAccessibleName(tr("Jour"))
        for weekday in range(7):
            self.day.addItem(weekday_name(weekday), weekday)
        form.addRow(tr("Jour"), self.day)
        self.start = QTimeEdit(QTime(2, 0))
        self.start.setDisplayFormat("HH:mm")
        self.start.setAccessibleName(tr("Début"))
        self.end = QTimeEdit(QTime(4, 0))
        self.end.setDisplayFormat("HH:mm")
        self.end.setAccessibleName(tr("Fin"))
        form.addRow(tr("Début"), self.start)
        form.addRow(tr("Fin"), self.end)
        self.hint = label(
            tr("Heures locales. Si la fin est avant le début, la maintenance passe minuit."),
            "meta",
            wrap=True,
        )
        form.addRow("", self.hint)
        self.target = QComboBox()
        self.target.setAccessibleName(tr("Objet"))
        self.target.addItem(tr("Tout le compte"), "")
        for key, _name in objects:
            self.target.addItem(target_text(key, objects), key)
        form.addRow(tr("Objet visé"), self.target)
        self.name = QLineEdit()
        self.name.setAccessibleName(tr("Libellé"))
        self.name.setMaxLength(120)
        self.name.setPlaceholderText(tr("Mise à jour des serveurs…"))
        form.addRow(tr("Libellé (facultatif)"), self.name)
        layout.addLayout(form)
        buttons, ok = dialog_buttons(self, tr("Ajouter"))
        ok.clicked.connect(self.accept)
        layout.addWidget(buttons)

    def values(self) -> MaintenanceWindow:
        return MaintenanceWindow(
            weekday=int(self.day.currentData()),
            start=self.start.time().toString("HH:mm"),
            end=self.end.time().toString("HH:mm"),
            target=str(self.target.currentData() or ""),
            label=self.name.text().strip(),
        )


def ask_maintenance(parent: QWidget, objects: list[tuple[str, str]]) -> MaintenanceWindow | None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    dialog = MaintenanceDialog(parent, objects)
    return dialog.values() if dialog.exec() == QDialog.DialogCode.Accepted else None


class AlertsSection:
    def __init__(self, view: SettingsView, form: QFormLayout) -> None:
        self.view = view
        self.ctx = view.ctx
        self._loading = False
        self.channels: list[AlertChannel] = []
        self.windows: list[MaintenanceWindow] = []
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
        # Maintenance et rappels.
        form.addRow(label(tr("Maintenance et rappels"), "section"))
        form.addRow(
            label(
                tr(
                    "Pendant une maintenance, l'objet visé est relevé mais ne déclenche ni notification ni alerte. "
                    "Une panne qui dure est rappelée à intervalle régulier."
                ),
                "muted",
                wrap=True,
            )
        )
        self.repeat = QSpinBox()
        self.repeat.setRange(0, 168)
        self.repeat.setSuffix(" h")
        self.repeat.setSpecialValueText(tr("Jamais"))
        self.repeat.setAccessibleName(tr("Rappeler une panne qui dure toutes les"))
        self.repeat.valueChanged.connect(lambda value: self._set("alert_repeat_hours", value))
        form.addRow(tr("Rappeler une panne qui dure toutes les"), self.repeat)
        self.window_table = data_table(
            [tr("Jour"), tr("Début"), tr("Fin"), tr("Objet"), tr("Libellé")], tr("Maintenances prévues")
        )
        self.window_table.setMinimumHeight(120)
        for column, width in enumerate((110, 80, 80, 260)):
            self.window_table.setColumnWidth(column, width)
        self.window_table.itemSelectionChanged.connect(self._update_actions)
        form.addRow(self.window_table)
        window_row = QHBoxLayout()
        self.add_window_button = button(tr("Ajouter…"), "plus")
        self.add_window_button.clicked.connect(self.add_window)
        window_row.addWidget(self.add_window_button)
        self.remove_window_button = button(tr("Retirer"), "trash", danger=True)
        self.remove_window_button.clicked.connect(self.remove_window)
        window_row.addWidget(self.remove_window_button)
        window_row.addStretch()
        form.addRow(window_row)

    def _set(self, key: str, value: Any) -> None:
        if self._loading:
            return
        self.ctx.update_config(lambda c: setattr(c.settings, key, value))

    def load(self, config: Config) -> None:
        self._loading = True
        self.repeat.setValue(config.settings.alert_repeat_hours)
        self._load_windows(config)
        self._loading = False
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
        self.remove_window_button.setEnabled(self.selected_window() is not None)

    # --- Maintenances ------------------------------------------------------------------------------------------

    def _load_windows(self, config: Config) -> None:
        self.windows = list(config.settings.maintenance_windows)
        objects = self.view.known_objects()
        clear_items(self.window_table, len(self.windows))
        for index, window in enumerate(self.windows):
            values = (
                weekday_name(window.weekday),
                window.start,
                window.end,
                target_text(window.target, objects),
                window.label,
            )
            for column, value in enumerate(values):
                self.window_table.setItem(index, column, QTableWidgetItem(value))

    def selected_window(self) -> MaintenanceWindow | None:
        index = self.window_table.currentRow()
        if 0 <= index < len(self.windows) and self.window_table.selectedItems():
            return self.windows[index]
        return None

    def add_window(self) -> None:
        window = ask_maintenance(self.view, self.view.known_objects())
        if window is None:
            return
        self.ctx.update_config(lambda c: c.settings.maintenance_windows.append(window))
        self.status.setText(
            tr("Maintenance du {day} de {start} à {end} ajoutée.").format(
                day=weekday_name(window.weekday).lower(), start=window.start, end=window.end
            )
        )

    def remove_window(self) -> None:
        index = self.window_table.currentRow()
        if self.selected_window() is None:
            return
        self.ctx.update_config(
            lambda c: setattr(
                c.settings,
                "maintenance_windows",
                [w for i, w in enumerate(c.settings.maintenance_windows) if i != index],
            )
        )
        self.status.setText(tr("Maintenance retirée."))

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
