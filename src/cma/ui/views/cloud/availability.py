"""Disponibilité (Outils) : taux sur 7 et 30 jours, temps de réponse et incidents de chaque tunnel et service publié,
lus dans le journal tenu par la surveillance (CMA ouvert et tâche planifiée)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QDialog, QHBoxLayout, QSplitter, QTableWidgetItem, QVBoxLayout, QWidget

from cma.core.availability import AvailabilityLog, Incident, Stats
from cma.i18n import tr
from cma.ui.icons import app_icon
from cma.ui.theme import current_tokens, status_colors
from cma.ui.views.cloud.access_log import request_time
from cma.ui.views.cloud.helpers import data_table
from cma.ui.widgets import button, clear_items, label, title


def percent(stats: Stats) -> str:
    if stats.uptime is None:
        return "—"
    value = stats.uptime * 100
    return f"{value:.0f} %" if value in (0, 100) else f"{value:.2f} %"


def uptime_tone(stats: Stats) -> str:
    if stats.uptime is None:
        return "neutral"
    return "success" if stats.uptime >= 0.999 else "warning" if stats.uptime >= 0.98 else "danger"


def duration_text(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    if minutes < 60:
        return tr("{n} min").format(n=max(1, minutes))
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return tr("{h} h {m:02d}").format(h=hours, m=minutes)
    return tr("{d} j {h} h").format(d=hours // 24, h=hours % 24)


def state_text(state: str) -> str:
    return {
        "down": tr("Hors ligne"),
        "degraded": tr("Dégradé"),
        "origin_down": tr("Service injoignable"),
        "no_connector": tr("Aucun connecteur"),
        "not_found": tr("Nom introuvable"),
    }.get(state, state)


class AvailabilityDialog(QDialog):
    def __init__(self, parent: QWidget | None, path: Path) -> None:
        super().__init__(parent)
        self.log = AvailabilityLog(path)
        self.keys = self.log.keys()
        self.setWindowTitle(tr("Disponibilité"))
        self.setWindowIcon(app_icon())
        self.resize(1000, 600)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Disponibilité des tunnels et des services"), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Relevés de la surveillance (toutes les 5 minutes pour les tunnels, 15 pour les services, CMA "
                    "ouvert ou fermé), gardés 90 jours. Un test « sans réponse » (réseau de ce poste) n'est pas compté."
                ),
                "muted",
                wrap=True,
            )
        )
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = data_table(
            [
                tr("Objet"),
                tr("Type"),
                tr("7 jours"),
                tr("30 jours"),
                tr("Temps moyen"),
                tr("Incidents (30 j)"),
            ],
            tr("Disponibilité par objet"),
        )
        for column, width in enumerate((300, 90, 100, 100, 120)):
            self.table.horizontalHeader().resizeSection(column, width)
        self.table.itemSelectionChanged.connect(self._show_incidents)
        splitter.addWidget(self.table)
        self.incidents = data_table(
            [tr("Début"), tr("Fin"), tr("Durée"), tr("Cause"), tr("Objet")], tr("Incidents")
        )
        for column, width in enumerate((140, 140, 100, 180)):
            self.incidents.horizontalHeader().resizeSection(column, width)
        splitter.addWidget(self.incidents)
        layout.addWidget(splitter, 1)
        self.empty = label(
            tr("Aucun relevé pour l'instant : la surveillance remplit ce tableau au fil des tests."), "muted"
        )
        layout.addWidget(self.empty)
        footer = QHBoxLayout()
        self.all_button = button(tr("Tous les incidents"), "history")
        self.all_button.clicked.connect(lambda: self.fill_incidents(None))
        footer.addWidget(self.all_button)
        footer.addStretch()
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)
        self._fill()

    def _fill(self) -> None:
        tokens = current_tokens()
        clear_items(self.table, len(self.keys))
        for row, key in enumerate(self.keys):
            week, month = self.log.stats(key, 7), self.log.stats(key, 30)
            mean = f"{month.mean_ms:.0f} ms" if month.mean_ms is not None else "—"
            kind = tr("Tunnel") if key.startswith("tunnel:") else tr("Service")
            count = len(self.log.history(key, 30))
            values = (self.log.label(key), kind, percent(week), percent(month), mean, str(count))
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column in (2, 3):
                    stats = week if column == 2 else month
                    item.setForeground(QBrush(QColor(status_colors(uptime_tone(stats), tokens)[0])))
                    item.setToolTip(tr("{n} tests").format(n=stats.checks))
                if column == 4 and month.max_ms is not None:
                    item.setToolTip(tr("Maximum : {ms:.0f} ms").format(ms=month.max_ms))
                self.table.setItem(row, column, item)
        self.table.setVisible(bool(self.keys))
        self.empty.setVisible(not self.keys)
        self.fill_incidents(None)

    def _show_incidents(self) -> None:
        row = self.table.currentRow()
        self.fill_incidents(self.keys[row] if 0 <= row < len(self.keys) else None)

    def fill_incidents(self, key: str | None) -> None:
        rows: list[Incident] = self.log.history(key)
        tokens = current_tokens()
        clear_items(self.incidents, len(rows))
        for index, incident in enumerate(rows):
            values = (
                request_time(incident.started),
                request_time(incident.ended) if incident.ended else tr("en cours"),
                duration_text(incident.duration()),
                state_text(incident.state),
                incident.label,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 1 and incident.open:
                    item.setForeground(QBrush(QColor(status_colors("danger", tokens)[0])))
                self.incidents.setItem(index, column, item)


def show_availability(parent: QWidget, path: Path) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    AvailabilityDialog(parent, path).exec()
