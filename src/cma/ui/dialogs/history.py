"""Historique des sessions : un résumé par accès sur la période choisie, puis le détail des sessions.

Les accès qui décrochent le plus viennent en tête ; la disponibilité est la part du temps passée à l'écoute.
"""

from __future__ import annotations

from datetime import timedelta

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.history import ProfileStats, SessionRecord
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.format import human_bytes, human_duration, short_datetime
from cma.ui.icons import app_icon
from cma.ui.theme import current_tokens, status_colors
from cma.ui.views.common import confirm
from cma.ui.widgets import button, clear_items, label, title

Key = tuple[str, str | None]
KEY_ROLE = 256


def periods() -> list[tuple[str, timedelta | None]]:
    return [
        (tr("7 derniers jours"), timedelta(days=7)),
        (tr("30 derniers jours"), timedelta(days=30)),
        (tr("Tout l'historique (90 jours)"), None),
    ]


def availability_text(stats: ProfileStats) -> str:
    value = stats.availability
    return "—" if value is None else f"{value * 100:.1f} %".replace(".", ",")


def availability_tone(stats: ProfileStats) -> str | None:
    """« danger » sous 90 % ou avec des erreurs, « warning » sous 99 % ou avec des reconnexions."""
    value = stats.availability
    if stats.errors or (value is not None and value < 0.9):
        return "danger"
    if stats.reconnects or (value is not None and value < 0.99):
        return "warning"
    return None


def end_label(record: SessionRecord) -> str:
    return tr("Erreur") if record.end_state == "error" else tr("Arrêtée")


def _table(headers: list[str], name: str) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setAccessibleName(name)
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().hide()
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    table.horizontalHeader().setStretchLastSection(True)
    return table


class HistoryDialog(QDialog):
    def __init__(self, parent: QWidget | None, ctx: GuiContext, selected: Key | None = None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.history = ctx.manager.history
        self.stats: list[ProfileStats] = []
        self.setWindowTitle(tr("Historique des sessions"))
        self.setWindowIcon(app_icon())
        self.resize(1000, 620)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Historique des sessions"), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Chaque accès avec son temps à l'écoute, ses reconnexions et ses erreurs : ceux qui décrochent "
                    "le plus viennent en tête. Les octets ne sont comptés que pour les redirections SSH."
                ),
                "muted",
                wrap=True,
            )
        )
        row = QHBoxLayout()
        row.addWidget(label(tr("Période"), "meta"))
        self.period = QComboBox()
        self.period.setAccessibleName(tr("Période"))
        for text, value in periods():
            self.period.addItem(text, value)
        self.period.setCurrentIndex(1)
        row.addWidget(self.period)
        row.addStretch()
        layout.addLayout(row)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.summary = _table(
            [
                tr("Accès"),
                tr("Sessions"),
                tr("À l'écoute"),
                tr("Disponibilité"),
                tr("Reconnexions"),
                tr("Erreurs"),
                tr("Données"),
                tr("Dernier incident"),
            ],
            tr("Résumé par accès"),
        )
        self.summary.horizontalHeader().resizeSection(0, 200)
        self.summary.itemSelectionChanged.connect(self._show_sessions)
        splitter.addWidget(self.summary)
        self.sessions = _table(
            [tr("Début"), tr("Durée"), tr("À l'écoute"), tr("Fin"), tr("Reconnexions"), tr("Incidents")],
            tr("Sessions de l'accès"),
        )
        splitter.addWidget(self.sessions)
        layout.addWidget(splitter, 1)
        self.empty = label(tr("Aucune session terminée sur cette période."), "muted")
        layout.addWidget(self.empty)
        footer = QHBoxLayout()
        self.clear_button = button(tr("Effacer l'historique…"), "trash", danger=True)
        self.clear_button.clicked.connect(self.clear)
        footer.addWidget(self.clear_button)
        footer.addStretch()
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)
        self.period.currentIndexChanged.connect(lambda _i: self.reload())
        self.reload(selected)

    def reload(self, selected: Key | None = None) -> None:
        current = selected or self.selected_key()
        self.stats = self.history.summary(self.period.currentData())
        tokens = current_tokens()
        clear_items(self.summary)
        for stats in self.stats:
            row = self.summary.rowCount()
            self.summary.insertRow(row)
            data = stats.bytes_up + stats.bytes_down
            values = (
                stats.name,
                str(stats.sessions),
                human_duration(stats.listening_seconds),
                availability_text(stats),
                str(stats.reconnects),
                str(stats.errors),
                human_bytes(data) if data else "—",
                stats.last_incident or "—",
            )
            tone = availability_tone(stats)
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 0:
                    item.setData(KEY_ROLE, stats.key)
                if column == 3 and tone:
                    item.setForeground(QBrush(QColor(status_colors(tone, tokens)[0])))
                self.summary.setItem(row, column, item)
            if stats.key == current:
                self.summary.selectRow(row)
        self.empty.setVisible(not self.stats)
        self.clear_button.setEnabled(bool(self.history.records()))
        self._show_sessions()

    def selected_key(self) -> Key | None:
        rows = self.summary.selectionModel().selectedRows()
        item = self.summary.item(rows[0].row(), 0) if rows else None
        key = item.data(KEY_ROLE) if item is not None else None
        return (str(key[0]), key[1]) if isinstance(key, tuple | list) else None

    def _show_sessions(self) -> None:
        key = self.selected_key()
        clear_items(self.sessions)
        if key is None:
            return
        records = self.history.records(key[0], since=self.period.currentData())
        for record in (r for r in records if r.forward_id == key[1]):
            row = self.sessions.rowCount()
            self.sessions.insertRow(row)
            values = (
                short_datetime(record.started_at),
                human_duration(record.duration),
                human_duration(min(record.listening_seconds, record.duration)),
                end_label(record),
                str(record.reconnects),
                " · ".join(record.incidents) or "—",
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.sessions.setItem(row, column, item)

    def clear(self) -> None:
        if confirm(
            self,
            tr("Effacer l'historique des sessions ?"),
            tr(
                "Toutes les sessions terminées sont oubliées. Les sessions en cours seront enregistrées à leur fin."
            ),
            tr("Effacer"),
        ):
            self.history.clear()
            self.reload()


def show_history(parent: QWidget, ctx: GuiContext, selected: Key | None = None) -> None:
    HistoryDialog(parent, ctx, selected).exec()
