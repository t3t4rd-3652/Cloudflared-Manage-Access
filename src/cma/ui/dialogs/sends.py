"""Boîte « Envois récents » : ce qui est parti vers les canaux d'alerte (pannes, retours, rappels, objectifs, résumés, tests), la
date, le canal, l'objet et le résultat, du plus récent au plus ancien (journal `alert_log.json`, 200 entrées au plus)."""

from __future__ import annotations

from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QDialog, QHBoxLayout, QTableWidgetItem, QVBoxLayout, QWidget

from cma.core.alertlog import MAX_ENTRIES, AlertLog, SendEntry
from cma.core.alerts import kind_label
from cma.i18n import tr
from cma.ui.icons import app_icon
from cma.ui.theme import current_tokens, status_colors
from cma.ui.views.cloud.helpers import data_table
from cma.ui.views.common import confirm
from cma.ui.widgets import button, clear_items, label, title


def nature_label(nature: str) -> str:
    return {
        "alert": tr("Panne"),
        "recovery": tr("Retour"),
        "reminder": tr("Rappel"),
        "digest": tr("Résumé"),
        "slo": tr("Objectif"),
        "test": tr("Test"),
    }.get(nature, nature)


def result_text(entry: SendEntry) -> str:
    if entry.ok:
        return tr("Réussi")
    return tr("Échec : {error}").format(error=entry.error) if entry.error else tr("Échec")


class SendsDialog(QDialog):
    def __init__(self, parent: QWidget | None, log: AlertLog) -> None:
        super().__init__(parent)
        self.log = log
        self.setWindowTitle(tr("Envois récents"))
        self.setWindowIcon(app_icon())
        self.resize(900, 480)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Envois récents"), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Les {n} derniers envois vers les canaux d'alerte, les plus récents en premier. L'adresse "
                    "d'un canal n'y figure jamais."
                ).format(n=MAX_ENTRIES),
                "muted",
                wrap=True,
            )
        )
        self.table = data_table(
            [tr("Date"), tr("Canal"), tr("Nature"), tr("Objet"), tr("Résultat")], tr("Envois récents")
        )
        for column, width in enumerate((140, 190, 80, 190)):
            self.table.horizontalHeader().resizeSection(column, width)
        self.table.setWordWrap(True)
        self.table.verticalHeader().setMinimumSectionSize(36)
        self.table.horizontalHeader().sectionResized.connect(lambda *_a: self.table.resizeRowsToContents())
        layout.addWidget(self.table, 1)
        self.empty = label(tr("Aucun envoi pour l'instant."), "muted")
        layout.addWidget(self.empty)
        footer = QHBoxLayout()
        self.clear_button = button(tr("Effacer le journal…"), "trash", danger=True)
        self.clear_button.clicked.connect(self.clear)
        footer.addWidget(self.clear_button)
        footer.addStretch()
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)
        self.entries: list[SendEntry] = []
        self._fill()

    def _fill(self) -> None:
        self.entries = self.log.latest()
        tokens = current_tokens()
        clear_items(self.table, len(self.entries))
        for row, entry in enumerate(self.entries):
            values = (
                entry.at.astimezone().strftime("%d/%m/%Y %H:%M:%S"),
                f"{entry.channel} ({kind_label(entry.kind)})",
                nature_label(entry.nature),
                entry.subject or "—",
                result_text(entry),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 4 and not entry.ok:
                    item.setForeground(QBrush(QColor(status_colors("danger", tokens)[0])))
                self.table.setItem(row, column, item)
        self.table.resizeRowsToContents()
        self.table.setVisible(bool(self.entries))
        self.empty.setVisible(not self.entries)
        self.clear_button.setEnabled(bool(self.entries))

    def clear(self) -> None:
        if not ask_clear(self):
            return
        self.log.clear()
        self._fill()


def ask_clear(parent: QWidget) -> bool:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    return confirm(
        parent,
        tr("Effacer le journal des envois ?"),
        tr("Les envois déjà faits ne sont pas rappelés : seul leur historique ici est effacé."),
        tr("Effacer"),
    )


def show_recent_sends(parent: QWidget, log: AlertLog) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    SendsDialog(parent, log).exec()
