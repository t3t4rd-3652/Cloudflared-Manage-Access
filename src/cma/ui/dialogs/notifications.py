"""Boîte « Notifications récentes » : l'historique de la session, avec l'action d'une notification encore possible."""

from __future__ import annotations

from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QDialog, QHBoxLayout, QTableWidgetItem, QVBoxLayout, QWidget

from cma.i18n import tr
from cma.ui.icons import app_icon
from cma.ui.notices import Notice, NoticeLog
from cma.ui.theme import current_tokens, status_colors
from cma.ui.views.cloud.helpers import data_table
from cma.ui.widgets import button, clear_items, label, primary_button, title


def level_label(level: str) -> str:
    return {
        "success": tr("Réussite"),
        "warning": tr("Avertissement"),
        "error": tr("Erreur"),
    }.get(level, tr("Information"))


class NotificationsDialog(QDialog):
    def __init__(self, parent: QWidget | None, log: NoticeLog) -> None:
        super().__init__(parent)
        self.log = log
        self.setWindowTitle(tr("Notifications récentes"))
        self.setWindowIcon(app_icon())
        self.resize(820, 460)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Notifications récentes"), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Les 100 dernières notifications depuis l'ouverture de CMA, les plus récentes en premier."
                ),
                "muted",
                wrap=True,
            )
        )
        self.table = data_table([tr("Heure"), tr("Niveau"), tr("Message")], tr("Notifications récentes"))
        for column, width in enumerate((80, 130)):
            self.table.horizontalHeader().resizeSection(column, width)
        # Un message long passe à la ligne : la hauteur de ligne suit le texte (au moins celle d'une ligne normale).
        self.table.setWordWrap(True)
        self.table.verticalHeader().setMinimumSectionSize(36)
        self.table.horizontalHeader().sectionResized.connect(lambda *_a: self.table.resizeRowsToContents())
        self.table.itemSelectionChanged.connect(self._update_actions)
        self.table.itemDoubleClicked.connect(lambda _item: self.run_action())
        layout.addWidget(self.table, 1)
        self.empty = label(tr("Aucune notification pour l'instant."), "muted")
        layout.addWidget(self.empty)
        footer = QHBoxLayout()
        self.action_button = primary_button(tr("Exécuter l'action"), "player-play-filled")
        self.action_button.clicked.connect(self.run_action)
        footer.addWidget(self.action_button)
        self.clear_button = button(tr("Effacer"), "trash")
        self.clear_button.clicked.connect(self.clear)
        footer.addWidget(self.clear_button)
        footer.addStretch()
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)
        self.notices: list[Notice] = []
        self._fill()

    def _fill(self) -> None:
        self.notices = self.log.latest()
        tokens = current_tokens()
        clear_items(self.table, len(self.notices))
        for row, notice in enumerate(self.notices):
            tone = {"error": "danger"}.get(notice.level, notice.level if notice.level != "info" else "info")
            values = (notice.at.strftime("%H:%M:%S"), level_label(notice.level), notice.text)
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 1:
                    item.setForeground(QBrush(QColor(status_colors(tone, tokens)[0])))
                self.table.setItem(row, column, item)
        self.table.resizeRowsToContents()
        self.table.setVisible(bool(self.notices))
        self.empty.setVisible(not self.notices)
        self.clear_button.setEnabled(bool(self.notices))
        self._update_actions()

    def selected(self) -> Notice | None:
        row = self.table.currentRow()
        return self.notices[row] if 0 <= row < len(self.notices) and self.table.selectedItems() else None

    def _update_actions(self) -> None:
        notice = self.selected()
        self.action_button.setEnabled(notice is not None and notice.action is not None)
        self.action_button.setText(notice.action[0] if notice and notice.action else tr("Exécuter l'action"))

    def run_action(self) -> None:
        notice = self.selected()
        if notice is None or notice.action is None:
            return
        self.accept()
        notice.action[1]()

    def clear(self) -> None:
        self.log.clear()
        self._fill()


def show_notifications(parent: QWidget, log: NoticeLog) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    NotificationsDialog(parent, log).exec()
