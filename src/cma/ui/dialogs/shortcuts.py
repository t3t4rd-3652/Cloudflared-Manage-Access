"""« Raccourcis clavier » (F1) : tous les raccourcis de CMA, avec les touches du système (Ctrl ou ⌘)."""

from __future__ import annotations

from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.i18n import tr
from cma.ui.icons import app_icon
from cma.ui.widgets import label, primary_button, title

Keys = QKeySequence | QKeySequence.StandardKey | str


def key_text(keys: Keys) -> str:
    """Touches telles que le système les écrit : « Ctrl+N » sous Windows et Linux, « ⌘N » sous macOS."""
    if isinstance(keys, QKeySequence.StandardKey):
        bindings = QKeySequence.keyBindings(keys)
        sequence = bindings[0] if bindings else QKeySequence()
    else:
        sequence = keys if isinstance(keys, QKeySequence) else QKeySequence(keys)
    return sequence.toString(QKeySequence.SequenceFormat.NativeText)


def shortcut_rows(pages: list[str]) -> list[tuple[str, str, str]]:
    """(où, touches, action) de chaque raccourci ; `pages` : les pages de la navigation, dans l'ordre de Ctrl+1…"""
    everywhere = tr("Partout")
    rows = [
        (
            everywhere,
            key_text("Ctrl+K"),
            tr("Palette de commandes : chercher un accès, un serveur, une action"),
        ),
        (everywhere, key_text("F1"), tr("Raccourcis clavier")),
    ]
    rows += [
        (everywhere, key_text(f"Ctrl+{index}"), tr("Aller à « {page} »").format(page=page))
        for index, page in enumerate(pages, start=1)
    ]
    rows += [
        (everywhere, key_text("Ctrl+L"), tr("Verrouiller CMA (coffre chiffré)")),
        (everywhere, key_text("Ctrl+Q"), tr("Quitter CMA")),
    ]
    lists = tr("Listes")
    rows += [
        (lists, key_text(QKeySequence.StandardKey.New), tr("Nouvel accès ou nouveau serveur SSH")),
        (lists, key_text(QKeySequence.StandardKey.Find), tr("Chercher dans la liste")),
        (lists, key_text(QKeySequence.StandardKey.Delete), tr("Supprimer l'élément choisi")),
        (lists, key_text("Shift+F10"), tr("Menu de l'élément choisi")),
    ]
    forms = tr("Fiches")
    rows += [
        (forms, key_text(QKeySequence.StandardKey.Save), tr("Enregistrer")),
        (
            forms,
            key_text("Ctrl+Return"),
            tr("Connecter ou arrêter l'accès (fiche d'un accès, redirection SSH)"),
        ),
    ]
    views = tr("Vues")
    rows += [
        (
            views,
            key_text(QKeySequence.StandardKey.Refresh),
            tr("Relire (compte Cloudflare, ports d'un serveur, Paramètres)"),
        ),
        (views, key_text(QKeySequence.StandardKey.Copy), tr("Copier les lignes choisies (Journaux)")),
    ]
    return [row for row in rows if row[1]]


class ShortcutsDialog(QDialog):
    def __init__(self, parent: QWidget | None, pages: list[str]) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Raccourcis clavier"))
        self.setWindowIcon(app_icon())
        self.resize(720, 560)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Raccourcis clavier"), "SectionTitle"))
        layout.addWidget(
            label(
                tr("Ctrl+K ouvre la palette : toute action de CMA s'y trouve par son nom."),
                "muted",
                wrap=True,
            )
        )
        rows = shortcut_rows(pages)
        self.table = QTableWidget(len(rows), 3)
        self.table.setAccessibleName(tr("Raccourcis clavier"))
        self.table.setTabKeyNavigation(False)  # Tab quitte le tableau au lieu de passer de case en case
        self.table.setHorizontalHeaderLabels([tr("Où"), tr("Touches"), tr("Action")])
        self.table.verticalHeader().hide()
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)
        for row, (where, keys, action) in enumerate(rows):
            for column, text in enumerate((where, keys, action)):
                self.table.setItem(row, column, QTableWidgetItem(text))
        layout.addWidget(self.table, 1)
        footer = QHBoxLayout()
        footer.addStretch()
        close = primary_button(tr("Fermer"))
        close.setDefault(True)
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)


def show_shortcuts(parent: QWidget | None, pages: list[str]) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    ShortcutsDialog(parent, pages).exec()
