"""Onglet « Fichiers » : parcourir le serveur en SFTP, télécharger, envoyer, créer, renommer, supprimer.

La connexion n'est ouverte qu'au premier « Parcourir » (elle peut demander un mot de passe). Remplacer un fichier
existant, ici ou sur le serveur, et supprimer demandent une confirmation.
"""

from __future__ import annotations

import posixpath
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QObject, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.models import SshProfile
from cma.core.ssh.sftp import RemoteEntry
from cma.i18n import tr
from cma.ui.format import human_bytes, short_datetime
from cma.ui.icons import token_icon
from cma.ui.views.common import confirm
from cma.ui.widgets import button, clear_items, label, primary_button

if TYPE_CHECKING:
    from cma.ui.views.ssh.view import SshProfilePanel

ENTRY_ROLE = 256


# Fonctions de module : les tests les remplacent pour ne pas ouvrir de boîte modale.


def ask_directory(parent: QWidget, heading: str) -> Path | None:
    chosen = QFileDialog.getExistingDirectory(parent, heading, str(Path.home() / "Downloads"))
    return Path(chosen) if chosen else None


def ask_files(parent: QWidget) -> list[Path]:
    chosen, _filter = QFileDialog.getOpenFileNames(parent, tr("Fichiers à envoyer"), str(Path.home()))
    return [Path(p) for p in chosen]


def ask_name(parent: QWidget, heading: str, text: str, default: str = "") -> str | None:
    value, accepted = QInputDialog.getText(parent, heading, text, QLineEdit.EchoMode.Normal, default)
    return value.strip() if accepted and value.strip() else None


class _Progress(QObject):
    """Relaie la progression des transferts (thread du moteur) vers l'interface."""

    changed = Signal(str, int, int)


class FilesTab(QWidget):
    def __init__(self, panel: SshProfilePanel) -> None:
        super().__init__()
        self.panel = panel
        self.directory: str | None = None
        self.entries: list[RemoteEntry] = []
        self._busy = False
        self.progress = _Progress()
        self.progress.changed.connect(self._on_progress)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 12, 0, 0)
        layout.setSpacing(8)
        toolbar = QHBoxLayout()
        self.browse_button = primary_button(tr("Parcourir"), "folder-open")
        self.browse_button.setToolTip(tr("Ouvrir le dossier personnel sur le serveur (SFTP)"))
        self.browse_button.clicked.connect(lambda: self.open_directory(self.directory))
        self.up_button = button(tr("Dossier parent"), "arrow-back-up")
        self.up_button.clicked.connect(self.go_up)
        self.home_button = button(tr("Dossier personnel"), "user")
        self.home_button.clicked.connect(lambda: self.open_directory(None))
        self.path = QLineEdit()
        self.path.setAccessibleName(tr("Chemin sur le serveur"))
        self.path.setPlaceholderText(tr("/chemin/sur/le/serveur"))
        self.path.returnPressed.connect(lambda: self.open_directory(self.path.text().strip() or None))
        toolbar.addWidget(self.browse_button)
        toolbar.addWidget(self.up_button)
        toolbar.addWidget(self.home_button)
        toolbar.addWidget(self.path, 1)
        layout.addLayout(toolbar)
        actions = QHBoxLayout()
        self.download_button = button(tr("Télécharger…"), "download")
        self.download_button.clicked.connect(self.download_selected)
        self.upload_button = button(tr("Envoyer des fichiers…"), "upload")
        self.upload_button.clicked.connect(self.upload_files)
        self.upload_dir_button = button(tr("Envoyer un dossier…"), "upload")
        self.upload_dir_button.clicked.connect(self.upload_directory)
        self.mkdir_button = button(tr("Nouveau dossier…"), "plus")
        self.mkdir_button.clicked.connect(self.make_directory)
        self.rename_button = button(tr("Renommer…"), "pencil")
        self.rename_button.clicked.connect(self.rename_selected)
        self.delete_button = button(tr("Supprimer…"), "trash", danger=True)
        self.delete_button.clicked.connect(self.delete_selected)
        for widget in (
            self.download_button,
            self.upload_button,
            self.upload_dir_button,
            self.mkdir_button,
            self.rename_button,
            self.delete_button,
        ):
            actions.addWidget(widget)
        actions.addStretch()
        layout.addLayout(actions)
        self.status = label("", "meta", wrap=True)
        layout.addWidget(self.status)
        self.error = label("", "error", wrap=True)
        self.error.hide()
        layout.addWidget(self.error)
        self.table = QTableWidget(0, 4)
        self.table.setAccessibleName(tr("Fichiers du serveur"))
        self.table.setHorizontalHeaderLabels([tr("Nom"), tr("Taille"), tr("Modifié"), tr("Droits")])
        self.table.verticalHeader().hide()
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        header.resizeSection(0, 320)
        header.resizeSection(1, 100)
        header.resizeSection(2, 150)
        self.table.itemSelectionChanged.connect(self._update_actions)
        self.table.cellDoubleClicked.connect(lambda row, _c: self._activate(row))
        layout.addWidget(self.table, 1)
        self.reset(None)

    # --- État ----------------------------------------------------------------------------------------

    @property
    def profile(self) -> SshProfile | None:
        return self.panel.profile

    def reset(self, _profile: SshProfile | None) -> None:
        """Nouveau profil affiché : rien n'est lu tant que l'utilisateur ne parcourt pas."""
        self.directory = None
        self.entries = []
        clear_items(self.table)
        self.path.clear()
        self.error.hide()
        self.status.setText(tr("« Parcourir » ouvre votre dossier personnel sur le serveur."))
        self._update_actions()

    def selected(self) -> list[RemoteEntry]:
        rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()})
        return [self.entries[row] for row in rows if row < len(self.entries)]

    def _update_actions(self) -> None:
        opened = self.directory is not None and not self._busy
        chosen = self.selected() if opened else []
        self.browse_button.setEnabled(not self._busy)
        self.home_button.setEnabled(not self._busy)
        self.path.setEnabled(not self._busy)
        self.up_button.setEnabled(opened and self.directory != "/")
        for widget in (self.upload_button, self.upload_dir_button, self.mkdir_button):
            widget.setEnabled(opened)
        self.download_button.setEnabled(bool(chosen))
        self.delete_button.setEnabled(bool(chosen))
        self.rename_button.setEnabled(len(chosen) == 1)

    def _set_busy(self, busy: bool, text: str = "") -> None:
        self._busy = busy
        if text:
            self.status.setText(text)
        if busy:
            self.error.hide()
        self._update_actions()

    def _failed(self, error: BaseException) -> None:
        self._set_busy(False)
        self.error.setText(str(error))
        self.error.show()

    def _on_progress(self, name: str, copied: int, total: int) -> None:
        self.status.setText(
            tr("Transfert : {name} — {copied} sur {total}").format(
                name=name, copied=human_bytes(copied), total=human_bytes(total)
            )
        )

    def _report(self, name: str, copied: int, total: int) -> None:
        self.progress.changed.emit(name, copied, total)  # appelé depuis le thread du moteur

    # --- Navigation ------------------------------------------------------------------------------------

    def open_directory(self, path: str | None) -> None:
        profile = self.profile
        if profile is None:
            return
        self._set_busy(True, tr("Lecture du dossier…"))

        def done(result: tuple[str, list[RemoteEntry]]) -> None:
            if self.profile is None or self.profile.id != profile.id:
                return
            self.directory, self.entries = result
            self.path.setText(self.directory)
            self._fill()
            self._set_busy(
                False, tr("{n} élément(s) dans {path}").format(n=len(self.entries), path=self.directory)
            )
            self.panel.update_connection_state()

        self.panel.ctx.run(self.panel.ctx.manager.sftp_list(profile.id, path), done, self._failed)

    def reload(self) -> None:
        self.open_directory(self.directory)

    def go_up(self) -> None:
        if self.directory is not None:
            self.open_directory(posixpath.dirname(self.directory.rstrip("/")) or "/")

    def _fill(self) -> None:
        clear_items(self.table)
        for entry in self.entries:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = (
                entry.name,
                "" if entry.is_dir else human_bytes(entry.size),
                short_datetime(entry.modified) if entry.modified else "",
                entry.permissions,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(entry.path if column == 0 else value)
                if column == 0:
                    item.setIcon(token_icon("folder" if entry.is_dir else "file-export", "muted"))
                    item.setData(ENTRY_ROLE, entry.path)
                if column == 1:
                    item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                self.table.setItem(row, column, item)
        self._update_actions()

    def _activate(self, row: int) -> None:
        if 0 <= row < len(self.entries):
            entry = self.entries[row]
            if entry.is_dir:
                self.open_directory(entry.path)
            else:
                self.table.selectRow(row)
                self.download_selected()

    # --- Transferts -------------------------------------------------------------------------------------

    def download_selected(self) -> None:
        profile, chosen = self.profile, self.selected()
        if profile is None or not chosen:
            return
        target = ask_directory(self, tr("Dossier où télécharger"))
        if target is None:
            return
        clashes = [e.name for e in chosen if (target / e.name).exists()]
        if clashes and not confirm(
            self,
            tr("Remplacer des fichiers existants ?"),
            tr("Déjà présents dans {folder} : {names}.").format(folder=target, names=", ".join(clashes)),
            tr("Remplacer"),
        ):
            return
        self._set_busy(True, tr("Téléchargement…"))

        def done(paths: list[Path]) -> None:
            self._set_busy(
                False, tr("{n} élément(s) téléchargé(s) dans {folder}.").format(n=len(paths), folder=target)
            )
            self.panel.ctx.notify(
                "success",
                tr("Téléchargement terminé : {folder}").format(folder=target),
                action=(
                    tr("Ouvrir le dossier"),
                    lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(target))),
                ),
            )

        self.panel.ctx.run(
            self.panel.ctx.manager.sftp_download(profile.id, [e.path for e in chosen], target, self._report),
            done,
            self._failed,
        )

    def upload_files(self) -> None:
        self._upload(ask_files(self))

    def upload_directory(self) -> None:
        folder = ask_directory(self, tr("Dossier à envoyer"))
        if folder is not None:
            self._upload([folder])

    def _upload(self, local_paths: list[Path]) -> None:
        profile, directory = self.profile, self.directory
        if profile is None or directory is None or not local_paths:
            return
        self._set_busy(True, tr("Vérification…"))

        def checked(clashes: list[str]) -> None:
            if clashes and not confirm(
                self,
                tr("Remplacer sur le serveur ?"),
                tr("Déjà présents dans {folder} : {names}.").format(
                    folder=directory, names=", ".join(clashes)
                ),
                tr("Remplacer"),
            ):
                self._set_busy(False, tr("Envoi annulé."))
                return
            self._set_busy(True, tr("Envoi…"))
            self.panel.ctx.run(
                self.panel.ctx.manager.sftp_upload(profile.id, local_paths, directory, self._report),
                lambda _paths: self.reload(),
                self._failed,
            )

        self.panel.ctx.run(
            self.panel.ctx.manager.sftp_existing(profile.id, directory, [p.name for p in local_paths]),
            checked,
            self._failed,
        )

    # --- Rangement -----------------------------------------------------------------------------------------

    def make_directory(self) -> None:
        profile, directory = self.profile, self.directory
        if profile is None or directory is None:
            return
        name = ask_name(self, tr("Nouveau dossier"), tr("Nom du dossier"))
        if name:
            self._set_busy(True, tr("Création du dossier…"))
            self.panel.ctx.run(
                self.panel.ctx.manager.sftp_mkdir(profile.id, directory, name),
                lambda _p: self.reload(),
                self._failed,
            )

    def rename_selected(self) -> None:
        profile, chosen = self.profile, self.selected()
        if profile is None or len(chosen) != 1:
            return
        name = ask_name(self, tr("Renommer"), tr("Nouveau nom"), chosen[0].name)
        if name and name != chosen[0].name:
            self._set_busy(True, tr("Renommage…"))
            self.panel.ctx.run(
                self.panel.ctx.manager.sftp_rename(profile.id, chosen[0].path, name),
                lambda _p: self.reload(),
                self._failed,
            )

    def delete_selected(self) -> None:
        profile, chosen = self.profile, self.selected()
        if profile is None or not chosen:
            return
        folders = sum(1 for e in chosen if e.is_dir and not e.is_link)
        text = tr("{names} sera supprimé du serveur, sans corbeille.").format(
            names=", ".join(e.name for e in chosen)
        )
        if folders:
            text += " " + tr("Les dossiers sont supprimés avec tout leur contenu.")
        if not confirm(self, tr("Supprimer sur le serveur ?"), text, tr("Supprimer")):
            return
        self._set_busy(True, tr("Suppression…"))

        async def remove_all() -> None:
            for entry in chosen:
                await self.panel.ctx.manager.sftp_remove(profile.id, entry)

        self.panel.ctx.run(remove_all(), lambda _r: self.reload(), self._failed)
