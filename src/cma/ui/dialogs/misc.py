"""Boîtes diverses : rapport de migration, texte à copier, empreintes connues, clés SSH, coffre de repli."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QFontDatabase
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.migrations import MigrationReport, delete_v1_files
from cma.core.ssh.hostkeys import KnownHostsFile
from cma.core.ssh.keys import KeySource, delete_key, generate_key, list_keys, public_key_line
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.dialogs.prompts import ask_new_passphrase
from cma.ui.icons import app_icon
from cma.ui.widgets import button, copy_to_clipboard, label, primary_button, title


def _dialog(parent: QWidget | None, window_title: str) -> tuple[QDialog, QVBoxLayout]:
    dialog = QDialog(parent)
    dialog.setWindowTitle(window_title)
    dialog.setWindowIcon(app_icon())
    layout = QVBoxLayout(dialog)
    return dialog, layout


def show_text(parent: QWidget | None, window_title: str, intro: str, text: str) -> None:
    dialog, layout = _dialog(parent, window_title)
    layout.addWidget(label(intro, wrap=True))
    editor = QPlainTextEdit(text)
    editor.setReadOnly(True)
    editor.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
    layout.addWidget(editor)
    buttons = QDialogButtonBox()
    copy = buttons.addButton(tr("Copier"), QDialogButtonBox.ButtonRole.ActionRole)
    copy.clicked.connect(lambda: copy_to_clipboard(text))
    close = buttons.addButton(tr("Fermer"), QDialogButtonBox.ButtonRole.RejectRole)
    close.clicked.connect(dialog.reject)
    layout.addWidget(buttons)
    dialog.resize(620, 360)
    dialog.exec()


def show_migration_report(ctx: GuiContext, parent: QWidget | None, report: MigrationReport) -> None:
    dialog, layout = _dialog(parent, tr("Données de la v1 migrées"))
    layout.addWidget(title(tr("Vos données ont été reprises"), "SectionTitle"))
    summary = tr(
        "{profiles} profil(s) Cloudflare, {tokens} service token(s) et {ssh} profil(s) SSH ont été importés. "
        "Les secrets sont désormais dans le coffre du système (Gestionnaire d'identifiants sous Windows), plus dans des fichiers."
    ).format(profiles=report.profiles, tokens=report.tokens, ssh=report.ssh_profiles)
    layout.addWidget(label(summary, wrap=True))
    if report.created_tokens:
        layout.addWidget(
            label(
                tr(
                    "Tokens créés pour des profils dont le secret ne correspondait à aucun token : {names}."
                ).format(names=", ".join(report.created_tokens)),
                "muted",
                wrap=True,
            )
        )
    if report.warnings:
        box = QPlainTextEdit("\n".join(f"• {w}" for w in report.warnings))
        box.setReadOnly(True)
        box.setMaximumHeight(160)
        layout.addWidget(label(tr("Points à vérifier :")))
        layout.addWidget(box)
    if report.backup_dir is not None:
        layout.addWidget(
            label(
                tr("Copie des fichiers d'origine : {path}").format(path=report.backup_dir),
                "muted",
                wrap=True,
                selectable=True,
            )
        )
    layout.addWidget(
        label(
            tr(
                "Les anciens fichiers contiennent vos secrets en clair. Supprimez-les quand vous aurez vérifié la migration "
                "(la v1.4 ne pourra plus s'en servir). Vous pourrez aussi le faire plus tard dans les paramètres."
            ),
            "warning",
            wrap=True,
        )
    )
    buttons = QDialogButtonBox()
    remove = buttons.addButton(tr("Supprimer les fichiers v1…"), QDialogButtonBox.ButtonRole.DestructiveRole)
    later = buttons.addButton(tr("Plus tard"), QDialogButtonBox.ButtonRole.AcceptRole)
    later.setDefault(True)

    def on_remove() -> None:
        if confirm_delete_v1(ctx, dialog):
            dialog.accept()

    remove.clicked.connect(on_remove)
    later.clicked.connect(dialog.accept)
    layout.addWidget(buttons)
    dialog.resize(600, dialog.sizeHint().height())
    dialog.exec()


def confirm_delete_v1(ctx: GuiContext, parent: QWidget | None) -> bool:
    answer = QMessageBox.question(
        parent,
        tr("Supprimer les fichiers v1"),
        tr(
            "Supprimer définitivement les fichiers de la v1 et leur copie de sauvegarde ?\n"
            "Ils contiennent vos secrets en clair. La v1.4 ne pourra plus les lire."
        ),
    )
    if answer != QMessageBox.StandardButton.Yes:
        return False
    try:
        removed = delete_v1_files(ctx.paths.data_dir)
    except OSError as exc:
        ctx.notify("error", tr("Suppression impossible : {error}").format(error=exc))
        return False

    def mark(config: object) -> None:
        config.settings.v1_files_handled = True  # type: ignore[attr-defined]

    ctx.update_config(mark)
    ctx.notify("success", tr("{n} fichier(s) ou dossier(s) v1 supprimé(s).").format(n=len(removed)))
    return True


class KnownHostsDialog(QDialog):
    def __init__(self, parent: QWidget | None, ctx: GuiContext) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle(tr("Empreintes des serveurs SSH"))
        self.setWindowIcon(app_icon())
        layout = QVBoxLayout(self)
        self.file = ctx.manager.ssh.known_hosts()
        layout.addWidget(label(tr("Fichier : {path}").format(path=self.file.path), "muted", selectable=True))
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels([tr("Serveur"), tr("Type"), tr("Empreinte SHA-256")])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().hide()
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)
        row = QHBoxLayout()
        remove = button(tr("Oublier ce serveur"), "trash", danger=True)
        remove.clicked.connect(self._remove)
        row.addWidget(remove)
        row.addStretch()
        close = QPushButton(tr("Fermer"))
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)
        self.resize(760, 380)
        self._load()

    def _load(self) -> None:
        entries = self.file.entries()
        self.table.setRowCount(len(entries))
        for index, entry in enumerate(entries):
            self.table.setItem(index, 0, QTableWidgetItem(entry.pattern))
            self.table.setItem(index, 1, QTableWidgetItem(entry.algorithm))
            self.table.setItem(index, 2, QTableWidgetItem(entry.fingerprint))

    def _remove(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        item = self.table.item(row, 0)
        if item is None:
            return
        pattern = item.text()
        KnownHostsFile(self.file.path).remove(pattern)
        self._load()


class KeysDialog(QDialog):
    """Clés SSH : celles de l'application et celles de ~/.ssh (lecture seule)."""

    def __init__(self, parent: QWidget | None, ctx: GuiContext) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle(tr("Clés SSH"))
        self.setWindowIcon(app_icon())
        layout = QVBoxLayout(self)
        layout.addWidget(
            label(
                tr(
                    "Les clés de l'application sont dans {path}. Celles de ~/.ssh sont proposées sans être modifiées."
                ).format(path=ctx.paths.keys_dir),
                "muted",
                wrap=True,
            )
        )
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            [tr("Nom"), tr("Type"), tr("Empreinte"), tr("Origine"), tr("Chiffrée")]
        )
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().hide()
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)
        row = QHBoxLayout()
        generate = primary_button(tr("Générer une clé…"), "plus")
        generate.clicked.connect(self._generate)
        copy = button(tr("Copier la clé publique"), "copy")
        copy.clicked.connect(self._copy)
        remove = button(tr("Supprimer"), "trash", danger=True)
        remove.clicked.connect(self._delete)
        folder = button(tr("Ouvrir le dossier"), "folder-open")
        folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(ctx.paths.keys_dir))))
        for widget in (generate, copy, remove, folder):
            row.addWidget(widget)
        row.addStretch()
        close = QPushButton(tr("Fermer"))
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)
        self.resize(820, 400)
        self.keys = []
        self._load()

    def _load(self) -> None:
        self.keys = list_keys(self.ctx.paths.keys_dir)
        self.table.setRowCount(len(self.keys))
        for index, key in enumerate(self.keys):
            values = [
                key.name,
                key.algorithm,
                key.fingerprint,
                tr("Application") if key.source == KeySource.APP else "~/.ssh",
                tr("oui") if key.encrypted else tr("non"),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, str(key.path))
                self.table.setItem(index, column, item)

    def _selected(self) -> Path | None:
        row = self.table.currentRow()
        return self.keys[row].path if 0 <= row < len(self.keys) else None

    def _generate(self) -> None:
        name, ok = QInputDialog.getText(
            self, tr("Nouvelle clé"), tr("Nom de la clé (ex. nas) :"), QLineEdit.EchoMode.Normal
        )
        if not ok or not name.strip():
            return
        protect = QMessageBox.question(
            self, tr("Phrase de passe"), tr("Protéger la clé par une phrase de passe ? (recommandé)")
        )
        passphrase = None
        if protect == QMessageBox.StandardButton.Yes:
            passphrase = ask_new_passphrase(
                self,
                tr("Phrase de passe de la clé"),
                tr("Elle sera demandée à chaque connexion, sauf si vous la mémorisez."),
            )
            if passphrase is None:
                return
        try:
            info = generate_key(self.ctx.paths.keys_dir, name, passphrase=passphrase)
        except (ValueError, FileExistsError, OSError) as exc:
            QMessageBox.warning(self, tr("Clé non créée"), str(exc))
            return
        self._load()
        self.ctx.notify("success", tr("Clé {name} créée ({fp}).").format(name=info.name, fp=info.fingerprint))

    def _copy(self) -> None:
        path = self._selected()
        if path is None:
            return
        try:
            copy_to_clipboard(public_key_line(path))
            self.ctx.notify("success", tr("Clé publique copiée."))
        except Exception as exc:
            QMessageBox.warning(self, tr("Clé illisible"), str(exc))

    def _delete(self) -> None:
        path = self._selected()
        if path is None:
            return
        if (
            QMessageBox.question(
                self, tr("Supprimer la clé"), tr("Supprimer définitivement {name} ?").format(name=path.name)
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        try:
            delete_key(path, self.ctx.paths.keys_dir)
        except (PermissionError, OSError) as exc:
            QMessageBox.warning(self, tr("Suppression impossible"), str(exc))
            return
        self._load()


def choose_secret_store(parent: QWidget | None, encrypted_file: Path) -> str | None:
    """Sans trousseau système : ouvrir ou créer le coffre chiffré. Renvoie la phrase de passe, ou None (mémoire)."""
    exists = encrypted_file.exists()
    box = QMessageBox(parent)
    box.setWindowTitle(tr("Coffre des secrets"))
    box.setWindowIcon(app_icon())
    box.setText(
        tr(
            "Aucun trousseau système n'est disponible. Les secrets peuvent être gardés dans un fichier chiffré par phrase de passe."
        )
    )
    use = box.addButton(
        tr("Ouvrir le coffre chiffré") if exists else tr("Créer un coffre chiffré"),
        QMessageBox.ButtonRole.AcceptRole,
    )
    box.addButton(tr("Continuer sans conserver les secrets"), QMessageBox.ButtonRole.RejectRole)
    box.exec()
    if box.clickedButton() is not use:
        return None
    if exists:
        value, ok = QInputDialog.getText(
            parent, tr("Coffre chiffré"), tr("Phrase de passe du coffre :"), QLineEdit.EchoMode.Password
        )
        return value if ok and value else None
    return ask_new_passphrase(
        parent, tr("Nouveau coffre chiffré"), tr("Cette phrase de passe sera demandée à chaque démarrage.")
    )
