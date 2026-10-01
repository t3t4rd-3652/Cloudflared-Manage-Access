"""Boîtes utilitaires : rapport de migration (D2), clés SSH (D9), empreintes (D10), coffre de repli (D11),
configuration à copier (D12) et suppression des fichiers v1 (D13)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QPoint, Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QListWidget,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.migrations import V1_FILES, V1_LEFTOVERS, MigrationReport, delete_v1_files
from cma.core.ssh.hostkeys import KnownHostsFile
from cma.core.ssh.keys import KeyInfo, KeySource, delete_key, generate_key, list_keys, public_key_line
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.dialogs.prompts import key_type_label
from cma.ui.icons import app_icon
from cma.ui.state import remember_header
from cma.ui.views.common import confirm
from cma.ui.widgets import button, copy_to_clipboard, label, primary_button, title


def _dialog(parent: QWidget | None, window_title: str) -> tuple[QDialog, QVBoxLayout]:
    dialog = QDialog(parent)
    dialog.setWindowTitle(window_title)
    dialog.setWindowIcon(app_icon())
    layout = QVBoxLayout(dialog)
    layout.setSpacing(10)
    return dialog, layout


def _table(headers: list[str], name: str) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setAccessibleName(name)
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().hide()
    table.verticalHeader().setDefaultSectionSize(34)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    table.horizontalHeader().setStretchLastSection(True)
    return table


# --- D12 — Texte à copier ----------------------------------------------------------------------------------


def show_text(parent: QWidget | None, window_title: str, intro: str, text: str) -> None:
    dialog, layout = _dialog(parent, window_title)
    layout.addWidget(title(window_title, "SectionTitle"))
    layout.addWidget(label(intro, "muted", wrap=True))
    editor = QPlainTextEdit(text)
    editor.setReadOnly(True)
    editor.setProperty("role", "code")
    editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    editor.setAccessibleName(window_title)
    layout.addWidget(editor, 1)
    if not text.strip():
        layout.addWidget(label(tr("Complétez le nom d'hôte et l'utilisateur du profil."), "muted", wrap=True))
    buttons = QDialogButtonBox()
    copy = buttons.addButton(tr("Copier"), QDialogButtonBox.ButtonRole.ActionRole)
    copy.setProperty("role", "primary")
    copy.setEnabled(bool(text.strip()))

    def do_copy() -> None:
        copy_to_clipboard(text)
        copy.setText(tr("Configuration copiée."))

    copy.clicked.connect(do_copy)
    close = buttons.addButton(tr("Fermer"), QDialogButtonBox.ButtonRole.RejectRole)
    close.clicked.connect(dialog.reject)
    layout.addWidget(buttons)
    dialog.resize(760, 480)
    dialog.exec()


# --- D2 — Rapport de migration v1 --------------------------------------------------------------------------


def v1_targets(data_dir: Path) -> list[Path]:
    """Fichiers et sauvegardes v1 réellement présents, tels que la suppression les retirera."""
    files = [data_dir / name for name in (*V1_FILES, *V1_LEFTOVERS) if (data_dir / name).is_file()]
    return files + sorted(p for p in data_dir.glob("backup-v1-*") if p.is_dir())


def show_migration_report(ctx: GuiContext, parent: QWidget | None, report: MigrationReport) -> None:
    partial = bool(report.warnings)
    heading = tr("Migration partielle") if partial else tr("Migration terminée")
    dialog, layout = _dialog(parent, heading)
    layout.addWidget(title(heading, "SectionTitle"))
    counts = " · ".join(
        (
            tr("{n} profil(s) Cloudflare").format(n=report.profiles),
            tr("{n} service token(s)").format(n=report.tokens),
            tr("{n} serveur(s) SSH repris").format(n=report.ssh_profiles),
        )
    )
    layout.addWidget(label(counts, wrap=True))
    if partial:
        layout.addWidget(label(tr("Certains éléments n'ont pas été repris."), "warning", wrap=True))
    points = [f"• {w}" for w in report.warnings]
    if report.created_tokens:
        points.append(
            "• "
            + tr(
                "Tokens créés pour des profils dont le secret ne correspondait à aucun token : {names}."
            ).format(names=", ".join(report.created_tokens))
        )
    if points:
        layout.addWidget(label(tr("À vérifier :")))
        items = QListWidget()
        items.setAccessibleName(tr("Points à vérifier"))
        items.setWordWrap(True)
        items.addItems(points)
        items.setMaximumHeight(160)
        layout.addWidget(items)
    layout.addWidget(
        label(
            tr("Les secrets sont désormais conservés dans le coffre de cet ordinateur."), "muted", wrap=True
        )
    )
    if report.backup_dir is not None:
        backup = report.backup_dir
        row = QHBoxLayout()
        row.addWidget(
            label(tr("Copie de sauvegarde : {path}").format(path=backup), "mono", wrap=True, selectable=True),
            1,
        )
        open_folder = button(tr("Ouvrir le dossier"), "folder-open")
        open_folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(backup))))
        row.addWidget(open_folder, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(row)
    layout.addWidget(
        label("! " + tr("Les anciens fichiers contiennent des secrets en clair."), "warning", wrap=True)
    )
    layout.addWidget(
        label(tr("Vous pourrez aussi les supprimer plus tard dans Paramètres › Données."), "muted", wrap=True)
    )
    layout.addStretch()
    buttons = QDialogButtonBox()
    later = buttons.addButton(tr("Plus tard"), QDialogButtonBox.ButtonRole.AcceptRole)
    remove = buttons.addButton(
        tr("Supprimer les anciens fichiers…"), QDialogButtonBox.ButtonRole.DestructiveRole
    )
    remove.setProperty("role", "danger")
    remove.setAutoDefault(False)
    later.setDefault(True)

    def on_remove() -> None:
        if confirm_delete_v1(ctx, dialog):
            dialog.accept()

    remove.clicked.connect(on_remove)
    later.clicked.connect(dialog.accept)
    layout.addWidget(buttons)
    dialog.resize(720, 500)
    dialog.exec()


def confirm_delete_v1(ctx: GuiContext, parent: QWidget | None) -> bool:
    targets = v1_targets(ctx.paths.data_dir)
    listing = "\n".join(f"• {path}" for path in targets) or tr("Aucun fichier v1 à supprimer.")
    if not confirm(
        parent,  # type: ignore[arg-type]
        tr("Supprimer les anciens fichiers v1 ?"),
        tr("Ces fichiers contiennent des secrets en clair.") + "\n\n" + listing,
        tr("Supprimer ces fichiers"),
    ):
        return False
    try:
        removed = delete_v1_files(ctx.paths.data_dir)
    except OSError as exc:
        ctx.notify(
            "error",
            tr("L'opération n'a pas abouti. Aucun élément supplémentaire ne sera supprimé.") + f" ({exc})",
        )
        return False

    def mark(config: object) -> None:
        config.settings.v1_files_handled = True  # type: ignore[attr-defined]

    ctx.update_config(mark)
    ctx.notify("success", tr("{n} fichier(s) ou dossier(s) v1 supprimé(s).").format(n=len(removed)))
    return True


# --- D10 — Empreintes des serveurs -------------------------------------------------------------------------


class KnownHostsDialog(QDialog):
    def __init__(self, parent: QWidget | None, ctx: GuiContext) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle(tr("Empreintes des serveurs"))
        self.setWindowIcon(app_icon())
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Empreintes des serveurs"), "SectionTitle"))
        self.file = ctx.manager.ssh.known_hosts()
        layout.addWidget(
            label(tr("Source : {path}").format(path=self.file.path), "muted", wrap=True, selectable=True)
        )
        self.table = _table([tr("Serveur"), tr("Type"), tr("Empreinte SHA-256")], tr("Serveurs de confiance"))
        self.table.horizontalHeader().resizeSection(0, 240)
        self.table.horizontalHeader().resizeSection(1, 100)
        remember_header(self.table.horizontalHeader(), "known-hosts")
        self.table.itemSelectionChanged.connect(self._on_selection)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.table, 1)
        self.empty = label(
            tr(
                "Aucune empreinte enregistrée. Une empreinte est proposée au premier contact avec un serveur."
            ),
            "muted",
            wrap=True,
        )
        layout.addWidget(self.empty)
        self.detail = label("", "mono", wrap=True, selectable=True)
        self.detail.setAccessibleName(tr("Empreinte complète"))
        layout.addWidget(self.detail)
        row = QHBoxLayout()
        self.remove_button = button(tr("Oublier ce serveur…"), "trash", danger=True)
        self.remove_button.clicked.connect(self._remove)
        row.addWidget(self.remove_button)
        row.addStretch()
        close = QPushButton(tr("Fermer"))
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)
        self.resize(800, 500)
        self._load()

    def _load(self) -> None:
        entries = self.file.entries()
        self.table.setRowCount(len(entries))
        for index, entry in enumerate(entries):
            for column, value in enumerate(
                (entry.pattern, key_type_label(entry.algorithm), entry.fingerprint)
            ):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(index, column, item)
        self.empty.setVisible(not entries)
        self._on_selection()

    def _selected(self) -> tuple[str, str] | None:
        row = self.table.currentRow()
        if row < 0 or not self.table.selectedItems():
            return None
        server, fingerprint = self.table.item(row, 0), self.table.item(row, 2)
        if server is None or fingerprint is None:
            return None
        return server.text(), fingerprint.text()

    def _on_selection(self) -> None:
        selected = self._selected()
        self.remove_button.setEnabled(selected is not None)
        self.detail.setText(tr("Empreinte complète : {fp}").format(fp=selected[1]) if selected else "")

    def _menu(self, pos: QPoint) -> None:
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        self.table.selectRow(index.row())
        selected = self._selected()
        if selected is None:
            return
        menu = QMenu(self)
        menu.addAction(tr("Copier l'empreinte"), lambda: copy_to_clipboard(selected[1]))
        menu.addAction(tr("Oublier ce serveur…"), self._remove)
        menu.exec(self.table.viewport().mapToGlobal(pos))
        menu.deleteLater()

    def _remove(self) -> None:
        selected = self._selected()
        if selected is None:
            return
        pattern = selected[0]
        if not confirm(
            self,
            tr("Oublier l'identité de « {server} » ?").format(server=pattern),
            tr("Vous devrez vérifier son empreinte à la prochaine connexion."),
            tr("Oublier"),
        ):
            return
        try:
            KnownHostsFile(self.file.path).remove(pattern)
        except OSError as exc:
            self.ctx.notify("error", str(exc))
            return
        self._load()
        self.ctx.notify("success", tr("Empreinte oubliée. Elle sera demandée à la prochaine connexion."))


# --- D9 — Clés SSH -----------------------------------------------------------------------------------------


class GenerateKeyDialog(QDialog):
    """Nom, type (ED25519 : le seul pris en charge par le générateur) et phrase de passe facultative."""

    def __init__(self, parent: QWidget | None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Générer une clé SSH"))
        self.setWindowIcon(app_icon())
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Générer une clé SSH"), "SectionTitle"))
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self.name = QLineEdit()
        self.name.setPlaceholderText("nas")
        self.name.setAccessibleName(tr("Nom"))
        form.addRow(tr("Nom"), self.name)
        form.addRow(tr("Type"), label("ED25519"))
        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase.setAccessibleName(tr("Phrase de passe"))
        self.confirmation = QLineEdit()
        self.confirmation.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirmation.setAccessibleName(tr("Confirmation"))
        pair = QHBoxLayout()
        first = QFormLayout()
        first.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        first.addRow(tr("Phrase de passe"), self.passphrase)
        second = QFormLayout()
        second.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        second.addRow(tr("Confirmation"), self.confirmation)
        pair.addLayout(first, 1)
        pair.addLayout(second, 1)
        form.addRow(pair)
        layout.addLayout(form)
        layout.addWidget(
            label(
                tr("Laissez vide pour une clé non chiffrée. Sinon, utilisez au moins 8 caractères."),
                "muted",
                wrap=True,
            )
        )
        self.error = label("", "error", wrap=True)
        layout.addWidget(self.error)
        layout.addStretch()
        buttons = QDialogButtonBox()
        buttons.addButton(tr("Annuler"), QDialogButtonBox.ButtonRole.RejectRole)
        self.ok_button = buttons.addButton(tr("Générer"), QDialogButtonBox.ButtonRole.AcceptRole)
        self.ok_button.setProperty("role", "primary")
        buttons.rejected.connect(self.reject)
        self.ok_button.clicked.connect(self._accept)
        layout.addWidget(buttons)
        self.name.textChanged.connect(lambda text: self.ok_button.setEnabled(bool(text.strip())))
        self.ok_button.setEnabled(False)
        self.resize(580, 400)

    def _accept(self) -> None:
        phrase = self.passphrase.text()
        if phrase and len(phrase) < 8:
            self.error.setText(tr("Utilisez au moins 8 caractères."))
        elif phrase != self.confirmation.text():
            self.error.setText(tr("Les deux phrases de passe ne correspondent pas."))
        elif self.name.text().strip():
            self.accept()

    def value(self) -> tuple[str, str | None]:
        return self.name.text().strip(), self.passphrase.text() or None


def ask_generate_key(parent: QWidget | None) -> tuple[str, str | None] | None:
    """Boîte de génération, isolée pour que les tests la remplacent."""
    dialog = GenerateKeyDialog(parent)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


class KeysDialog(QDialog):
    """Clés SSH : celles de l'application et celles de ~/.ssh (jamais supprimées d'ici)."""

    def __init__(self, parent: QWidget | None, ctx: GuiContext) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle(tr("Clés SSH"))
        self.setWindowIcon(app_icon())
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Clés SSH"), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Les clés de CMA et celles de votre dossier .ssh sont listées ici. Clés de CMA : {path}"
                ).format(path=ctx.paths.keys_dir),
                "muted",
                wrap=True,
                selectable=True,
            )
        )
        self.table = _table(
            [tr("Nom"), tr("Type"), tr("Empreinte SHA-256"), tr("Origine"), tr("Chiffrée")], tr("Clés SSH")
        )
        for column, width in enumerate((200, 90, 300, 110)):
            self.table.horizontalHeader().resizeSection(column, width)
        remember_header(self.table.horizontalHeader(), "ssh-keys")
        self.table.itemSelectionChanged.connect(self._on_selection)
        self.table.doubleClicked.connect(lambda _i: self._on_selection())
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        layout.addWidget(self.table, 1)
        self.empty = label(tr("Aucune clé SSH disponible."), "muted")
        layout.addWidget(self.empty)
        self.detail = label("", "mono", wrap=True, selectable=True)
        self.detail.setAccessibleName(tr("Empreinte complète"))
        layout.addWidget(self.detail)
        row = QHBoxLayout()
        generate = primary_button(tr("Générer une clé…"), "plus")
        generate.clicked.connect(self._generate)
        self.copy_button = button(tr("Copier la clé publique"), "copy")
        self.copy_button.clicked.connect(self._copy)
        self.delete_button = button(tr("Supprimer…"), "trash", danger=True)
        self.delete_button.clicked.connect(self._delete)
        folder = button(tr("Ouvrir le dossier"), "folder-open")
        folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(ctx.paths.keys_dir))))
        for widget in (generate, self.copy_button, self.delete_button, folder):
            row.addWidget(widget)
        row.addStretch()
        close = QPushButton(tr("Fermer"))
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)
        self.resize(840, 560)
        self.keys: list[KeyInfo] = []
        self._load()

    def _load(self, select: Path | None = None) -> None:
        self.keys = list_keys(self.ctx.paths.keys_dir)
        self.table.setRowCount(len(self.keys))
        for index, key in enumerate(self.keys):
            values = [
                key.name,
                key_type_label(key.algorithm),
                key.fingerprint,
                tr("Application") if key.source == KeySource.APP else "~/.ssh",
                tr("Oui") if key.encrypted else tr("Non"),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(str(key.path) if column == 0 else value)
                item.setData(Qt.ItemDataRole.UserRole, str(key.path))
                self.table.setItem(index, column, item)
            if select is not None and key.path == select:
                self.table.selectRow(index)
        self.empty.setVisible(not self.keys)
        self._on_selection()

    def _selected_key(self) -> KeyInfo | None:
        row = self.table.currentRow()
        if not self.table.selectedItems() or not 0 <= row < len(self.keys):
            return None
        return self.keys[row]

    def _selected(self) -> Path | None:
        key = self._selected_key()
        return key.path if key else None

    def _on_selection(self) -> None:
        key = self._selected_key()
        self.copy_button.setEnabled(key is not None)
        own = key is not None and key.source == KeySource.APP
        self.delete_button.setEnabled(own)
        self.delete_button.setToolTip(
            "" if own or key is None else tr("Les clés de ~/.ssh ne sont pas supprimées depuis CMA.")
        )
        self.detail.setText(tr("Empreinte complète : {fp}").format(fp=key.fingerprint) if key else "")

    def _menu(self, pos: QPoint) -> None:
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        self.table.selectRow(index.row())
        menu = QMenu(self)
        menu.addAction(tr("Copier la clé publique"), self._copy)
        delete = menu.addAction(tr("Supprimer…"), self._delete)
        delete.setEnabled(self.delete_button.isEnabled())
        menu.exec(self.table.viewport().mapToGlobal(pos))
        menu.deleteLater()

    def _generate(self) -> None:
        answer = ask_generate_key(self)
        if answer is None:
            return
        name, passphrase = answer
        try:
            info = generate_key(self.ctx.paths.keys_dir, name, passphrase=passphrase)
        except (ValueError, FileExistsError) as exc:
            self.ctx.notify("error", str(exc))
            return
        except OSError as exc:
            self.ctx.notify("error", tr("Impossible de créer la clé dans ce dossier.") + f" ({exc})")
            return
        self._load(select=info.path)
        self.ctx.notify("success", tr("Clé {name} créée.").format(name=info.name))

    def _copy(self) -> None:
        path = self._selected()
        if path is None:
            return
        try:
            copy_to_clipboard(public_key_line(path))
        except Exception as exc:
            self.ctx.notify("error", tr("Clé illisible : {error}").format(error=exc))
            return
        self.ctx.notify("success", tr("Clé publique copiée."))

    def _delete(self) -> None:
        key = self._selected_key()
        if key is None or key.source != KeySource.APP:
            return
        stored = {key.name, str(key.path)}
        users = [p.name for p in self.ctx.config().ssh_profiles if p.key_path in stored]
        details = [str(key.path)]
        if users:
            details.append(tr("Utilisée par : {names}.").format(names=", ".join(users)))
        details.append(tr("Cette suppression ne retire pas la clé publique des serveurs."))
        if not confirm(
            self,
            tr("Supprimer la clé « {name} » ?").format(name=key.name),
            "\n".join(details),
            tr("Supprimer la clé"),
        ):
            return
        try:
            delete_key(key.path, self.ctx.paths.keys_dir)
        except OSError as exc:
            self.ctx.notify(
                "error",
                tr("L'opération n'a pas abouti. Aucun élément supplémentaire ne sera supprimé.")
                + f" ({exc})",
            )
            return
        self._load()


# --- D11 — Coffre des secrets de repli ---------------------------------------------------------------------


class SecretStoreDialog(QDialog):
    """Sans Gestionnaire d'identifiants : coffre chiffré (création ou ouverture) ou secrets en mémoire."""

    def __init__(self, parent: QWidget | None, encrypted_file: Path, *, portable: bool = False) -> None:
        super().__init__(parent)
        self.exists = encrypted_file.exists()
        self.passphrase_value: str | None = None
        self.setWindowTitle(tr("Coffre des secrets"))
        self.setWindowIcon(app_icon())
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Choisir comment conserver vos secrets"), "SectionTitle"))
        intro = (
            tr(
                "Version portable : les secrets sont gardés dans un coffre chiffré du dossier data/, "
                "pour vous suivre d'un poste à l'autre."
            )
            if portable
            else tr("Le Gestionnaire d'identifiants Windows n'est pas disponible.")
        )
        layout.addWidget(label(intro, "muted", wrap=True))
        self.create_new = QRadioButton(tr("Créer un coffre chiffré"))
        self.open_existing = QRadioButton(tr("Ouvrir un coffre existant"))
        self.memory = QRadioButton(tr("Continuer sans conserver les secrets"))
        group = QButtonGroup(self)
        for radio in (self.create_new, self.open_existing, self.memory):
            group.addButton(radio)
            layout.addWidget(radio)
        self.create_new.setEnabled(not self.exists)
        self.open_existing.setEnabled(self.exists)
        (self.open_existing if self.exists else self.create_new).setChecked(True)
        self.location = label(
            tr("Emplacement : {path}").format(path=encrypted_file), "mono", wrap=True, selectable=True
        )
        layout.addWidget(self.location)
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase.setAccessibleName(tr("Phrase de passe"))
        self.confirmation = QLineEdit()
        self.confirmation.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirmation.setAccessibleName(tr("Confirmation"))
        form.addRow(tr("Phrase de passe"), self.passphrase)
        self.confirmation_label = label(tr("Confirmation"))
        form.addRow(self.confirmation_label, self.confirmation)
        layout.addLayout(form)
        self.hint = label("", "muted", wrap=True)
        layout.addWidget(self.hint)
        self.error = label("", "error", wrap=True)
        layout.addWidget(self.error)
        layout.addStretch()
        buttons = QDialogButtonBox()
        buttons.addButton(tr("Annuler"), QDialogButtonBox.ButtonRole.RejectRole)
        self.ok_button = buttons.addButton(tr("Continuer"), QDialogButtonBox.ButtonRole.AcceptRole)
        self.ok_button.setProperty("role", "primary")
        buttons.rejected.connect(self.reject)
        self.ok_button.clicked.connect(self._accept)
        layout.addWidget(buttons)
        for radio in (self.create_new, self.open_existing, self.memory):
            radio.toggled.connect(self._refresh)
        for field in (self.passphrase, self.confirmation):
            field.textChanged.connect(self._refresh)
        self._refresh()
        self.resize(640, 460)

    def _refresh(self, *_args: object) -> None:
        memory = self.memory.isChecked()
        creating = self.create_new.isChecked()
        self.location.setVisible(not memory)
        self.passphrase.setVisible(not memory)
        self.confirmation.setVisible(creating)
        self.confirmation_label.setVisible(creating)
        if memory:
            self.hint.setText(
                tr("Les secrets seront perdus à la fermeture de CMA. Vous devrez les saisir à nouveau.")
            )
        elif creating:
            self.hint.setText(
                tr("Utilisez au moins 8 caractères. Cette phrase de passe sera demandée à chaque démarrage.")
            )
        else:
            self.hint.setText(tr("Saisissez la phrase de passe de ce coffre."))
        self.ok_button.setEnabled(memory or bool(self.passphrase.text()))

    def _accept(self) -> None:
        if self.memory.isChecked():
            self.passphrase_value = None
            self.accept()
            return
        phrase = self.passphrase.text()
        if self.create_new.isChecked():
            if len(phrase) < 8:
                self.error.setText(tr("Utilisez au moins 8 caractères."))
                return
            if phrase != self.confirmation.text():
                self.error.setText(tr("Les deux phrases de passe ne correspondent pas."))
                return
        if not phrase:
            return
        self.passphrase_value = phrase
        self.accept()


def choose_secret_store(
    parent: QWidget | None, encrypted_file: Path, *, portable: bool = False
) -> str | None:
    """Renvoie la phrase de passe du coffre chiffré, ou None pour garder les secrets en mémoire."""
    dialog = SecretStoreDialog(parent, encrypted_file, portable=portable)
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return None
    return dialog.passphrase_value
