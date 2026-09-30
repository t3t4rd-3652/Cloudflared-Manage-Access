"""Importer (D7, aperçu des conflits) et exporter (D8, secrets exclus par défaut, chiffrés sinon)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QMenu,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.crypto import WrongPassphraseError
from cma.core.transfer import (
    Action,
    ImportError_,
    ImportItem,
    ImportPlan,
    apply_import,
    build_export,
    plan_import,
    read_import_file,
    write_export,
)
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.icons import app_icon
from cma.ui.widgets import copy_to_clipboard, label, title


def kind_label(kind: str) -> str:
    return {"token": tr("Service token"), "cloudflare": tr("Accès Cloudflare"), "ssh": tr("Serveur SSH")}.get(
        kind, kind
    )


def conflict_label(item: ImportItem) -> str:
    if item.existing is None:
        return "—"
    return tr("Même profil") if item.existing.id == item.incoming.id else tr("Même nom")


def _buttons(dialog: QDialog, action: str) -> tuple[QDialogButtonBox, QPushButton]:
    buttons = QDialogButtonBox()
    buttons.addButton(tr("Annuler"), QDialogButtonBox.ButtonRole.RejectRole)
    ok = buttons.addButton(action, QDialogButtonBox.ButtonRole.AcceptRole)
    ok.setProperty("role", "primary")
    buttons.rejected.connect(dialog.reject)
    return buttons, ok


# --- D7 — Importer -----------------------------------------------------------------------------------------


class ImportDialog(QDialog):
    def __init__(self, parent: QWidget | None, plan: ImportPlan, path: Path | None = None) -> None:
        super().__init__(parent)
        self.plan = plan
        self.setWindowTitle(tr("Importer des données"))
        self.setWindowIcon(app_icon())
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Importer des données"), "SectionTitle"))
        source = {
            "v2": tr("Export CMA 2"),
            "v1-profiles": tr("Profils de la v1"),
            "v1-tokens": tr("Tokens de la v1"),
            "v1-ssh": tr("Profils SSH de la v1"),
        }.get(plan.source, plan.source)
        if path is not None:
            layout.addWidget(
                label(tr("Fichier : {path}").format(path=path), "mono", wrap=True, selectable=True)
            )
        layout.addWidget(
            label(
                tr("Format : {source}. Examinez les conflits avant d'importer.").format(source=source),
                "muted",
                wrap=True,
            )
        )
        self.table = QTableWidget(len(plan.items), 4)
        self.table.setAccessibleName(tr("Éléments à importer"))
        self.table.setHorizontalHeaderLabels([tr("Type"), tr("Nom"), tr("Conflit"), tr("Action")])
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(38)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.resizeSection(0, 150)
        header.resizeSection(2, 130)
        header.resizeSection(3, 220)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        self._combos: list[QComboBox] = []
        for row, item in enumerate(plan.items):
            for column, value in enumerate((kind_label(item.kind), item.name, conflict_label(item))):
                cell = QTableWidgetItem(value)
                cell.setToolTip(value)
                self.table.setItem(row, column, cell)
            combo = QComboBox()
            combo.setAccessibleName(tr("Action pour {name}").format(name=item.name))
            actions = (
                [Action.ADD, Action.SKIP]
                if item.existing is None
                else [Action.REPLACE, Action.RENAME, Action.SKIP]
            )
            for action in actions:
                combo.addItem(action.label, action)
            # Même objet déjà présent : « Ignorer » par prudence, le remplacement se choisit explicitement.
            initial = (
                Action.SKIP
                if item.existing is not None and item.existing.id == item.incoming.id
                else item.action
            )
            combo.setCurrentIndex(max(0, combo.findData(initial)))
            combo.currentIndexChanged.connect(self._refresh)
            self.table.setCellWidget(row, 3, combo)
            self._combos.append(combo)
        layout.addWidget(self.table, 1)
        if plan.warnings:
            layout.addWidget(label("! " + "\n! ".join(plan.warnings), "warning", wrap=True))
        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase.setAccessibleName(tr("Phrase de passe des secrets"))
        self.passphrase_error = label("", "error", wrap=True)
        if plan.needs_passphrase:
            layout.addWidget(
                label(
                    "! " + tr("Les secrets de cet export sont chiffrés par une phrase de passe."), "warning"
                )
            )
            form = QFormLayout()
            form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
            form.addRow(tr("Phrase de passe"), self.passphrase)
            layout.addLayout(form)
            layout.addWidget(label(tr("Laissez vide pour importer sans les secrets."), "muted"))
            layout.addWidget(self.passphrase_error)
        self.summary = label("", "meta")
        layout.addWidget(self.summary)
        buttons, self.ok_button = _buttons(self, tr("Importer"))
        self.ok_button.clicked.connect(self._accept)
        layout.addWidget(buttons)
        self.resize(880, 600)
        self._refresh()

    def _chosen(self) -> list[Action]:
        return [combo.currentData() for combo in self._combos]

    def _refresh(self, *_args: object) -> None:
        chosen = self._chosen()
        added = sum(1 for a in chosen if a in (Action.ADD, Action.RENAME))
        replaced = chosen.count(Action.REPLACE)
        skipped = chosen.count(Action.SKIP)
        self.summary.setText(
            tr("Résumé : {a} ajout(s) · {r} remplacement(s) · {s} ignoré(s)").format(
                a=added, r=replaced, s=skipped
            )
        )
        count = added + replaced
        self.ok_button.setText(
            tr("Importer 1 élément") if count == 1 else tr("Importer {n} éléments").format(n=count)
        )
        self.ok_button.setEnabled(count > 0)

    def _menu(self, pos: QPoint) -> None:
        row = self.table.rowAt(pos.y())
        if row < 0:
            return
        item = self.plan.items[row]
        line = "\t".join(
            (kind_label(item.kind), item.name, conflict_label(item), self._combos[row].currentText())
        )
        menu = QMenu(self)
        menu.addAction(tr("Copier la ligne"), lambda: copy_to_clipboard(line))
        menu.exec(self.table.viewport().mapToGlobal(pos))
        menu.deleteLater()

    def _accept(self) -> None:
        for combo, item in zip(self._combos, self.plan.items, strict=True):
            item.action = combo.currentData()
        if self.plan.needs_passphrase and self.passphrase.text():
            try:
                self.plan.unlock(self.passphrase.text())
            except WrongPassphraseError:
                self.passphrase_error.setText(tr("Phrase de passe incorrecte."))
                return
        self.accept()


def run_import(ctx: GuiContext, parent: QWidget | None) -> None:
    path, _ = QFileDialog.getOpenFileName(
        parent, tr("Importer des données"), str(Path.home()), tr("Fichiers JSON (*.json)")
    )
    if not path:
        return
    try:
        plan = plan_import(read_import_file(Path(path)), ctx.config())
    except ImportError_ as exc:
        ctx.notify("error", tr("Ce fichier n'est pas un export CMA reconnu.") + f" ({exc})")
        return
    dialog = ImportDialog(parent, plan, Path(path))
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return
    try:
        summary = apply_import(plan, ctx.store, ctx.core.secrets)
    except Exception as exc:
        ctx.notify("error", tr("Import impossible : {error}").format(error=exc))
        return
    done = summary.added + summary.replaced
    text = tr("1 élément importé.") if done == 1 else tr("{n} éléments importés.").format(n=done)
    if summary.skipped:
        text += " " + (
            tr("1 élément ignoré.")
            if summary.skipped == 1
            else tr("{n} éléments ignorés.").format(n=summary.skipped)
        )
    if summary.secrets:
        text += " " + tr("{n} secret(s) enregistré(s) dans le coffre.").format(n=summary.secrets)
    ctx.notify(
        "success" if not summary.warnings else "warning",
        text + ("\n• " + "\n• ".join(summary.warnings) if summary.warnings else ""),
    )


# --- D8 — Exporter -----------------------------------------------------------------------------------------


class ExportDialog(QDialog):
    def __init__(self, parent: QWidget | None, ctx: GuiContext, preselect: set[str] | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Exporter des données"))
        self.setWindowIcon(app_icon())
        config = ctx.config()
        self.config = config
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Exporter des données"), "SectionTitle"))
        layout.addWidget(
            label(
                tr("Les service tokens utilisés par les accès cochés sont toujours inclus."),
                "muted",
                wrap=True,
            )
        )
        self.tree = QTreeWidget()
        self.tree.setAccessibleName(tr("Éléments à exporter"))
        self.tree.setHeaderHidden(True)
        self._items: list[tuple[QTreeWidgetItem, str, str]] = []
        for kind, heading, entries in (
            ("cloudflare", tr("Accès Cloudflare ({n})"), config.cloudflare_profiles),
            ("token", tr("Service tokens ({n})"), config.tokens),
            ("ssh", tr("Serveurs SSH ({n})"), config.ssh_profiles),
        ):
            if not entries:
                continue
            parent_item = QTreeWidgetItem([heading.format(n=len(entries))])
            parent_item.setFlags(
                parent_item.flags() | Qt.ItemFlag.ItemIsAutoTristate | Qt.ItemFlag.ItemIsUserCheckable
            )
            self.tree.addTopLevelItem(parent_item)
            for entry in sorted(entries, key=lambda e: e.name.lower()):
                child = QTreeWidgetItem([entry.name])
                child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                checked = preselect is None or entry.id in preselect
                child.setCheckState(0, Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
                parent_item.addChild(child)
                self._items.append((child, kind, entry.id))
            parent_item.setExpanded(True)
        layout.addWidget(self.tree, 1)
        self.empty = label(tr("Aucune donnée à exporter."), "muted")
        self.empty.setVisible(not self._items)
        layout.addWidget(self.empty)
        self.dependencies = label("", "warning", wrap=True)
        layout.addWidget(self.dependencies)
        self.with_secrets = QCheckBox(tr("Inclure les secrets (chiffrés par une phrase de passe)"))
        layout.addWidget(self.with_secrets)
        self.secrets_box = QWidget()
        phrases = QHBoxLayout(self.secrets_box)
        phrases.setContentsMargins(24, 0, 0, 0)
        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase.setAccessibleName(tr("Phrase de passe"))
        self.passphrase.setPlaceholderText(tr("Phrase de passe"))
        self.confirmation = QLineEdit()
        self.confirmation.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirmation.setAccessibleName(tr("Confirmation"))
        self.confirmation.setPlaceholderText(tr("Confirmation"))
        phrases.addWidget(self.passphrase)
        phrases.addWidget(self.confirmation)
        layout.addWidget(self.secrets_box)
        self.secrets_hint = label("", "muted", wrap=True)
        layout.addWidget(self.secrets_hint)
        buttons, self.ok_button = _buttons(self, tr("Exporter…"))
        self.ok_button.clicked.connect(self._accept)
        layout.addWidget(buttons)
        self.tree.itemChanged.connect(lambda *_a: self._refresh())
        self.with_secrets.toggled.connect(lambda _c: self._refresh())
        for field in (self.passphrase, self.confirmation):
            field.textChanged.connect(lambda _t: self._refresh())
        self.resize(720, 560)
        self._refresh()

    def selection(self, kind: str) -> set[str]:
        return {
            entry_id
            for item, item_kind, entry_id in self._items
            if item_kind == kind and item.checkState(0) == Qt.CheckState.Checked
        }

    def passphrase_value(self) -> str | None:
        return self.passphrase.text() if self.with_secrets.isChecked() else None

    def _passphrase_problem(self) -> str | None:
        if not self.with_secrets.isChecked():
            return None
        if len(self.passphrase.text()) < 8:
            return tr("Utilisez au moins 8 caractères.")
        if self.passphrase.text() != self.confirmation.text():
            return tr("Les deux phrases de passe ne correspondent pas.")
        return None

    def _refresh(self) -> None:
        secrets = self.with_secrets.isChecked()
        self.secrets_box.setVisible(secrets)
        problem = self._passphrase_problem()
        if secrets:
            self.secrets_hint.setText(problem or tr("Cette phrase de passe sera demandée à l'import."))
        else:
            self.secrets_hint.setText(
                tr("Sans secrets, les destinataires devront renseigner leurs identifiants.")
            )
        chosen_cf = self.selection("cloudflare")
        notes = []
        for profile in self.config.ssh_profiles:
            via = profile.via_cloudflare_profile
            if profile.id in self.selection("ssh") and via and via not in chosen_cf:
                access = self.config.cloudflare_profile(via)
                if access is not None:
                    notes.append(
                        tr("{name} utilise l'accès {access}. Incluez-le pour conserver ce passage.").format(
                            name=profile.name, access=access.name
                        )
                    )
        self.dependencies.setText("\n".join(notes))
        self.dependencies.setVisible(bool(notes))
        selected = any(item.checkState(0) == Qt.CheckState.Checked for item, _k, _i in self._items)
        self.ok_button.setEnabled(selected and problem is None)

    def _accept(self) -> None:
        if self.ok_button.isEnabled():
            self.accept()


def run_export(ctx: GuiContext, parent: QWidget | None, preselect: set[str] | None = None) -> None:
    dialog = ExportDialog(parent, ctx, preselect)
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return
    passphrase = dialog.passphrase_value()
    path, _ = QFileDialog.getSaveFileName(
        parent, tr("Exporter des données"), str(Path.home() / "cma-export.json"), tr("Fichiers JSON (*.json)")
    )
    if not path:
        return
    data = build_export(
        ctx.config(),
        ctx.core.secrets,
        cloudflare_ids=dialog.selection("cloudflare"),
        ssh_ids=dialog.selection("ssh"),
        token_ids=dialog.selection("token"),
        passphrase=passphrase,
    )
    try:
        write_export(Path(path), data)
    except OSError as exc:
        ctx.notify("error", tr("Impossible d'enregistrer le fichier.") + f" ({exc})")
        return
    ctx.notify("success", tr("Export créé : {path}").format(path=path))
