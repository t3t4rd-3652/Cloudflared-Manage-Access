"""Import (avec aperçu des conflits) et export (secrets exclus par défaut, chiffrés sinon)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHeaderView,
    QLineEdit,
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
    ImportPlan,
    apply_import,
    build_export,
    plan_import,
    read_import_file,
    write_export,
)
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.dialogs.prompts import ask_new_passphrase
from cma.ui.icons import app_icon
from cma.ui.widgets import label

KIND_LABELS = {"token": "Token", "cloudflare": "Cloudflare", "ssh": "SSH"}


class ImportDialog(QDialog):
    def __init__(self, parent: QWidget | None, plan: ImportPlan) -> None:
        super().__init__(parent)
        self.plan = plan
        self.setWindowTitle(tr("Importer des profils"))
        self.setWindowIcon(app_icon())
        layout = QVBoxLayout(self)
        source = {
            "v2": tr("Export CMA 2"),
            "v1-profiles": tr("Profils de la v1"),
            "v1-tokens": tr("Tokens de la v1"),
            "v1-ssh": tr("Profils SSH de la v1"),
        }.get(plan.source, plan.source)
        layout.addWidget(
            label(
                tr("Format détecté : {source}. Choisissez le sort de chaque élément.").format(source=source),
                wrap=True,
            )
        )
        self.table = QTableWidget(len(plan.items), 4)
        self.table.setHorizontalHeaderLabels([tr("Type"), tr("Nom"), tr("Conflit"), tr("Action")])
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._combos: list[QComboBox] = []
        for row, item in enumerate(plan.items):
            self.table.setItem(row, 0, QTableWidgetItem(KIND_LABELS[item.kind]))
            self.table.setItem(row, 1, QTableWidgetItem(item.name))
            conflict = (
                tr("même profil")
                if item.existing is not None and item.existing.id == item.incoming.id
                else (tr("même nom") if item.existing is not None else "-")
            )
            self.table.setItem(row, 2, QTableWidgetItem(conflict))
            combo = QComboBox()
            if item.existing is None:
                actions = [Action.ADD, Action.SKIP]
            else:
                actions = [Action.REPLACE, Action.RENAME, Action.SKIP]
            for action in actions:
                combo.addItem(action.label, action)
            combo.setCurrentIndex(max(0, combo.findData(item.action)))
            self.table.setCellWidget(row, 3, combo)
            self._combos.append(combo)
        layout.addWidget(self.table)
        if plan.warnings:
            layout.addWidget(
                label(tr("Avertissements :") + "\n• " + "\n• ".join(plan.warnings), "warning", wrap=True)
            )
        self.passphrase = QLineEdit()
        self.passphrase.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase_error = label("", "error")
        if plan.needs_passphrase:
            form = QFormLayout()
            form.addRow(tr("Phrase de passe des secrets :"), self.passphrase)
            layout.addLayout(form)
            layout.addWidget(label(tr("Laissez vide pour importer sans les secrets."), "muted"))
            layout.addWidget(self.passphrase_error)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("Importer"))
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("Annuler"))
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.resize(640, 420)

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
        parent, tr("Importer des profils"), str(Path.home()), tr("Fichiers JSON (*.json)")
    )
    if not path:
        return
    try:
        plan = plan_import(read_import_file(Path(path)), ctx.config())
    except ImportError_ as exc:
        ctx.notify("error", str(exc))
        return
    dialog = ImportDialog(parent, plan)
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return
    try:
        summary = apply_import(plan, ctx.store, ctx.core.secrets)
    except Exception as exc:
        ctx.notify("error", tr("Import impossible : {error}").format(error=exc))
        return
    text = tr(
        "Import terminé : {added} ajouté(s), {replaced} remplacé(s), {skipped} ignoré(s), {secrets} secret(s)."
    ).format(added=summary.added, replaced=summary.replaced, skipped=summary.skipped, secrets=summary.secrets)
    ctx.notify(
        "success" if not summary.warnings else "warning",
        text + ("\n• " + "\n• ".join(summary.warnings) if summary.warnings else ""),
    )


class ExportDialog(QDialog):
    def __init__(self, parent: QWidget | None, ctx: GuiContext, preselect: set[str] | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Exporter des profils"))
        self.setWindowIcon(app_icon())
        config = ctx.config()
        layout = QVBoxLayout(self)
        layout.addWidget(
            label(
                tr(
                    "Choisissez les éléments à exporter. Les tokens utilisés par les profils cochés sont toujours inclus."
                ),
                wrap=True,
            )
        )
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self._items: list[tuple[QTreeWidgetItem, str, str]] = []
        for kind, heading, entries in (
            ("cloudflare", tr("Profils Cloudflare"), config.cloudflare_profiles),
            ("token", tr("Service tokens"), config.tokens),
            ("ssh", tr("Profils SSH"), config.ssh_profiles),
        ):
            parent_item = QTreeWidgetItem([heading])
            parent_item.setFlags(
                parent_item.flags() | Qt.ItemFlag.ItemIsAutoTristate | Qt.ItemFlag.ItemIsUserCheckable
            )
            self.tree.addTopLevelItem(parent_item)
            for entry in entries:
                child = QTreeWidgetItem([entry.name])
                child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                checked = preselect is None or entry.id in preselect
                child.setCheckState(0, Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
                parent_item.addChild(child)
                self._items.append((child, kind, entry.id))
            parent_item.setExpanded(True)
        layout.addWidget(self.tree)
        self.with_secrets = QCheckBox(tr("Inclure les secrets (chiffrés par une phrase de passe)"))
        layout.addWidget(self.with_secrets)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("Exporter…"))
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText(tr("Annuler"))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.resize(460, 480)

    def selection(self, kind: str) -> set[str]:
        return {
            entry_id
            for item, item_kind, entry_id in self._items
            if item_kind == kind and item.checkState(0) == Qt.CheckState.Checked
        }


def run_export(ctx: GuiContext, parent: QWidget | None, preselect: set[str] | None = None) -> None:
    dialog = ExportDialog(parent, ctx, preselect)
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return
    passphrase = None
    if dialog.with_secrets.isChecked():
        passphrase = ask_new_passphrase(
            parent,
            tr("Chiffrement des secrets"),
            tr("Cette phrase de passe sera demandée à l'import. Elle n'est enregistrée nulle part."),
        )
        if passphrase is None:
            return
    path, _ = QFileDialog.getSaveFileName(
        parent, tr("Exporter des profils"), str(Path.home() / "cma-export.json"), tr("Fichiers JSON (*.json)")
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
        ctx.notify("error", tr("Export impossible : {error}").format(error=exc))
        return
    ctx.notify("success", tr("Export enregistré : {path}").format(path=path))
