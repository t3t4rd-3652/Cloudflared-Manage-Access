"""Instantanés de la configuration Cloudflare : prendre, comparer (à l'état actuel ou au précédent), exporter."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QSplitter,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.cfadmin import CloudflareAdmin
from cma.core.cfapi import Account
from cma.core.snapshot import (
    SnapshotChange,
    SnapshotFile,
    counts,
    diff_snapshots,
    list_snapshots,
    load_snapshot,
    save_snapshot,
    section_label,
)
from cma.i18n import tr
from cma.paths import AppPaths
from cma.ui.context import GuiContext
from cma.ui.icons import app_icon
from cma.ui.states import plural
from cma.ui.views.cloud.helpers import data_table, describe_api_error
from cma.ui.widgets import button, clear_items, label, primary_button, title


def snapshot_dir(paths: AppPaths) -> Path:
    return paths.data_dir / "snapshots"


def kind_label(kind: str) -> str:
    return {"added": tr("ajouté"), "removed": tr("supprimé"), "changed": tr("modifié")}.get(kind, kind)


def content_summary(snapshot: dict[str, Any]) -> str:
    numbers = counts(snapshot)
    parts = [
        plural(numbers["tunnels"], tr("{n} tunnel"), tr("{n} tunnels")),
        plural(numbers["apps"], tr("{n} application"), tr("{n} applications")),
        plural(numbers["policies"], tr("{n} politique"), tr("{n} politiques")),
        plural(numbers["service_tokens"], tr("{n} token"), tr("{n} tokens")),
    ]
    return " · ".join(parts)


def ask_export_path(parent: QWidget, name: str) -> Path | None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    path, _filter = QFileDialog.getSaveFileName(
        parent, tr("Exporter l'instantané"), str(Path.home() / name), "JSON (*.json)"
    )
    return Path(path) if path else None


class SnapshotsDialog(QDialog):
    def __init__(
        self, parent: QWidget | None, ctx: GuiContext, admin: CloudflareAdmin, account: Account
    ) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.admin = admin
        self.account = account
        self.directory = snapshot_dir(ctx.paths)
        self.files: list[SnapshotFile] = []
        self.setWindowTitle(tr("Instantanés de la configuration"))
        self.setWindowIcon(app_icon())
        self.resize(960, 600)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Instantanés de « {name} »").format(name=account.name), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Un instantané garde la configuration du compte (tunnels et règles, applications, politiques, "
                    "tokens sans leurs secrets, DNS des noms publiés, réseaux privés). Comparer deux instantanés "
                    "montre ce qui a changé, y compris depuis le tableau de bord. Les 30 derniers sont gardés."
                ),
                "muted",
                wrap=True,
            )
        )
        actions = QHBoxLayout()
        self.take_button = primary_button(tr("Prendre un instantané"), "plus")
        self.take_button.clicked.connect(self.take)
        actions.addWidget(self.take_button)
        self.now_button = button(tr("Comparer à l'état actuel"), "arrows-right-left")
        self.now_button.clicked.connect(self.compare_with_now)
        actions.addWidget(self.now_button)
        self.previous_button = button(tr("Comparer au précédent"), "history")
        self.previous_button.clicked.connect(self.compare_with_previous)
        actions.addWidget(self.previous_button)
        actions.addStretch()
        self.export_button = button(tr("Exporter…"), "file-export")
        self.export_button.clicked.connect(self.export)
        actions.addWidget(self.export_button)
        folder = button(tr("Ouvrir le dossier"), "folder-open")
        folder.clicked.connect(self.open_folder)
        actions.addWidget(folder)
        layout.addLayout(actions)
        splitter = QSplitter()
        self.table = data_table([tr("Date"), tr("Contenu")], tr("Instantanés enregistrés"))
        self.table.horizontalHeader().resizeSection(0, 150)
        self.table.itemSelectionChanged.connect(self._update_actions)
        splitter.addWidget(self.table)
        self.changes = QTreeWidget()
        self.changes.setHeaderHidden(True)
        self.changes.setAccessibleName(tr("Changements"))
        splitter.addWidget(self.changes)
        splitter.setSizes([380, 580])
        layout.addWidget(splitter, 1)
        self.status = label("", "meta", wrap=True)
        layout.addWidget(self.status)
        footer = QHBoxLayout()
        footer.addStretch()
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)
        self.reload()

    # --- Liste ------------------------------------------------------------------------------------------

    def reload(self, select: Path | None = None) -> None:
        self.files = list_snapshots(self.directory, self.account.id)
        clear_items(self.table, len(self.files))
        for row, item in enumerate(self.files):
            try:
                summary = content_summary(load_snapshot(item.path))
            except (OSError, ValueError) as exc:
                summary = tr("illisible : {error}").format(error=exc)
            moment = item.taken_at.astimezone().strftime("%d/%m/%Y %H:%M")
            self.table.setItem(row, 0, QTableWidgetItem(moment))
            content = QTableWidgetItem(summary)
            content.setToolTip(summary)
            self.table.setItem(row, 1, content)
        if self.files:
            index = next((i for i, f in enumerate(self.files) if f.path == select), 0)
            self.table.selectRow(index)
        else:
            self.status.setText(tr("Aucun instantané pour ce compte : prenez-en un pour commencer."))
        self._update_actions()

    def selected(self) -> SnapshotFile | None:
        row = self.table.currentRow()
        return self.files[row] if 0 <= row < len(self.files) and self.table.selectedItems() else None

    def _update_actions(self, busy: bool = False) -> None:
        chosen = self.selected()
        self.take_button.setEnabled(not busy)
        self.now_button.setEnabled(not busy and chosen is not None)
        self.previous_button.setEnabled(not busy and chosen is not None and chosen != self.files[-1])
        self.export_button.setEnabled(not busy and chosen is not None)

    # --- Actions ----------------------------------------------------------------------------------------

    def _failed(self, error: BaseException) -> None:
        self._update_actions()
        self.status.setText(describe_api_error(error))

    def take(self) -> None:
        """Lit le compte, enregistre l'instantané, puis le compare au précédent s'il y en a un."""
        previous = self.files[0] if self.files else None
        self._update_actions(busy=True)
        self.status.setText(tr("Lecture de la configuration du compte…"))

        def done(snapshot: dict[str, Any]) -> None:
            try:
                path = save_snapshot(self.directory, snapshot)
            except OSError as exc:
                self._failed(exc)
                return
            self.reload(select=path)
            if previous is not None:
                self.show_changes(
                    load_snapshot(previous.path),
                    snapshot,
                    previous.taken_at.astimezone().strftime("%d/%m/%Y %H:%M"),
                )
            else:
                self.status.setText(
                    tr("Instantané enregistré : {summary}.").format(summary=content_summary(snapshot))
                )
                clear_items(self.changes)

        self.ctx.run(self.admin.snapshot(self.account), done, self._failed)

    def compare_with_now(self) -> None:
        chosen = self.selected()
        if chosen is None:
            return
        self._update_actions(busy=True)
        self.status.setText(tr("Lecture de la configuration du compte…"))

        def done(current: dict[str, Any]) -> None:
            self._update_actions()
            self.show_changes(
                load_snapshot(chosen.path), current, chosen.taken_at.astimezone().strftime("%d/%m/%Y %H:%M")
            )

        self.ctx.run(self.admin.snapshot(self.account), done, self._failed)

    def compare_with_previous(self) -> None:
        chosen = self.selected()
        if chosen is None or chosen == self.files[-1]:
            return
        older = self.files[self.files.index(chosen) + 1]
        self.show_changes(
            load_snapshot(older.path),
            load_snapshot(chosen.path),
            older.taken_at.astimezone().strftime("%d/%m/%Y %H:%M"),
        )

    def show_changes(self, old: dict[str, Any], new: dict[str, Any], since: str) -> None:
        changes = diff_snapshots(old, new)
        self.fill_changes(changes)
        if changes:
            count = plural(len(changes), tr("{n} changement"), tr("{n} changements"))
            self.status.setText(tr("{changes} depuis le {date}.").format(changes=count, date=since))
        else:
            self.status.setText(tr("Aucun changement depuis le {date}.").format(date=since))
        skipped = sorted(set(old.get("unreadable") or []) | set(new.get("unreadable") or []))
        if skipped:
            self.status.setText(
                self.status.text()
                + " "
                + tr("Non comparé (permission manquante) : {sections}.").format(
                    sections=", ".join(section_label(s) for s in skipped)
                )
            )

    def fill_changes(self, changes: list[SnapshotChange]) -> None:
        clear_items(self.changes)
        for change in changes:
            top = QTreeWidgetItem(
                [f"{section_label(change.section)} · {change.name} — {kind_label(change.kind)}"]
            )
            for detail in change.details:
                child = QTreeWidgetItem([detail])
                child.setToolTip(0, detail)
                top.addChild(child)
            self.changes.addTopLevelItem(top)
            top.setExpanded(len(changes) <= 10)

    def export(self) -> None:
        chosen = self.selected()
        if chosen is None:
            return
        target = ask_export_path(self, chosen.path.name)
        if target is None:
            return
        try:
            shutil.copyfile(chosen.path, target)
        except OSError as exc:
            self.status.setText(tr("Export impossible : {error}").format(error=exc))
            return
        self.status.setText(tr("Instantané exporté : {file}").format(file=target.name))

    def open_folder(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.directory)))


def show_snapshots(parent: QWidget, ctx: GuiContext, admin: CloudflareAdmin, account: Account) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    SnapshotsDialog(parent, ctx, admin, account).exec()
