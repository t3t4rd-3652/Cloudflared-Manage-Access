"""Journaux en direct : application et sessions, filtrables par source, niveau et texte."""

from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QSortFilterProxyModel,
    Qt,
    QTimer,
    QUrl,
)
from PySide6.QtGui import QColor, QDesktopServices, QFontDatabase
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from cma.core.events import LogLine
from cma.core.sessions import SessionInfo
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.theme import current_tokens
from cma.ui.widgets import button, copy_to_clipboard, title

MAX_LINES = 10000
LEVEL_ORDER = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}


def level_label(level: str) -> str:
    return {"DEBUG": tr("débogage"), "INFO": tr("info"), "WARNING": tr("avert."), "ERROR": tr("erreur")}.get(
        level, level
    )


class LogModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self.lines: deque[LogLine] = deque()
        self._pending: list[LogLine] = []
        self._timer = QTimer(self)
        self._timer.setInterval(150)
        self._timer.timeout.connect(self._flush)
        self._timer.start()

    def add(self, line: LogLine) -> None:
        self._pending.append(line)

    def _flush(self) -> None:
        if not self._pending:
            return
        pending, self._pending = self._pending[-MAX_LINES:], []
        overflow = len(self.lines) + len(pending) - MAX_LINES
        if overflow > 0:
            overflow = min(overflow, len(self.lines))
            self.beginRemoveRows(QModelIndex(), 0, overflow - 1)
            for _ in range(overflow):
                self.lines.popleft()
            self.endRemoveRows()
        start = len(self.lines)
        self.beginInsertRows(QModelIndex(), start, start + len(pending) - 1)
        self.lines.extend(pending)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self.lines.clear()
        self._pending.clear()
        self.endResetModel()

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.lines)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 4

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return [tr("Heure"), tr("Niveau"), tr("Source"), tr("Message")][section]
        return None

    def data(
        self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if not index.isValid():
            return None
        line = self.lines[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return [
                line.timestamp.strftime("%H:%M:%S"),
                level_label(line.level),
                line.source_label,
                line.message,
            ][index.column()]
        if role == Qt.ItemDataRole.ForegroundRole and index.column() in (1, 3):
            tokens = current_tokens()
            color = {"ERROR": tokens.danger, "WARNING": tokens.warning, "DEBUG": tokens.muted}.get(line.level)
            return QColor(color) if color else None
        if role == Qt.ItemDataRole.ToolTipRole and index.column() == 3:
            return line.message
        return None


class LogFilter(QSortFilterProxyModel):
    def __init__(self, model: LogModel) -> None:
        super().__init__()
        self.setSourceModel(model)
        self._model = model
        self.min_level = 1
        self.source: str | None = None
        self.needle = ""

    def set_criteria(self, min_level: int, source: str | None, needle: str) -> None:
        self.min_level, self.source, self.needle = min_level, source, needle.lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, row: int, parent: QModelIndex | QPersistentModelIndex) -> bool:
        line = self._model.lines[row]
        if LEVEL_ORDER.get(line.level, 1) < self.min_level:
            return False
        if self.source is not None and (line.source_id or "cma") != self.source:
            return False
        return (
            not self.needle or self.needle in line.message.lower() or self.needle in line.source_label.lower()
        )


class LogsView(QWidget):
    def __init__(self, ctx: GuiContext) -> None:
        super().__init__()
        self.ctx = ctx
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 16)
        layout.addWidget(title(tr("Journaux")))
        toolbar = QHBoxLayout()
        self.source = QComboBox()
        self.source.setAccessibleName(tr("Filtrer par session"))
        self.source.addItem(tr("Toutes les sources"), None)
        self.source.addItem("CMA", "cma")
        self.level = QComboBox()
        self.level.setAccessibleName(tr("Filtrer par niveau"))
        for text, value in (
            (tr("Tout, y compris débogage"), 0),
            (tr("Info et plus"), 1),
            (tr("Avertissements et erreurs"), 2),
            (tr("Erreurs"), 3),
        ):
            self.level.addItem(text, value)
        self.level.setCurrentIndex(1)
        self.search = QLineEdit()
        self.search.setPlaceholderText(tr("Rechercher dans les journaux"))
        self.search.setClearButtonEnabled(True)
        self.follow = QCheckBox(tr("Suivre"))
        self.follow.setChecked(True)
        toolbar.addWidget(self.source)
        toolbar.addWidget(self.level)
        toolbar.addWidget(self.search, 1)
        toolbar.addWidget(self.follow)
        layout.addLayout(toolbar)
        self.model = LogModel()
        self.proxy = LogFilter(self.model)
        self.table = QTableView()
        self.table.setAccessibleName(tr("Journal"))
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(22)
        self.table.setWordWrap(False)
        self.table.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.resizeSection(2, 180)
        header.setStretchLastSection(True)
        layout.addWidget(self.table, 1)
        actions = QHBoxLayout()
        copy = button(
            tr("Copier"),
            "copy",
            tooltip=tr("Copier les lignes sélectionnées (ou toutes les lignes affichées)"),
        )
        copy.clicked.connect(self._copy)
        export = button(tr("Exporter…"), "file-export")
        export.clicked.connect(self._export)
        clear = button(tr("Effacer l'affichage"), "trash")
        clear.clicked.connect(self.model.clear)
        folder = button(tr("Dossier des journaux"), "folder-open")
        folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(ctx.paths.logs_dir))))
        for widget in (copy, export, clear, folder):
            actions.addWidget(widget)
        actions.addStretch()
        layout.addLayout(actions)

        for widget in (self.source, self.level):
            widget.currentIndexChanged.connect(self._apply)
        self.search.textChanged.connect(self._apply)
        self.proxy.rowsInserted.connect(self._scroll)
        ctx.bridge.log_line.connect(self.model.add)
        ctx.bridge.session_changed.connect(self._register_source)

    def _register_source(self, info: SessionInfo) -> None:
        if self.source.findData(info.id) < 0:
            self.source.addItem(info.name, info.id)

    def show_source(self, session_id: str) -> None:
        index = self.source.findData(session_id)
        if index >= 0:
            self.source.setCurrentIndex(index)
        self.level.setCurrentIndex(0)

    def load_history(self, lines: list[LogLine]) -> None:
        for line in lines:
            self.model.add(line)

    def _apply(self) -> None:
        self.proxy.set_criteria(self.level.currentData(), self.source.currentData(), self.search.text())

    def _scroll(self) -> None:
        if self.follow.isChecked():
            self.table.scrollToBottom()

    def _visible_lines(self, only_selected: bool) -> list[str]:
        rows = (
            sorted({i.row() for i in self.table.selectionModel().selectedRows()})
            if only_selected
            else range(self.proxy.rowCount())
        )
        result = []
        for row in rows:
            line = self.model.lines[self.proxy.mapToSource(self.proxy.index(row, 0)).row()]
            result.append(
                f"{line.timestamp:%Y-%m-%d %H:%M:%S} {line.level:<7} {line.source_label} : {line.message}"
            )
        return result

    def _copy(self) -> None:
        lines = self._visible_lines(bool(self.table.selectionModel().selectedRows())) or self._visible_lines(
            False
        )
        copy_to_clipboard("\n".join(lines))
        self.ctx.notify("success", tr("{n} ligne(s) copiée(s).").format(n=len(lines)))

    def _export(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, tr("Exporter les journaux"), str(Path.home() / "cma-journaux.txt"), tr("Texte (*.txt)")
        )
        if path:
            Path(path).write_text("\n".join(self._visible_lines(False)) + "\n", encoding="utf-8")
            self.ctx.notify("success", tr("Journaux exportés : {path}").format(path=path))

    def error_count(self) -> int:
        return sum(1 for line in self.model.lines if line.level == "ERROR")
