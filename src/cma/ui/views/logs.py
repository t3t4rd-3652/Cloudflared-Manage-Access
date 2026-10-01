"""Journaux en direct : application et sessions, filtrables par source, niveau et texte (spécification §4.7).

- Seule la cellule « Niveau » porte la couleur sémantique, doublée d'un symbole ; le message garde le texte normal.
- Un défilement vers le haut suspend « Suivre » et révèle « Reprendre le suivi ».
- « Effacer l'affichage » vide le modèle visible, jamais les fichiers.
"""

from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QPoint,
    QSortFilterProxyModel,
    Qt,
    QTimer,
    QUrl,
)
from PySide6.QtGui import QColor, QDesktopServices, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QAbstractSlider,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QSplitter,
    QStackedWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from cma.core.events import LogLine
from cma.core.sessions import SessionInfo
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.state import remember_header
from cma.ui.theme import current_tokens
from cma.ui.widgets import (
    EmptyState,
    add_shortcut,
    button,
    copy_to_clipboard,
    label,
    primary_button,
    title,
)

MAX_LINES = 10000
LEVEL_ORDER = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}
LEVEL_SYMBOL = {"DEBUG": "·", "INFO": "i", "WARNING": "!", "ERROR": "×"}


def level_label(level: str) -> str:
    return {
        "DEBUG": tr("Débogage"),
        "INFO": tr("Info"),
        "WARNING": tr("Avertissement"),
        "ERROR": tr("Erreur"),
    }.get(level, level)


def level_text(level: str) -> str:
    """Libellé affiché : symbole puis mot, pour ne jamais dépendre de la seule couleur."""
    return f"{LEVEL_SYMBOL.get(level, '?')} {level_label(level)}"


def format_line(line: LogLine) -> str:
    return f"{line.timestamp:%Y-%m-%d %H:%M:%S} {line.level:<7} {line.source_label} : {line.message}"


class LogModel(QAbstractTableModel):
    """Tampon circulaire de `MAX_LINES` lignes, alimenté par lots toutes les 150 ms."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: deque[LogLine] = deque()
        self.dropped = 0
        self._pending: list[LogLine] = []
        self._timer = QTimer(self)
        self._timer.setInterval(150)
        self._timer.timeout.connect(self.flush)
        self._timer.start()

    def add(self, line: LogLine) -> None:
        self._pending.append(line)

    def flush(self) -> None:
        if not self._pending:
            return
        skipped = max(0, len(self._pending) - MAX_LINES)
        pending, self._pending = self._pending[-MAX_LINES:], []
        self.dropped += skipped
        overflow = len(self.lines) + len(pending) - MAX_LINES
        if overflow > 0:
            overflow = min(overflow, len(self.lines))
            self.beginRemoveRows(QModelIndex(), 0, overflow - 1)
            for _ in range(overflow):
                self.lines.popleft()
            self.endRemoveRows()
            self.dropped += overflow
        start = len(self.lines)
        self.beginInsertRows(QModelIndex(), start, start + len(pending) - 1)
        self.lines.extend(pending)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self.lines.clear()
        self._pending.clear()
        self.dropped = 0
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
        column = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return [
                line.timestamp.strftime("%H:%M:%S"),
                level_text(line.level),
                line.source_label,
                line.message.replace("\n", " ⏎ "),
            ][column]
        if role == Qt.ItemDataRole.ForegroundRole and column == 1:
            tokens = current_tokens()
            color = {
                "ERROR": tokens.danger,
                "WARNING": tokens.warning,
                "INFO": tokens.info,
                "DEBUG": tokens.muted,
            }.get(line.level)
            return QColor(color) if color else None
        if role == Qt.ItemDataRole.ToolTipRole and column == 0:
            return line.timestamp.strftime("%d/%m/%Y %H:%M:%S")
        if role == Qt.ItemDataRole.ToolTipRole and column == 3 and len(line.message) > 80:
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

    def line_at(self, row: int) -> LogLine:
        return self._model.lines[self.mapToSource(self.index(row, 0)).row()]


def save_path(parent: QWidget, count: int) -> str:
    """Boîte d'enregistrement de l'export, isolée pour que les tests la remplacent."""
    heading = (
        tr("Exporter 1 événement filtré")
        if count == 1
        else tr("Exporter {n} événements filtrés").format(n=count)
    )
    path, _ = QFileDialog.getSaveFileName(
        parent, heading, str(Path.home() / "cma-journaux.txt"), tr("Texte (*.txt)")
    )
    return path


class LogsView(QWidget):
    def __init__(self, ctx: GuiContext) -> None:
        super().__init__()
        self.ctx = ctx
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 16)
        layout.setSpacing(8)
        layout.addWidget(title(tr("Journaux")))
        filters = QHBoxLayout()
        filters.setSpacing(8)
        self.source = QComboBox()
        self.source.setAccessibleName(tr("Source"))
        self.source.setMinimumWidth(200)
        self.source.addItem(tr("Toutes les sources"), None)
        self.source.addItem("CMA", "cma")
        self.level = QComboBox()
        self.level.setAccessibleName(tr("Niveau"))
        for text, value in (
            (tr("Tout, y compris débogage"), 0),
            (tr("Info et plus"), 1),
            (tr("Avertissements et erreurs"), 2),
            (tr("Erreurs"), 3),
        ):
            self.level.addItem(text, value)
        self.level.setCurrentIndex(1)
        filters.addWidget(label(tr("Source")))
        filters.addWidget(self.source)
        filters.addSpacing(8)
        filters.addWidget(label(tr("Niveau")))
        filters.addWidget(self.level)
        filters.addStretch()
        layout.addLayout(filters)
        search_row = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText(tr("Rechercher dans les journaux…"))
        self.search.setAccessibleName(tr("Rechercher dans les journaux"))
        self.search.setClearButtonEnabled(True)
        self.follow = QCheckBox(tr("Suivre"))
        self.follow.setToolTip(tr("Afficher automatiquement les derniers événements"))
        self.follow.setChecked(True)
        search_row.addWidget(self.search, 1)
        search_row.addWidget(self.follow)
        layout.addLayout(search_row)

        self.model = LogModel()
        self.proxy = LogFilter(self.model)
        self.table = QTableView()
        self.table.setAccessibleName(tr("Journal"))
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(28)
        self.table.setWordWrap(False)
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.table.setProperty("role", "mono")
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for column, width in enumerate((88, 144, 210)):
            header.resizeSection(column, width)
        header.setStretchLastSection(True)
        header.setMinimumSectionSize(64)
        remember_header(header, "logs")
        self.table.doubleClicked.connect(lambda _i: self.show_detail(expand=True))
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.selectionModel().selectionChanged.connect(lambda *_a: self._on_selection())
        self.table.verticalScrollBar().actionTriggered.connect(self._on_user_scroll)
        copy_shortcut = add_shortcut(self.table, QKeySequence.StandardKey.Copy, self._copy_selected)
        copy_shortcut.setContext(Qt.ShortcutContext.WidgetShortcut)

        reset = primary_button(tr("Réinitialiser les filtres"), "filter")
        reset.clicked.connect(self.reset_filters)
        self.no_match = EmptyState("filter", tr("Aucun événement pour ces filtres."), "", [reset])
        self.no_match.body.hide()
        self.first_use = EmptyState(
            "history",
            tr("Aucun événement"),
            tr("Les événements des connexions apparaîtront ici."),
        )
        self.table_stack = QStackedWidget()
        self.table_stack.addWidget(self.table)
        self.table_stack.addWidget(self.no_match)
        self.table_stack.addWidget(self.first_use)

        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setAccessibleName(tr("Message sélectionné"))
        self.detail.setPlaceholderText(tr("Sélectionnez un événement pour lire le message complet."))
        self.detail.setProperty("role", "code")
        self.detail.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.splitter = QSplitter(Qt.Orientation.Vertical)
        self.splitter.addWidget(self.table_stack)
        self.splitter.addWidget(self.detail)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setCollapsible(0, False)
        self.splitter.setSizes([480, 120])
        layout.addWidget(self.splitter, 1)

        counter_row = QHBoxLayout()
        self.counter = label("", "meta")
        self.resume = button(tr("Reprendre le suivi"), "player-play")
        self.resume.clicked.connect(lambda: self.follow.setChecked(True))
        self.resume.hide()
        counter_row.addWidget(self.counter)
        counter_row.addWidget(self.resume)
        counter_row.addStretch()
        layout.addLayout(counter_row)
        actions = QHBoxLayout()
        self.copy_button = button(tr("Copier"), "copy")
        self.copy_button.clicked.connect(self._copy)
        self.export_button = button(tr("Exporter…"), "file-export")
        self.export_button.clicked.connect(self._export)
        clear = button(
            tr("Effacer l'affichage"),
            "x",
            tooltip=tr("Vide l'affichage ; les fichiers journaux sont conservés."),
        )
        clear.clicked.connect(self.clear_display)
        folder = button(tr("Dossier des journaux"), "folder-open")
        folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(ctx.paths.logs_dir))))
        for widget in (self.copy_button, self.export_button, clear, folder):
            actions.addWidget(widget)
        actions.addStretch()
        layout.addLayout(actions)

        for widget in (self.source, self.level):
            widget.currentIndexChanged.connect(self._apply)
        self.search.textChanged.connect(self._apply)
        self.follow.toggled.connect(self._on_follow)
        self.proxy.rowsInserted.connect(self._scroll)
        for signal in (self.proxy.rowsInserted, self.proxy.rowsRemoved, self.proxy.modelReset):
            signal.connect(self._update_state)
        ctx.bridge.log_line.connect(self.model.add)
        ctx.bridge.session_changed.connect(self._register_source)
        self._update_state()

    # --- Filtres et sources ------------------------------------------------------------------------------

    def _register_source(self, info: SessionInfo) -> None:
        index = self.source.findData(info.id)
        if index < 0:
            self.source.addItem(info.name, info.id)
        elif self.source.itemText(index) != info.name:
            self.source.setItemText(index, info.name)

    def show_source(self, session_id: str) -> None:
        index = self.source.findData(session_id)
        if index >= 0:
            self.source.setCurrentIndex(index)
        self.level.setCurrentIndex(0)

    def reset_filters(self) -> None:
        self.source.setCurrentIndex(0)
        self.level.setCurrentIndex(1)
        self.search.clear()

    def load_history(self, lines: list[LogLine]) -> None:
        for line in lines:
            self.model.add(line)

    def _apply(self) -> None:
        self.proxy.set_criteria(self.level.currentData(), self.source.currentData(), self.search.text())
        self._update_state()

    # --- Suivi -------------------------------------------------------------------------------------------

    def _scroll(self) -> None:
        if self.follow.isChecked():
            self.table.scrollToBottom()

    def _on_user_scroll(self, action: int) -> None:
        if action == QAbstractSlider.SliderAction.SliderNoAction.value:
            return
        # La valeur n'est appliquée qu'après le signal : on la lit au tour suivant de la boucle.
        QTimer.singleShot(0, self._check_scrolled_up)

    def _check_scrolled_up(self) -> None:
        bar = self.table.verticalScrollBar()
        if self.follow.isChecked() and bar.value() < bar.maximum():
            self.follow.setChecked(False)

    def _on_follow(self, checked: bool) -> None:
        self.resume.setVisible(not checked)
        if checked:
            self.table.scrollToBottom()

    # --- État, détail et sélection -----------------------------------------------------------------------

    def _update_state(self, *_args: object) -> None:
        shown = self.proxy.rowCount()
        total = self.model.rowCount()
        if total == 0:
            self.table_stack.setCurrentWidget(self.first_use)
        elif shown == 0:
            self.table_stack.setCurrentWidget(self.no_match)
        else:
            self.table_stack.setCurrentWidget(self.table)
        text = (
            tr("1 événement affiché · limite 10 000")
            if shown == 1
            else tr("{n} événements affichés · limite 10 000").format(n=shown)
        )
        if self.model.dropped:
            text += " · " + tr("{n} plus anciens retirés").format(n=self.model.dropped)
        self.counter.setText(text)
        self.export_button.setEnabled(shown > 0)
        self._on_selection()

    def _selected_rows(self) -> list[int]:
        return sorted({i.row() for i in self.table.selectionModel().selectedRows()})

    def _on_selection(self) -> None:
        rows = self._selected_rows()
        shown = self.proxy.rowCount()
        self.copy_button.setEnabled(shown > 0)
        if rows:
            scope = (
                tr("Copier la ligne sélectionnée")
                if len(rows) == 1
                else tr("Copier les {n} lignes sélectionnées").format(n=len(rows))
            )
        else:
            scope = tr("Copier les {n} lignes affichées").format(n=shown)
        self.copy_button.setAccessibleName(scope)
        self.copy_button.setToolTip(scope)
        self.show_detail()

    def show_detail(self, *, expand: bool = False) -> None:
        index = self.table.currentIndex()
        rows = self._selected_rows()
        if not rows or not index.isValid():
            self.detail.clear()
            return
        line = self.proxy.line_at(index.row())
        self.detail.setPlainText(
            f"{line.timestamp:%d/%m/%Y %H:%M:%S} · {level_text(line.level)} · {line.source_label}\n\n{line.message}"
        )
        if expand:
            sizes = self.splitter.sizes()
            if len(sizes) == 2 and sizes[1] < 120:
                self.splitter.setSizes([max(sizes[0] - 160, 120), sizes[1] + 160])

    def _context_menu(self, pos: QPoint) -> None:
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        if index.row() not in self._selected_rows():
            self.table.selectRow(index.row())
        menu = QMenu(self)
        menu.addAction(tr("Copier les lignes sélectionnées"), self._copy_selected)
        menu.addAction(tr("Afficher le message complet"), lambda: self.show_detail(expand=True))
        menu.exec(self.table.viewport().mapToGlobal(pos))
        menu.deleteLater()

    # --- Actions -----------------------------------------------------------------------------------------

    def visible_lines(self, only_selected: bool) -> list[str]:
        rows = self._selected_rows() if only_selected else range(self.proxy.rowCount())
        return [format_line(self.proxy.line_at(row)) for row in rows]

    def _copy_lines(self, lines: list[str]) -> None:
        if not lines:
            return
        copy_to_clipboard("\n".join(lines))
        self.ctx.notify(
            "success",
            tr("1 ligne copiée.") if len(lines) == 1 else tr("{n} lignes copiées.").format(n=len(lines)),
        )

    def _copy_selected(self) -> None:
        self._copy_lines(self.visible_lines(True))

    def _copy(self) -> None:
        self._copy_lines(self.visible_lines(bool(self._selected_rows())))

    def _export(self) -> None:
        lines = self.visible_lines(False)
        if not lines:
            return
        path = save_path(self, len(lines))
        if not path:
            return
        try:
            Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        except OSError:
            self.ctx.notify("error", tr("Impossible d'écrire le fichier. Choisissez un autre emplacement."))
            return
        self.ctx.notify("success", tr("Journaux exportés."))

    def clear_display(self) -> None:
        self.model.clear()
        self.detail.clear()
        self._update_state()
        self.ctx.notify("info", tr("Affichage effacé. Les fichiers journaux sont conservés."))

    def error_count(self) -> int:
        return sum(1 for line in self.model.lines if line.level == "ERROR")
