"""Onglet « Ports distants » : ports en écoute découverts sur le serveur, à rediriger en un clic."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QPoint,
    QSortFilterProxyModel,
    Qt,
)
from PySide6.QtGui import QColor, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QMenu,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from cma.core.ssh.discovery import DiscoveryResult, RemotePort
from cma.i18n import tr
from cma.ui.format import last_read
from cma.ui.state import remember_header
from cma.ui.theme import current_tokens
from cma.ui.widgets import (
    add_shortcut,
    button,
    copy_to_clipboard,
    label,
    primary_button,
)

if TYPE_CHECKING:
    from cma.ui.views.ssh.view import SshProfilePanel


def port_columns() -> list[str]:
    return [tr("Port"), tr("Écoute"), tr("Service ou conteneur"), tr("Web")]


class RemotePortsModel(QAbstractTableModel):
    def __init__(self) -> None:
        super().__init__()
        self.ports: list[RemotePort] = []

    def set_ports(self, ports: list[RemotePort]) -> None:
        self.beginResetModel()
        self.ports = ports
        self.endResetModel()

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 0 if parent.isValid() else len(self.ports)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:  # noqa: B008
        return 4

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return port_columns()[section]
        return None

    def data(
        self, index: QModelIndex | QPersistentModelIndex, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if not index.isValid():
            return None
        port = self.ports[index.row()]
        column = index.column()
        web = "—" if port.web_label in ("", "-") else port.web_label
        if role == Qt.ItemDataRole.DisplayRole:
            return [str(port.port), ", ".join(port.bind), port.display_name, web][column]
        if role == Qt.ItemDataRole.UserRole:
            return [port.port, ", ".join(port.bind), port.display_name.lower(), port.web_label][column]
        if role == Qt.ItemDataRole.AccessibleTextRole:
            return tr("Port {port}, écoute {bind}, {service}, web : {web}").format(
                port=port.port, bind=", ".join(port.bind) or "?", service=port.display_name, web=web
            )
        if role == Qt.ItemDataRole.ToolTipRole:
            details = [f"{port.port}/tcp", tr("écoute : {bind}").format(bind=", ".join(port.bind) or "?")]
            if port.final_url:
                details.append(port.final_url)
            if port.local_only:
                details.append(
                    tr(
                        "n'écoute que localement sur le serveur : une redirection SSH est le bon moyen d'y accéder"
                    )
                )
            return "\n".join(details)
        if role == Qt.ItemDataRole.ForegroundRole and column == 3 and port.http_code:
            tokens = current_tokens()
            return QColor(tokens.success if 200 <= port.http_code < 400 else tokens.warning)
        return None


class PortsTab(QWidget):
    def __init__(self, panel: SshProfilePanel) -> None:
        super().__init__()
        self.panel = panel
        self._last_when: datetime | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 12, 0, 0)
        layout.setSpacing(8)
        toolbar = QHBoxLayout()
        self.refresh_button = primary_button(tr("Lister les ports"), "list-details")
        self.refresh_button.setToolTip(tr("Interroger le serveur (F5)"))
        self.refresh_button.clicked.connect(self.refresh)
        self.probe = QCheckBox(tr("Sonder HTTP/HTTPS"))
        self.probe.setChecked(True)
        toolbar.addWidget(self.refresh_button)
        toolbar.addWidget(self.probe)
        toolbar.addStretch()
        layout.addLayout(toolbar)
        filters = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText(tr("Filtrer : port, service, conteneur…"))
        self.filter.setAccessibleName(tr("Filtrer les ports"))
        self.filter.setClearButtonEnabled(True)
        filters.addWidget(self.filter, 1)
        layout.addLayout(filters)
        # Métadonnées sous le filtre : à 980 px, elles ne lui volent plus sa largeur (§4.5).
        meta = QHBoxLayout()
        self.status = label("", "meta")
        self.read_at = label("", "meta", wrap=True)
        self.read_at.setAlignment(Qt.AlignmentFlag.AlignRight)
        meta.addWidget(self.status)
        meta.addWidget(self.read_at, 1)
        layout.addLayout(meta)
        self.warnings = label("", "warning", wrap=True)
        self.warnings.hide()
        layout.addWidget(self.warnings)
        self.error_host = QWidget()
        error_row = QHBoxLayout(self.error_host)
        error_row.setContentsMargins(0, 0, 0, 0)
        self.error = label("", "error", wrap=True)
        self.retry = button(tr("Réessayer"), "refresh")
        self.retry.clicked.connect(self.refresh)
        error_row.addWidget(self.error, 1)
        error_row.addWidget(self.retry)
        self.error_host.hide()
        layout.addWidget(self.error_host)
        self.model = RemotePortsModel()
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(Qt.ItemDataRole.UserRole)
        self.proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)
        self.filter.textChanged.connect(self.proxy.setFilterFixedString)
        self.filter.textChanged.connect(lambda _t: self._update_empty())
        self.table = QTableView()
        self.table.setAccessibleName(tr("Ports distants"))
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(40)
        header = self.table.horizontalHeader()
        header.resizeSection(0, 80)
        header.resizeSection(1, 150)
        header.resizeSection(3, 110)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        remember_header(header, "ssh-ports")
        self.table.doubleClicked.connect(lambda _i: self.redirect_selected())
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.selectionModel().selectionChanged.connect(lambda *_a: self._update_redirect_button())
        layout.addWidget(self.table, 1)
        self.empty_hint = label("", "muted", wrap=True)
        layout.addWidget(self.empty_hint)
        bottom = QHBoxLayout()
        bottom.addWidget(label(tr("La destination est vue depuis le serveur SSH."), "muted"), 1)
        self.redirect_button = primary_button(tr("Rediriger…"), "arrows-right-left")
        self.redirect_button.clicked.connect(self.redirect_selected)
        bottom.addWidget(self.redirect_button)
        layout.addLayout(bottom)
        add_shortcut(self, QKeySequence.StandardKey.Refresh, self.refresh)
        self._update_empty()

    def _selected_port(self) -> RemotePort | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        return self.model.ports[self.proxy.mapToSource(rows[0]).row()]

    def _update_redirect_button(self) -> None:
        port = self._selected_port()
        self.redirect_button.setText(
            tr("Rediriger le port {port}…").format(port=port.port) if port else tr("Rediriger…")
        )

    def _update_empty(self) -> None:
        if self._last_when is None:
            text = tr("Le script de découverte est envoyé au serveur. Rien n'y est installé.")
        elif self.model.rowCount() == 0:
            text = tr("Aucun port découvert.")
        elif self.proxy.rowCount() == 0:
            text = tr("Aucun port ne correspond au filtre.")
        else:
            text = ""
        self.empty_hint.setText(text)
        self.empty_hint.setVisible(bool(text))

    def show_result(self, result: DiscoveryResult | None, when: datetime | None) -> None:
        self.model.set_ports(result.ports if result else [])
        self._last_when = when if result is not None else None
        self.error_host.hide()
        self._update_empty()
        self._update_redirect_button()
        if result is None:
            self.status.setText("")
            self.read_at.setText("")
            self.warnings.hide()
            return
        system = "Windows" if result.os == "windows" else "Linux"
        script = (
            tr("ports-report {version}").format(version=result.script_version or "?")
            if result.mode == "script"
            else "ss"
        )
        count = len(result.ports)
        ports = tr("1 port") if count == 1 else tr("{n} ports").format(n=count)
        self.status.setText(f"{ports} · {system} · {script}")
        self.read_at.setText(last_read(when))
        self.warnings.setText("\n".join("! " + w for w in result.warnings))
        self.warnings.setVisible(bool(result.warnings))

    def mark_disconnected(self, disconnected: bool) -> None:
        if self._last_when is None:
            return
        suffix = " · " + tr("Résultats conservés — serveur déconnecté.") if disconnected else ""
        self.read_at.setText(last_read(self._last_when) + suffix)

    def refresh(self) -> None:
        profile = self.panel.profile
        if profile is None:
            return
        self.refresh_button.setEnabled(False)
        self.error_host.hide()
        self.status.setText(
            tr("Recherche des ports…")
            if self.panel.is_connected()
            else tr("Connexion à {name}…").format(name=profile.name)
        )

        def done(result: DiscoveryResult) -> None:
            self.refresh_button.setEnabled(True)
            when = datetime.now()
            self.panel.view.discoveries[profile.id] = (result, when)
            if self.panel.profile is not None and self.panel.profile.id == profile.id:
                self.show_result(result, when)
                self.panel.update_connection_state()

        def failed(error: BaseException) -> None:
            self.refresh_button.setEnabled(True)
            if self.panel.profile is None or self.panel.profile.id != profile.id:
                return
            previous = self.panel.view.discoveries.get(profile.id)
            self.show_result(*(previous if previous else (None, None)))
            self.error.setText(tr("Impossible de lister les ports.") + f" {error}")
            self.error_host.show()

        self.panel.ctx.run(
            self.panel.ctx.manager.discover_ports(profile.id, probe_web=self.probe.isChecked()), done, failed
        )

    def redirect_selected(self) -> None:
        self.panel.add_forward(self._selected_port())

    def _context_menu(self, pos: QPoint) -> None:
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        self.table.selectRow(index.row())
        port = self._selected_port()
        if port is None:
            return
        menu = QMenu(self)
        menu.addAction(tr("Rediriger…"), self.redirect_selected)
        line = "\t".join((str(port.port), ", ".join(port.bind), port.display_name, port.web_label))
        menu.addAction(tr("Copier la ligne"), lambda: copy_to_clipboard(line))
        menu.exec(self.table.viewport().mapToGlobal(pos))
        menu.deleteLater()
