"""État des connecteurs d'un tunnel : diagnostic en clair, puis une ligne par connexion vers Cloudflare."""

from __future__ import annotations

from PySide6.QtWidgets import QDialog, QHBoxLayout, QTableWidgetItem, QVBoxLayout, QWidget

from cma.core.cfapi import Connector, Tunnel
from cma.core.tunnelhealth import diagnose_connectors
from cma.i18n import tr
from cma.ui.icons import app_icon
from cma.ui.theme import mono_font
from cma.ui.views.cloud.helpers import data_table, expiry_label, tunnel_status_label
from cma.ui.widgets import button, label, title

FINDING_ROLES = {"success": "success", "info": "muted", "warning": "warning", "error": "error"}


def _when(value: str) -> str:
    """« 2026-10-01T08:00:01Z » → « 01/10/2026 08:00 »."""
    return f"{expiry_label(value)} {value[11:16]}".strip() if len(value) >= 16 else value or "—"


class ConnectorsDialog(QDialog):
    def __init__(self, parent: QWidget | None, tunnel: Tunnel, connectors: list[Connector]) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("État des connecteurs"))
        self.setWindowIcon(app_icon())
        self.resize(820, 440)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Connecteurs du tunnel {name}").format(name=tunnel.name), "SectionTitle"))
        layout.addWidget(label(tr("État : {state}").format(state=tunnel_status_label(tunnel.status)), "meta"))
        self.findings = diagnose_connectors(connectors)
        for finding in self.findings:
            layout.addWidget(label(finding.message, FINDING_ROLES[finding.level], wrap=True, selectable=True))
        self.table = data_table(
            [
                tr("Connecteur"),
                tr("Version"),
                tr("Système"),
                tr("Origine"),
                tr("Centre Cloudflare"),
                tr("Ouverte le"),
            ],
            tr("Connexions vers Cloudflare"),
        )
        mono = mono_font()
        for connector in connectors:
            for connection in connector.connections:
                row = self.table.rowCount()
                self.table.insertRow(row)
                state = tr(" (reconnexion)") if connection.pending_reconnect else ""
                values = (
                    connector.id[:8],
                    connector.version or "—",
                    connector.arch or "—",
                    connection.origin_ip or "—",
                    connection.colo.upper() + state,
                    _when(connection.opened_at),
                )
                for column, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    item.setToolTip(connector.id if column == 0 else value)
                    if column in (0, 3):
                        item.setFont(mono)
                    self.table.setItem(row, column, item)
        self.table.setVisible(self.table.rowCount() > 0)
        layout.addWidget(self.table, 1)
        if not connectors:
            layout.addStretch()
        footer = QHBoxLayout()
        footer.addStretch()
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)


def show_connectors(parent: QWidget, tunnel: Tunnel, connectors: list[Connector]) -> None:
    ConnectorsDialog(parent, tunnel, connectors).exec()
