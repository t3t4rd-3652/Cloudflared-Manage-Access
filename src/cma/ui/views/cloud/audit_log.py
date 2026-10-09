"""Journal d'audit du compte Cloudflare : modifications des 30 derniers jours (qui, quoi, d'où), filtrables par
période et par texte, exportables en CSV."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta
from pathlib import Path

from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLineEdit,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.audit import AuditEntry
from cma.core.fsutil import atomic_write_text
from cma.i18n import tr
from cma.ui.icons import app_icon
from cma.ui.states import plural
from cma.ui.theme import current_tokens, status_colors
from cma.ui.views.cloud.access_log import request_time
from cma.ui.views.cloud.helpers import data_table
from cma.ui.widgets import button, clear_items, label, title


def action_label(action: str) -> str:
    return {
        "create": tr("Création"),
        "update": tr("Modification"),
        "delete": tr("Suppression"),
        "view": tr("Lecture"),
    }.get(action, action or "—")


def product_label(product: str) -> str:
    return {
        "access": "Access",
        "cfd_tunnel": tr("Tunnels"),
        "teamnet": tr("Réseaux privés"),
        "dns": "DNS",
        "dns_records": "DNS",
        "certificates": tr("Certificats"),
        "zone": tr("Zone"),
        "members": tr("Membres"),
        "api_tokens": tr("Jetons d'API"),
    }.get(product, product or "—")


def context_label(context: str) -> str:
    return {
        "dash": tr("Tableau de bord"),
        "api_token": tr("Jeton d'API"),
        "api": tr("Clé d'API globale"),
        "oauth": "OAuth",
    }.get(context, context or "—")


def actor_label(entry: AuditEntry) -> str:
    if entry.actor:
        return entry.actor
    if entry.actor_type == "system":
        return tr("Cloudflare (automatique)")
    return tr("Jeton d'API") if entry.context == "api_token" else "—"


def entry_moment(entry: AuditEntry) -> datetime | None:
    try:
        moment = datetime.fromisoformat(entry.time.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def audit_csv(entries: list[AuditEntry]) -> str:
    """Le journal en CSV pour un tableur : séparateur « ; », dates ISO en UTC, une ligne par modification."""
    out = io.StringIO()
    writer = csv.writer(out, delimiter=";", lineterminator="\r\n")
    writer.writerow(
        [
            tr("Date"),
            tr("Action"),
            tr("Produit"),
            tr("Description"),
            tr("Ressource"),
            tr("Auteur"),
            tr("Origine"),
            tr("Résultat"),
        ]
    )
    for entry in entries:
        writer.writerow(
            [
                entry.time,
                action_label(entry.action),
                product_label(entry.product),
                entry.description,
                entry.resource_id,
                actor_label(entry),
                context_label(entry.context),
                entry.result,
            ]
        )
    return out.getvalue()


def ask_audit_csv_path(parent: QWidget) -> Path | None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    name = f"journal-audit-{datetime.now():%Y%m%d}.csv"
    path, _filter = QFileDialog.getSaveFileName(
        parent, tr("Exporter le journal d'audit"), str(Path.home() / name), "CSV (*.csv)"
    )
    return Path(path) if path else None


class AuditLogDialog(QDialog):
    def __init__(self, parent: QWidget | None, entries: list[AuditEntry]) -> None:
        super().__init__(parent)
        self.entries = entries
        self.setWindowTitle(tr("Journal d'audit du compte"))
        self.setWindowIcon(app_icon())
        self.resize(980, 540)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Journal d'audit du compte"), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Modifications du compte Cloudflare des 30 derniers jours (au plus 1 000), depuis le tableau de "
                    "bord, un jeton d'API (dont CMA) ou Cloudflare lui-même, les plus récentes en premier."
                ),
                "muted",
                wrap=True,
            )
        )
        row = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText(tr("Filtrer : description, auteur, ressource…"))
        self.search.setAccessibleName(tr("Filtrer le journal d'audit"))
        self.search.setClearButtonEnabled(True)
        row.addWidget(self.search, 1)
        self.period = QComboBox()
        self.period.setAccessibleName(tr("Période"))
        self.period.addItem(tr("24 dernières heures"), timedelta(days=1))
        self.period.addItem(tr("7 derniers jours"), timedelta(days=7))
        self.period.addItem(tr("30 derniers jours"), timedelta(days=30))
        self.period.setCurrentIndex(1)
        row.addWidget(self.period)
        self.summary = label("", "muted")
        row.addWidget(self.summary)
        layout.addLayout(row)
        self.table = data_table(
            [tr("Date"), tr("Action"), tr("Produit"), tr("Description"), tr("Auteur"), tr("Origine")],
            tr("Journal d'audit du compte"),
        )
        for column, width in enumerate((130, 110, 100, 300, 200)):
            self.table.horizontalHeader().resizeSection(column, width)
        layout.addWidget(self.table, 1)
        footer = QHBoxLayout()
        self.export_button = button(tr("Exporter en CSV…"), "file-export")
        self.export_button.clicked.connect(self.export_csv)
        footer.addWidget(self.export_button)
        self.export_note = label("", "muted")
        footer.addWidget(self.export_note, 1)
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)
        self.search.textChanged.connect(lambda _t: self._fill())
        self.period.currentIndexChanged.connect(lambda _i: self._fill())
        self._fill()

    def shown(self, now: datetime | None = None) -> list[AuditEntry]:
        period = self.period.currentData()
        since = (now or datetime.now(UTC)) - period if isinstance(period, timedelta) else None
        words = self.search.text().lower().split()
        shown: list[AuditEntry] = []
        for entry in self.entries:
            moment = entry_moment(entry)
            if since is not None and moment is not None and moment < since:
                continue
            haystack = " ".join(
                (
                    entry.description,
                    actor_label(entry),
                    entry.resource_id,
                    entry.resource_type,
                    product_label(entry.product),
                    action_label(entry.action),
                )
            ).lower()
            if all(word in haystack for word in words):
                shown.append(entry)
        return shown

    def export_csv(self) -> None:
        path = ask_audit_csv_path(self)
        if path is None:
            return
        rows = self.shown()
        try:
            atomic_write_text(path, "﻿" + audit_csv(rows))
        except OSError as exc:
            self.export_note.setText(tr("Export impossible : {error}").format(error=exc))
            return
        exported = plural(len(rows), tr("{n} modification exportée"), tr("{n} modifications exportées"))
        self.export_note.setText(f"{exported} : {path.name}")

    def _fill(self) -> None:
        rows = self.shown()
        tokens = current_tokens()
        clear_items(self.table, len(rows))
        for index, entry in enumerate(rows):
            values = (
                request_time(entry.time),
                action_label(entry.action),
                product_label(entry.product),
                entry.description or entry.resource_type or "—",
                actor_label(entry),
                context_label(entry.context),
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                tip = f"{entry.resource_type} {entry.resource_id}".strip() if column == 3 else value
                item.setToolTip(tip or value)
                if entry.failed and column == 1:
                    item.setForeground(QBrush(QColor(status_colors("danger", tokens)[0])))
                    item.setToolTip(tr("Échec : {result}").format(result=entry.result))
                self.table.setItem(index, column, item)
        failed = sum(1 for e in rows if e.failed)
        text = plural(len(rows), tr("{n} modification"), tr("{n} modifications"))
        if failed:
            text += " · " + plural(failed, tr("{n} en échec"), tr("{n} en échec"))
        self.summary.setText(text)


def show_audit_log(parent: QWidget, entries: list[AuditEntry]) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    AuditLogDialog(parent, entries).exec()
