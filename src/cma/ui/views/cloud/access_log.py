"""Journal des accès Access : dernières connexions aux applications, filtrables par application."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QComboBox, QDialog, QHBoxLayout, QTableWidgetItem, QVBoxLayout, QWidget

from cma.core.cfapi import AccessApp, AccessRequest
from cma.i18n import tr
from cma.ui.icons import app_icon
from cma.ui.states import plural
from cma.ui.theme import current_tokens, status_colors
from cma.ui.views.cloud.helpers import data_table
from cma.ui.widgets import button, clear_items, label, title


def request_time(value: str) -> str:
    """Date ISO de l'API (UTC) en heure locale, « 08/10/2026 11:12 » ; une valeur illisible reste telle quelle."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone().strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return value or "—"


def request_user(request: AccessRequest, token_names: dict[str, str] | None = None) -> str:
    """L'utilisateur ; pour un service token (Cloudflare met son Client ID à la place de l'adresse), son nom."""
    name = (token_names or {}).get(request.user)
    if name:
        return tr("Service token « {name} »").format(name=name)
    if request.user:
        return request.user
    connection = request.connection.lower()
    return tr("Service token") if "service" in connection or "nonidentity" in connection else "—"


def matches(request: AccessRequest, app: AccessApp | None) -> bool:
    """La connexion concerne-t-elle `app` (toutes si None) ? Par identifiant, sinon par nom d'hôte."""
    if app is None:
        return True
    if app.uid and request.app_uid:
        return request.app_uid == app.uid
    return request.app_domain.split("/")[0].lower() == app.domain.split("/")[0].lower()


class AccessLogDialog(QDialog):
    def __init__(
        self,
        parent: QWidget | None,
        requests: list[AccessRequest],
        apps: list[AccessApp],
        selected: AccessApp | None = None,
        token_names: dict[str, str] | None = None,
    ) -> None:
        super().__init__(parent)
        self.token_names = token_names or {}
        self.setWindowTitle(tr("Journal des accès"))
        self.setWindowIcon(app_icon())
        self.resize(900, 520)
        self.requests = requests
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Journal des accès"), "SectionTitle"))
        layout.addWidget(
            label(
                tr("Dernières connexions aux applications Access, les plus récentes en premier."),
                "muted",
                wrap=True,
            )
        )
        row = QHBoxLayout()
        self.app_filter = QComboBox()
        self.app_filter.setAccessibleName(tr("Application"))
        self.app_filter.addItem(tr("Toutes les applications"), None)
        for app in sorted(apps, key=lambda a: a.name.lower()):
            self.app_filter.addItem(f"{app.name} ({app.domain})", app)
        if selected is not None:
            self.app_filter.setCurrentIndex(
                max(0, self.app_filter.findText(f"{selected.name} ({selected.domain})"))
            )
        row.addWidget(self.app_filter, 1)
        self.summary = label("", "muted")
        row.addWidget(self.summary)
        layout.addLayout(row)
        self.table = data_table(
            [tr("Date"), tr("Utilisateur"), tr("Application"), tr("Résultat"), tr("Pays"), tr("Adresse IP")],
            tr("Journal des accès"),
        )
        for column, width in enumerate((140, 220, 220, 100, 60)):
            self.table.horizontalHeader().resizeSection(column, width)
        layout.addWidget(self.table, 1)
        footer = QHBoxLayout()
        footer.addStretch()
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)
        self.app_filter.currentIndexChanged.connect(lambda _i: self._fill())
        self._fill()

    def shown(self) -> list[AccessRequest]:
        app = self.app_filter.currentData()
        return [r for r in self.requests if matches(r, app if isinstance(app, AccessApp) else None)]

    def _fill(self) -> None:
        rows = self.shown()
        tokens = current_tokens()
        clear_items(self.table, len(rows))
        for index, request in enumerate(rows):
            result = tr("Autorisé") if request.allowed else tr("Refusé")
            values = (
                request_time(request.created_at),
                request_user(request, self.token_names),
                request.app_name or request.app_domain or "—",
                result,
                request.country or "—",
                request.ip or "—",
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(request.app_domain if column == 2 and request.app_domain else value)
                if column == 3:
                    tone = "success" if request.allowed else "danger"
                    item.setForeground(QBrush(QColor(status_colors(tone, tokens)[0])))
                self.table.setItem(index, column, item)
        refused = sum(1 for r in rows if not r.allowed)
        text = plural(len(rows), tr("{n} connexion"), tr("{n} connexions"))
        if refused:
            text += " · " + plural(refused, tr("{n} refusée"), tr("{n} refusées"))
        self.summary.setText(text)


def show_access_log(
    parent: QWidget,
    requests: list[AccessRequest],
    apps: list[AccessApp],
    selected: AccessApp | None,
    token_names: dict[str, str] | None = None,
) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    AccessLogDialog(parent, requests, apps, selected, token_names).exec()
