"""Libellés et petites fonctions de présentation de la vue Cloudflare."""

from __future__ import annotations

import urllib.error
from datetime import datetime

from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QHeaderView,
    QPushButton,
    QTableWidget,
)

from cma.core.cfapi import CloudflareApiError
from cma.core.tunnelwatch import status_label
from cma.i18n import tr
from cma.ui.states import plural  # noqa: F401 (réexporté pour la vue)


def token_durations() -> list[tuple[str, str]]:
    """Durées proposées, au format de l'API Cloudflare (« 8760h ») ; 1 an est la valeur par défaut de l'API."""
    return [(tr("1 an"), "8760h"), (tr("2 ans"), "17520h"), (tr("3 ans"), "26280h"), (tr("6 mois"), "4380h")]


def tunnel_state(status: str) -> tuple[str, str, str]:
    """(libellé, ton, symbole) de l'état d'un tunnel donné par l'API ; libellé commun avec la surveillance et la CLI."""
    tone, symbol = {
        "healthy": ("success", "✓"),
        "degraded": ("warning", "!"),
        "down": ("danger", "×"),
    }.get(status, ("neutral", "■"))
    return status_label(status), tone, symbol


def tunnel_status_label(status: str) -> str:
    return tunnel_state(status)[0]


def app_type_label(kind: str) -> str:
    known = {"self_hosted": "Self-hosted", "ssh": "SSH", "vnc": "VNC", "rdp": "RDP", "saas": "SaaS"}
    return known.get(kind, kind.replace("_", " ").capitalize())


def expiry_label(value: str) -> str:
    try:
        return datetime.fromisoformat(value[:10]).strftime("%d/%m/%Y")
    except ValueError:
        return value or "—"


def expiry_status(value: str) -> str | None:
    """Teinte de la date d'expiration : « danger » si dépassée, « warning » à moins de 30 jours."""
    try:
        expires = datetime.fromisoformat(value[:10])
    except ValueError:
        return None
    days = (expires - datetime.now()).days
    return "danger" if days < 0 else "warning" if days < 30 else None


def describe_api_error(error: BaseException) -> str:
    """Refus de l'API, réseau injoignable ou autre erreur : jamais tout confondre avec un 401 (§4.6)."""
    if isinstance(error, CloudflareApiError):
        if error.status in (401, 403):
            return tr("L'API a refusé la demande. Vérifiez le jeton et ses permissions.") + f" ({error})"
        if error.status is None and isinstance(error.__cause__, (urllib.error.URLError, OSError)):
            return tr("Impossible de joindre l'API Cloudflare.") + f" ({error})"
    return str(error)


def dialog_buttons(dialog: QDialog, action: str) -> tuple[QDialogButtonBox, QPushButton]:
    buttons = QDialogButtonBox()
    buttons.addButton(tr("Annuler"), QDialogButtonBox.ButtonRole.RejectRole)
    ok = buttons.addButton(action, QDialogButtonBox.ButtonRole.AcceptRole)
    ok.setProperty("role", "primary")
    buttons.rejected.connect(dialog.reject)
    return buttons, ok


def service_error(service: str) -> str | None:
    """Message d'erreur si le service publié n'a pas de schéma (tcp://, ssh://, http://…), sinon None."""
    if "://" not in service and not service.startswith("http_status:"):
        return tr("Service invalide : indiquez un schéma, par exemple tcp://localhost:22")
    return None


def data_table(headers: list[str], name: str) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setAccessibleName(name)
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().hide()
    table.verticalHeader().setDefaultSectionSize(36)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    table.horizontalHeader().setStretchLastSection(True)
    return table


# --- D14 — Publier un service ------------------------------------------------------------------------------
