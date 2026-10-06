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
from cma.i18n import tr


def token_durations() -> list[tuple[str, str]]:
    """Durées proposées, au format de l'API Cloudflare (« 8760h ») ; 1 an est la valeur par défaut de l'API."""
    return [(tr("1 an"), "8760h"), (tr("2 ans"), "17520h"), (tr("3 ans"), "26280h"), (tr("6 mois"), "4380h")]


def plural(n: int, one: str, many: str) -> str:
    return (one if n <= 1 else many).format(n=n)


def tunnel_state(status: str) -> tuple[str, str, str]:
    """(libellé, ton, symbole) de l'état d'un tunnel donné par l'API."""
    return {
        "healthy": (tr("En ligne"), "success", "✓"),
        "degraded": (tr("Dégradé"), "warning", "!"),
        "down": (tr("Hors ligne"), "danger", "×"),
        "inactive": (tr("Inactif"), "neutral", "■"),
    }.get(status, (status, "neutral", "■"))


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
