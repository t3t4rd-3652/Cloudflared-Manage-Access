"""Alertes vers l'extérieur : une panne ou un retour de tunnel ou de service, envoyé là où on le verra (téléphone,
messagerie d'équipe), même loin de ce poste.

Cinq formats : webhook générique (JSON), ntfy (texte, en-têtes Title et Priority), Slack et Discord (webhooks
entrants), Microsoft Teams (« workflow » qui reçoit une requête webhook, carte adaptative). L'adresse de chaque canal
est un secret (elle contient souvent un jeton) : elle est dans le coffre, jamais dans la configuration ni un journal.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cma import APP_NAME, __version__
from cma.i18n import tr

KINDS = ("ntfy", "slack", "teams", "discord", "webhook")
TIMEOUT = 10.0


class AlertError(RuntimeError):
    """Envoi refusé ou impossible (message lisible, sans l'adresse du canal)."""


def kind_label(kind: str) -> str:
    return {
        "ntfy": "ntfy",
        "slack": "Slack",
        "teams": "Microsoft Teams",
        "discord": "Discord",
        "webhook": tr("Webhook (JSON)"),
    }.get(kind, kind)


def secret_key(channel_id: str) -> str:
    return f"alert:{channel_id}"


@dataclass(frozen=True)
class Alert:
    title: str
    text: str
    level: str  # error, warning, success, info


def build_request(kind: str, url: str, alert: Alert, now: datetime | None = None) -> urllib.request.Request:
    """La requête HTTP d'une alerte, selon le canal."""
    headers = {"User-Agent": f"CloudflaredManageAccess/{__version__}"}
    line = f"{alert.title} — {alert.text}"
    if kind == "ntfy":
        body = alert.text.encode("utf-8")
        headers.update(
            {
                # En-têtes HTTP en Latin-1 : ntfy accepte l'UTF-8 encodé en RFC 2047.
                "Title": f"=?UTF-8?B?{_b64(alert.title)}?=",
                "Priority": {"error": "high", "warning": "default"}.get(alert.level, "low"),
                "Tags": {"error": "rotating_light", "warning": "warning", "success": "white_check_mark"}.get(
                    alert.level, "information_source"
                ),
                "Content-Type": "text/plain; charset=utf-8",
            }
        )
        return urllib.request.Request(url, data=body, method="POST", headers=headers)
    payload: dict[str, Any]
    if kind == "slack":
        payload = {"text": f"*{alert.title}*\n{alert.text}"}
    elif kind == "discord":
        payload = {"content": f"**{alert.title}**\n{alert.text}", "username": APP_NAME}
    elif kind == "teams":
        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "body": [
                            {"type": "TextBlock", "text": alert.title, "weight": "Bolder", "wrap": True},
                            {"type": "TextBlock", "text": alert.text, "wrap": True},
                        ],
                    },
                }
            ],
        }
    else:
        payload = {
            "source": APP_NAME,
            "title": alert.title,
            "text": alert.text,
            "level": alert.level,
            "summary": line,
            "at": (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    headers["Content-Type"] = "application/json"
    return urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), method="POST", headers=headers
    )


def _b64(text: str) -> str:
    import base64

    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def send_alert(kind: str, url: str, alert: Alert, *, timeout: float = TIMEOUT) -> None:
    """Envoie l'alerte ; AlertError (sans l'adresse, qui est un secret) si le canal la refuse ou ne répond pas."""
    if not url.lower().startswith(("https://", "http://")):
        raise AlertError(tr("Adresse invalide : elle doit commencer par https://."))
    request = build_request(kind, url, alert)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read(1024)
    except urllib.error.HTTPError as exc:
        raise AlertError(tr("Le canal a refusé l'alerte ({status}).").format(status=exc.code)) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise AlertError(tr("Canal injoignable : {error}").format(error=reason)) from exc
