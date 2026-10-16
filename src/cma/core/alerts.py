"""Alertes vers l'extérieur : une panne ou un retour de tunnel ou de service, envoyé là où on le verra (téléphone,
messagerie d'équipe), même loin de ce poste.

Cinq formats : webhook générique (JSON), ntfy (texte, en-têtes Title et Priority), Slack et Discord (webhooks
entrants), Microsoft Teams (« workflow » qui reçoit une requête webhook, carte adaptative). L'adresse de chaque canal
est un secret (elle contient souvent un jeton) : elle est dans le coffre, jamais dans la configuration ni un journal.
"""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cma import APP_NAME, __version__
from cma.i18n import tr

KINDS = ("ntfy", "slack", "teams", "discord", "webhook")
TIMEOUT = 10.0


class AlertError(RuntimeError):
    """Envoi refusé ou impossible (message lisible, sans l'adresse du canal).

    `error_code` est un code stable (`invalid_address`, `refused`, `timeout`, `dns`, `tls`, `unreachable`) et
    `error_args` ses paramètres, de simples valeurs (code HTTP, nom d'un type d'exception) : jamais d'adresse, de
    jeton ni de texte libre. Le journal des envois les garde pour traduire le message à l'affichage."""

    def __init__(
        self, message: str, error_code: str = "", error_args: dict[str, int | str] | None = None
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.error_args: dict[str, int | str] = dict(error_args or {})


def _unreachable(exc: BaseException) -> AlertError:
    """Classe l'échec de connexion : délai dépassé, nom introuvable, TLS, ou autre (nom du type seulement)."""
    reason: BaseException | str = getattr(exc, "reason", exc)
    message = tr("Canal injoignable : {error}").format(error=reason)
    if isinstance(reason, TimeoutError):
        return AlertError(message, "timeout")
    if isinstance(reason, socket.gaierror):
        return AlertError(message, "dns")
    if isinstance(reason, ssl.SSLError):
        return AlertError(message, "tls")
    return AlertError(message, "unreachable", {"type": type(reason).__name__})


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


def elapsed_text(delta: timedelta) -> str:
    """Durée lisible : « 12 min », « 5 h 20 », « 3 j 4 h » (au-delà de deux jours)."""
    minutes = int(delta.total_seconds() // 60)
    if minutes < 60:
        return tr("{n} min").format(n=max(1, minutes))
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return tr("{h} h {m:02d}").format(h=hours, m=minutes)
    return tr("{d} j {h} h").format(d=hours // 24, h=hours % 24)


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
        raise AlertError(tr("Adresse invalide : elle doit commencer par https://."), "invalid_address")
    request = build_request(kind, url, alert)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read(1024)
    except urllib.error.HTTPError as exc:
        raise AlertError(
            tr("Le canal a refusé l'alerte ({status}).").format(status=exc.code),
            "refused",
            {"status": exc.code},
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise _unreachable(exc) from exc
