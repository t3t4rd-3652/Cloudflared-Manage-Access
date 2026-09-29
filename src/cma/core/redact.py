"""Masquage des secrets dans les journaux et les messages.

Chaque secret lu ou écrit dans le coffre est enregistré ici ; `redact()` le remplace
par un masque partout où il apparaît. Des motifs couvrent aussi les formes connues
(en-têtes Access que cloudflared affiche en niveau debug, variables d'environnement).
"""

from __future__ import annotations

import re
import threading

MASK = "••••••"
_MIN_SECRET_LENGTH = 4

_lock = threading.Lock()
_secrets: set[str] = set()

_PATTERNS = [
    re.compile(r"(?i)(cf-access-client-secret\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(tunnel_service_token_secret\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(--service-token-secret[= ]+)\S+"),
    re.compile(r"(?i)(--secret[= ]+)\S+"),
    re.compile(r"(?i)\b(password\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(cf_authorization=)[^;\s]+"),
]


def register_secret(value: str | None) -> None:
    if value and len(value) >= _MIN_SECRET_LENGTH:
        with _lock:
            _secrets.add(value)


def forget_secret(value: str | None) -> None:
    if value:
        with _lock:
            _secrets.discard(value)


def redact(text: str) -> str:
    if not text:
        return text
    with _lock:
        known = sorted(_secrets, key=len, reverse=True)
    for secret in known:
        if secret in text:
            text = text.replace(secret, MASK)
    for pattern in _PATTERNS:
        text = pattern.sub(lambda m: m.group(1) + MASK, text)
    return text
