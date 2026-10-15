"""Journal des envois d'alertes (ADR 0002) : ce qui est parti, quand, vers quel canal, et si l'envoi a réussi.

Fichier `alert_log.json` du dossier de données, à part de `alert_state.json` : `{"entries": [...]}`, 200 entrées au
plus (les plus récentes). Une entrée : date UTC, nom et type du canal, nature (`alert`, `recovery`, `reminder`,
`digest`, `test`), objet (libellé d'un tunnel ou d'un nom d'hôte, vide pour un résumé ou un test), résultat.

Aucun secret : ni l'adresse du canal ni un fragment d'adresse (`scrub`), et un message d'erreur court (200
caractères). La lecture est tolérante (fichier absent ou illisible = journal vide) et l'écriture atomique ; un
journal qui ne s'écrit pas ne doit jamais empêcher une alerte de partir. Comme pour le journal de disponibilité, la
tâche planifiée n'écrit que si CMA est fermé ; CMA ouvert, plusieurs fils peuvent noter en même temps (envois des
relevés, rappels, test des Paramètres) : un verrou de processus sérialise « lire, ajouter, écrire ».
"""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from cma.core.alerts import Alert, AlertError
from cma.core.fsutil import atomic_write_json, read_json_lenient
from cma.core.redact import MASK, redact

logger = logging.getLogger(__name__)

LOG_FILE = "alert_log.json"
MAX_ENTRIES = 200
MAX_MESSAGE = 200
_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_FRAGMENT_MIN = 8  # un morceau d'adresse plus court n'est pas un secret, et masquerait des mots du message
_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://\S+")
_SPLIT = re.compile(r"[/?&=#:@;,]+")

NATURES = ("alert", "recovery", "reminder", "digest", "test")

_lock = threading.Lock()

Send = Callable[[str, str, Alert], None]


def log_path(data_dir: Path) -> Path:
    return data_dir / LOG_FILE


@dataclass(frozen=True)
class SendEntry:
    at: datetime  # UTC
    channel: str
    kind: str
    nature: str
    subject: str
    ok: bool
    error: str = ""


def scrub(text: str, url: str = "") -> str:
    """Retire d'un message tout ce qui peut venir de l'adresse d'un canal : secrets connus du coffre, adresses
    complètes, puis l'adresse du canal (hôte, identifiants et morceaux de chemin ou de paramètres assez longs
    pour être un jeton) et tronque à `MAX_MESSAGE` caractères."""
    text = " ".join(redact(text).split())
    text = _URL.sub(MASK, text)
    if url:
        parts = urlsplit(url)
        fragments = {url}
        fragments.update(p for p in (parts.netloc, parts.hostname, parts.username, parts.password) if p)
        for piece in (parts.path, parts.query, parts.fragment):
            fragments.update(f for f in _SPLIT.split(piece) if len(f) >= _FRAGMENT_MIN)
        for fragment in sorted(fragments, key=len, reverse=True):
            text = text.replace(fragment, MASK)
    return text if len(text) <= MAX_MESSAGE else text[: MAX_MESSAGE - 1] + "…"


def _parse(value: Any) -> SendEntry | None:
    if not isinstance(value, dict):
        return None
    raw = cast(dict[str, Any], value)
    at, channel, kind, nature = raw.get("at"), raw.get("channel"), raw.get("kind"), raw.get("nature")
    if not (isinstance(at, str) and isinstance(channel, str) and isinstance(kind, str)):
        return None
    try:
        moment = datetime.strptime(at, _FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None
    subject, error = raw.get("subject"), raw.get("error")
    return SendEntry(
        moment,
        channel,
        kind,
        nature if isinstance(nature, str) else "alert",
        subject if isinstance(subject, str) else "",
        raw.get("ok") is True,
        error if isinstance(error, str) else "",
    )


def _dump(entry: SendEntry) -> dict[str, Any]:
    data: dict[str, Any] = {
        "at": entry.at.astimezone(UTC).strftime(_FORMAT),
        "channel": entry.channel,
        "kind": entry.kind,
        "nature": entry.nature,
        "subject": entry.subject,
        "ok": entry.ok,
    }
    if entry.error:
        data["error"] = entry.error
    return data


class AlertLog:
    def __init__(self, path: Path) -> None:
        self.path = path

    def entries(self) -> list[SendEntry]:
        """Les entrées, de la plus ancienne à la plus récente ; vide si le fichier est absent ou illisible."""
        try:
            data: Any = read_json_lenient(self.path) if self.path.exists() else {}
        except (OSError, ValueError):
            return []
        items = cast(dict[str, Any], data).get("entries") if isinstance(data, dict) else None
        if not isinstance(items, list):
            return []
        parsed = (_parse(item) for item in cast(list[Any], items))
        return [entry for entry in parsed if entry is not None][-MAX_ENTRIES:]

    def latest(self) -> list[SendEntry]:
        """Les entrées, la plus récente d'abord."""
        return list(reversed(self.entries()))

    def note(
        self,
        *,
        channel: str,
        kind: str,
        nature: str,
        subject: str = "",
        error: str | None = None,
        url: str = "",
        at: datetime | None = None,
    ) -> None:
        """Note un envoi (`error` None = réussi). `url` n'est jamais écrite : elle sert à masquer le message."""
        entry = SendEntry(
            at or datetime.now(UTC),
            channel,
            kind,
            nature,
            subject,
            error is None,
            scrub(error, url) if error is not None else "",
        )
        with _lock:
            kept = [*self.entries(), entry][-MAX_ENTRIES:]
            try:
                atomic_write_json(self.path, {"entries": [_dump(e) for e in kept]})
            except OSError as exc:
                logger.warning("Journal des envois non enregistré : %s", exc)

    def clear(self) -> bool:
        """Efface le journal ; False si le fichier n'a pas pu être écrit."""
        with _lock:
            try:
                atomic_write_json(self.path, {"entries": []})
            except OSError as exc:
                logger.warning("Journal des envois non effacé : %s", exc)
                return False
        return True


def send_and_note(
    journal: AlertLog | None,
    send: Send,
    name: str,
    kind: str,
    url: str,
    alert: Alert,
    *,
    nature: str,
    subject: str = "",
) -> str | None:
    """Envoie vers un canal et note le résultat ; renvoie le message d'erreur (`AlertError`), None si réussi."""
    try:
        send(kind, url, alert)
    except AlertError as exc:
        if journal is not None:
            journal.note(channel=name, kind=kind, nature=nature, subject=subject, error=str(exc), url=url)
        return str(exc)
    if journal is not None:
        journal.note(channel=name, kind=kind, nature=nature, subject=subject, url=url)
    return None
