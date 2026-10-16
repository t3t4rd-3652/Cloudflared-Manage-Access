"""Journal des envois d'alertes (ADR 0002) : ce qui est parti, quand, vers quel canal, et si l'envoi a réussi.

Fichier `alert_log.json` du dossier de données, à part de `alert_state.json` : `{"entries": [...]}`, 200 entrées au
plus (les plus récentes). Une entrée : date UTC, nom et type du canal, nature (`alert`, `recovery`, `reminder`,
`digest`, `slo`, `test`), objet (libellé d'un tunnel ou d'un nom d'hôte, vide pour un résumé ou un test), résultat.

Aucun secret : ni l'adresse du canal ni un fragment d'adresse (`scrub`), et un message d'erreur court (200
caractères) ; le code d'erreur stable (`error_code`) et ses paramètres simples (`error_args` : code HTTP, nom d'un
type d'exception) permettent de traduire le message à l'affichage, le texte restant le repli. La lecture est tolérante (fichier absent ou illisible = journal vide) et l'écriture atomique ; un
journal qui ne s'écrit pas ne doit jamais empêcher une alerte de partir. Comme pour le journal de disponibilité, la
tâche planifiée n'écrit que si CMA est fermé ; CMA ouvert, plusieurs fils peuvent noter en même temps (envois des
relevés, rappels, test des Paramètres) : un verrou de processus sérialise « lire, ajouter, écrire ».
"""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
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
_LAST_SEGMENT_MIN = 4  # dernier segment du chemin (sujet ntfy, jeton de webhook) : masqué même court
_URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://\S+")
_SPLIT = re.compile(r"[/?&=#:@;,]+")
_CODE = re.compile(r"[a-z][a-z_]{0,31}")
_ARG_KEY = re.compile(r"[a-z][a-z_]{0,15}")
_ARG_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_MAX_ARGS = 4

NATURES = ("alert", "recovery", "reminder", "digest", "slo", "test")

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
    error_code: str = ""
    error_args: dict[str, int | str] = field(default_factory=dict[str, int | str])


def safe_code(value: Any) -> str:
    """Un code d'erreur est un court identifiant en minuscules, sinon vide."""
    return value if isinstance(value, str) and _CODE.fullmatch(value) else ""


def _simple_value(item: Any, url: str) -> bool:
    if isinstance(item, int):
        return not isinstance(item, bool)
    return isinstance(item, str) and bool(_ARG_WORD.fullmatch(item)) and item.lower() not in url.lower()


def safe_args(value: Any, url: str = "") -> dict[str, int | str]:
    """Ne garde que des valeurs simples : un entier (code HTTP) ou un mot identifiant (nom d'un type d'exception),
    quelques clés au plus ; jamais un texte libre, ni rien qui figure dans l'adresse du canal."""
    if not isinstance(value, dict):
        return {}
    kept: dict[str, int | str] = {}
    for key, item in cast(dict[Any, Any], value).items():
        if len(kept) >= _MAX_ARGS or not (isinstance(key, str) and _ARG_KEY.fullmatch(key)):
            continue
        if _simple_value(item, url):
            kept[key] = item
    return kept


def scrub(text: str, url: str = "", kind: str = "", *, known_secrets: bool = True) -> str:
    """Retire d'un message tout ce qui peut venir de l'adresse d'un canal : secrets connus du coffre, adresses
    complètes, puis l'adresse du canal (hôte, identifiants et morceaux de chemin ou de paramètres assez longs
    pour être un jeton) et tronque à `MAX_MESSAGE` caractères."""
    # `known_secrets` : passer aussi par la rédaction globale du coffre (journal écrit sur disque). Le message
    # rendu à l'interface n'a besoin que du masquage de l'adresse du canal.
    text = " ".join((redact(text) if known_secrets else text).split())
    text = _URL.sub(MASK, text)
    if url:
        parts = urlsplit(url)
        fragments = {url}
        fragments.update(p for p in (parts.netloc, parts.hostname, parts.username, parts.password) if p)
        for piece in (parts.path, parts.query, parts.fragment):
            fragments.update(f for f in _SPLIT.split(piece) if len(f) >= _FRAGMENT_MIN)
        segments = [s for s in parts.path.split("/") if s]
        if kind == "ntfy" and segments and len(segments[-1]) >= _LAST_SEGMENT_MIN:
            # Le sujet ntfy (« mytopic » de https://ntfy.sh/mytopic) vaut un jeton, même court : masqué en mot entier.
            text = re.sub(rf"(?i)(?<![\w-]){re.escape(segments[-1])}(?![\w-])", MASK, text)
        for fragment in sorted(fragments, key=len, reverse=True):
            # Sans tenir compte de la casse : un hôte ou un sujet peut revenir en majuscules dans un message.
            text = re.sub(re.escape(fragment), MASK, text, flags=re.IGNORECASE)
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
        safe_code(raw.get("error_code")),
        safe_args(raw.get("error_args")),
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
    if entry.error_code:
        data["error_code"] = entry.error_code
        if entry.error_args:
            data["error_args"] = entry.error_args
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

    def _readable(self) -> bool:
        """Faux si le fichier existe mais ne peut pas être ouvert (verrou passager de Windows, droits) : le
        réécrire ferait perdre son contenu. Un contenu illisible (JSON abîmé) reste remplaçable."""
        if not self.path.exists():
            return True
        try:
            with self.path.open("rb"):
                return True
        except OSError:
            return False

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
        error_code: str = "",
        error_args: dict[str, int | str] | None = None,
    ) -> None:
        """Note un envoi (`error` None = réussi). `url` n'est jamais écrite : elle sert à masquer le message.
        `error_code` et `error_args` (valeurs simples, filtrées par `safe_args`) servent à traduire l'erreur."""
        failed = error is not None
        entry = SendEntry(
            at or datetime.now(UTC),
            channel,
            kind,
            nature,
            subject,
            error is None,
            scrub(error, url, kind) if error is not None else "",
            safe_code(error_code) if failed else "",
            safe_args(error_args, url) if failed else {},
        )
        with _lock:
            if not self._readable():
                logger.warning(
                    "Journal des envois illisible pour l'instant : entrée non notée, journal conservé"
                )
                return
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
            journal.note(
                channel=name,
                kind=kind,
                nature=nature,
                subject=subject,
                error=str(exc),
                url=url,
                error_code=exc.error_code or "other",
                error_args=exc.error_args,
            )
        # L'appelant l'affiche : jamais l'adresse du canal non plus (la rédaction globale reste au journal).
        return scrub(str(exc), url, kind, known_secrets=False)
    if journal is not None:
        journal.note(channel=name, kind=kind, nature=nature, subject=subject, url=url)
    return None
