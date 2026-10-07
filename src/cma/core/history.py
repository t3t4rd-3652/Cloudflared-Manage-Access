"""Historique des sessions : combien de temps chaque accès a tenu, ce qui l'a fait décrocher.

L'historique écoute le bus d'événements : il suit chaque session de son démarrage à sa fin (arrêt ou erreur),
puis range un enregistrement dans `history.json` (écriture atomique). Il garde 90 jours et 2 000 sessions au plus.
Rien de secret n'y entre : les messages d'incident sont déjà masqués par les sessions.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

from cma.core.events import Event, SessionChanged
from cma.core.fsutil import atomic_write_json, read_json_lenient
from cma.core.sessions import SessionInfo, SessionState

log = logging.getLogger(__name__)

KEEP = timedelta(days=90)
MAX_RECORDS = 2000
MAX_INCIDENTS = 5
_UP = (SessionState.LISTENING, SessionState.DEGRADED)


@dataclass
class SessionRecord:
    """Une session terminée."""

    profile_id: str
    forward_id: str | None
    kind: str
    name: str
    started_at: datetime
    ended_at: datetime
    end_state: str  # « stopped » (arrêt demandé) ou « error »
    listening_seconds: float = 0.0
    reconnects: int = 0
    incidents: list[str] = field(default_factory=list[str])
    peak_connections: int = 0
    bytes_up: int = 0
    bytes_down: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, (self.ended_at - self.started_at).total_seconds())

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        data["started_at"] = self.started_at.isoformat()
        data["ended_at"] = self.ended_at.isoformat()
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> SessionRecord:
        values = dict(data)
        values["started_at"] = datetime.fromisoformat(str(values["started_at"]))
        values["ended_at"] = datetime.fromisoformat(str(values["ended_at"]))
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in values.items() if k in known})


@dataclass
class ProfileStats:
    """Résumé d'un profil (ou d'une redirection) sur la période lue."""

    key: tuple[str, str | None]
    name: str
    sessions: int = 0
    seconds: float = 0.0
    listening_seconds: float = 0.0
    reconnects: int = 0
    errors: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    last_started: datetime | None = None
    last_incident: str = ""

    @property
    def availability(self) -> float | None:
        """Part du temps passée à l'écoute, de 0 à 1 ; None sans durée mesurable."""
        return self.listening_seconds / self.seconds if self.seconds > 0 else None

    @property
    def incidents(self) -> int:
        return self.reconnects + self.errors


@dataclass
class _Open:
    """Session en cours de suivi."""

    record: SessionRecord
    state: SessionState
    up_since: datetime | None = None


class SessionHistory:
    def __init__(
        self,
        path: Path,
        *,
        now: Callable[[], datetime] = datetime.now,
        keep: timedelta = KEEP,
        max_records: int = MAX_RECORDS,
    ) -> None:
        self.path = Path(path)
        self._now = now
        self._keep = keep
        self._max = max_records
        self._open: dict[str, _Open] = {}
        self._lock = threading.Lock()
        self._records: list[SessionRecord] | None = None  # lu à la première consultation

    # --- Suivi des sessions --------------------------------------------------------------------------

    def handle(self, event: Event) -> None:
        """Abonné au bus : chaque changement d'état d'une session."""
        if isinstance(event, SessionChanged):
            self.track(event.info)

    def track(self, info: SessionInfo) -> None:
        now = self._now()
        with self._lock:
            current = self._open.get(info.id)
            if current is None:
                if not info.state.active:
                    return  # session déjà terminée quand on la découvre : rien à mesurer
                current = _Open(
                    SessionRecord(
                        profile_id=info.profile_id,
                        forward_id=info.forward_id,
                        kind=info.kind.value,
                        name=info.name,
                        started_at=info.started_at,
                        ended_at=now,
                        end_state="",
                    ),
                    SessionState.STARTING,
                )
                self._open[info.id] = current
            record = current.record
            record.peak_connections = max(record.peak_connections, info.connections)
            record.bytes_up, record.bytes_down = info.bytes_up, info.bytes_down
            if info.state != current.state:
                self._transition(current, info, now)
            if not info.state.active:
                del self._open[info.id]
                record.ended_at = now
                record.end_state = info.state.value
                self._append(record)

    def _transition(self, current: _Open, info: SessionInfo, now: datetime) -> None:
        record = current.record
        was_up, is_up = current.state in _UP, info.state in _UP
        if was_up and not is_up and current.up_since is not None:
            record.listening_seconds += (now - current.up_since).total_seconds()
            current.up_since = None
        elif is_up and not was_up:
            current.up_since = now
        if info.state == SessionState.RECONNECTING:
            record.reconnects += 1
        if info.state in (SessionState.RECONNECTING, SessionState.ERROR) and info.message:
            record.incidents = [*record.incidents, info.message][-MAX_INCIDENTS:]
        current.state = info.state

    def close_all(self) -> None:
        """À la fermeture de CMA : les sessions encore suivies sont rangées comme arrêtées."""
        now = self._now()
        with self._lock:
            for current in list(self._open.values()):
                if current.up_since is not None:
                    current.record.listening_seconds += (now - current.up_since).total_seconds()
                current.record.ended_at = now
                current.record.end_state = SessionState.STOPPED.value
                self._append(current.record)
            self._open.clear()

    # --- Stockage -------------------------------------------------------------------------------------

    def _load(self) -> list[SessionRecord]:
        if self._records is None:
            records: list[SessionRecord] = []
            try:
                raw = read_json_lenient(self.path) if self.path.exists() else None
            except (OSError, ValueError) as exc:  # fichier abîmé : on repart d'un historique vide
                log.warning("Historique illisible, ignoré : %s", exc)
                raw = None
            for item in cast(list[dict[str, Any]], raw if isinstance(raw, list) else []):
                try:
                    records.append(SessionRecord.from_json(item))
                except (KeyError, TypeError, ValueError):
                    log.warning("Historique : enregistrement illisible ignoré")
            self._records = records
        return self._records

    def _append(self, record: SessionRecord) -> None:
        records = self._load()
        records.append(record)
        limit = self._now() - self._keep
        kept = [r for r in records if r.ended_at >= limit][-self._max :]
        self._records = kept
        try:
            atomic_write_json(self.path, [r.to_json() for r in kept])
        except OSError as exc:
            log.warning("Historique non enregistré : %s", exc)

    # --- Consultation ---------------------------------------------------------------------------------

    def records(
        self, profile_id: str | None = None, *, since: timedelta | None = None
    ) -> list[SessionRecord]:
        """Sessions terminées (dans la période `since` si elle est donnée), la plus récente d'abord."""
        with self._lock:
            records = list(self._load())
        if profile_id is not None:
            records = [r for r in records if r.profile_id == profile_id]
        if since is not None:
            limit = self._now() - since
            records = [r for r in records if r.ended_at >= limit]
        return sorted(records, key=lambda r: r.started_at, reverse=True)

    def summary(self, since: timedelta | None = None) -> list[ProfileStats]:
        """Un résumé par profil (et par redirection SSH), le plus instable d'abord."""
        stats: dict[tuple[str, str | None], ProfileStats] = {}
        for record in reversed(
            self.records(since=since)
        ):  # du plus ancien au plus récent : le dernier nom l'emporte
            key = (record.profile_id, record.forward_id)
            entry = stats.setdefault(key, ProfileStats(key, record.name))
            entry.name = record.name
            entry.sessions += 1
            entry.seconds += record.duration
            entry.listening_seconds += min(record.listening_seconds, record.duration)
            entry.reconnects += record.reconnects
            entry.errors += record.end_state == SessionState.ERROR.value
            entry.bytes_up += record.bytes_up
            entry.bytes_down += record.bytes_down
            entry.last_started = record.started_at
            if record.incidents:
                entry.last_incident = record.incidents[-1]
        return sorted(stats.values(), key=lambda s: (-s.incidents, s.name.lower()))

    def clear(self) -> None:
        with self._lock:
            self._records = []
            try:
                self.path.unlink(missing_ok=True)
            except OSError as exc:
                log.warning("Historique non effacé : %s", exc)
