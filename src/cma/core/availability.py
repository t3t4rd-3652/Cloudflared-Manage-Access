"""Disponibilité des tunnels et des services publiés : incidents et taux, gardés 90 jours.

La surveillance prévient puis oubliait ; ce journal garde la mémoire, pour CMA ouvert comme pour la tâche planifiée
(qui s'en sert aussi pour ne prévenir qu'à un changement, et pas à chaque passage) :
- incidents : début, fin, cause (état relevé), objet (tunnel ou nom d'hôte) ;
- tests : agrégés par jour et par objet (réussis, total, somme et maximum du temps de réponse), d'où le taux de
  disponibilité et le temps moyen sur 7 ou 30 jours sans garder chaque test.
Fichier `availability.json` du dossier de données, écrit d'un coup (écriture atomique).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from cma.core.fsutil import atomic_write_json, read_json_lenient

KEEP_DAYS = 90
MAX_INCIDENTS = 1000


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


@dataclass
class Incident:
    kind: str  # « tunnel » ou « service »
    key: str  # identifiant du tunnel, ou nom d'hôte (et chemin)
    label: str
    state: str  # état relevé au début (down, degraded, origin_down, no_connector, not_found…)
    started: str
    ended: str | None = None

    @property
    def open(self) -> bool:
        return self.ended is None

    def duration(self, now: datetime | None = None) -> timedelta:
        end = _parse(self.ended) if self.ended else (now or datetime.now(UTC))
        return end - _parse(self.started)


@dataclass(frozen=True)
class Stats:
    uptime: float | None  # part des tests réussis (0 à 1) ; None sans test
    mean_ms: float | None
    max_ms: float | None
    checks: int


class AvailabilityLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            data: Any = read_json_lenient(path) if path.exists() else {}
        except (OSError, ValueError):
            data = {}  # journal illisible : on repart d'un journal vide plutôt que de bloquer la surveillance
        data = cast(dict[str, Any], data) if isinstance(data, dict) else {}
        self.incidents = [
            Incident(**cast(dict[str, Any], item))
            for item in cast(list[Any], data.get("incidents") or [])
            if isinstance(item, dict)
        ]
        # objet → jour (AAAA-MM-JJ) → [réussis, total, somme des ms, maximum des ms, nombre de mesures en ms]
        self.days: dict[str, dict[str, list[float]]] = cast(
            dict[str, dict[str, list[float]]], data.get("days") or {}
        )
        self.labels: dict[str, str] = cast(dict[str, str], data.get("labels") or {})

    def save(self, now: datetime | None = None) -> None:
        self.prune(now)
        atomic_write_json(
            self.path,
            {"incidents": [asdict(i) for i in self.incidents], "days": self.days, "labels": self.labels},
        )

    def prune(self, now: datetime | None = None) -> None:
        limit = (now or datetime.now(UTC)) - timedelta(days=KEEP_DAYS)
        day_limit = limit.strftime("%Y-%m-%d")
        self.incidents = [i for i in self.incidents if i.open or _parse(i.ended or i.started) >= limit][
            -MAX_INCIDENTS:
        ]
        for key in list(self.days):
            self.days[key] = {d: v for d, v in self.days[key].items() if d >= day_limit}
            if not self.days[key]:
                del self.days[key]
                self.labels.pop(key, None)

    # --- Tests ----------------------------------------------------------------------------------------------

    def record_check(
        self, key: str, label: str, ok: bool, ms: float | None, at: datetime | None = None
    ) -> None:
        day = (at or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%d")
        counts = self.days.setdefault(key, {}).setdefault(day, [0, 0, 0.0, 0.0, 0])
        counts[0] += 1 if ok else 0
        counts[1] += 1
        if ms is not None:
            counts[2] += ms
            counts[3] = max(counts[3], ms)
            counts[4] += 1
        self.labels[key] = label

    def stats(self, key: str, days: int, now: datetime | None = None) -> Stats:
        first = ((now or datetime.now(UTC)) - timedelta(days=days - 1)).strftime("%Y-%m-%d")
        rows = [v for d, v in self.days.get(key, {}).items() if d >= first]
        ok, total = sum(r[0] for r in rows), sum(r[1] for r in rows)
        timed = sum(r[4] for r in rows)
        return Stats(
            uptime=ok / total if total else None,
            mean_ms=sum(r[2] for r in rows) / timed if timed else None,
            max_ms=max((r[3] for r in rows if r[4]), default=None),
            checks=int(total),
        )

    def keys(self) -> list[str]:
        return sorted(set(self.days) | {i.key for i in self.incidents}, key=lambda k: self.label(k).lower())

    def label(self, key: str) -> str:
        return self.labels.get(key) or next((i.label for i in reversed(self.incidents) if i.key == key), key)

    # --- Incidents ------------------------------------------------------------------------------------------

    def open_incident(self, kind: str, key: str) -> Incident | None:
        return next((i for i in self.incidents if i.kind == kind and i.key == key and i.open), None)

    def start(self, kind: str, key: str, label: str, state: str, at: datetime | None = None) -> bool:
        """Ouvre un incident ; False s'il y en avait déjà un ouvert pour cet objet (rien de nouveau)."""
        if self.open_incident(kind, key) is not None:
            return False
        self.incidents.append(Incident(kind, key, label, state, _iso(at or datetime.now(UTC))))
        return True

    def end(self, kind: str, key: str, at: datetime | None = None) -> Incident | None:
        """Ferme l'incident ouvert de cet objet ; None s'il n'y en avait pas."""
        incident = self.open_incident(kind, key)
        if incident is not None:
            incident.ended = _iso(at or datetime.now(UTC))
        return incident

    def history(
        self, key: str | None = None, days: int = KEEP_DAYS, now: datetime | None = None
    ) -> list[Incident]:
        """Incidents des `days` derniers jours (d'un objet ou de tous), du plus récent au plus ancien."""
        limit = (now or datetime.now(UTC)) - timedelta(days=days)
        chosen = [
            i
            for i in self.incidents
            if (key is None or i.key == key) and (i.open or _parse(i.ended or i.started) >= limit)
        ]
        return sorted(chosen, key=lambda i: i.started, reverse=True)
