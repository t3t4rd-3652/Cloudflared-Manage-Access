"""État des envois d'alertes (ADR 0002) : dernier rappel de chaque panne, semaine du dernier résumé.

Fichier `alert_state.json` du dossier de données, à part de la configuration (exportée) et du journal de
disponibilité : `{"reminders": {"<clé>": "<ISO 8601 UTC>"}, "digest_week": "2026-W42", "slo": {"<clé>": "<ISO 8601 UTC>"}}`
(`slo` : objets déjà annoncés sous leur objectif de disponibilité, clé absente sans objet annoncé). La lecture est
tolérante (fichier absent ou illisible = état vide : au pire, un rappel ou un résumé part une fois de trop) et
l'écriture atomique. Comme pour le journal, la tâche planifiée n'écrit que si CMA est fermé.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from cma.core.fsutil import atomic_write_json, read_json_lenient

STATE_FILE = "alert_state.json"
_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def state_path(data_dir: Path) -> Path:
    return data_dir / STATE_FILE


class AlertState:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.reminders: dict[str, str] = {}
        self.digest_week = ""
        # Tunnel de chaque nom d'hôte (clé de service → identifiant du tunnel), d'après le dernier relevé connu.
        self.tunnels: dict[str, str] = {}
        # Objets dont la disponibilité sur 30 jours est sous l'objectif et déjà annoncée (clé → date de l'annonce).
        self.slo: dict[str, str] = {}
        self.dirty = False
        try:
            data: Any = read_json_lenient(path) if path.exists() else {}
        except (OSError, ValueError):
            data = {}  # illisible : état vide plutôt qu'une surveillance bloquée
        if not isinstance(data, dict):
            return
        values = cast(dict[str, Any], data)
        reminders = values.get("reminders")
        if isinstance(reminders, dict):
            self.reminders = {
                str(key): value
                for key, value in cast(dict[Any, Any], reminders).items()
                if isinstance(value, str)
            }
        week = values.get("digest_week")
        if isinstance(week, str):
            self.digest_week = week
        slo = values.get("slo")
        if isinstance(slo, dict):
            self.slo = {
                str(key): value for key, value in cast(dict[Any, Any], slo).items() if isinstance(value, str)
            }
        tunnels = values.get("tunnels")
        if isinstance(tunnels, dict):
            self.tunnels = {
                str(key): value
                for key, value in cast(dict[Any, Any], tunnels).items()
                if isinstance(value, str)
            }

    # --- Rappels ----------------------------------------------------------------------------------------------

    def last_reminder(self, key: str) -> datetime | None:
        value = self.reminders.get(key)
        if not value:
            return None
        try:
            return datetime.strptime(value, _FORMAT).replace(tzinfo=UTC)
        except ValueError:
            return None

    def mark_reminder(self, key: str, at: datetime) -> None:
        self.reminders[key] = at.astimezone(UTC).strftime(_FORMAT)
        self.dirty = True

    def keep_only(self, keys: Iterable[str]) -> None:
        """Oublie les rappels des objets dont l'incident est clos : le prochain incident repart de son début."""
        wanted = set(keys)
        stale = [key for key in self.reminders if key not in wanted]
        for key in stale:
            del self.reminders[key]
        if stale:
            self.dirty = True

    def remember_tunnels(self, tunnel_of: Mapping[str, str]) -> None:
        """Complète la correspondance nom d'hôte → tunnel avec celle d'un relevé (les anciennes clés restent)."""
        changed = {key: value for key, value in tunnel_of.items() if self.tunnels.get(key) != value}
        if changed:
            self.tunnels.update(changed)
            self.dirty = True

    # --- Objectifs de disponibilité ---------------------------------------------------------------------------

    def slo_below(self, key: str) -> bool:
        """Le passage sous l'objectif de cet objet est-il déjà annoncé (et son retour pas encore) ?"""
        return key in self.slo

    def mark_slo(self, key: str, below: bool, at: datetime) -> None:
        """Note l'annonce d'un passage sous l'objectif (`below`) ou celle du retour au-dessus."""
        if below:
            self.slo[key] = at.astimezone(UTC).strftime(_FORMAT)
            self.dirty = True
        elif self.slo.pop(key, None) is not None:
            self.dirty = True

    def keep_only_slo(self, keys: Iterable[str]) -> None:
        """Oublie les objets sans objectif ou sans relevé connu : un futur passage sous l'objectif repart à zéro."""
        wanted = set(keys)
        stale = [key for key in self.slo if key not in wanted]
        for key in stale:
            del self.slo[key]
        if stale:
            self.dirty = True

    # --- Résumé hebdomadaire ----------------------------------------------------------------------------------

    def mark_digest(self, week: str) -> None:
        self.digest_week = week
        self.dirty = True

    # --- Enregistrement ---------------------------------------------------------------------------------------

    def save(self) -> None:
        """Écrit le fichier s'il a changé (OSError si le dossier n'est pas accessible)."""
        if not self.dirty:
            return
        data: dict[str, Any] = {
            "reminders": self.reminders,
            "digest_week": self.digest_week,
            "tunnels": self.tunnels,
        }
        if self.slo:  # la clé n'apparaît que pour qui a des objectifs : le fichier des autres ne change pas
            data["slo"] = self.slo
        atomic_write_json(self.path, data)
        self.dirty = False
