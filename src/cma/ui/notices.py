"""Historique des notifications de la session : un bandeau d'information disparaît après 5 s, une notification de la
zone de notification aussi ; les 100 dernières restent ici, avec le nombre d'alertes (avertissements, erreurs) non
lues. Sans Qt, testé à part ; la boîte qui l'affiche est `cma.ui.dialogs.notifications`."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

LIMIT = 100
ALERTS = ("warning", "error")

Action = tuple[str, Callable[[], None]]


@dataclass(frozen=True)
class Notice:
    level: str  # info, success, warning ou error
    text: str
    action: Action | None = None
    at: datetime = field(default_factory=datetime.now)


class NoticeLog:
    def __init__(self, limit: int = LIMIT) -> None:
        self._notices: deque[Notice] = deque(maxlen=limit)
        self.unread = 0

    def add(self, level: str, text: str, action: Action | None = None, at: datetime | None = None) -> Notice:
        """Note une notification ; une notification identique à la dernière ne fait que la remplacer (une même
        alerte répétée ne remplit pas l'historique)."""
        notice = Notice(level, text, action, at or datetime.now())
        if self._notices and (self._notices[-1].level, self._notices[-1].text) == (level, text):
            self._notices.pop()
        elif level in ALERTS:
            self.unread += 1
        self._notices.append(notice)
        return notice

    def latest(self) -> list[Notice]:
        """De la plus récente à la plus ancienne."""
        return list(reversed(self._notices))

    def mark_read(self) -> None:
        self.unread = 0

    def clear(self) -> None:
        self._notices.clear()
        self.unread = 0

    def __len__(self) -> int:
        return len(self._notices)
