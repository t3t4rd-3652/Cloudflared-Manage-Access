"""Événements publiés par le moteur, et bus qui les distribue aux abonnés (interface, CLI, journaux)."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from cma.core.sessions import SessionInfo

log = logging.getLogger(__name__)

Level = Literal["DEBUG", "INFO", "WARNING", "ERROR"]
NotificationLevel = Literal["info", "success", "warning", "error"]


def _now() -> datetime:
    return datetime.now()


@dataclass(frozen=True)
class Event:
    pass


@dataclass(frozen=True)
class SessionChanged(Event):
    info: SessionInfo


@dataclass(frozen=True)
class SessionRemoved(Event):
    session_id: str


@dataclass(frozen=True)
class LogLine(Event):
    source_id: str | None
    source_label: str
    level: Level
    message: str
    timestamp: datetime = field(default_factory=_now)


@dataclass(frozen=True)
class Notification(Event):
    level: NotificationLevel
    title: str
    message: str
    session_id: str | None = None


@dataclass(frozen=True)
class SshConnectionChanged(Event):
    profile_id: str
    state: Literal["connecting", "connected", "disconnected", "error"]
    message: str = ""


@dataclass(frozen=True)
class ConfigChanged(Event):
    pass


@dataclass(frozen=True)
class DownloadProgress(Event):
    received: int
    total: int | None


class EventBus:
    """Distribution synchrone dans le thread de l'émetteur. L'interface re-publie vers son thread."""

    def __init__(self) -> None:
        self._subscribers: list[Callable[[Event], None]] = []
        self._lock = threading.Lock()

    def subscribe(self, callback: Callable[[Event], None]) -> Callable[[], None]:
        with self._lock:
            self._subscribers.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                if callback in self._subscribers:
                    self._subscribers.remove(callback)

        return unsubscribe

    def publish(self, event: Event) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for callback in subscribers:
            try:
                callback(event)
            except Exception:
                log.exception("Erreur dans un abonné au bus d'événements")
