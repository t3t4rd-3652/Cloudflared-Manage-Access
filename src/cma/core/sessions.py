"""Base commune des sessions (cloudflared et redirections SSH) : état, journal, reconnexion."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import ClassVar

from cma.core.events import EventBus, Level, LogLine, SessionChanged
from cma.core.models import ServiceType
from cma.core.netutil import format_host_port
from cma.core.redact import redact
from cma.i18n import tr

log = logging.getLogger(__name__)

LOG_BUFFER_SIZE = 2000


class SessionState(StrEnum):
    STARTING = "starting"
    LISTENING = "listening"
    DEGRADED = "degraded"
    RECONNECTING = "reconnecting"
    ERROR = "error"
    STOPPED = "stopped"

    @property
    def label(self) -> str:
        return {
            SessionState.STARTING: tr("Démarrage"),
            SessionState.LISTENING: tr("À l'écoute"),
            SessionState.DEGRADED: tr("Dégradée"),
            SessionState.RECONNECTING: tr("Reconnexion"),
            SessionState.ERROR: tr("Erreur"),
            SessionState.STOPPED: tr("Arrêtée"),
        }[self]

    @property
    def active(self) -> bool:
        return self not in (SessionState.ERROR, SessionState.STOPPED)


class SessionKind(StrEnum):
    CLOUDFLARE = "cloudflare"
    SSH_FORWARD = "ssh_forward"


def connect_host(bind_host: str) -> str:
    """Adresse à utiliser pour joindre un port local ouvert sur `bind_host`."""
    if bind_host in ("0.0.0.0", "", "*"):
        return "127.0.0.1"
    if bind_host == "::":
        return "::1"
    return bind_host


@dataclass(frozen=True)
class SessionInfo:
    id: str
    kind: SessionKind
    profile_id: str
    forward_id: str | None
    name: str
    subtitle: str
    local_host: str
    local_port: int
    state: SessionState
    message: str
    started_at: datetime
    listening_since: datetime | None
    service_type: ServiceType
    scheme: str | None
    service_user: str
    connections: int
    bytes_up: int
    bytes_down: int
    reconnect_in: float | None
    attempts: int
    probe_ok: bool | None = None
    probe_message: str = ""

    @property
    def local_address(self) -> str:
        return format_host_port(connect_host(self.local_host), self.local_port)

    @property
    def url(self) -> str | None:
        if self.scheme in ("http", "https"):
            return f"{self.scheme}://{self.local_address}/"
        if self.service_type in (ServiceType.HTTP, ServiceType.HTTPS):
            return f"{self.service_type.value}://{self.local_address}/"
        return None


class Backoff:
    """Délais de reconnexion : 1, 2, 4… jusqu'à 60 s ; abandon après `max_failures` échecs consécutifs."""

    def __init__(self, delays: tuple[float, ...] = (1, 2, 4, 8, 16, 32, 60), max_failures: int = 10) -> None:
        self._delays = delays
        self.max_failures = max_failures
        self.failures = 0

    def next_delay(self) -> float:
        delay = self._delays[min(self.failures, len(self._delays) - 1)]
        self.failures += 1
        return delay

    @property
    def exhausted(self) -> bool:
        return self.failures >= self.max_failures

    def reset(self) -> None:
        self.failures = 0


class Session(ABC):
    kind: ClassVar[SessionKind]

    def __init__(
        self,
        *,
        bus: EventBus,
        name: str,
        subtitle: str,
        profile_id: str,
        local_host: str,
        local_port: int,
        service_type: ServiceType = ServiceType.GENERIC,
        scheme: str | None = None,
        service_user: str = "",
        forward_id: str | None = None,
    ) -> None:
        self.id = uuid.uuid4().hex[:12]
        self.bus = bus
        self.name = name
        self.subtitle = subtitle
        self.profile_id = profile_id
        self.forward_id = forward_id
        self.local_host = local_host
        self.local_port = local_port
        self.service_type = service_type
        self.scheme = scheme
        self.service_user = service_user
        self.started_at = datetime.now()
        self.listening_since: datetime | None = None
        self.connections = 0
        # Dernier test du service distant (« Tester le service ») : None tant qu'il n'a pas été lancé.
        self.probe_ok: bool | None = None
        self.probe_message = ""
        self.bytes_up = 0
        self.bytes_down = 0
        self.backoff = Backoff()
        self.logs: deque[LogLine] = deque(maxlen=LOG_BUFFER_SIZE)
        self._state = SessionState.STARTING
        self._message = ""
        self._reconnect_at: float | None = None
        self._task: asyncio.Task[None] | None = None
        self._stop_event: asyncio.Event | None = None
        self._stopping = False

    # --- État ----------------------------------------------------------------------

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def message(self) -> str:
        return self._message

    @property
    def stopping(self) -> bool:
        return self._stopping

    def info(self) -> SessionInfo:
        reconnect_in = None
        if self._reconnect_at is not None:
            reconnect_in = max(0.0, self._reconnect_at - time.monotonic())
        return SessionInfo(
            id=self.id,
            kind=self.kind,
            profile_id=self.profile_id,
            forward_id=self.forward_id,
            name=self.name,
            subtitle=self.subtitle,
            local_host=self.local_host,
            local_port=self.local_port,
            state=self._state,
            message=self._message,
            started_at=self.started_at,
            listening_since=self.listening_since,
            service_type=self.service_type,
            scheme=self.scheme,
            service_user=self.service_user,
            connections=self.connections,
            bytes_up=self.bytes_up,
            bytes_down=self.bytes_down,
            reconnect_in=reconnect_in,
            attempts=self.backoff.failures,
            probe_ok=self.probe_ok,
            probe_message=self.probe_message,
        )

    def publish(self) -> None:
        self.bus.publish(SessionChanged(self.info()))

    def set_state(self, state: SessionState, message: str | None = None) -> None:
        if state not in (SessionState.LISTENING, SessionState.DEGRADED):
            self.probe_ok, self.probe_message = None, ""
        if state == SessionState.LISTENING and self._state not in (
            SessionState.LISTENING,
            SessionState.DEGRADED,
        ):
            self.listening_since = datetime.now()
        if state != SessionState.RECONNECTING:
            self._reconnect_at = None
        changed = state != self._state or (message is not None and message != self._message)
        self._state = state
        if message is not None:
            self._message = redact(message)
        if changed:
            self.publish()

    def log(self, level: Level, message: str) -> None:
        line = LogLine(source_id=self.id, source_label=self.name, level=level, message=redact(message))
        self.logs.append(line)
        self.bus.publish(line)

    # --- Cycle de vie -------------------------------------------------------------------

    def start(self) -> None:
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._run_guarded(), name=f"session-{self.id}")

    async def _run_guarded(self) -> None:
        try:
            await self.run()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.exception("Session %s interrompue par une erreur inattendue", self.name)
            self.log("ERROR", tr("Erreur inattendue : {error}").format(error=exc))
            self.set_state(SessionState.ERROR, str(exc))

    @abstractmethod
    async def run(self) -> None:
        """Boucle principale : démarre, surveille, reconnecte, jusqu'à l'arrêt."""

    @abstractmethod
    async def _shutdown(self) -> None:
        """Libère les ressources (processus, écoute locale)."""

    async def stop(self) -> None:
        if self._stopping:
            return
        self._stopping = True
        if self._stop_event is not None:
            self._stop_event.set()
        try:
            await self._shutdown()
        finally:
            if self._task is not None and not self._task.done():
                self._task.cancel()
                await asyncio.gather(self._task, return_exceptions=True)
            self.set_state(SessionState.STOPPED, "")
            self.log("INFO", tr("Session arrêtée."))

    async def wait_done(self) -> None:
        if self._task is not None:
            await asyncio.gather(self._task, return_exceptions=True)

    async def sleep_unless_stopped(self, delay: float) -> bool:
        """Attend `delay` secondes ; renvoie False si l'arrêt a été demandé entre-temps."""
        if self._stop_event is None:
            await asyncio.sleep(delay)
            return not self._stopping
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=delay)
        except TimeoutError:
            return True
        return False

    async def wait_before_retry(self, reason: str) -> bool:
        """Passe en reconnexion et attend le prochain délai. False si on abandonne ou si l'arrêt est demandé."""
        if self.backoff.exhausted:
            self.set_state(
                SessionState.ERROR,
                tr("{reason} Abandon après {n} tentatives.").format(reason=reason, n=self.backoff.failures),
            )
            return False
        delay = self.backoff.next_delay()
        self._reconnect_at = time.monotonic() + delay
        self.set_state(SessionState.RECONNECTING, reason)
        self.log(
            "WARNING", tr("{reason} Nouvelle tentative dans {delay:g} s.").format(reason=reason, delay=delay)
        )
        return await self.sleep_unless_stopped(delay)
