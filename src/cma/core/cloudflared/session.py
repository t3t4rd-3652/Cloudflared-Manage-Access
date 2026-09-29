"""Session `cloudflared access tcp` : lancement, surveillance, reconnexion, arrêt.

cloudflared annonce « Start Websocket listener » avant d'ouvrir réellement le port : l'état
« à l'écoute » n'est donné qu'une fois le port local vérifié occupé, processus toujours vivant.
Les erreurs de connexion cliente (token refusé, DNS, proxy) ne tuent pas le processus : la session
passe alors « dégradée » et redevient « à l'écoute » après une minute sans nouvelle erreur.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

from cma.core.cloudflared.command import CommandSpec, proxy_host_port
from cma.core.cloudflared.log_parser import LogKind, parse_line
from cma.core.events import Notification
from cma.core.models import CloudflareProfile
from cma.core.netutil import PortStatus, check_local_port, is_port_listening
from cma.core.sessions import Session, SessionKind, SessionState
from cma.i18n import tr
from cma.platform.winjob import ProcessJob

log = logging.getLogger(__name__)

LISTEN_CONFIRM_TIMEOUT = 10.0
DEGRADED_RECOVERY_DELAY = 60.0
STABLE_AFTER = 60.0


@dataclass
class _Outcome:
    message: str
    fatal: bool
    listened_for: float


class CloudflaredSession(Session):
    kind = SessionKind.CLOUDFLARE

    def __init__(
        self, *, bus: Any, profile: CloudflareProfile, command: CommandSpec, job: ProcessJob | None = None
    ) -> None:
        assert profile.local_port is not None
        super().__init__(
            bus=bus,
            name=profile.name,
            subtitle=profile.hostname,
            profile_id=profile.id,
            local_host=profile.local_host,
            local_port=profile.local_port,
            service_type=profile.service_type,
            service_user=profile.service_user,
        )
        self.command = command
        self.auto_reconnect = profile.auto_reconnect
        self.auth_url: str | None = None
        self._job = job
        self._proxy = proxy_host_port(profile.proxy)
        self._proc: asyncio.subprocess.Process | None = None
        self._last_connection_error: float | None = None
        self._notified: set[str] = set()

    @property
    def pid(self) -> int | None:
        return self._proc.pid if self._proc is not None else None

    async def run(self) -> None:
        while not self.stopping:
            check = check_local_port(self.local_host, self.local_port)
            if check.status != PortStatus.FREE:
                self.log("ERROR", check.message)
                self.set_state(SessionState.ERROR, check.message)
                return
            self.set_state(SessionState.STARTING, tr("Lancement de cloudflared…"))
            outcome = await self._run_process()
            if self.stopping:
                return
            if outcome.fatal or not self.auto_reconnect:
                self.log("ERROR", outcome.message)
                self.set_state(SessionState.ERROR, outcome.message)
                self._notify_once("error", outcome.message)
                return
            if outcome.listened_for >= STABLE_AFTER:
                self.backoff.reset()
            if not await self.wait_before_retry(outcome.message):
                return

    async def _run_process(self) -> _Outcome:
        kwargs: dict[str, Any] = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        else:
            kwargs["start_new_session"] = True
        self.log("INFO", tr("Commande : {command}").format(command=self.command.display()))
        try:
            proc = await asyncio.create_subprocess_exec(
                *self.command.args,
                env=self.command.env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                **kwargs,
            )
        except FileNotFoundError:
            return _Outcome(
                tr("cloudflared est introuvable : {path}").format(path=self.command.args[0]), True, 0
            )
        except OSError as exc:
            return _Outcome(tr("Impossible de lancer cloudflared : {error}").format(error=exc), True, 0)

        self._proc = proc
        if self._job is not None:
            self._job.assign(proc.pid)
        listening_at: list[float] = []
        fatal_message: str | None = None
        last_problem: str | None = None

        confirm_task = asyncio.create_task(self._confirm_listening(proc, listening_at, fallback=True))
        watch_task = asyncio.create_task(self._watch_degraded())
        try:
            assert proc.stdout is not None
            async for raw in proc.stdout:
                parsed = parse_line(raw.decode("utf-8", "replace"), proxy_host_port=self._proxy)
                if not parsed.raw.strip():
                    continue
                self.log(parsed.level, parsed.raw)
                if parsed.kind == LogKind.LISTENER_STARTING and not listening_at:
                    confirm_task.cancel()
                    confirm_task = asyncio.create_task(
                        self._confirm_listening(proc, listening_at, fallback=False)
                    )
                elif parsed.fatal:
                    fatal_message = parsed.hint
                elif parsed.connection_error and parsed.hint:
                    last_problem = parsed.hint
                    self._connection_problem(parsed.hint)
                elif parsed.kind == LogKind.AUTH_REQUIRED:
                    self.auth_url = parsed.url
                    self._notify_once("warning", parsed.hint or "")
                elif parsed.kind == LogKind.AUTH_OK and self.state == SessionState.DEGRADED:
                    self.set_state(SessionState.LISTENING, "")
            await proc.wait()
        finally:
            confirm_task.cancel()
            watch_task.cancel()
            await asyncio.gather(confirm_task, watch_task, return_exceptions=True)
            self._proc = None

        listened_for = time.monotonic() - listening_at[0] if listening_at else 0.0
        if fatal_message:
            return _Outcome(fatal_message, True, listened_for)
        if not listening_at and last_problem is None:
            message = tr("cloudflared s'est arrêté avant d'ouvrir le port (code {code}).").format(
                code=proc.returncode
            )
            # Arrêt immédiat sans message connu : réessayer ne changera rien.
            return _Outcome(message, True, listened_for)
        message = last_problem or tr("cloudflared s'est arrêté (code {code}).").format(code=proc.returncode)
        return _Outcome(message, False, listened_for)

    async def _confirm_listening(
        self, proc: asyncio.subprocess.Process, listening_at: list[float], *, fallback: bool
    ) -> None:
        """Le port est-il réellement ouvert par cloudflared ? Sondage par bind, sans jamais s'y connecter."""
        if fallback:
            # Sans ligne « Start Websocket listener » (autre version de cloudflared), on sonde plus tard.
            await asyncio.sleep(3)
        deadline = time.monotonic() + LISTEN_CONFIRM_TIMEOUT
        while time.monotonic() < deadline:
            await asyncio.sleep(0.25)
            if proc.returncode is not None:
                return
            listening = await asyncio.to_thread(is_port_listening, self.local_host, self.local_port)
            if listening and proc.returncode is None:
                listening_at.append(time.monotonic())
                self.set_state(SessionState.LISTENING, "")
                self.log("INFO", tr("À l'écoute sur {address}.").format(address=self.info().local_address))
                return
        if proc.returncode is None and not fallback:
            self.log(
                "WARNING",
                tr("Le port local n'est toujours pas ouvert après {s} s.").format(
                    s=int(LISTEN_CONFIRM_TIMEOUT)
                ),
            )

    def _connection_problem(self, hint: str) -> None:
        self._last_connection_error = time.monotonic()
        if self.state in (SessionState.LISTENING, SessionState.DEGRADED):
            self.set_state(SessionState.DEGRADED, hint)
        self._notify_once("error", hint)

    async def _watch_degraded(self) -> None:
        while True:
            await asyncio.sleep(5)
            if (
                self.state == SessionState.DEGRADED
                and self._last_connection_error is not None
                and time.monotonic() - self._last_connection_error > DEGRADED_RECOVERY_DELAY
            ):
                self.set_state(SessionState.LISTENING, "")

    def _notify_once(self, level: str, message: str) -> None:
        if not message or message in self._notified:
            return
        self._notified.add(message)
        self.bus.publish(Notification(level=level, title=self.name, message=message, session_id=self.id))  # type: ignore[arg-type]

    async def _shutdown(self) -> None:
        proc = self._proc
        if proc is None or proc.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            await proc.wait()
