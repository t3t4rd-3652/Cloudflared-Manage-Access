"""Redirection locale SSH : 127.0.0.1:port_local → hôte:port vus depuis le serveur.

Le relais est fait par asyncio (blocs de 64 Kio), avec comptage des connexions et des octets.
Si la connexion SSH tombe, le port local reste ouvert et la session se reconnecte avec délai progressif.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import Any

import asyncssh

from cma.core.models import SavedForward, ServiceType, SshProfile
from cma.core.netutil import PortStatus, check_local_port, format_host_port
from cma.core.sessions import Session, SessionKind, SessionState
from cma.core.ssh.connection import SshConnectionManager
from cma.core.ssh.errors import SshCancelled, SshError
from cma.i18n import tr

log = logging.getLogger(__name__)

CHUNK_SIZE = 64 * 1024
STATS_INTERVAL = 1.0


class SshForwardSession(Session):
    kind = SessionKind.SSH_FORWARD

    def __init__(
        self,
        *,
        bus: Any,
        profile: SshProfile,
        forward: SavedForward,
        connections: SshConnectionManager,
        local_host: str = "127.0.0.1",
    ) -> None:
        target = format_host_port(forward.remote_host, forward.remote_port)
        label = forward.label or f"{forward.remote_port}"
        service = {"http": ServiceType.HTTP, "https": ServiceType.HTTPS}.get(
            forward.scheme or "", ServiceType.GENERIC
        )
        super().__init__(
            bus=bus,
            name=f"{profile.name} · {label}",
            subtitle=tr("{profile} → {target} (vu du serveur)").format(profile=profile.name, target=target),
            profile_id=profile.id,
            local_host=local_host,
            local_port=forward.local_port,
            service_type=service,
            scheme=forward.scheme,
            forward_id=forward.id,
        )
        self.profile = profile
        self.forward = forward
        self._connections = connections
        self._conn: asyncssh.SSHClientConnection | None = None
        self._server: asyncio.Server | None = None
        self._writers: set[asyncio.StreamWriter] = set()
        self._last_stats = 0.0

    async def run(self) -> None:
        while not self.stopping:
            self.set_state(
                SessionState.STARTING, tr("Connexion SSH à {profile}…").format(profile=self.profile.name)
            )
            try:
                conn = await self._connections.get(self.profile)
            except SshCancelled as exc:
                self.set_state(SessionState.ERROR, str(exc))
                return
            except SshError as exc:
                self.log("ERROR", str(exc))
                if exc.fatal or not await self.wait_before_retry(str(exc)):
                    if exc.fatal:
                        self.set_state(SessionState.ERROR, str(exc))
                    return
                continue
            self._conn = conn
            if self._server is None:
                check = check_local_port(self.local_host, self.local_port)
                if check.status != PortStatus.FREE:
                    self.log("ERROR", check.message)
                    self.set_state(SessionState.ERROR, check.message)
                    return
                try:
                    self._server = await asyncio.start_server(
                        self._handle_client, host=self.local_host, port=self.local_port
                    )
                except OSError as exc:
                    message = tr("Impossible d'ouvrir le port local {port} : {error}").format(
                        port=self.local_port, error=exc
                    )
                    self.log("ERROR", message)
                    self.set_state(SessionState.ERROR, message)
                    return
            self.backoff.reset()
            self.set_state(SessionState.LISTENING, "")
            self.log(
                "INFO",
                tr("À l'écoute sur {local}, vers {remote} depuis {profile}.").format(
                    local=self.info().local_address,
                    remote=format_host_port(self.forward.remote_host, self.forward.remote_port),
                    profile=self.profile.name,
                ),
            )
            await conn.wait_closed()
            self._conn = None
            if self.stopping:
                return
            if not await self.wait_before_retry(tr("Connexion SSH perdue.")):
                return

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = self._conn
        if conn is None or self.state not in (SessionState.LISTENING, SessionState.DEGRADED):
            writer.close()
            return
        self._writers.add(writer)
        self.connections += 1
        self.publish()
        target = format_host_port(self.forward.remote_host, self.forward.remote_port)
        try:
            try:
                remote_reader, remote_writer = await conn.open_connection(  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
                    self.forward.remote_host, self.forward.remote_port
                )
            except (asyncssh.Error, OSError) as exc:
                reason = getattr(exc, "reason", None) or str(exc)
                message = tr("Le serveur n'a pas pu joindre {target} : {reason}").format(
                    target=target, reason=reason
                )
                self.log("WARNING", message)
                self.set_state(SessionState.DEGRADED, message)
                return
            if self.state == SessionState.DEGRADED:
                self.set_state(SessionState.LISTENING, "")
            await asyncio.gather(
                self._pipe(reader, remote_writer, upstream=True),
                self._pipe(remote_reader, writer, upstream=False),
                return_exceptions=True,
            )
            with contextlib.suppress(Exception):
                remote_writer.close()
        finally:
            with contextlib.suppress(Exception):
                writer.close()
            self._writers.discard(writer)
            self.connections -= 1
            self.publish()

    async def _pipe(self, reader: Any, writer: Any, *, upstream: bool) -> None:
        try:
            while True:
                data = await reader.read(CHUNK_SIZE)
                if not data:
                    break
                writer.write(data)
                if upstream:
                    self.bytes_up += len(data)
                else:
                    self.bytes_down += len(data)
                self._publish_stats()
                await writer.drain()
        finally:
            with contextlib.suppress(Exception):
                if writer.can_write_eof():
                    writer.write_eof()

    def _publish_stats(self) -> None:
        now = time.monotonic()
        if now - self._last_stats >= STATS_INTERVAL:
            self._last_stats = now
            self.publish()

    async def _shutdown(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.close()
            for writer in list(self._writers):
                with contextlib.suppress(Exception):
                    writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), timeout=5)
