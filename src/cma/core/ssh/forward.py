"""Redirections SSH : locale (-L), dynamique SOCKS (-D) et inverse (-R).

- Locale : 127.0.0.1:port_local → hôte:port vus depuis le serveur.
- SOCKS : proxy SOCKS 5/4a sur le port local ; chaque connexion sort depuis le serveur vers la cible demandée.
- Inverse : le serveur écoute sur hôte:port et renvoie chaque connexion vers une adresse joignable depuis ce poste.

Le relais est fait par asyncio (blocs de 64 Kio), avec comptage des connexions et des octets.
Si la connexion SSH tombe, le port local reste ouvert et la session se reconnecte avec délai progressif.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import asyncssh
else:
    from cma.core.ssh._lazy import asyncssh

from cma.core.models import SavedForward, ServiceType, SshProfile
from cma.core.netutil import PortStatus, check_local_port
from cma.core.sessions import Session, SessionKind, SessionState
from cma.core.ssh import socks
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
        service = {"http": ServiceType.HTTP, "https": ServiceType.HTTPS}.get(
            forward.scheme or "", ServiceType.GENERIC
        )
        if forward.kind == "local":
            subtitle = tr("{target} depuis {profile}").format(
                profile=profile.name, target=forward.server_side
            )
        elif forward.kind == "socks":
            subtitle = tr("proxy SOCKS, sorties depuis {profile}").format(profile=profile.name)
        else:
            subtitle = tr("{profile} écoute sur {remote}").format(
                profile=profile.name, remote=forward.server_side
            )
        super().__init__(
            bus=bus,
            name=f"{profile.name} · {forward.short_label}",
            subtitle=subtitle,
            profile_id=profile.id,
            local_host=forward.local_host if forward.kind == "remote" else local_host,
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
        self._listener: Any = None
        self._writers: set[Any] = set()
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
            opened = await (
                self._listen_remote(conn) if self.forward.kind == "remote" else self._listen_local()
            )
            if not opened:
                return
            self.backoff.reset()
            self.set_state(SessionState.LISTENING, "")
            self.log("INFO", self._listening_message())
            await conn.wait_closed()
            self._conn = None
            self._listener = None
            if self.stopping:
                return
            if not await self.wait_before_retry(tr("Connexion SSH perdue.")):
                return

    def _listening_message(self) -> str:
        if self.forward.kind == "socks":
            return tr("Proxy SOCKS à l'écoute sur {local}, sorties depuis {profile}.").format(
                local=self.info().local_address, profile=self.profile.name
            )
        if self.forward.kind == "remote":
            return tr("{profile} écoute sur {remote}, vers {local} sur ce poste.").format(
                profile=self.profile.name, remote=self.forward.server_side, local=self.forward.local_side
            )
        return tr("À l'écoute sur {local}, vers {remote} depuis {profile}.").format(
            local=self.info().local_address, remote=self.forward.server_side, profile=self.profile.name
        )

    async def _listen_local(self) -> bool:
        """Port local (redirection locale ou proxy SOCKS), ouvert une fois et gardé pendant les reconnexions."""
        if self._server is not None:
            return True
        check = check_local_port(self.local_host, self.local_port)
        if check.status != PortStatus.FREE:
            self.log("ERROR", check.message)
            self.set_state(SessionState.ERROR, check.message)
            return False
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
            return False
        return True

    async def _listen_remote(self, conn: asyncssh.SSHClientConnection) -> bool:
        """Demande au serveur d'écouter (redirection inverse) ; refaite après chaque reconnexion."""
        forward = self.forward
        assert forward.remote_port is not None
        try:
            listener = await conn.start_server(  # pyright: ignore[reportUnknownMemberType]
                self._remote_handler, forward.remote_host, forward.remote_port
            )
        except (asyncssh.Error, asyncssh.ChannelListenError, OSError) as exc:
            # ChannelListenError ne dérive pas d'asyncssh.Error : refus d'écoute du serveur.
            listener, error = None, getattr(exc, "reason", None) or str(exc)
        else:
            error = tr("requête refusée")
        if listener is None:
            message = tr("Le serveur refuse d'écouter sur {remote} : {error}").format(
                remote=forward.server_side, error=error
            )
            self.log("ERROR", message)
            self.set_state(SessionState.ERROR, message)
            return False
        self._listener = listener
        return True

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = self._conn
        if conn is None or self.state not in (SessionState.LISTENING, SessionState.DEGRADED):
            writer.close()
            return
        self._writers.add(writer)
        self.connections += 1
        self.publish()
        try:
            version = 0
            if self.forward.kind == "socks":
                try:
                    host, port, version = await asyncio.wait_for(socks.negotiate(reader, writer), 15)
                except (
                    socks.SocksError,
                    asyncio.IncompleteReadError,
                    asyncio.LimitOverrunError,
                    TimeoutError,
                ):
                    return
            else:
                host, port = self.forward.remote_host, int(self.forward.remote_port or 0)
            target = f"{host}:{port}"
            try:
                remote_reader, remote_writer = await conn.open_connection(host, port)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
            except (asyncssh.Error, OSError) as exc:
                if version:
                    with contextlib.suppress(Exception):
                        writer.write(socks.failure_reply(version))
                        await writer.drain()
                reason = getattr(exc, "reason", None) or str(exc)
                message = tr("Le serveur n'a pas pu joindre {target} : {reason}").format(
                    target=target, reason=reason
                )
                self.log("WARNING", message)
                if self.forward.kind == "local":
                    # Un proxy SOCKS sert des cibles variées : une cible injoignable ne dégrade pas la session.
                    self.set_state(SessionState.DEGRADED, message)
                return
            if version:
                writer.write(socks.success_reply(version))
                await writer.drain()
            if self.state == SessionState.DEGRADED:
                self.set_state(SessionState.LISTENING, "")
            await self._relay(reader, writer, remote_reader, remote_writer)
        finally:
            with contextlib.suppress(Exception):
                writer.close()
            self._writers.discard(writer)
            self.connections -= 1
            self.publish()

    def _remote_handler(self, _host: str, _port: int) -> Any:
        """Fabrique demandée par asyncssh pour chaque connexion entrante côté serveur."""
        return self._handle_remote

    async def _handle_remote(self, reader: Any, writer: Any) -> None:
        """Connexion arrivée sur le serveur (redirection inverse) : relayée vers la cible de ce poste."""
        self._writers.add(writer)
        self.connections += 1
        self.publish()
        target = self.forward.local_side
        try:
            try:
                local_reader, local_writer = await asyncio.wait_for(
                    asyncio.open_connection(self.forward.local_host, self.forward.local_port), 10
                )
            except (OSError, TimeoutError) as exc:
                message = tr("Ce poste n'a pas pu joindre {target} : {error}").format(
                    target=target, error=exc
                )
                self.log("WARNING", message)
                self.set_state(SessionState.DEGRADED, message)
                return
            if self.state == SessionState.DEGRADED:
                self.set_state(SessionState.LISTENING, "")
            # Pour une redirection inverse, « envoyé » compte ce qui part de ce poste vers le serveur.
            await self._relay(local_reader, local_writer, reader, writer)
        finally:
            with contextlib.suppress(Exception):
                writer.close()
            self._writers.discard(writer)
            self.connections -= 1
            self.publish()

    async def _relay(self, near_reader: Any, near_writer: Any, far_reader: Any, far_writer: Any) -> None:
        await asyncio.gather(
            self._pipe(near_reader, far_writer, upstream=True),
            self._pipe(far_reader, near_writer, upstream=False),
            return_exceptions=True,
        )
        with contextlib.suppress(Exception):
            far_writer.close()

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
        listener, self._listener = self._listener, None
        if listener is not None:
            with contextlib.suppress(Exception):
                listener.close()
        server, self._server = self._server, None
        if server is not None:
            server.close()
        for writer in list(self._writers):
            with contextlib.suppress(Exception):
                writer.close()
        if server is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), timeout=5)
