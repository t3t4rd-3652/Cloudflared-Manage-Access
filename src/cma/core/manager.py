"""Orchestrateur du moteur : transforme les profils en sessions et expose toutes les actions.

L'interface graphique et la ligne de commande n'appellent que cette classe. Toutes ses méthodes
asynchrones s'exécutent dans la boucle du moteur.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from cma.core.cfadmin import CloudflareAdmin
from cma.core.cloudflared.binary import detect as detect_cloudflared
from cma.core.cloudflared.command import (
    CommandError,
    CommandSpec,
    build_access_login,
    build_access_tcp,
    build_access_token,
    build_ssh_config,
)
from cma.core.cloudflared.session import CloudflaredSession
from cma.core.config_store import ConfigStore
from cma.core.events import EventBus, Notification, SessionRemoved
from cma.core.models import AuthMode, CloudflareProfile, SavedForward, SshAuthMode
from cma.core.netutil import find_free_port
from cma.core.prompts import Prompter
from cma.core.secrets import SecretStore
from cma.core.sessions import Session, SessionInfo, SessionKind, SessionState, connect_host
from cma.core.ssh.connection import SshConnectionManager
from cma.core.ssh.discovery import DiscoveryResult, discover
from cma.core.ssh.errors import SshError
from cma.core.ssh.forward import SshForwardSession
from cma.core.ssh.keys import DeployResult, deploy_public_key, public_key_line, resolve_key_path
from cma.i18n import tr
from cma.paths import AppPaths
from cma.platform.winjob import ProcessJob

log = logging.getLogger(__name__)

BRIDGE_TIMEOUT = 30.0


class ManagerError(RuntimeError):
    """Action impossible, avec un message destiné à l'utilisateur."""


class SessionManager:
    def __init__(
        self,
        *,
        paths: AppPaths,
        store: ConfigStore,
        secrets: SecretStore,
        bus: EventBus,
        prompter: Prompter,
        job: ProcessJob | None = None,
    ) -> None:
        self.paths = paths
        self.store = store
        self.secrets = secrets
        self.bus = bus
        self.job = job
        self.sessions: dict[str, Session] = {}
        self.ssh = SshConnectionManager(
            paths=paths,
            settings=lambda: store.snapshot().settings,
            secrets=secrets,
            prompter=prompter,
            bus=bus,
            cloudflare_bridge=self._cloudflare_bridge,
            on_password_remembered=self._mark_password_remembered,
        )
        self.cloudflare = CloudflareAdmin(
            store, secrets, lambda preferred, avoid: self.suggest_local_port(preferred, avoid=avoid)
        )

    # --- Consultation ------------------------------------------------------------------

    def list_sessions(self) -> list[SessionInfo]:
        return [s.info() for s in self.sessions.values()]

    def session(self, session_id: str) -> Session | None:
        return self.sessions.get(session_id)

    def active_session_for(self, profile_id: str, forward_id: str | None = None) -> Session | None:
        for session in self.sessions.values():
            if session.profile_id == profile_id and session.forward_id == forward_id and session.state.active:
                return session
        return None

    def cloudflared_path(self) -> Path | None:
        return detect_cloudflared(self.paths, self.store.snapshot().settings.cloudflared_path)

    def used_local_ports(self) -> set[int]:
        return {s.local_port for s in self.sessions.values() if s.state.active}

    def suggest_local_port(
        self, preferred: int | None = None, host: str = "127.0.0.1", avoid: set[int] | None = None
    ) -> int | None:
        settings = self.store.snapshot().settings
        return find_free_port(
            host,
            preferred=preferred,
            port_range=(settings.auto_port_min, settings.auto_port_max),
            avoid=self.used_local_ports() | (avoid or set()),
        )

    def _check_port_conflict(self, port: int, ignore: Session | None = None) -> None:
        for session in self.sessions.values():
            if session is not ignore and session.state.active and session.local_port == port:
                raise ManagerError(
                    tr("Le port local {port} est déjà utilisé par la session « {name} ».").format(
                        port=port, name=session.name
                    )
                )

    def _add(self, session: Session) -> None:
        # Une session terminée du même profil est remplacée par la nouvelle.
        for old_id, old in list(self.sessions.items()):
            if (
                old.profile_id == session.profile_id
                and old.forward_id == session.forward_id
                and not old.state.active
            ):
                del self.sessions[old_id]
                self.bus.publish(SessionRemoved(old_id))
        self.sessions[session.id] = session
        session.start()
        session.publish()

    # --- Cloudflare -----------------------------------------------------------------------

    def _cloudflared_command(self, profile: CloudflareProfile) -> Any:
        config = self.store.snapshot()
        problems = profile.readiness_problems(config.tokens_by_id())
        if problems:
            raise ManagerError(
                tr("Profil « {name} » incomplet : {problems}.").format(
                    name=profile.name, problems=", ".join(problems)
                )
            )
        binary = self.cloudflared_path()
        if binary is None:
            raise ManagerError(
                tr("cloudflared est introuvable. Indiquez son chemin ou téléchargez-le dans les paramètres.")
            )
        client_id = client_secret = None
        if profile.auth == AuthMode.SERVICE_TOKEN:
            token = config.token(profile.token_id)
            assert token is not None
            client_id = token.client_id
            client_secret = self.secrets.get(token.secret_key)
            if not client_secret:
                raise ManagerError(
                    tr("Le secret du token « {name} » est absent du coffre. Saisissez-le à nouveau.").format(
                        name=token.name
                    )
                )
        try:
            return build_access_tcp(
                binary,
                profile,
                client_id=client_id,
                client_secret=client_secret,
                log_level=config.settings.cloudflared_log_level,
            )
        except CommandError as exc:
            raise ManagerError(str(exc)) from exc

    async def start_cloudflare(self, profile_id: str) -> SessionInfo:
        profile = self.store.snapshot().cloudflare_profile(profile_id)
        if profile is None:
            raise ManagerError(tr("Profil introuvable."))
        existing = self.active_session_for(profile.id)
        if existing is not None:
            return existing.info()
        command = self._cloudflared_command(profile)
        assert profile.local_port is not None
        self._check_port_conflict(profile.local_port)
        session = CloudflaredSession(bus=self.bus, profile=profile, command=command, job=self.job)
        self._add(session)
        return session.info()

    async def _cloudflare_bridge(self, cloudflare_profile_id: str) -> tuple[str, int, str]:
        """Démarre (si besoin) la session Cloudflare d'un profil et attend qu'elle soit à l'écoute."""
        profile = self.store.snapshot().cloudflare_profile(cloudflare_profile_id)
        if profile is None:
            raise SshError(tr("Le profil Cloudflare de passage n'existe plus."), fatal=True)
        try:
            await self.start_cloudflare(profile.id)
        except ManagerError as exc:
            raise SshError(str(exc), fatal=True) from exc
        session = self.active_session_for(profile.id)
        deadline = time.monotonic() + BRIDGE_TIMEOUT
        while session is not None and time.monotonic() < deadline:
            if session.state in (SessionState.LISTENING, SessionState.DEGRADED):
                return connect_host(session.local_host), session.local_port, profile.hostname
            if not session.state.active:
                break
            await asyncio.sleep(0.2)
        message = session.message if session is not None and session.message else tr("délai dépassé")
        raise SshError(
            tr("Le tunnel Cloudflare « {name} » n'a pas démarré : {message}").format(
                name=profile.name, message=message
            )
        )

    async def test_cloudflare_profile(self, profile_id: str, timeout: float = 12) -> tuple[bool, str]:
        """Lance brièvement cloudflared sur un port libre et ouvre une connexion pour vérifier l'accès."""
        profile = self.store.snapshot().cloudflare_profile(profile_id)
        if profile is None:
            raise ManagerError(tr("Profil introuvable."))
        if profile.auth != AuthMode.SERVICE_TOKEN:
            raise ManagerError(tr("Le test automatique ne concerne que les profils avec service token."))
        port = self.suggest_local_port()
        if port is None:
            raise ManagerError(tr("Aucun port local libre pour le test."))
        test_profile = profile.model_copy(
            update={"local_host": "127.0.0.1", "local_port": port, "auto_reconnect": False}
        )
        command = self._cloudflared_command(test_profile)
        private_bus = EventBus()
        session = CloudflaredSession(bus=private_bus, profile=test_profile, command=command, job=self.job)
        session.start()
        try:
            deadline = time.monotonic() + timeout
            while session.state == SessionState.STARTING and time.monotonic() < deadline:
                await asyncio.sleep(0.2)
            if session.state != SessionState.LISTENING:
                return False, session.message or tr("cloudflared n'a pas ouvert le port de test.")
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 5)
            except (OSError, TimeoutError) as exc:
                return False, str(exc)
            with contextlib.suppress(TimeoutError, OSError):
                await asyncio.wait_for(reader.read(64), 5)
            writer.close()
            await asyncio.sleep(0.5)
            # L'état a pu changer pendant les attentes : on relit un instantané.
            final = session.info()
            if final.state == SessionState.DEGRADED:
                return False, final.message
            return True, tr("Cloudflare Access a accepté la connexion.")
        finally:
            await session.stop()

    async def access_login(self, profile_id: str) -> str:
        """`cloudflared access login` : ouvre le navigateur pour s'authentifier auprès d'Access."""
        profile = self.store.snapshot().cloudflare_profile(profile_id)
        binary = self.cloudflared_path()
        if profile is None or binary is None or not profile.hostname:
            raise ManagerError(tr("Profil incomplet ou cloudflared introuvable."))
        output = await self._run_cloudflared(
            build_access_login(binary, profile.hostname, proxy=profile.proxy), timeout=300
        )
        return output

    async def access_token_valid(self, profile_id: str) -> bool:
        """`cloudflared access token` : vrai si cloudflared a un jeton Access en cache pour ce hostname.

        Le jeton lui-même n'est jamais renvoyé ni journalisé.
        """
        profile = self.store.snapshot().cloudflare_profile(profile_id)
        binary = self.cloudflared_path()
        if profile is None or binary is None or not profile.hostname:
            raise ManagerError(tr("Profil incomplet ou cloudflared introuvable."))
        try:
            output = await self._run_cloudflared(
                build_access_token(binary, profile.hostname, proxy=profile.proxy), timeout=30
            )
        except ManagerError:
            return False
        return bool(output.strip())

    # --- Groupes ---------------------------------------------------------------------------

    def group_profiles(self, group: str) -> list[CloudflareProfile]:
        """Profils Cloudflare d'un groupe (nom comparé sans tenir compte de la casse)."""
        wanted = group.strip().lower()
        return [p for p in self.store.snapshot().cloudflare_profiles if p.group.strip().lower() == wanted]

    async def start_group(self, group: str) -> list[SessionInfo]:
        """Connecte tous les profils du groupe qui ne le sont pas déjà. Un échec n'arrête pas les autres."""
        profiles = self.group_profiles(group)
        if not profiles:
            raise ManagerError(tr("Groupe introuvable ou vide : {name}").format(name=group))
        pending = [p for p in profiles if self.active_session_for(p.id) is None]
        results = await asyncio.gather(
            *(self.start_cloudflare(p.id) for p in pending), return_exceptions=True
        )
        infos: list[SessionInfo] = []
        for profile, result in zip(pending, results, strict=True):
            if isinstance(result, SessionInfo):
                infos.append(result)
            elif isinstance(result, ManagerError):
                self.bus.publish(Notification("error", profile.name, str(result)))
            else:
                raise result
        return infos

    async def stop_group(self, group: str) -> None:
        profiles = self.group_profiles(group)
        if not profiles:
            raise ManagerError(tr("Groupe introuvable ou vide : {name}").format(name=group))
        await asyncio.gather(*(self.stop_profile(p.id) for p in profiles))

    async def ssh_config_snippet(self, profile_id: str) -> str:
        profile = self.store.snapshot().cloudflare_profile(profile_id)
        binary = self.cloudflared_path()
        if profile is None or binary is None or not profile.hostname:
            raise ManagerError(tr("Profil incomplet ou cloudflared introuvable."))
        return await self._run_cloudflared(
            build_ssh_config(binary, profile.hostname, proxy=profile.proxy), timeout=30
        )

    async def _run_cloudflared(self, spec: CommandSpec, timeout: float) -> str:
        kwargs: dict[str, Any] = {}
        if sys.platform == "win32":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        proc = await asyncio.create_subprocess_exec(
            *spec.args,
            env=dict(spec.env),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            **kwargs,
        )
        try:
            output, _ = await asyncio.wait_for(proc.communicate(), timeout)
        except TimeoutError as exc:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            raise ManagerError(tr("cloudflared n'a pas répondu à temps.")) from exc
        text = output.decode("utf-8", "replace").strip()
        if proc.returncode != 0:
            raise ManagerError(text or tr("cloudflared a échoué (code {code}).").format(code=proc.returncode))
        return text

    # --- SSH -------------------------------------------------------------------------------

    def _ssh_profile(self, profile_id: str) -> Any:
        profile = self.store.snapshot().ssh_profile(profile_id)
        if profile is None:
            raise ManagerError(tr("Profil SSH introuvable."))
        config = self.store.snapshot()
        problems = profile.readiness_problems(config.cloudflare_by_id())
        if problems:
            raise ManagerError(
                tr("Profil « {name} » incomplet : {problems}.").format(
                    name=profile.name, problems=", ".join(problems)
                )
            )
        return profile

    async def ssh_connect(self, profile_id: str) -> None:
        profile = self._ssh_profile(profile_id)
        try:
            await self.ssh.get(profile)
        except SshError as exc:
            raise ManagerError(str(exc)) from exc

    async def ssh_disconnect(self, profile_id: str) -> None:
        for session in list(self.sessions.values()):
            if session.kind == SessionKind.SSH_FORWARD and session.profile_id == profile_id:
                await self.stop(session.id)
        await self.ssh.disconnect(profile_id)

    async def discover_ports(self, profile_id: str, *, probe_web: bool = True) -> DiscoveryResult:
        profile = self._ssh_profile(profile_id)
        try:
            conn = await self.ssh.get(profile)
            return await discover(conn, probe_web=probe_web)
        except SshError as exc:
            raise ManagerError(str(exc)) from exc
        except Exception as exc:
            raise ManagerError(tr("Découverte des ports impossible : {error}").format(error=exc)) from exc

    async def start_forward(
        self, profile_id: str, forward: SavedForward, *, save: bool = False
    ) -> SessionInfo:
        profile = self._ssh_profile(profile_id)
        existing = self.active_session_for(profile.id, forward.id)
        if existing is not None:
            return existing.info()
        self._check_port_conflict(forward.local_port)
        if save and not any(f.id == forward.id for f in profile.saved_forwards):

            def add(config: Any) -> None:
                config.ssh_profile(profile_id).saved_forwards.append(forward)

            self.store.update(add)
            profile = self._ssh_profile(profile_id)
        session = SshForwardSession(bus=self.bus, profile=profile, forward=forward, connections=self.ssh)
        self._add(session)
        return session.info()

    async def start_saved_forwards(self, profile_id: str) -> list[SessionInfo]:
        profile = self._ssh_profile(profile_id)
        started: list[SessionInfo] = []
        for forward in profile.saved_forwards:
            try:
                started.append(await self.start_forward(profile_id, forward))
            except ManagerError as exc:
                self.bus.publish(Notification("error", profile.name, str(exc)))
        return started

    async def deploy_key(self, profile_id: str, key_path: str) -> DeployResult:
        """Envoie la clé publique sur le serveur, via une connexion ponctuelle par mot de passe."""
        profile = self.store.snapshot().ssh_profile(profile_id)
        if profile is None:
            raise ManagerError(tr("Profil SSH introuvable."))
        path = resolve_key_path(key_path, self.paths.keys_dir)
        try:
            line = public_key_line(path)
        except Exception as exc:
            raise ManagerError(tr("Clé publique illisible : {error}").format(error=exc)) from exc
        password_profile = profile.model_copy(update={"auth": SshAuthMode.PASSWORD})
        try:
            conn = await self.ssh.open(password_profile)
        except SshError as exc:
            raise ManagerError(str(exc)) from exc
        try:
            return await deploy_public_key(conn, line)
        except Exception as exc:
            raise ManagerError(tr("Déploiement de la clé impossible : {error}").format(error=exc)) from exc
        finally:
            conn.close()

    def _mark_password_remembered(self, profile_id: str) -> None:
        def mark(config: Any) -> None:
            profile = config.ssh_profile(profile_id)
            if profile is not None:
                profile.remember_password = True

        with contextlib.suppress(Exception):
            self.store.update(mark)

    # --- Arrêt -------------------------------------------------------------------------------

    async def stop(self, session_id: str, *, remove: bool = True) -> None:
        session = self.sessions.get(session_id)
        if session is None:
            return
        await session.stop()
        if remove:
            self.sessions.pop(session_id, None)
            self.bus.publish(SessionRemoved(session_id))

    async def restart(self, session_id: str) -> SessionInfo:
        session = self.sessions.get(session_id)
        if session is None:
            raise ManagerError(tr("Session introuvable."))
        await self.stop(session_id)
        if isinstance(session, SshForwardSession):
            return await self.start_forward(session.profile_id, session.forward)
        return await self.start_cloudflare(session.profile_id)

    async def stop_profile(self, profile_id: str) -> None:
        for session in list(self.sessions.values()):
            if session.profile_id == profile_id:
                await self.stop(session.id)

    async def stop_all(self) -> None:
        await asyncio.gather(*(self.stop(sid) for sid in list(self.sessions)), return_exceptions=True)

    async def start_auto_profiles(self) -> None:
        config = self.store.snapshot()
        for profile in config.cloudflare_profiles:
            if profile.auto_start:
                try:
                    await self.start_cloudflare(profile.id)
                except ManagerError as exc:
                    self.bus.publish(Notification("error", profile.name, str(exc)))

    async def shutdown(self) -> None:
        await self.stop_all()
        await self.ssh.close_all()
        if self.job is not None:
            self.job.close()


def local_hostname() -> str:
    return socket.gethostname()
