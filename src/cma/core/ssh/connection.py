"""Connexions SSH partagées, une par profil, réutilisées par la découverte et les redirections.

- Clé d'hôte : si elle est inconnue ou a changé, on récupère celle du serveur (sans s'authentifier),
  on montre son empreinte SHA-256, et on ne l'enregistre qu'après confirmation.
- Authentification : mot de passe (mémorisé pour la session, ou dans le coffre si demandé),
  clé (avec phrase de passe), ou agent SSH.
- Keepalive toutes les 30 s : une connexion morte est détectée et les redirections se reconnectent.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import asyncssh

from cma.core.events import EventBus, SshConnectionChanged
from cma.core.models import KnownHostsMode, Settings, SshAuthMode, SshProfile
from cma.core.prompts import PassphraseRequest, PasswordRequest, Prompter
from cma.core.secrets import SecretStore
from cma.core.ssh.errors import SshCancelled, SshError, describe_error
from cma.core.ssh.hostkeys import HostKeyPrompt, KnownHostsFile
from cma.core.ssh.keys import resolve_key_path
from cma.i18n import tr
from cma.paths import AppPaths

log = logging.getLogger(__name__)

# Profil Cloudflare → (hôte local, port local, hostname Cloudflare) une fois la session à l'écoute.
CloudflareBridge = Callable[[str], Awaitable[tuple[str, int, str]]]

MAX_PASSWORD_ATTEMPTS = 3
MAX_PASSPHRASE_ATTEMPTS = 3


class SshConnectionManager:
    def __init__(
        self,
        *,
        paths: AppPaths,
        settings: Callable[[], Settings],
        secrets: SecretStore,
        prompter: Prompter,
        bus: EventBus,
        cloudflare_bridge: CloudflareBridge | None = None,
        on_password_remembered: Callable[[str], None] | None = None,
    ) -> None:
        self._paths = paths
        self._settings = settings
        self._secrets = secrets
        self.prompter = prompter
        self._bus = bus
        self._bridge = cloudflare_bridge
        self._on_password_remembered = on_password_remembered
        self._connections: dict[str, asyncssh.SSHClientConnection] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._passwords: dict[str, str] = {}
        self._passphrases: dict[str, str] = {}

    # --- État ---------------------------------------------------------------------

    def known_hosts(self) -> KnownHostsFile:
        user_file = Path.home() / ".ssh" / "known_hosts"
        if self._settings().known_hosts == KnownHostsMode.USER:
            return KnownHostsFile(user_file)
        return KnownHostsFile(self._paths.known_hosts, extra_read_only=[user_file])

    def is_connected(self, profile_id: str) -> bool:
        conn = self._connections.get(profile_id)
        return conn is not None and not _is_closed(conn)

    def connected_profiles(self) -> list[str]:
        return [pid for pid in self._connections if self.is_connected(pid)]

    def _publish(self, profile_id: str, state: str, message: str = "") -> None:
        self._bus.publish(SshConnectionChanged(profile_id=profile_id, state=state, message=message))  # type: ignore[arg-type]

    # --- Connexion --------------------------------------------------------------------

    async def get(self, profile: SshProfile) -> asyncssh.SSHClientConnection:
        """Connexion du profil, ouverte si besoin. Une seule ouverture à la fois par profil."""
        lock = self._locks.setdefault(profile.id, asyncio.Lock())
        async with lock:
            conn = self._connections.get(profile.id)
            if conn is not None and not _is_closed(conn):
                return conn
            conn = await self.open(profile)
            self._connections[profile.id] = conn
            asyncio.get_running_loop().create_task(self._watch(profile.id, conn))
            return conn

    async def _watch(self, profile_id: str, conn: asyncssh.SSHClientConnection) -> None:
        await conn.wait_closed()
        if self._connections.get(profile_id) is conn:
            del self._connections[profile_id]
            log.info("Connexion SSH fermée (profil %s)", profile_id)
            self._publish(profile_id, "disconnected")

    async def open(self, profile: SshProfile) -> asyncssh.SSHClientConnection:
        """Ouvre une nouvelle connexion (hors cache). Lève SshError ou SshCancelled."""
        if not profile.user:
            raise SshError(tr("L'utilisateur SSH n'est pas renseigné."), fatal=True)
        host, port = profile.host, profile.port
        identity_host, identity_port, via = profile.host, profile.port, None
        if profile.via_cloudflare_profile:
            if self._bridge is None:
                raise SshError(tr("Passage par Cloudflare indisponible."), fatal=True)
            host, port, cf_hostname = await self._bridge(profile.via_cloudflare_profile)
            identity_host = profile.host or cf_hostname
            identity_port = profile.port if profile.host else 22
            via = cf_hostname
        elif not host:
            raise SshError(tr("L'hôte SSH n'est pas renseigné."), fatal=True)

        self._publish(profile.id, "connecting")
        options: dict[str, Any] = {
            "username": profile.user,
            "port": port,
            "keepalive_interval": 30,
            "keepalive_count_max": 3,
            "connect_timeout": 20,
            "login_timeout": 60,
        }
        if profile.auth == SshAuthMode.PASSWORD:
            options.update(client_keys=None, agent_path=None, preferred_auth="keyboard-interactive,password")
        elif profile.auth == SshAuthMode.KEY:
            options.update(
                client_keys=[await self._load_key(profile)], agent_path=None, preferred_auth="publickey"
            )
        else:
            options.update(preferred_auth="publickey")

        password: str | None = None
        remember = False
        password_error: str | None = None
        password_attempts = 0
        trusted_retry = False
        while True:
            if profile.auth == SshAuthMode.PASSWORD and (password is None or password_error is not None):
                password, remember = await self._password(profile, password_error)
                password_error = None
                options["password"] = password
            known = self.known_hosts()
            options["known_hosts"] = known.trusted_for(identity_host, identity_port)
            try:
                conn = await asyncssh.connect(host, **options)
            except asyncssh.HostKeyNotVerifiable:
                if trusted_retry:
                    error = SshError(
                        tr("La clé d'hôte ne correspond toujours pas après confirmation."), fatal=True
                    )
                    self._publish(profile.id, "error", str(error))
                    raise error from None
                await self._trust_host_key(host, port, identity_host, identity_port, via, known)
                trusted_retry = True
                continue
            except asyncssh.PermissionDenied as exc:
                if profile.auth == SshAuthMode.PASSWORD and password_attempts < MAX_PASSWORD_ATTEMPTS - 1:
                    password_attempts += 1
                    self._forget_password(profile)
                    password_error = tr("Mot de passe refusé, réessayez.")
                    continue
                hint = {
                    SshAuthMode.PASSWORD: tr("mot de passe refusé"),
                    SshAuthMode.KEY: tr("clé non autorisée sur le serveur ; déployez-la d'abord"),
                    SshAuthMode.AGENT: tr("aucune clé de l'agent n'est acceptée"),
                }[profile.auth]
                error = SshError(tr("Authentification refusée : {hint}.").format(hint=hint), fatal=True)
                self._publish(profile.id, "error", str(error))
                raise error from exc
            except SshCancelled:
                self._publish(profile.id, "disconnected")
                raise
            except Exception as exc:
                error = describe_error(exc, host, port)
                self._publish(profile.id, "error", str(error))
                raise error from exc
            break

        if password is not None:
            self._passwords[profile.id] = password
            if remember and self._secrets.persistent:
                self._secrets.set(profile.password_key, password)
                if self._on_password_remembered is not None:
                    self._on_password_remembered(profile.id)
        log.info("Connexion SSH établie : %s@%s:%s%s", profile.user, host, port, f" via {via}" if via else "")
        self._publish(profile.id, "connected")
        return conn

    async def _password(self, profile: SshProfile, error: str | None) -> tuple[str, bool]:
        if error is None:
            cached = self._passwords.get(profile.id)
            if cached:
                return cached, False
            if profile.remember_password:
                stored = self._secrets.get(profile.password_key)
                if stored:
                    return stored, False
        target = f"{profile.user}@{profile.host or tr('(via Cloudflare)')}:{profile.port}"
        answer = await self.prompter.ask_password(
            PasswordRequest(
                profile_name=profile.name, target=target, error=error, can_remember=self._secrets.persistent
            )
        )
        if answer is None:
            raise SshCancelled(tr("Saisie du mot de passe annulée."))
        return answer.password, answer.remember

    def _forget_password(self, profile: SshProfile) -> None:
        self._passwords.pop(profile.id, None)
        if profile.remember_password:
            with contextlib.suppress(Exception):
                self._secrets.delete(profile.password_key)

    async def _load_key(self, profile: SshProfile) -> asyncssh.SSHKey:
        if not profile.key_path:
            raise SshError(tr("Aucune clé n'est choisie pour ce profil."), fatal=True)
        path = resolve_key_path(profile.key_path, self._paths.keys_dir)
        if not path.is_file():
            raise SshError(tr("Clé introuvable : {path}").format(path=path), fatal=True)
        try:
            return asyncssh.read_private_key(str(path))
        except asyncssh.KeyImportError as exc:
            if "passphrase" not in str(exc).lower():
                raise SshError(tr("Clé illisible : {error}").format(error=exc), fatal=True) from exc
        passphrase = self._passphrases.get(str(path)) or self._secrets.get(profile.passphrase_key)
        error: str | None = None
        for _attempt in range(MAX_PASSPHRASE_ATTEMPTS):
            if not passphrase:
                passphrase = await self.prompter.ask_passphrase(
                    PassphraseRequest(key_path=str(path), error=error)
                )
                if passphrase is None:
                    raise SshCancelled(tr("Saisie de la phrase de passe annulée."))
            try:
                key = asyncssh.read_private_key(str(path), passphrase)
            except (asyncssh.KeyImportError, asyncssh.KeyEncryptionError):
                error = tr("Phrase de passe incorrecte.")
                passphrase = None
                continue
            self._passphrases[str(path)] = passphrase
            return key
        raise SshError(tr("Phrase de passe incorrecte."), fatal=True)

    async def _trust_host_key(
        self,
        host: str,
        port: int,
        identity_host: str,
        identity_port: int,
        via: str | None,
        known: KnownHostsFile,
    ) -> None:
        try:
            key = await asyncio.wait_for(asyncssh.get_server_host_key(host, port), timeout=20)
        except Exception as exc:
            raise describe_error(exc, host, port) from exc
        if key is None:
            raise SshError(tr("Le serveur n'a présenté aucune clé d'hôte."), fatal=True)
        previous = known.fingerprints_for(identity_host, identity_port)
        prompt = HostKeyPrompt(
            host=identity_host,
            port=identity_port,
            algorithm=key.get_algorithm(),
            fingerprint=key.get_fingerprint("sha256"),
            changed=bool(previous),
            previous_fingerprints=previous,
            via=via,
        )
        if not await self.prompter.confirm_host_key(prompt):
            raise SshCancelled(tr("Clé d'hôte refusée : connexion annulée."))
        known.add(identity_host, identity_port, key, replace=True)
        log.info("Clé d'hôte enregistrée pour %s : %s", prompt.identity, prompt.fingerprint)

    # --- Fermeture ------------------------------------------------------------------------

    async def disconnect(self, profile_id: str, *, forget_password: bool = True) -> None:
        conn = self._connections.pop(profile_id, None)
        if forget_password:
            self._passwords.pop(profile_id, None)
        if conn is not None:
            conn.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(conn.wait_closed(), timeout=5)
            self._publish(profile_id, "disconnected")

    async def close_all(self) -> None:
        for profile_id in list(self._connections):
            await self.disconnect(profile_id)
        self._passphrases.clear()


def _is_closed(conn: asyncssh.SSHClientConnection) -> bool:
    return conn.is_closed()
