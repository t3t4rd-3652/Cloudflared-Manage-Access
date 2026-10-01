"""Gestion du compte Cloudflare depuis CMA : relie l'API (cfapi) à la configuration et au coffre.

- Le jeton d'API reste dans le coffre ; le compte choisi est mémorisé dans les paramètres.
- Un service token créé ici arrive directement dans le coffre de CMA : son secret n'est jamais affiché.
- Les noms d'hôte publiés par les tunnels peuvent devenir des profils CMA en un clic.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field

from cma.core.cfapi import (
    API_BASE,
    TOKEN_SECRET_KEY,
    AccessApp,
    Account,
    CloudflareApi,
    CloudflareApiError,
    IngressRule,
    RemoteServiceToken,
    Tunnel,
    Zone,
    guess_service_from_ingress,
)
from cma.core.config_store import ConfigStore
from cma.core.models import (
    AuthMode,
    CloudflareProfile,
    Config,
    ServiceToken,
    ServiceType,
    guess_service_type,
    unique_name,
)
from cma.core.secrets import SecretStore
from cma.i18n import tr

_SCHEME_TYPES = {
    "ssh": ServiceType.SSH,
    "rdp": ServiceType.RDP,
    "smb": ServiceType.SMB,
    "http": ServiceType.HTTP,
    "https": ServiceType.HTTPS,
}


@dataclass(frozen=True)
class TunnelView:
    tunnel: Tunnel
    hostnames: list[IngressRule]


@dataclass(frozen=True)
class Overview:
    account: Account
    tunnels: list[TunnelView] = field(default_factory=list[TunnelView])
    apps: list[AccessApp] = field(default_factory=list[AccessApp])
    tokens: list[RemoteServiceToken] = field(default_factory=list[RemoteServiceToken])
    zones: list[Zone] = field(default_factory=list[Zone])


@dataclass(frozen=True)
class PublishRequest:
    tunnel: Tunnel
    hostname: str
    service: str
    protect: bool = True
    token_id: str | None = None
    create_profile: bool = True


@dataclass(frozen=True)
class PublishStep:
    """Résultat d'une étape de la publication : « hostname », « access », « token » ou « profile »."""

    name: str
    ok: bool
    detail: str = ""


@dataclass(frozen=True)
class PublishResult:
    rule: IngressRule
    app: AccessApp | None
    profile: CloudflareProfile | None
    steps: tuple[PublishStep, ...] = ()

    @property
    def complete(self) -> bool:
        return all(step.ok for step in self.steps)


class CloudflareAdmin:
    def __init__(
        self,
        store: ConfigStore,
        secrets: SecretStore,
        suggest_port: Callable[[int | None, set[int]], int | None],
        *,
        base_url: str = API_BASE,
    ) -> None:
        self.store = store
        self.secrets = secrets
        self.suggest_port = suggest_port
        self.base_url = base_url

    # --- Jeton et compte ----------------------------------------------------------------------------

    def has_token(self) -> bool:
        return bool(self.secrets.get(TOKEN_SECRET_KEY))

    def api(self, token: str | None = None) -> CloudflareApi:
        value = token if token is not None else self.secrets.get(TOKEN_SECRET_KEY)
        if not value:
            raise CloudflareApiError(tr("Aucun jeton d'API Cloudflare : connectez-vous d'abord."))
        return CloudflareApi(value, base_url=self.base_url)

    async def connect(self, token: str | None = None) -> list[Account]:
        """Vérifie le jeton (en listant les comptes) puis, s'il est nouveau, le range dans le coffre."""
        api = self.api(token)
        accounts = await asyncio.to_thread(api.list_accounts)
        if not accounts:
            raise CloudflareApiError(tr("Ce jeton ne donne accès à aucun compte Cloudflare."))
        if token is not None:
            self.secrets.set(TOKEN_SECRET_KEY, token.strip())
        current = self.store.snapshot().settings.cloudflare_account_id
        if current not in {a.id for a in accounts}:
            self.select_account(accounts[0].id)
        return accounts

    def forget(self) -> None:
        self.secrets.delete(TOKEN_SECRET_KEY)
        self.store.update(lambda c: setattr(c.settings, "cloudflare_account_id", None))

    def account_id(self) -> str:
        value = self.store.snapshot().settings.cloudflare_account_id
        if not value:
            raise CloudflareApiError(tr("Aucun compte Cloudflare sélectionné."))
        return value

    def select_account(self, account_id: str) -> None:
        self.store.update(lambda c: setattr(c.settings, "cloudflare_account_id", account_id))

    # --- Lecture ----------------------------------------------------------------------------------------

    async def overview(self, account: Account) -> Overview:
        api = self.api()

        def load() -> Overview:
            tunnels = [
                TunnelView(t, api.tunnel_hostnames(account.id, t.id)) for t in api.list_tunnels(account.id)
            ]
            return Overview(
                account=account,
                tunnels=tunnels,
                apps=api.list_access_apps(account.id),
                tokens=api.list_service_tokens(account.id),
                zones=api.list_zones(account.id),
            )

        return await asyncio.to_thread(load)

    # --- Profils ----------------------------------------------------------------------------------------

    def _profile_for(
        self, config: Config, rule: IngressRule, group: str, used: set[int]
    ) -> CloudflareProfile:
        scheme, port = guess_service_from_ingress(rule.service)
        service = _SCHEME_TYPES.get(scheme) or guess_service_type(hostname=rule.hostname, port=port)
        preferred = port if port is not None and port >= 1024 else None
        local_port = self.suggest_port(preferred, used)
        if local_port is not None:
            used.add(local_port)
        name = unique_name(
            rule.hostname.split(".")[0] or rule.hostname, {p.name for p in config.cloudflare_profiles}
        )
        return CloudflareProfile(
            name=name,
            group=group,
            hostname=rule.hostname,
            local_port=local_port,
            service_type=service,
            notes=tr("Importé depuis le tunnel {tunnel} ({service}).").format(
                tunnel=group, service=rule.service
            ),
        )

    def import_profiles(
        self, items: list[tuple[Tunnel, IngressRule]], *, token_id: str | None = None
    ) -> list[CloudflareProfile]:
        """Crée un profil par nom d'hôte absent de CMA, en une seule écriture. Les noms connus sont ignorés.

        Avec `token_id`, les profils créés s'authentifient directement par ce service token.
        """
        config = self.store.snapshot()
        known = {p.hostname for p in config.cloudflare_profiles}
        used = {p.local_port for p in config.cloudflare_profiles if p.local_port is not None}
        created: list[CloudflareProfile] = []
        for tunnel, rule in items:
            if rule.hostname in known:
                continue
            known.add(rule.hostname)
            profile = self._profile_for(config, rule, tunnel.name, used)
            if token_id is not None:
                profile = profile.model_copy(update={"auth": AuthMode.SERVICE_TOKEN, "token_id": token_id})
            config.cloudflare_profiles.append(profile)  # pour l'unicité des noms suivants
            created.append(profile)
        if created:
            self.store.update(lambda c: c.cloudflare_profiles.extend(created))
        return created

    # --- Service tokens ---------------------------------------------------------------------------------

    async def create_service_token(self, name: str, *, duration: str = "8760h") -> ServiceToken:
        """Crée le token chez Cloudflare et le range aussitôt dans CMA (secret dans le coffre)."""
        api = self.api()
        account = self.account_id()
        created = await asyncio.to_thread(api.create_service_token, account, name, duration=duration)
        names = {t.name for t in self.store.snapshot().tokens}
        token = ServiceToken(
            name=unique_name(created.name, names),
            client_id=created.client_id,
            notes=tr("Créé depuis CMA (id Cloudflare {id}).").format(id=created.id),
        )
        self.secrets.set(token.secret_key, created.client_secret)
        self.store.update(lambda c: c.tokens.append(token))
        return token

    async def allow_token(self, app: AccessApp, token_id: str) -> str:
        """Autorise un service token de CMA sur une application Access (règle « Service Auth »)."""
        token = self.store.snapshot().token(token_id)
        if token is None:
            raise CloudflareApiError(tr("Service token introuvable."))
        api = self.api()
        account = self.account_id()

        def run() -> str:
            remote = next(
                (t for t in api.list_service_tokens(account) if t.client_id == token.client_id), None
            )
            if remote is None:
                raise CloudflareApiError(
                    tr("Le token « {name} » n'existe pas dans ce compte Cloudflare.").format(name=token.name)
                )
            return api.allow_service_token(account, app.id, remote.id, f"CMA - {token.name}")

        return await asyncio.to_thread(run)

    async def protect_hostname(self, hostname: str) -> AccessApp:
        """Application Access « self-hosted » pour ce nom d'hôte ; l'existante est réutilisée."""
        api = self.api()
        account = self.account_id()
        existing = await asyncio.to_thread(api.list_access_apps, account)
        app = next((a for a in existing if a.domain.split("/")[0] == hostname), None)
        if app is None:
            app = await asyncio.to_thread(api.create_access_app, account, hostname, hostname)
        return app

    # --- Publication ----------------------------------------------------------------------------------

    async def publish(
        self, request: PublishRequest, progress: Callable[[str], None] | None = None
    ) -> PublishResult:
        """Publie `hostname → service` sur le tunnel, le protège par Access et crée le profil CMA.

        Si la publication du nom d'hôte échoue, rien n'est créé et l'erreur remonte. Après elle, chaque étape est
        tentée et son résultat rapporté : un échec d'Access n'efface pas un nom d'hôte déjà publié.
        """

        def report(text: str) -> None:
            if progress is not None:
                progress(text)

        api = self.api()
        account = self.account_id()
        report(tr("Publication du nom d'hôte…"))
        rule = await asyncio.to_thread(
            api.publish_hostname, account, request.tunnel, request.hostname, request.service
        )
        steps = [PublishStep("hostname", True)]
        app: AccessApp | None = None
        if request.protect:
            report(tr("Configuration d'Access…"))
            try:
                app = await self.protect_hostname(rule.hostname)
                steps.append(PublishStep("access", True))
            except Exception as exc:
                steps.append(PublishStep("access", False, str(exc)))
            if request.token_id:
                if app is None:
                    steps.append(PublishStep("token", False, tr("Application Access absente.")))
                else:
                    try:
                        await self.allow_token(app, request.token_id)
                        steps.append(PublishStep("token", True))
                    except Exception as exc:
                        steps.append(PublishStep("token", False, str(exc)))
        profile: CloudflareProfile | None = None
        if request.create_profile:
            report(tr("Création du profil CMA…"))
            try:
                token_id = request.token_id if request.protect else None
                created = self.import_profiles([(request.tunnel, rule)], token_id=token_id)
                profile = created[0] if created else None
                steps.append(PublishStep("profile", True))
            except Exception as exc:
                steps.append(PublishStep("profile", False, str(exc)))
        return PublishResult(rule, app, profile, tuple(steps))

    async def unpublish(self, tunnel: Tunnel, hostname: str) -> None:
        api = self.api()
        await asyncio.to_thread(api.unpublish_hostname, self.account_id(), tunnel, hostname)
