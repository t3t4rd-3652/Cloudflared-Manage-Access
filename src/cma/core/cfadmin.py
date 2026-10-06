"""Gestion du compte Cloudflare depuis CMA : relie l'API (cfapi) à la configuration et au coffre.

- Le jeton d'API reste dans le coffre ; le compte choisi est mémorisé dans les paramètres.
- Un service token créé ici arrive directement dans le coffre de CMA : son secret n'est jamais affiché.
- Les noms d'hôte publiés par les tunnels peuvent devenir des profils CMA en un clic.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from cma.core.cfapi import (
    API_BASE,
    TOKEN_SECRET_KEY,
    AccessApp,
    Account,
    CloudflareApi,
    CloudflareApiError,
    Connector,
    IngressRule,
    RemoteServiceToken,
    Tunnel,
    Zone,
    guess_service_from_ingress,
)
from cma.core.config_store import ConfigStore
from cma.core.expiry import parse_expiry
from cma.core.models import (
    AuthMode,
    CloudflareProfile,
    Config,
    ServiceToken,
    ServiceType,
    guess_service_type,
    unique_name,
)
from cma.core.policies import AccessGroup, AccessPolicy
from cma.core.redact import register_secret
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
class NewTunnel:
    tunnel: Tunnel
    token: str  # secret : sert seulement à installer le connecteur, CMA ne le conserve pas

    def __repr__(self) -> str:  # le jeton ne doit jamais apparaître dans un journal
        return f"NewTunnel(tunnel={self.tunnel!r})"


def connector_commands(token: str) -> list[tuple[str, str]]:
    """Commandes d'installation du connecteur sur le serveur, par système : (libellé, commande)."""
    return [
        (tr("Linux (service systemd)"), f"sudo cloudflared service install {token}"),
        (tr("Windows (PowerShell administrateur)"), f"cloudflared.exe service install {token}"),
        (
            tr("Docker"),
            "docker run -d --restart unless-stopped --name cloudflared cloudflare/cloudflared:latest "
            f"tunnel --no-autoupdate run --token {token}",
        ),
    ]


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
            # Sans « Account Settings : Read », /accounts est vide alors que le reste du compte est lisible :
            # le compte se retrouve par ses zones (si le jeton a « Zone : Read »).
            try:
                accounts = await asyncio.to_thread(api.accounts_from_zones)
            except CloudflareApiError:
                accounts = []
        if not accounts:
            raise CloudflareApiError(
                tr(
                    "Ce jeton ne donne accès à aucun compte Cloudflare. Vérifiez qu'il a la permission "
                    "« Account Settings : Read »."
                )
            )
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

        overview = await asyncio.to_thread(load)
        self.sync_expirations(overview.tokens)
        return overview

    async def create_tunnel(self, name: str) -> NewTunnel:
        """Crée le tunnel puis lit le jeton de son connecteur (masqué dans les journaux dès sa réception)."""
        api = self.api()
        account = self.account_id()

        def run() -> NewTunnel:
            tunnel = api.create_tunnel(account, name)
            token = api.tunnel_token(account, tunnel.id)
            register_secret(token)
            return NewTunnel(tunnel, token)

        return await asyncio.to_thread(run)

    async def connectors(self, tunnel: Tunnel) -> list[Connector]:
        api = self.api()
        return await asyncio.to_thread(api.tunnel_connectors, self.account_id(), tunnel.id)

    def sync_expirations(self, remote: list[RemoteServiceToken]) -> int:
        """Recopie l'échéance des tokens du compte sur les tokens de CMA (même `client_id`). Renvoie le nombre de
        tokens modifiés ; la configuration n'est écrite que si quelque chose change."""
        known = {t.client_id: parse_expiry(t.expires_at) for t in remote}
        changes = {
            token.id: known[token.client_id]
            for token in self.store.snapshot().tokens
            if token.client_id in known and known[token.client_id] != token.expires_at
        }
        if changes:

            def apply(config: Config) -> None:
                for token in config.tokens:
                    if token.id in changes:
                        token.expires_at = changes[token.id]

            self.store.update(apply)
        return len(changes)

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
            expires_at=parse_expiry(created.expires_at),
            notes=tr("Créé depuis CMA (id Cloudflare {id}).").format(id=created.id),
        )
        self.secrets.set(token.secret_key, created.client_secret)
        self.store.update(lambda c: c.tokens.append(token))
        return token

    def _local_token(self, token_id: str) -> ServiceToken:
        token = self.store.snapshot().token(token_id)
        if token is None:
            raise CloudflareApiError(tr("Service token introuvable."))
        return token

    @staticmethod
    def _remote_token(api: CloudflareApi, account: str, token: ServiceToken) -> RemoteServiceToken:
        """Le token du compte Cloudflare qui correspond à un token de CMA (même `client_id`)."""
        remote = next((t for t in api.list_service_tokens(account) if t.client_id == token.client_id), None)
        if remote is None:
            raise CloudflareApiError(
                tr("Le token « {name} » n'existe pas dans ce compte Cloudflare.").format(name=token.name)
            )
        return remote

    async def allow_token(self, app: AccessApp, token_id: str) -> str:
        """Autorise un service token de CMA sur une application Access (règle « Service Auth »)."""
        token = self._local_token(token_id)
        api = self.api()
        account = self.account_id()

        def run() -> str:
            remote = self._remote_token(api, account, token)
            return api.allow_service_token(account, app.id, remote.id, f"CMA - {token.name}")

        return await asyncio.to_thread(run)

    async def extend_token(self, remote: RemoteServiceToken) -> str:
        """Repousse l'échéance d'un token du compte (même secret). Le token de CMA lié suit. Renvoie l'échéance."""
        api = self.api()
        expires_at = await asyncio.to_thread(api.refresh_service_token, self.account_id(), remote.id)
        self.sync_expirations([RemoteServiceToken(remote.id, remote.name, remote.client_id, expires_at)])
        return expires_at

    async def rotate_token(self, token_id: str) -> ServiceToken:
        """Nouveau secret pour un token de CMA, rangé aussitôt dans le coffre : le `client_id` ne change pas, les
        profils qui l'utilisent n'ont rien à modifier. L'ancien secret est révoqué par Cloudflare."""
        token = self._local_token(token_id)
        api = self.api()
        account = self.account_id()

        def run() -> str:
            remote = self._remote_token(api, account, token)
            return api.rotate_service_token(account, remote.id).client_secret

        secret = await asyncio.to_thread(run)
        self.secrets.set(token.secret_key, secret)
        return token

    # --- Politiques Access ----------------------------------------------------------------------------------

    async def policies(self, app: AccessApp) -> tuple[list[AccessPolicy], list[AccessGroup]]:
        """Politiques de l'application et groupes Access du compte (pour la saisie « groupe : Nom »).

        Sans la permission de lire les groupes, la liste des groupes est simplement vide."""
        api = self.api()
        account = self.account_id()

        def load() -> tuple[list[AccessPolicy], list[AccessGroup]]:
            policies = api.list_policies(account, app.id)
            shared = {p.id: p.app_count for p in api.list_account_policies(account)}
            policies = [replace(p, app_count=shared.get(p.id)) if p.reusable else p for p in policies]
            try:
                groups = api.list_access_groups(account)
            except CloudflareApiError:
                groups = []
            return policies, groups

        return await asyncio.to_thread(load)

    async def groups(self) -> list[AccessGroup]:
        """Groupes Access du compte ; vide sans la permission (facultative) de les lire."""
        api = self.api()
        try:
            return await asyncio.to_thread(api.list_access_groups, self.account_id())
        except CloudflareApiError:
            return []

    async def account_policies(self) -> list[AccessPolicy]:
        """Politiques réutilisables du compte, avec leur nombre d'applications."""
        api = self.api()
        return await asyncio.to_thread(api.list_account_policies, self.account_id())

    async def save_policy(self, app: AccessApp | None, policy: AccessPolicy) -> AccessPolicy:
        """Nouvelle politique (sans id) : créée dans le compte, puis attachée à `app` s'il y en a une.
        Politique existante : modifiée là où elle vit (dans le compte si elle est réutilisable)."""
        api = self.api()
        account = self.account_id()

        def run() -> AccessPolicy:
            if policy.id:
                return api.update_policy(account, app.id if app else "", policy)
            if app is not None:
                api.app_for_update(
                    account, app.id
                )  # avant de créer : pas de politique orpheline en cas de refus
            created = api.create_account_policy(account, policy)
            if app is not None:
                api.attach_policy(account, app.id, created.id)
            return created

        return await asyncio.to_thread(run)

    async def attach_policy(self, app: AccessApp, policy: AccessPolicy) -> None:
        api = self.api()
        await asyncio.to_thread(api.attach_policy, self.account_id(), app.id, policy.id)

    async def remove_policy(self, app: AccessApp, policy: AccessPolicy) -> None:
        """Retire la politique de l'application. Réutilisable : elle reste dans le compte. Legacy : supprimée."""
        api = self.api()
        account = self.account_id()
        if policy.reusable:
            await asyncio.to_thread(api.detach_policy, account, app.id, policy.id)
        else:
            await asyncio.to_thread(api.delete_legacy_policy, account, app.id, policy.id)

    async def delete_account_policy(self, policy: AccessPolicy) -> None:
        """Supprime une politique réutilisable que plus aucune application n'utilise."""
        if policy.app_count:
            raise CloudflareApiError(
                tr("« {name} » sert encore à {n} application(s) : retirez-la d'abord de chacune.").format(
                    name=policy.name, n=policy.app_count
                )
            )
        api = self.api()
        await asyncio.to_thread(api.delete_account_policy, self.account_id(), policy.id)

    # --- Ménage --------------------------------------------------------------------------------------------

    async def rename_tunnel(self, tunnel: Tunnel, name: str) -> Tunnel:
        api = self.api()
        return await asyncio.to_thread(api.rename_tunnel, self.account_id(), tunnel, name)

    async def delete_tunnel(self, tunnel: Tunnel, hostnames: list[str]) -> int:
        """Supprime un tunnel arrêté et les enregistrements DNS de ses noms d'hôte qui le visent encore.
        Renvoie le nombre d'enregistrements DNS supprimés. Refusé tant qu'un connecteur est actif."""
        api = self.api()
        account = self.account_id()

        def run() -> int:
            active = api.tunnel_connectors(account, tunnel.id)
            if active:
                raise CloudflareApiError(
                    tr(
                        "Le tunnel {name} a encore {n} connecteur(s) actif(s) : arrêtez ou désinstallez cloudflared "
                        "sur le serveur, puis recommencez."
                    ).format(name=tunnel.name, n=len(active))
                )
            removed = sum(1 for hostname in hostnames if api.delete_tunnel_cname(account, tunnel, hostname))
            api.delete_tunnel(account, tunnel.id)
            return removed

        return await asyncio.to_thread(run)

    async def delete_app(self, app: AccessApp) -> None:
        api = self.api()
        await asyncio.to_thread(api.delete_access_app, self.account_id(), app.id)

    async def delete_remote_token(self, remote: RemoteServiceToken) -> None:
        """Révoque le token chez Cloudflare. Sa copie dans CMA, si elle existe, reste à supprimer à part."""
        api = self.api()
        await asyncio.to_thread(api.delete_service_token, self.account_id(), remote.id)

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

    async def edit_hostname(
        self, tunnel: Tunnel, hostname: str, service: str, origin: dict[str, Any] | None = None
    ) -> IngressRule:
        """Change le service publié pour `hostname` et, si `origin` est donné, ses options d'origine. Le profil
        CMA lié suit si le type de service change (ssh:// → rdp://…) ; son port local est gardé."""
        api = self.api()
        rule = await asyncio.to_thread(
            api.update_hostname_service, self.account_id(), tunnel, hostname, service, origin
        )
        scheme, _port = guess_service_from_ingress(service)
        kind = _SCHEME_TYPES.get(scheme)
        if kind is not None:

            def apply(config: Config) -> None:
                for profile in config.cloudflare_profiles:
                    if profile.hostname == hostname and profile.service_type != kind:
                        profile.service_type = kind

            if any(
                p.hostname == hostname and p.service_type != kind
                for p in self.store.snapshot().cloudflare_profiles
            ):
                self.store.update(apply)
        return rule

    async def unpublish(self, tunnel: Tunnel, hostname: str) -> None:
        api = self.api()
        await asyncio.to_thread(api.unpublish_hostname, self.account_id(), tunnel, hostname)
