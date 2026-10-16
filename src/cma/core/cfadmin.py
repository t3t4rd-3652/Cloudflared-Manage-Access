"""Gestion du compte Cloudflare depuis CMA : relie l'API (cfapi) à la configuration et au coffre.

- Le jeton d'API reste dans le coffre ; le compte choisi est mémorisé dans les paramètres.
- Un service token créé ici arrive directement dans le coffre de CMA : son secret n'est jamais affiché.
- Les noms d'hôte publiés par les tunnels peuvent devenir des profils CMA en un clic.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from cma.core.audit import AuditEntry, account_audit
from cma.core.cfapi import (
    API_BASE,
    TOKEN_SECRET_KEY,
    AccessApp,
    AccessRequest,
    Account,
    AppSettings,
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
from cma.core.dnscheck import DnsCheck, check_all, zone_of
from cma.core.expiry import parse_expiry
from cma.core.hostprobe import HostProbe
from cma.core.models import (
    ApiToken,
    AuthMode,
    CloudflareProfile,
    Config,
    ServiceToken,
    ServiceType,
    guess_service_type,
    unique_name,
)
from cma.core.permissions import PermissionCheck, check_permissions
from cma.core.policies import AccessGroup, AccessPolicy, PolicyRule
from cma.core.privnet import (
    PrivateRoute,
    VirtualNetwork,
    create_route,
    delete_route,
    list_routes,
    list_virtual_networks,
    set_warp_routing,
    warp_routing,
)
from cma.core.redact import register_secret
from cma.core.secrets import SecretStore
from cma.core.security import AccountData, Finding, covering_app, review
from cma.core.servicewatch import ServiceTarget, probe_targets, probe_token, targets_of
from cma.core.snapshot import take_snapshot
from cma.core.traffic import HostTraffic, zone_traffic
from cma.core.tunnelwatch import with_account
from cma.i18n import tr

log = logging.getLogger(__name__)

# Appels simultanés pour lire un compte : assez pour un compte ordinaire, sans assaillir l'API.
OVERVIEW_WORKERS = 8
# Le jeton d'avant les jetons nommés : il garde sa clé du coffre (`cfapi:token`), aucune migration de secret.
LEGACY_TOKEN_ID = "principal"  # noqa: S105 (identifiant, pas un secret)


def token_secret_key(token_id: str) -> str:
    return TOKEN_SECRET_KEY if token_id == LEGACY_TOKEN_ID else f"{TOKEN_SECRET_KEY}:{token_id}"


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
    hostnames: list[IngressRule]  # règles nommées, dans l'ordre où cloudflared les essaie
    catch_all: str = "http_status:404"  # service de la règle finale


@dataclass(frozen=True)
class Overview:
    account: Account
    tunnels: list[TunnelView] = field(default_factory=list[TunnelView])
    apps: list[AccessApp] = field(default_factory=list[AccessApp])
    tokens: list[RemoteServiceToken] = field(default_factory=list[RemoteServiceToken])
    zones: list[Zone] = field(default_factory=list[Zone])
    # État du DNS de chaque nom d'hôte publié (clé : nom d'hôte en minuscules).
    dns: dict[str, DnsCheck] = field(default_factory=dict[str, DnsCheck])
    # Routes de réseau privé de tous les tunnels (vide si illisible).
    routes: list[PrivateRoute] = field(default_factory=list[PrivateRoute])
    # Trafic des 24 dernières heures par nom d'hôte (en minuscules) ; `traffic_note` dit pourquoi il manque.
    traffic: dict[str, HostTraffic] = field(default_factory=dict[str, HostTraffic])
    traffic_note: str = ""


@dataclass(frozen=True)
class PrivateNetwork:
    """Réseaux privés d'un tunnel : ses routes, les réseaux virtuels du compte et l'état du routage WARP."""

    routes: list[PrivateRoute]
    virtual_networks: list[VirtualNetwork]
    warp_routing: bool


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


@dataclass(frozen=True)
class WatchedAccount:
    """Un compte relevé par la surveillance de tous les comptes (ADR 0003) : le jeton qui le lit, et le nom affiché
    (celui du compte chez Cloudflare, à défaut celui du jeton)."""

    token_id: str
    token_name: str
    account_id: str
    name: str


@dataclass(frozen=True)
class WatchFailure:
    """Un jeton dont le relevé a échoué (refusé, absent du coffre, réseau) : journalisé, sans arrêter les autres."""

    token_name: str
    account_id: str | None
    error: str


@dataclass(frozen=True)
class WatchFallback:
    """Repli (ADR 0003, P38) : le compte `account_id` a été relevé par le jeton `used`, parce que `token_name`, avant lui
    dans l'ordre, a été refusé (401, 403) ou n'est plus dans le coffre (`error`). Journalisé et porté par le relevé : un
    jeton en lecture seule refusé ne fait jamais lire le compte par un jeton qui sait écrire sans le dire."""

    token_name: str
    account_id: str
    error: str
    used: str


# Refus du jeton lui-même (authentification ou permission) : seuls ces statuts font essayer le jeton suivant.
REFUSED_STATUSES = (401, 403)

# Replis d'un relevé d'un seul compte : `tunnel_states` et `check_services` gardent leur forme (l'interface et ses tests
# les appellent ou les remplacent tels quels) ; `watch_tunnels` et `watch_services` recueillent ici leurs replis.
_fallbacks_seen: ContextVar[list[WatchFallback] | None] = ContextVar("cma_watch_fallbacks", default=None)


def token_refused(error: BaseException) -> bool:
    """Le jeton est refusé (401, 403) : un autre jeton qui voit le même compte peut le relever. Une erreur du réseau ou
    de Cloudflare (5xx, réponse sans succès) n'est pas un refus : changer de jeton n'y changerait rien."""
    return isinstance(error, CloudflareApiError) and error.status in REFUSED_STATUSES


class _Unread(Exception):
    """Aucun jeton n'a lu le compte : chaque jeton essayé (`failures`) et la première erreur rencontrée."""

    def __init__(self, failures: list[WatchFailure], error: BaseException | None) -> None:
        super().__init__("; ".join(f"{f.token_name} : {f.error}" for f in failures))
        self.failures = failures
        self.error = error


def _report_fallbacks(fallbacks: list[WatchFallback]) -> None:
    """Un repli n'est jamais silencieux : il est journalisé (nom du jeton, jamais son secret) et, pendant un relevé d'un
    seul compte, recueilli pour être porté par le relevé."""
    for fallback in fallbacks:
        log.warning(
            "Surveillance : jeton « %s » écarté (%s) ; compte %s relevé avec le jeton « %s »",
            fallback.token_name,
            fallback.error,
            fallback.account_id,
            fallback.used,
        )
    seen = _fallbacks_seen.get()
    if seen is not None:
        seen.extend(fallbacks)


async def _collecting[T](read: Awaitable[T]) -> tuple[T, list[WatchFallback]]:
    """Attend un relevé d'un seul compte en recueillant ses replis, notés par `_single_read` dans la même tâche : deux
    relevés en même temps (tunnels et services) ont chacun leur contexte, donc leur liste."""
    fallbacks: list[WatchFallback] = []
    mark = _fallbacks_seen.set(fallbacks)
    try:
        return await read, fallbacks
    finally:
        _fallbacks_seen.reset(mark)


@dataclass(frozen=True)
class TunnelSweep:
    """Relevé des tunnels de la surveillance, d'un compte ou de plusieurs. Dès que deux comptes sont surveillés, le nom
    de chaque tunnel est suivi de celui de son compte : notifications, alertes, journal de disponibilité et pannes
    affichées le reprennent tel quel."""

    tunnels: list[Tunnel]
    failures: list[WatchFailure] = field(default_factory=list[WatchFailure])
    # Surveillance de tous les comptes : compte de chaque tunnel et nom d'origine (sans le compte), par identifiant.
    accounts: dict[str, WatchedAccount] = field(default_factory=dict[str, WatchedAccount])
    names: dict[str, str] = field(default_factory=dict[str, str])
    # Comptes relevés par un autre jeton que le premier de leur ordre (repli) : lus, donc pas des échecs.
    fallbacks: list[WatchFallback] = field(default_factory=list[WatchFallback])

    @property
    def complete(self) -> bool:
        """Chaque compte a été lu : un tunnel absent du relevé a vraiment disparu."""
        return not self.failures


@dataclass(frozen=True)
class ServiceSweep:
    """Relevé des services publiés de la surveillance ; chaque cible porte son compte (tous les comptes)."""

    results: list[tuple[ServiceTarget, HostProbe]]
    failures: list[WatchFailure] = field(default_factory=list[WatchFailure])
    fallbacks: list[WatchFallback] = field(default_factory=list[WatchFallback])

    @property
    def complete(self) -> bool:
        return not self.failures


def _distinct_names[T](found: list[tuple[WatchedAccount, T]]) -> list[tuple[WatchedAccount, T]]:
    """Deux comptes du même nom (« Mon compte ») : chacun prend le nom de son jeton, unique par construction."""
    counts = Counter(watched.name for watched, _value in found)
    return [
        (replace(watched, name=watched.token_name) if counts[watched.name] > 1 else watched, value)
        for watched, value in found
    ]


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
        # Noms des comptes vus (identifiant → nom), pour les nommer quand la surveillance en relève plusieurs ; et les
        # jetons dont la liste des comptes a déjà été demandée (une fois par jeton, même sans réponse utile).
        self._account_names: dict[str, str] = {}
        self._names_tried: set[str] = set()

    # --- Jeton et compte ----------------------------------------------------------------------------

    def tokens(self) -> list[ApiToken]:
        """Jetons enregistrés ; un jeton d'avant les jetons nommés apparaît sous le nom « Principal »."""
        settings = self.store.snapshot().settings
        if settings.cloudflare_tokens:
            return list(settings.cloudflare_tokens)
        if self.secrets.get(TOKEN_SECRET_KEY):
            return [
                ApiToken(id=LEGACY_TOKEN_ID, name=tr("Principal"), account_id=settings.cloudflare_account_id)
            ]
        return []

    def active_token(self) -> ApiToken | None:
        tokens = self.tokens()
        chosen = self.store.snapshot().settings.cloudflare_token_id
        return next((t for t in tokens if t.id == chosen), tokens[0] if tokens else None)

    def _active_key(self) -> str | None:
        active = self.active_token()
        return token_secret_key(active.id) if active is not None else None

    def has_token(self) -> bool:
        key = self._active_key()
        return bool(key and self.secrets.get(key))

    def watch_api(self) -> CloudflareApi:
        """API de la surveillance : le jeton choisi pour elle s'il est encore là, sinon le jeton actif. Un jeton en
        lecture seule suffit : la surveillance ne fait que lire."""
        chosen = self.store.snapshot().settings.watch_token_id
        if chosen and any(t.id == chosen for t in self.tokens()):
            value = self.secrets.get(token_secret_key(chosen))
            if value:
                return CloudflareApi(value, base_url=self.base_url)
        return self.api()

    def api(self, token: str | None = None) -> CloudflareApi:
        key = self._active_key()
        value = token if token is not None else (self.secrets.get(key) if key else None)
        if not value:
            raise CloudflareApiError(tr("Aucun jeton d'API Cloudflare : connectez-vous d'abord."))
        return CloudflareApi(value, base_url=self.base_url)

    async def connect(self, token: str | None = None, name: str = "") -> list[Account]:
        """Vérifie le jeton (en listant les comptes) puis, s'il est nouveau, le range dans le coffre comme un jeton
        nommé de plus (`name`, sinon le nom du premier compte), qui devient le jeton actif."""
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
        self._account_names.update({a.id: a.name for a in accounts})
        if token is not None:
            self._add_token(token.strip(), name.strip() or accounts[0].name)
        current = self.store.snapshot().settings.cloudflare_account_id
        if current not in {a.id for a in accounts}:
            self.select_account(accounts[0].id)
        return accounts

    def _add_token(self, value: str, name: str) -> None:
        existing = self.tokens()  # avec le jeton d'avant, gardé sous son ancienne clé
        # Le premier jeton prend l'ancienne clé : un seul jeton, c'est exactement le rangement d'avant.
        first = not existing
        new = ApiToken(name=unique_name(name, [t.name for t in existing]))
        if first:
            new = ApiToken(id=LEGACY_TOKEN_ID, name=new.name)
        self.secrets.set(token_secret_key(new.id), value)

        def apply(config: Config) -> None:
            config.settings.cloudflare_tokens = [*existing, new]
            config.settings.cloudflare_token_id = new.id
            config.settings.cloudflare_account_id = None

        self.store.update(apply)

    def switch_token(self, token_id: str) -> None:
        """Change de jeton actif et revient au dernier compte choisi avec lui."""
        tokens = self.tokens()
        chosen = next((t for t in tokens if t.id == token_id), None)
        if chosen is None:
            raise CloudflareApiError(tr("Jeton d'API introuvable."))

        def apply(config: Config) -> None:
            config.settings.cloudflare_tokens = tokens
            config.settings.cloudflare_token_id = chosen.id
            config.settings.cloudflare_account_id = chosen.account_id

        self.store.update(apply)

    def forget(self) -> None:
        """Retire le jeton actif du coffre ; le suivant (s'il y en a) devient actif."""
        active = self.active_token()
        if active is None:
            return
        self.secrets.delete(token_secret_key(active.id))
        remaining = [t for t in self.tokens() if t.id != active.id]

        def apply(config: Config) -> None:
            config.settings.cloudflare_tokens = remaining
            config.settings.cloudflare_token_id = remaining[0].id if remaining else None
            config.settings.cloudflare_account_id = remaining[0].account_id if remaining else None

        self.store.update(apply)

    def account_id(self) -> str:
        value = self.store.snapshot().settings.cloudflare_account_id
        if not value:
            raise CloudflareApiError(tr("Aucun compte Cloudflare sélectionné."))
        return value

    def select_account(self, account_id: str) -> None:
        active = self.active_token()

        def apply(config: Config) -> None:
            config.settings.cloudflare_account_id = account_id
            for token in config.settings.cloudflare_tokens:
                if active is not None and token.id == active.id:
                    token.account_id = account_id

        self.store.update(apply)

    # --- Lecture ----------------------------------------------------------------------------------------

    async def overview(self, account: Account) -> Overview:
        """Tout le compte en une lecture. Les appels indépendants partent en même temps : Cloudflare met 0,3 à 1 s
        à répondre à chacun, et en série la lecture d'un compte ordinaire prenait 7 à 10 s."""
        api = self.api()

        def load() -> Overview:
            with ThreadPoolExecutor(max_workers=OVERVIEW_WORKERS, thread_name_prefix="cma-cf") as pool:
                tunnels_call = pool.submit(api.list_tunnels, account.id)
                apps_call = pool.submit(api.list_access_apps, account.id)
                tokens_call = pool.submit(api.list_service_tokens, account.id)
                zones_call = pool.submit(api.list_zones, account.id)
                routes_call = pool.submit(self._optional, lambda: list_routes(api, account.id), [])
                listed = tunnels_call.result()
                ingress = [pool.submit(api.tunnel_ingress, account.id, t.id) for t in listed]
                tunnels = [TunnelView(t, *call.result()) for t, call in zip(listed, ingress, strict=True)]
                zones = zones_call.result()
                traffic_call = pool.submit(self._traffic, api, tunnels, zones)
                dns = self._dns_checks(api, tunnels, zones, pool)  # en même temps que le trafic
                traffic, note = traffic_call.result()
                return Overview(
                    account=account,
                    tunnels=tunnels,
                    apps=apps_call.result(),
                    tokens=tokens_call.result(),
                    zones=zones,
                    dns=dns,
                    routes=routes_call.result(),
                    traffic=traffic,
                    traffic_note=note,
                )

        overview = await asyncio.to_thread(load)
        self.sync_expirations(overview.tokens)
        return overview

    @staticmethod
    def _optional(call: Callable[[], Any], default: Any) -> Any:
        """Lecture facultative de la vue du compte : une permission manquante ne la fait pas échouer."""
        try:
            return call()
        except CloudflareApiError:
            return default

    @staticmethod
    def _traffic(
        api: CloudflareApi, tunnels: list[TunnelView], zones: list[Zone]
    ) -> tuple[dict[str, HostTraffic], str]:
        """Trafic des zones qui portent des noms publiés (une requête GraphQL par zone, en série : elles sont peu
        nombreuses). Sans la permission d'analyse, rien, avec la raison."""
        hosts = [rule.hostname for view in tunnels for rule in view.hostnames]
        used = {zone.id for host in hosts if (zone := zone_of(host, zones)) is not None}
        traffic: dict[str, HostTraffic] = {}
        for zone_id in sorted(used):
            try:
                traffic.update(zone_traffic(api, zone_id))
            except CloudflareApiError as exc:
                return {}, str(exc)
        return traffic, ""

    @staticmethod
    def _dns_checks(
        api: CloudflareApi, tunnels: list[TunnelView], zones: list[Zone], pool: ThreadPoolExecutor
    ) -> dict[str, DnsCheck]:
        """Vérifie le DNS des noms d'hôte publiés : une lecture par zone utilisée, toutes en même temps. Une zone
        illisible (permission, réseau) donne « inconnu » pour ses noms, sans faire échouer la lecture du compte."""
        rules = [(view.tunnel, rule.hostname) for view in tunnels for rule in view.hostnames]
        used = {zone.id for _t, host in rules if (zone := zone_of(host, zones)) is not None}
        calls = {zone_id: pool.submit(api.zone_records, zone_id) for zone_id in used}
        records: dict[str, list[dict[str, Any]] | None] = {}
        for zone_id, call in calls.items():
            try:
                records[zone_id] = call.result()
            except CloudflareApiError:
                records[zone_id] = None
        names = {view.tunnel.id: view.tunnel.name for view in tunnels}
        return check_all(rules, zones, records, names)

    async def fix_dns(self, tunnel: Tunnel, hostname: str) -> None:
        """CNAME de `hostname` vers ce tunnel, proxifié (créé ou corrigé). Un enregistrement A ou AAAA bloque :
        `ensure_cname` refuse de le remplacer."""
        api = self.api()
        account = self.account_id()

        def run() -> None:
            zone = api.zone_for_hostname(account, hostname)
            if zone is None:
                raise CloudflareApiError(
                    tr("Aucune zone du compte ne contient {host}.").format(host=hostname)
                )
            api.ensure_cname(zone, hostname, tunnel.cname_target)

        await asyncio.to_thread(run)

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

    async def tunnel_states(self) -> list[Tunnel]:
        """Tunnels du compte choisi avec leur état, en une seule requête (relevé de la surveillance)."""
        return await self._single_read(lambda api, account: api.list_tunnels(account))

    async def service_targets(self, *, web_only: bool = True) -> list[ServiceTarget]:
        """Noms d'hôte publiés par les tunnels en service : la liste des tunnels, puis leurs règles en même temps."""
        return await self._single_read(lambda api, account: self._active_targets(api, account, web_only))

    def _single_tokens(self) -> list[ApiToken]:
        """Jetons qui peuvent relever le compte choisi (un seul compte), dans l'ordre du repli : le jeton de la
        surveillance, le jeton actif, puis les autres jetons dont le dernier compte choisi est celui-là."""
        settings = self.store.snapshot().settings
        active = self.active_token()
        own = {settings.watch_token_id, active.id if active is not None else None}
        account = settings.cloudflare_account_id
        return [
            token
            for token in self._ranked_tokens()
            if token.id in own or (account is not None and token.account_id == account)
        ]

    async def _single_read[T](self, read: Callable[[CloudflareApi, str], T]) -> T:
        """Relevé du compte choisi, par le premier jeton qui l'accepte (`_single_tokens`). Tous refusés : l'erreur du
        premier jeton essayé, comme avant le repli."""
        candidates = [
            (token, self.secrets.get(token_secret_key(token.id))) for token in self._single_tokens()
        ]
        if not any(value for _token, value in candidates):
            raise CloudflareApiError(tr("Aucun jeton d'API Cloudflare : connectez-vous d'abord."))
        account = self.account_id()

        def attempt(_token: ApiToken, value: str) -> T:
            return read(CloudflareApi(value, base_url=self.base_url), account)

        try:
            used, result, skipped = await asyncio.to_thread(
                self._read_with_fallback, candidates, account, attempt
            )
        except _Unread as exc:
            unread = exc
        else:
            _report_fallbacks([WatchFallback(s.token_name, account, s.error, used.name) for s in skipped])
            return result
        # Levée hors du bloc except : l'erreur garde sa propre cause (réponse HTTP), sans le signal interne.
        raise unread.error or CloudflareApiError(str(unread))

    @staticmethod
    def _read_with_fallback[T](
        candidates: list[tuple[ApiToken, str | None]],
        account: str | None,
        read: Callable[[ApiToken, str], T],
    ) -> tuple[ApiToken, T, list[WatchFailure]]:
        """Lit un compte avec le premier jeton qui l'accepte, dans l'ordre de `candidates` (jeton, secret du coffre). Un
        jeton absent du coffre ou refusé (401, 403) passe la main au suivant ; toute autre erreur (réseau, 5xx) arrête
        là. Renvoie le jeton qui a lu, sa lecture et les jetons écartés avant lui ; lève `_Unread` si aucun n'a lu."""
        skipped: list[WatchFailure] = []
        first: BaseException | None = None
        for token, value in candidates:
            if not value:
                skipped.append(WatchFailure(token.name, account, tr("jeton absent du coffre")))
                continue
            try:
                return token, read(token, value), skipped
            except (CloudflareApiError, OSError) as exc:
                skipped.append(WatchFailure(token.name, account, str(exc)))
                first = first or exc
                if not token_refused(exc):
                    break
        raise _Unread(skipped, first)

    @staticmethod
    def _active_targets(api: CloudflareApi, account: str, web_only: bool = True) -> list[ServiceTarget]:
        """Noms d'hôte des tunnels en service d'un compte : la liste des tunnels, puis leurs règles en même temps."""
        tunnels = [t for t in api.list_tunnels(account) if t.status in ("healthy", "degraded")]
        with ThreadPoolExecutor(max_workers=OVERVIEW_WORKERS, thread_name_prefix="cma-cf") as pool:
            calls = [pool.submit(api.tunnel_ingress, account, t.id) for t in tunnels]
            rules = [call.result()[0] for call in calls]
        return targets_of(zip(tunnels, rules, strict=True), web_only=web_only)

    async def probe_services(self, targets: list[ServiceTarget]) -> list[tuple[ServiceTarget, HostProbe]]:
        """Teste chaque nom depuis Internet, avec le service token du profil CMA quand il y en a un."""
        config = self.store.snapshot()
        return await probe_targets(targets, lambda host: probe_token(config, self.secrets, host))

    async def check_services(self) -> list[tuple[ServiceTarget, HostProbe]]:
        """Relevé de la surveillance des services : noms HTTP des tunnels en service, tous testés."""
        return await self.probe_services(await self.service_targets())

    # --- Surveillance de tous les comptes (ADR 0003) -----------------------------------------------------------

    def _ranked_tokens(self) -> list[ApiToken]:
        """Jetons dans l'ordre où la surveillance les essaie : le jeton de la surveillance (conseillé en lecture seule),
        le jeton actif, puis les autres dans l'ordre de `Settings.cloudflare_tokens`."""
        settings = self.store.snapshot().settings
        active = self.active_token()
        active_id = active.id if active is not None else None

        def rank(token: ApiToken) -> int:
            return 0 if token.id == settings.watch_token_id else 1 if token.id == active_id else 2

        return sorted(self.tokens(), key=rank)

    def _watch_plan(self) -> list[tuple[str | None, list[ApiToken]]]:
        """Comptes à relever avec « Surveiller tous les comptes » et, pour chacun, ses jetons dans l'ordre du repli
        (`_ranked_tokens`). Le compte d'un jeton est le dernier choisi avec lui (pour le jeton actif, celui de la vue
        Cloudflare). Un compte vu par plusieurs jetons n'est relevé qu'une fois, par le premier qui l'accepte ; un jeton
        qui n'a encore choisi aucun compte (None) est seul de son groupe : son compte n'est connu qu'à la lecture."""
        settings = self.store.snapshot().settings
        active = self.active_token()
        active_id = active.id if active is not None else None
        plan: list[tuple[str | None, list[ApiToken]]] = []
        groups: dict[str, list[ApiToken]] = {}
        for token in self._ranked_tokens():
            account = token.account_id
            if token.id == active_id:
                account = settings.cloudflare_account_id or account
            if account is None:
                plan.append((None, [token]))
            elif account in groups:
                groups[account].append(token)
            else:
                groups[account] = [token]
                plan.append((account, groups[account]))
        return plan

    def watch_scope(self) -> str:
        """Ce que relève la surveillance de tous les comptes : pour chaque compte, le premier de ses jetons présent dans
        le coffre ; vide s'il n'y a rien à relever. Quand elle change (jeton ajouté ou oublié, autre compte choisi), le
        résultat d'un relevé en cours est ignoré. Un jeton refusé pendant le relevé ne la change pas."""
        parts: list[str] = []
        for account, tokens in self._watch_plan():
            token = next((t for t in tokens if self.secrets.get(token_secret_key(t.id))), None)
            if token is not None:
                parts.append(f"{token.id}={account or '?'}")
        return "|".join(parts)

    def _resolve(
        self, token: ApiToken, account: str | None, value: str, named: bool
    ) -> tuple[WatchedAccount, CloudflareApi]:
        """Compte d'un jeton (le premier qu'il voit, comme à la connexion, s'il n'en a pas encore choisi) et son nom. Les
        noms sont demandés une fois par jeton (`/accounts`, sinon les zones), puis gardés en mémoire ; sans nom lisible,
        celui du jeton. Lève CloudflareApiError si le jeton ne mène à aucun compte."""
        api = CloudflareApi(value, base_url=self.base_url)
        unnamed = named and account not in self._account_names and token.id not in self._names_tried
        if account is None or unnamed:
            self._names_tried.add(token.id)
            accounts: list[Account] = []
            try:
                accounts = api.list_accounts() or api.accounts_from_zones()
            except CloudflareApiError:
                if account is None:
                    raise
            self._account_names.update({a.id: a.name for a in accounts})
            if account is None:
                if not accounts:
                    raise CloudflareApiError(tr("Ce jeton ne donne accès à aucun compte Cloudflare."))
                account = accounts[0].id
        return WatchedAccount(
            token.id, token.name, account, self._account_names.get(account, token.name)
        ), api

    async def _each_account[T](
        self, read: Callable[[CloudflareApi, str], T]
    ) -> tuple[list[tuple[WatchedAccount, T]], list[WatchFailure], list[WatchFallback], bool]:
        """Lit chaque compte surveillé, tous en même temps (un fil par compte), chacun par le premier de ses jetons qui
        l'accepte (repli : un jeton refusé ou absent du coffre passe la main au suivant, journalisé). Un compte qu'aucun
        jeton n'a lu (tous refusés, réseau, 5xx) est journalisé et noté dans les échecs, un par jeton essayé, sans arrêter
        les autres. Renvoie aussi les replis et si plusieurs comptes sont surveillés (leur nom accompagne alors celui des
        objets). Lève CloudflareApiError si aucun compte n'a pu être lu."""
        plan = self._watch_plan()
        if not plan:
            raise CloudflareApiError(tr("Aucun jeton d'API Cloudflare : connectez-vous d'abord."))
        named = len(plan) > 1
        # Le coffre est lu ici, une fois par jeton ; les fils ne font que des requêtes.
        groups = [
            (account, [(token, self.secrets.get(token_secret_key(token.id))) for token in tokens])
            for account, tokens in plan
        ]

        def one(
            account: str | None, candidates: list[tuple[ApiToken, str | None]]
        ) -> tuple[WatchedAccount, T, list[WatchFallback]] | list[WatchFailure]:
            def attempt(token: ApiToken, value: str) -> tuple[WatchedAccount, T]:
                watched, api = self._resolve(token, account, value, named)
                return watched, read(api, watched.account_id)

            try:
                _used, (watched, result), skipped = self._read_with_fallback(candidates, account, attempt)
            except _Unread as exc:
                return exc.failures
            moved = [
                WatchFallback(s.token_name, watched.account_id, s.error, watched.token_name) for s in skipped
            ]
            return watched, result, moved

        outcomes = await asyncio.gather(*(asyncio.to_thread(one, *group) for group in groups))
        found: list[tuple[WatchedAccount, T]] = []
        failures: list[WatchFailure] = []
        fallbacks: list[WatchFallback] = []
        unread = 0
        seen: set[str] = set()
        for outcome in outcomes:
            if isinstance(outcome, list):
                failures.extend(outcome)
                unread += 1
            elif outcome[0].account_id not in seen:  # un compte trouvé par deux jetons sans compte choisi
                seen.add(outcome[0].account_id)
                found.append((outcome[0], outcome[1]))
                fallbacks.extend(outcome[2])
        for failure in failures:
            log.warning("Surveillance : jeton « %s » illisible (%s)", failure.token_name, failure.error)
        _report_fallbacks(fallbacks)
        if not found and failures:
            raise CloudflareApiError("; ".join(f"{f.token_name} : {f.error}" for f in failures))
        return _distinct_names(found), failures, fallbacks, len(found) + unread > 1

    async def watch_tunnels(self) -> TunnelSweep:
        """Relevé des tunnels de la surveillance : le compte choisi (comme `tunnel_states`) ou, avec « Surveiller tous
        les comptes », chaque jeton avec son compte (ADR 0003). Un tunnel vu par deux comptes compte une fois."""
        if not self.store.snapshot().settings.watch_all_accounts:
            tunnels, fallbacks = await _collecting(self.tunnel_states())
            return TunnelSweep(tunnels, fallbacks=fallbacks)
        found, failures, fallbacks, several = await self._each_account(
            lambda api, account: api.list_tunnels(account)
        )
        tunnels: list[Tunnel] = []
        accounts: dict[str, WatchedAccount] = {}
        names: dict[str, str] = {}
        for watched, listed in found:
            for tunnel in listed:
                if tunnel.id in accounts:
                    continue
                accounts[tunnel.id] = watched
                names[tunnel.id] = tunnel.name
                tunnels.append(
                    replace(tunnel, name=with_account(tunnel.name, watched.name)) if several else tunnel
                )
        return TunnelSweep(tunnels, failures, accounts, names, fallbacks)

    async def watch_services(self) -> ServiceSweep:
        """Relevé des services publiés de la surveillance : le compte choisi (comme `check_services`) ou chaque compte.
        Un nom public n'a qu'une destination : déclaré par deux comptes, il n'est testé qu'une fois, avec le premier."""
        if not self.store.snapshot().settings.watch_all_accounts:
            results, fallbacks = await _collecting(self.check_services())
            return ServiceSweep(results, fallbacks=fallbacks)
        found, failures, fallbacks, several = await self._each_account(self._active_targets)
        targets: list[ServiceTarget] = []
        seen: set[str] = set()
        for watched, listed in found:
            for target in listed:
                if target.key in seen:
                    continue
                seen.add(target.key)
                targets.append(
                    replace(target, account_id=watched.account_id, account=watched.name if several else "")
                )
        return ServiceSweep(await self.probe_services(targets), failures, fallbacks)

    # --- Réseaux privés, audit, instantanés, permissions -------------------------------------------------

    async def private_network(self, tunnel: Tunnel) -> PrivateNetwork:
        api = self.api()
        account = self.account_id()

        def load() -> PrivateNetwork:
            with ThreadPoolExecutor(max_workers=3, thread_name_prefix="cma-cf") as pool:
                routes = pool.submit(list_routes, api, account, tunnel.id)
                networks = pool.submit(list_virtual_networks, api, account)
                config = pool.submit(api.tunnel_config, account, tunnel.id)
                return PrivateNetwork(routes.result(), networks.result(), warp_routing(config.result()))

        return await asyncio.to_thread(load)

    async def add_route(
        self, tunnel: Tunnel, network: str, *, comment: str = "", virtual_network_id: str | None = None
    ) -> PrivateRoute:
        """Nouvelle route vers ce tunnel ; le routage WARP du tunnel est activé s'il ne l'était pas (sans lui, la
        route ne sert à rien)."""
        api = self.api()
        account = self.account_id()

        def run() -> PrivateRoute:
            route = create_route(
                api, account, tunnel.id, network, comment=comment, virtual_network_id=virtual_network_id
            )
            if not warp_routing(api.tunnel_config(account, tunnel.id)):
                set_warp_routing(api, account, tunnel, True)
            return route

        return await asyncio.to_thread(run)

    async def remove_route(self, route: PrivateRoute) -> None:
        api = self.api()
        await asyncio.to_thread(delete_route, api, self.account_id(), route.id)

    async def set_warp_routing(self, tunnel: Tunnel, enabled: bool) -> None:
        api = self.api()
        await asyncio.to_thread(set_warp_routing, api, self.account_id(), tunnel, enabled)

    async def audit_log(self, *, days: int = 7, limit: int = 1000) -> list[AuditEntry]:
        api = self.api()
        return await asyncio.to_thread(account_audit, api, self.account_id(), days=days, limit=limit)

    async def snapshot(self, account: Account) -> dict[str, Any]:
        api = self.api()
        return await asyncio.to_thread(take_snapshot, api, account)

    async def permissions(self) -> list[PermissionCheck]:
        api = self.api()
        return await asyncio.to_thread(check_permissions, api, self.account_id())

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

    async def access_requests(self, limit: int = 1000, days: int = 30) -> list[AccessRequest]:
        """Connexions des `days` derniers jours (au plus `limit`) : la boîte du journal choisit ensuite sa période."""
        api = self.api()
        since = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return await asyncio.to_thread(api.access_requests, self.account_id(), limit, since)

    async def app_settings(self, app: AccessApp) -> AppSettings:
        api = self.api()
        return await asyncio.to_thread(api.app_settings, self.account_id(), app.id)

    async def save_app_settings(self, app: AccessApp, settings: AppSettings) -> AppSettings:
        api = self.api()
        return await asyncio.to_thread(api.update_app_settings, self.account_id(), app.id, settings)

    async def delete_app(self, app: AccessApp) -> None:
        api = self.api()
        await asyncio.to_thread(api.delete_access_app, self.account_id(), app.id)

    async def delete_remote_token(self, remote: RemoteServiceToken) -> list[str]:
        """Révoque le token chez Cloudflare et renvoie le nom des politiques supprimées avec lui.

        Cloudflare refuse de supprimer un token cité par une politique. Les politiques inutilisées qui ne servent
        qu'à ce token (celles que « Autoriser un service token » crée) partent avec lui ; s'il est cité ailleurs,
        rien n'est supprimé et le message nomme les politiques à revoir. Sa copie dans CMA reste à part."""
        api = self.api()
        account = self.account_id()
        return await asyncio.to_thread(self._delete_remote_token, api, account, remote)

    @staticmethod
    def _delete_remote_token(api: CloudflareApi, account: str, remote: RemoteServiceToken) -> list[str]:
        only_this = (PolicyRule("service_token", remote.id),)
        users = api.policies_using_token(account, remote.id)
        blocking = [p for p in users if p.app_count or p.include != only_this or p.exclude or p.require]
        if blocking:
            raise CloudflareApiError(
                tr(
                    "Le token « {name} » est encore cité par : {policies}. Retirez-le de ces politiques (ou "
                    "retirez-les de leurs applications), ou changez son secret pour couper les accès."
                ).format(name=remote.name, policies=", ".join(p.name for p in blocking))
            )
        for policy in users:
            api.delete_account_policy(account, policy.id)
        api.delete_service_token(account, remote.id)
        return [p.name for p in users]

    # --- Bilan de sécurité ----------------------------------------------------------------------------

    async def security_review(self) -> list[Finding]:
        """Lit le compte (tunnels et règles, applications, politiques, tokens, DNS de toutes les zones) et en tire
        les constats de `cma.core.security`."""
        api = self.api()
        account = self.account_id()

        def records_of(zone_id: str) -> list[tuple[str, dict[str, Any]]]:
            try:
                return [(zone_id, record) for record in api.zone_records(zone_id)]
            except CloudflareApiError:
                return []

        def load() -> list[Finding]:
            with ThreadPoolExecutor(max_workers=OVERVIEW_WORKERS, thread_name_prefix="cma-cf") as pool:
                tunnels_call = pool.submit(api.list_tunnels, account)
                apps_call = pool.submit(api.list_access_apps, account)
                policies_call = pool.submit(self._optional, lambda: api.list_account_policies(account), [])
                tokens_call = pool.submit(api.list_service_tokens, account)
                zones_call = pool.submit(self._optional, lambda: api.list_zones(account), [])
                listed = tunnels_call.result()
                ingress = [pool.submit(api.tunnel_ingress, account, t.id) for t in listed]
                records = [pool.submit(records_of, zone.id) for zone in zones_call.result()]
                data = AccountData(
                    tunnels=[(t, *call.result()) for t, call in zip(listed, ingress, strict=True)],
                    apps=apps_call.result(),
                    policies=policies_call.result(),
                    tokens=tokens_call.result(),
                    records=[item for call in records for item in call.result()],
                )
            return review(data)

        return await asyncio.to_thread(load)

    async def fix_findings(self, findings: list[Finding]) -> list[tuple[Finding, str | None]]:
        """Applique les corrections, une par une ; renvoie chaque constat avec son erreur (None si corrigé)."""
        api = self.api()
        account = self.account_id()

        def run() -> list[tuple[Finding, str | None]]:
            tunnels = {t.id: t for t in api.list_tunnels(account)}
            tokens: dict[str, RemoteServiceToken] = {}
            team: str | None = None
            results: list[tuple[Finding, str | None]] = []
            for finding in findings:
                try:
                    if finding.fix == "protect":
                        if covering_app(finding.key, api.list_access_apps(account)) is None:
                            api.create_access_app(account, finding.key, finding.key)
                    elif finding.fix == "require_access":
                        team = team or api.access_team(account)
                        tunnel_id, path, aud = finding.data
                        api.require_access(account, tunnels[tunnel_id], finding.key, path, team, aud)
                    elif finding.fix == "delete_token":
                        tokens = tokens or {t.id: t for t in api.list_service_tokens(account)}
                        self._delete_remote_token(api, account, tokens[finding.key])
                    elif finding.fix == "delete_dns":
                        api.delete_dns_record(finding.data[0], finding.key)
                    elif finding.fix == "catch_all_404":
                        api.set_catch_all(account, tunnels[finding.key], "http_status:404")
                    elif finding.fix == "delete_policy":
                        api.delete_account_policy(account, finding.key)
                    else:
                        raise CloudflareApiError(tr("Aucune correction automatique pour ce constat."))
                except (CloudflareApiError, KeyError) as exc:
                    message = str(exc) if isinstance(exc, CloudflareApiError) else tr("Objet introuvable.")
                    results.append((finding, message))
                else:
                    results.append((finding, None))
            return results

        return await asyncio.to_thread(run)

    async def require_access(self, tunnel: Tunnel, rule: IngressRule, required: bool = True) -> None:
        """Le tunnel exige (ou n'exige plus) le jeton de l'application Access qui protège ce nom d'hôte."""
        api = self.api()
        account = self.account_id()

        def run() -> None:
            if not required:
                api.require_access(account, tunnel, rule.hostname, rule.path, "", None)
                return
            app = covering_app(rule.hostname, api.list_access_apps(account))
            if app is None or not app.aud:
                raise CloudflareApiError(
                    tr("{host} n'est protégé par aucune application Access : protégez-le d'abord.").format(
                        host=rule.hostname
                    )
                )
            api.require_access(account, tunnel, rule.hostname, rule.path, api.access_team(account), app.aud)

        await asyncio.to_thread(run)

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
        self,
        tunnel: Tunnel,
        hostname: str,
        service: str,
        origin: dict[str, Any] | None = None,
        path: str = "",
    ) -> IngressRule:
        """Change le service publié pour `hostname` (+ `path`) et, si `origin` est donné, ses options d'origine. Pour
        la règle sans chemin, le profil CMA lié suit si le type de service change (ssh:// → rdp://…) ; son port local
        est gardé."""
        api = self.api()
        rule = await asyncio.to_thread(
            api.update_hostname_service, self.account_id(), tunnel, hostname, service, origin, path
        )
        scheme, _port = guess_service_from_ingress(service)
        kind = _SCHEME_TYPES.get(scheme)
        if kind is not None and not path:

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

    async def unpublish(self, tunnel: Tunnel, hostname: str, path: str = "") -> None:
        api = self.api()
        await asyncio.to_thread(api.unpublish_hostname, self.account_id(), tunnel, hostname, path)

    async def add_path_rule(self, tunnel: Tunnel, hostname: str, path: str, service: str) -> IngressRule:
        """Règle avec chemin (`/api` → autre service) sur un nom d'hôte : même DNS, même protection Access."""
        path = path.strip()
        if not path:
            raise CloudflareApiError(tr("Indiquez un chemin, par exemple /api."))
        api = self.api()
        return await asyncio.to_thread(
            api.publish_hostname, self.account_id(), tunnel, hostname, service, path
        )

    async def move_rule(self, tunnel: Tunnel, rule: IngressRule, offset: int) -> int:
        api = self.api()
        return await asyncio.to_thread(
            api.move_rule, self.account_id(), tunnel, rule.hostname, rule.path, offset
        )

    async def set_catch_all(self, tunnel: Tunnel, service: str) -> None:
        api = self.api()
        await asyncio.to_thread(api.set_catch_all, self.account_id(), tunnel, service)
