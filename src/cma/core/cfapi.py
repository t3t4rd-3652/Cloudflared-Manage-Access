"""Client de l'API Cloudflare (v4) pour gérer le côté serveur : tunnels, DNS, Access, service tokens.

Le jeton d'API est gardé dans le coffre (clé `cfapi:token`) et n'apparaît jamais dans les journaux.
Permissions conseillées pour le jeton (Mon profil › Jetons d'API › Créer un jeton personnalisé) :

- Compte › Cloudflare Tunnel : Modifier
- Compte › Access: Apps and Policies : Modifier
- Compte › Access: Service Tokens : Modifier
- Zone › DNS : Modifier (sur les zones concernées)
- Zone › Zone : Lire

Les appels sont bloquants : le moteur les exécute via `asyncio.to_thread`.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, cast

from cma import __version__
from cma.i18n import tr

log = logging.getLogger(__name__)

API_BASE = "https://api.cloudflare.com/client/v4"
TOKEN_SECRET_KEY = "cfapi:token"  # noqa: S105 (nom de la clé dans le coffre, pas un secret)
TOKENS_PAGE = "https://dash.cloudflare.com/profile/api-tokens"
CATCH_ALL = {"service": "http_status:404"}


class CloudflareApiError(RuntimeError):
    """Refus ou erreur de l'API, avec un message lisible."""

    def __init__(self, message: str, *, status: int | None = None, codes: tuple[int, ...] = ()) -> None:
        super().__init__(message)
        self.status = status
        self.codes = codes


@dataclass(frozen=True)
class Account:
    id: str
    name: str
    # Compte déduit des zones, faute de la permission « Account Settings : Read » (`/accounts` vide).
    inferred: bool = False


@dataclass(frozen=True)
class Zone:
    id: str
    name: str


@dataclass(frozen=True)
class Tunnel:
    id: str
    name: str
    status: str

    @property
    def cname_target(self) -> str:
        return f"{self.id}.cfargotunnel.com"


@dataclass(frozen=True)
class EdgeConnection:
    """Une connexion d'un connecteur vers un centre de données Cloudflare."""

    colo: str
    origin_ip: str
    opened_at: str
    pending_reconnect: bool = False


@dataclass(frozen=True)
class Connector:
    """Un cloudflared qui fait tourner le tunnel sur un serveur ; normalement 4 connexions vers Cloudflare."""

    id: str
    version: str
    arch: str
    run_at: str
    connections: tuple[EdgeConnection, ...] = ()

    @property
    def origin_ip(self) -> str:
        return next((c.origin_ip for c in self.connections if c.origin_ip), "")


@dataclass(frozen=True)
class IngressRule:
    hostname: str
    service: str
    path: str = ""


@dataclass(frozen=True)
class AccessApp:
    id: str
    name: str
    domain: str
    type: str


@dataclass(frozen=True)
class RemoteServiceToken:
    id: str
    name: str
    client_id: str
    expires_at: str = ""


@dataclass(frozen=True)
class CreatedServiceToken:
    id: str
    name: str
    client_id: str
    client_secret: str
    expires_at: str = ""

    def __repr__(self) -> str:  # le secret ne doit jamais apparaître dans un journal
        return f"CreatedServiceToken(id={self.id!r}, name={self.name!r}, client_id={self.client_id!r})"


def _describe_errors(payload: dict[str, Any]) -> tuple[str, tuple[int, ...]]:
    errors = cast(list[dict[str, Any]], payload.get("errors") or [])
    messages = [str(e.get("message", "")) for e in errors if e.get("message")]
    codes = tuple(int(e.get("code", 0)) for e in errors if str(e.get("code", "")).isdigit())
    return "; ".join(messages), codes


class CloudflareApi:
    def __init__(self, token: str, *, base_url: str = API_BASE, timeout: float = 20) -> None:
        if not token.strip():
            raise CloudflareApiError(tr("Jeton d'API Cloudflare manquant."))
        self._token = token.strip()
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def __repr__(self) -> str:
        return f"CloudflareApi(base_url={self.base_url!r})"

    # --- Transport ---------------------------------------------------------------------------------

    def _call(
        self, method: str, path: str, *, params: dict[str, Any] | None = None, body: Any = None
    ) -> dict[str, Any]:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": f"CloudflaredManageAccess/{__version__}",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            try:
                payload = cast(dict[str, Any], json.loads(exc.read().decode("utf-8") or "{}"))
            except ValueError:
                payload = {}
            message, codes = _describe_errors(payload)
            if exc.code in (401, 403):
                raise CloudflareApiError(
                    tr("Accès refusé par l'API Cloudflare ({status}) : {detail}").format(
                        status=exc.code, detail=message or tr("jeton invalide ou permissions insuffisantes")
                    ),
                    status=exc.code,
                    codes=codes,
                ) from exc
            raise CloudflareApiError(
                tr("Erreur de l'API Cloudflare ({status}) : {detail}").format(
                    status=exc.code, detail=message or "-"
                ),
                status=exc.code,
                codes=codes,
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise CloudflareApiError(tr("API Cloudflare injoignable : {error}").format(error=reason)) from exc
        if not payload.get("success", False):
            message, codes = _describe_errors(payload)
            raise CloudflareApiError(
                tr("Erreur de l'API Cloudflare : {detail}").format(detail=message or "-"), codes=codes
            )
        log.debug("API Cloudflare %s %s : succès", method, path)
        return payload

    def _result(self, method: str, path: str, **kwargs: Any) -> Any:
        return self._call(method, path, **kwargs).get("result")

    def _paged(
        self, path: str, params: dict[str, Any] | None = None, *, per_page: int = 50
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            payload = self._call("GET", path, params={**(params or {}), "page": page, "per_page": per_page})
            result = cast(list[dict[str, Any]], payload.get("result") or [])
            items.extend(result)
            info = cast(dict[str, Any], payload.get("result_info") or {})
            total_pages = int(info.get("total_pages") or 1)
            if page >= total_pages or not result:
                return items
            page += 1

    # --- Comptes et zones ----------------------------------------------------------------------------

    def list_accounts(self) -> list[Account]:
        return [Account(str(a["id"]), str(a.get("name", a["id"]))) for a in self._paged("/accounts")]

    def accounts_from_zones(self) -> list[Account]:
        """Comptes propriétaires des zones lisibles : le repli quand `/accounts` ne renvoie rien."""
        found: dict[str, Account] = {}
        for zone in self._paged("/zones"):
            owner = cast(dict[str, Any], zone.get("account") or {})
            if owner.get("id"):
                key = str(owner["id"])
                found.setdefault(key, Account(key, str(owner.get("name") or key), inferred=True))
        return list(found.values())

    def list_zones(self, account_id: str) -> list[Zone]:
        zones = self._paged("/zones", {"account.id": account_id})
        return sorted((Zone(str(z["id"]), str(z["name"])) for z in zones), key=lambda z: z.name)

    def zone_for_hostname(self, account_id: str, hostname: str) -> Zone | None:
        """Zone la plus précise qui contient `hostname` (app.lab.exemple.fr → lab.exemple.fr ou exemple.fr)."""
        hostname = hostname.lower().rstrip(".")
        matches = [
            z for z in self.list_zones(account_id) if hostname == z.name or hostname.endswith("." + z.name)
        ]
        return max(matches, key=lambda z: len(z.name), default=None)

    # --- Tunnels ---------------------------------------------------------------------------------------

    def list_tunnels(self, account_id: str) -> list[Tunnel]:
        tunnels = self._paged(f"/accounts/{account_id}/cfd_tunnel", {"is_deleted": "false"})
        return sorted(
            (
                Tunnel(str(t["id"]), str(t.get("name", t["id"])), str(t.get("status", "inactive")))
                for t in tunnels
            ),
            key=lambda t: t.name.lower(),
        )

    def tunnel_connectors(self, account_id: str, tunnel_id: str) -> list[Connector]:
        """Connecteurs actifs du tunnel et leurs connexions vers Cloudflare."""
        result = cast(
            list[dict[str, Any]],
            self._result("GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections") or [],
        )
        return [
            Connector(
                str(c.get("id", "")),
                str(c.get("version", "")),
                str(c.get("arch", "")),
                str(c.get("run_at", "")),
                tuple(
                    EdgeConnection(
                        str(e.get("colo_name", "")),
                        str(e.get("origin_ip", "")),
                        str(e.get("opened_at", "")),
                        bool(e.get("is_pending_reconnect", False)),
                    )
                    for e in cast(list[dict[str, Any]], c.get("conns") or [])
                ),
            )
            for c in result
        ]

    def tunnel_config(self, account_id: str, tunnel_id: str) -> dict[str, Any]:
        result = cast(
            dict[str, Any],
            self._result("GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations") or {},
        )
        return cast(dict[str, Any], result.get("config") or {})

    def tunnel_hostnames(self, account_id: str, tunnel_id: str) -> list[IngressRule]:
        config = self.tunnel_config(account_id, tunnel_id)
        rules: list[IngressRule] = []
        for rule in cast(list[dict[str, Any]], config.get("ingress") or []):
            if rule.get("hostname"):
                rules.append(
                    IngressRule(
                        str(rule["hostname"]), str(rule.get("service", "")), str(rule.get("path", ""))
                    )
                )
        return rules

    def publish_hostname(self, account_id: str, tunnel: Tunnel, hostname: str, service: str) -> IngressRule:
        """Ajoute (ou met à jour) `hostname → service` dans le tunnel, puis crée l'enregistrement DNS."""
        hostname = hostname.lower().strip().rstrip(".")
        zone = self.zone_for_hostname(account_id, hostname)
        if zone is None:
            raise CloudflareApiError(
                tr("Aucune zone du compte ne contient {host} : ajoutez le domaine à Cloudflare.").format(
                    host=hostname
                )
            )
        config = self.tunnel_config(account_id, tunnel.id)
        ingress = [
            r
            for r in cast(list[dict[str, Any]], config.get("ingress") or [])
            if r.get("hostname") != hostname
        ]
        catch_all = [r for r in ingress if not r.get("hostname")]
        named = [r for r in ingress if r.get("hostname")]
        named.append({"hostname": hostname, "service": service})
        config["ingress"] = [*named, *(catch_all or [CATCH_ALL])]
        self._result(
            "PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel.id}/configurations", body={"config": config}
        )
        self.ensure_cname(zone, hostname, tunnel.cname_target)
        return IngressRule(hostname, service)

    def update_hostname_service(
        self, account_id: str, tunnel: Tunnel, hostname: str, service: str
    ) -> IngressRule:
        """Change le service d'un nom d'hôte déjà publié. Les autres clés de la règle (`path`, `originRequest`)
        sont gardées ; le DNS ne change pas."""
        config = self.tunnel_config(account_id, tunnel.id)
        ingress = cast(list[dict[str, Any]], config.get("ingress") or [])
        rule = next((r for r in ingress if r.get("hostname") == hostname), None)
        if rule is None:
            raise CloudflareApiError(
                tr("{host} n'est pas publié sur le tunnel {tunnel}.").format(
                    host=hostname, tunnel=tunnel.name
                )
            )
        rule["service"] = service
        self._result(
            "PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel.id}/configurations", body={"config": config}
        )
        return IngressRule(hostname, service, str(rule.get("path", "")))

    def unpublish_hostname(self, account_id: str, tunnel: Tunnel, hostname: str) -> None:
        """Retire `hostname` du tunnel. L'enregistrement DNS est supprimé s'il vise encore ce tunnel."""
        config = self.tunnel_config(account_id, tunnel.id)
        ingress = cast(list[dict[str, Any]], config.get("ingress") or [])
        config["ingress"] = [r for r in ingress if r.get("hostname") != hostname] or [CATCH_ALL]
        self._result(
            "PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel.id}/configurations", body={"config": config}
        )
        zone = self.zone_for_hostname(account_id, hostname)
        if zone is None:
            return
        for record in self._paged(f"/zones/{zone.id}/dns_records", {"name": hostname, "type": "CNAME"}):
            if record.get("content") == tunnel.cname_target:
                self._result("DELETE", f"/zones/{zone.id}/dns_records/{record['id']}")

    def ensure_cname(self, zone: Zone, hostname: str, target: str) -> None:
        existing = self._paged(f"/zones/{zone.id}/dns_records", {"name": hostname})
        body = {
            "type": "CNAME",
            "name": hostname,
            "content": target,
            "proxied": True,
            "comment": "Cloudflared Manage Access",
        }
        cname = next((r for r in existing if r.get("type") == "CNAME"), None)
        others = [r for r in existing if r.get("type") != "CNAME"]
        if others:
            raise CloudflareApiError(
                tr("{host} a déjà un enregistrement DNS {type} : supprimez-le d'abord.").format(
                    host=hostname, type=others[0].get("type")
                )
            )
        if cname is None:
            self._result("POST", f"/zones/{zone.id}/dns_records", body=body)
        elif cname.get("content") != target or not cname.get("proxied"):
            self._result("PUT", f"/zones/{zone.id}/dns_records/{cname['id']}", body=body)

    # --- Access -------------------------------------------------------------------------------------------

    def list_access_apps(self, account_id: str) -> list[AccessApp]:
        apps = self._paged(f"/accounts/{account_id}/access/apps")
        return sorted(
            (
                AccessApp(
                    str(a["id"]), str(a.get("name", "")), str(a.get("domain", "")), str(a.get("type", ""))
                )
                for a in apps
            ),
            key=lambda a: a.name.lower(),
        )

    def create_access_app(
        self, account_id: str, name: str, domain: str, *, session_duration: str = "24h"
    ) -> AccessApp:
        result = self._result(
            "POST",
            f"/accounts/{account_id}/access/apps",
            body={
                "name": name,
                "domain": domain,
                "type": "self_hosted",
                "session_duration": session_duration,
            },
        )
        return AccessApp(
            str(result["id"]), str(result.get("name", name)), str(result.get("domain", domain)), "self_hosted"
        )

    def allow_service_token(self, account_id: str, app_id: str, token_id: str, policy_name: str) -> str:
        """Ajoute une règle « Service Auth » qui laisse passer ce service token. Renvoie l'id de la règle."""
        result = self._result(
            "POST",
            f"/accounts/{account_id}/access/apps/{app_id}/policies",
            body={
                "name": policy_name,
                "decision": "non_identity",
                "include": [{"service_token": {"token_id": token_id}}],
            },
        )
        return str(result["id"])

    def list_service_tokens(self, account_id: str) -> list[RemoteServiceToken]:
        tokens = self._paged(f"/accounts/{account_id}/access/service_tokens")
        return sorted(
            (
                RemoteServiceToken(
                    str(t["id"]),
                    str(t.get("name", "")),
                    str(t.get("client_id", "")),
                    str(t.get("expires_at") or ""),
                )
                for t in tokens
            ),
            key=lambda t: t.name.lower(),
        )

    def create_service_token(
        self, account_id: str, name: str, *, duration: str = "8760h"
    ) -> CreatedServiceToken:
        """Le secret n'est renvoyé qu'une seule fois par Cloudflare : il part aussitôt dans le coffre."""
        result = self._result(
            "POST", f"/accounts/{account_id}/access/service_tokens", body={"name": name, "duration": duration}
        )
        return _created_token(result, name)

    def refresh_service_token(self, account_id: str, token_id: str) -> str:
        """Repousse l'échéance du token d'une durée (même secret, aucune coupure). Renvoie la nouvelle échéance."""
        result = self._result("POST", f"/accounts/{account_id}/access/service_tokens/{token_id}/refresh")
        return str(result.get("expires_at") or "")

    def rotate_service_token(self, account_id: str, token_id: str) -> CreatedServiceToken:
        """Nouveau secret pour le même `client_id` ; Cloudflare révoque l'ancien."""
        result = self._result("POST", f"/accounts/{account_id}/access/service_tokens/{token_id}/rotate")
        return _created_token(result, "")


def _created_token(result: dict[str, Any], name: str) -> CreatedServiceToken:
    return CreatedServiceToken(
        str(result["id"]),
        str(result.get("name") or name),
        str(result["client_id"]),
        str(result["client_secret"]),
        str(result.get("expires_at") or ""),
    )


def guess_service_from_ingress(service: str) -> tuple[str, int | None]:
    """« ssh://localhost:22 » → (« ssh », 22). Sert à choisir le type de service d'un profil importé."""
    if "://" not in service:  # « http_status:404 », « hello_world »…
        return service.split(":", 1)[0].lower(), None
    parsed = urllib.parse.urlsplit(service)
    try:
        port = parsed.port
    except ValueError:
        port = None
    return parsed.scheme.lower(), port
