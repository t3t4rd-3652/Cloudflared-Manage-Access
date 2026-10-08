"""Client de l'API Cloudflare (v4) pour gérer le côté serveur : tunnels, DNS, Access, service tokens.

Le jeton d'API est gardé dans le coffre (clé `cfapi:token`) et n'apparaît jamais dans les journaux.
Permissions conseillées pour le jeton (Mon profil › Jetons d'API › Créer un jeton personnalisé) :

- Compte › Cloudflare Tunnel : Modifier
- Compte › Access: Apps and Policies : Modifier
- Compte › Access: Service Tokens : Modifier
- Zone › DNS : Modifier (sur les zones concernées)
- Zone › Zone : Lire
- Facultatif : Compte › Access: Organizations, Identity Providers, and Groups : Lire (groupes dans les politiques)

Les appels sont bloquants : le moteur les exécute via `asyncio.to_thread`.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from typing import Any, cast

from cma import __version__
from cma.core.policies import AccessGroup, AccessPolicy, PolicyRule, policy_from_api, policy_to_api
from cma.i18n import tr

log = logging.getLogger(__name__)

API_BASE = "https://api.cloudflare.com/client/v4"
TOKEN_SECRET_KEY = "cfapi:token"  # noqa: S105 (nom de la clé dans le coffre, pas un secret)
TOKENS_PAGE = "https://dash.cloudflare.com/profile/api-tokens"
CATCH_ALL = {"service": "http_status:404"}
# Champs d'une application Access calculés par Cloudflare : jamais renvoyés dans un PUT.
_APP_READ_ONLY = {"id", "uid", "aud", "created_at", "updated_at"}


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
    # `originRequest` de la règle (noTLSVerify, httpHostHeader, originServerName…), tel que Cloudflare le garde.
    origin: dict[str, Any] = field(default_factory=dict[str, Any], compare=False, hash=False)


@dataclass(frozen=True)
class AccessApp:
    id: str
    name: str
    domain: str
    type: str
    # Nombre de politiques attachées (None : inconnu) et identifiant repris par le journal des accès (`app_uid`).
    policy_count: int | None = field(default=None, compare=False)
    uid: str = field(default="", compare=False)


# Durées de session proposées pour une application Access ; « 0s » : la session expire aussitôt.
SESSION_DURATIONS = ("0s", "15m", "30m", "6h", "12h", "24h", "168h", "730h")


@dataclass(frozen=True)
class AppSettings:
    """Réglages d'une application Access que CMA modifie. Les fournisseurs d'identité choisis sont lus et renvoyés
    tels quels (la liste des fournisseurs demande une permission que le jeton n'a pas toujours)."""

    name: str
    session_duration: str
    app_launcher_visible: bool
    auto_redirect_to_identity: bool
    allowed_idps: tuple[str, ...] = ()


@dataclass(frozen=True)
class AccessRequest:
    """Une connexion à une application Access, telle que Cloudflare la journalise."""

    created_at: str
    # Adresse de l'utilisateur ; pour un service token (`connection` « nonidentity »), son Client ID.
    user: str
    app_domain: str
    app_uid: str
    allowed: bool
    action: str
    country: str = ""
    ip: str = ""
    connection: str = ""
    app_name: str = ""


AUDIT_PERMISSION = "Access: Audit Logs : Read"


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

    def create_tunnel(self, account_id: str, name: str) -> Tunnel:
        """Tunnel dont la configuration (noms d'hôte publiés) est gérée depuis Cloudflare, donc depuis CMA."""
        result = cast(
            dict[str, Any],
            self._result(
                "POST", f"/accounts/{account_id}/cfd_tunnel", body={"name": name, "config_src": "cloudflare"}
            ),
        )
        return Tunnel(
            str(result["id"]), str(result.get("name", name)), str(result.get("status") or "inactive")
        )

    def tunnel_token(self, account_id: str, tunnel_id: str) -> str:
        """Jeton qui permet à un cloudflared de faire tourner ce tunnel : un secret, à ne jamais journaliser."""
        return str(self._result("GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token") or "")

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
        return self.tunnel_ingress(account_id, tunnel_id)[0]

    def tunnel_ingress(self, account_id: str, tunnel_id: str) -> tuple[list[IngressRule], str]:
        """Règles nommées du tunnel, dans l'ordre où cloudflared les essaie, et service de la règle finale."""
        config = self.tunnel_config(account_id, tunnel_id)
        rules: list[IngressRule] = []
        catch_all = CATCH_ALL["service"]
        for rule in cast(list[dict[str, Any]], config.get("ingress") or []):
            if rule.get("hostname"):
                rules.append(
                    IngressRule(
                        str(rule["hostname"]),
                        str(rule.get("service", "")),
                        str(rule.get("path", "")),
                        dict(cast(dict[str, Any], rule.get("originRequest") or {})),
                    )
                )
            else:
                catch_all = str(rule.get("service") or catch_all)
        return rules, catch_all

    def _put_ingress(self, account_id: str, tunnel: Tunnel, config: dict[str, Any]) -> None:
        self._result(
            "PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel.id}/configurations", body={"config": config}
        )

    @staticmethod
    def _same_rule(rule: dict[str, Any], hostname: str, path: str) -> bool:
        """Une règle est identifiée par son nom d'hôte et son chemin : `app.fr` et `app.fr` + `/api` sont deux règles."""
        return rule.get("hostname") == hostname and str(rule.get("path") or "") == path

    def _find_rule(
        self, ingress: list[dict[str, Any]], tunnel: Tunnel, hostname: str, path: str
    ) -> dict[str, Any]:
        rule = next((r for r in ingress if self._same_rule(r, hostname, path)), None)
        if rule is None:
            raise CloudflareApiError(
                tr("{host} n'est pas publié sur le tunnel {tunnel}.").format(
                    host=hostname + path, tunnel=tunnel.name
                )
            )
        return rule

    def publish_hostname(
        self, account_id: str, tunnel: Tunnel, hostname: str, service: str, path: str = ""
    ) -> IngressRule:
        """Ajoute (ou met à jour) la règle `hostname` + `path` → `service` dans le tunnel, avant la règle finale, puis
        crée l'enregistrement DNS s'il manque. Les autres règles du même nom d'hôte (autres chemins) sont gardées."""
        hostname = hostname.lower().strip().rstrip(".")
        path = path.strip()
        zone = self.zone_for_hostname(account_id, hostname)
        if zone is None:
            raise CloudflareApiError(
                tr("Aucune zone du compte ne contient {host} : ajoutez le domaine à Cloudflare.").format(
                    host=hostname
                )
            )
        config = self.tunnel_config(account_id, tunnel.id)
        ingress = cast(list[dict[str, Any]], config.get("ingress") or [])
        existing = next((r for r in ingress if self._same_rule(r, hostname, path)), None)
        if existing is not None:
            # Déjà publiée : seul le service change ; position, options d'origine et clés inconnues sont gardées.
            existing["service"] = service
        else:
            catch_all = [r for r in ingress if not r.get("hostname")]
            named = [r for r in ingress if r.get("hostname")]
            rule: dict[str, Any] = {"hostname": hostname, "service": service}
            if path:
                rule["path"] = path
            named.append(rule)
            config["ingress"] = [*named, *(catch_all or [CATCH_ALL])]
        self._put_ingress(account_id, tunnel, config)
        self.ensure_cname(zone, hostname, tunnel.cname_target)
        return IngressRule(hostname, service, path)

    def update_hostname_service(
        self,
        account_id: str,
        tunnel: Tunnel,
        hostname: str,
        service: str,
        origin: dict[str, Any] | None = None,
        path: str = "",
    ) -> IngressRule:
        """Change le service d'une règle déjà publiée (nom d'hôte + chemin). Les autres clés de la règle (`id`,
        autres options d'origine) sont gardées ; le DNS ne change pas.

        `origin` modifie des options d'origine : une valeur vide, fausse ou None retire l'option."""
        config = self.tunnel_config(account_id, tunnel.id)
        ingress = cast(list[dict[str, Any]], config.get("ingress") or [])
        rule = self._find_rule(ingress, tunnel, hostname, path)
        rule["service"] = service
        if origin is not None:
            options = dict(cast(dict[str, Any], rule.get("originRequest") or {}))
            for key, value in origin.items():
                if value in (None, False, ""):
                    options.pop(key, None)
                else:
                    options[key] = value
            if options:
                rule["originRequest"] = options
            else:
                rule.pop("originRequest", None)
        self._put_ingress(account_id, tunnel, config)
        return IngressRule(
            hostname,
            service,
            str(rule.get("path", "")),
            dict(cast(dict[str, Any], rule.get("originRequest") or {})),
        )

    def unpublish_hostname(self, account_id: str, tunnel: Tunnel, hostname: str, path: str = "") -> None:
        """Retire la règle `hostname` + `path` du tunnel. L'enregistrement DNS n'est supprimé que si plus aucune
        règle du tunnel n'utilise ce nom d'hôte (et seulement s'il vise ce tunnel)."""
        config = self.tunnel_config(account_id, tunnel.id)
        ingress = cast(list[dict[str, Any]], config.get("ingress") or [])
        config["ingress"] = [r for r in ingress if not self._same_rule(r, hostname, path)] or [CATCH_ALL]
        self._put_ingress(account_id, tunnel, config)
        if not any(r.get("hostname") == hostname for r in config["ingress"]):
            self.delete_tunnel_cname(account_id, tunnel, hostname)

    def move_rule(self, account_id: str, tunnel: Tunnel, hostname: str, path: str, offset: int) -> int:
        """Avance (offset -1) ou recule (+1) une règle parmi les règles nommées ; la règle finale reste la dernière.
        Renvoie la nouvelle position (0 = première essayée)."""
        config = self.tunnel_config(account_id, tunnel.id)
        ingress = cast(list[dict[str, Any]], config.get("ingress") or [])
        named = [r for r in ingress if r.get("hostname")]
        rest = [r for r in ingress if not r.get("hostname")]
        rule = self._find_rule(named, tunnel, hostname, path)
        position = named.index(rule)
        target = max(0, min(len(named) - 1, position + offset))
        if target != position:
            named.insert(target, named.pop(position))
            config["ingress"] = [*named, *(rest or [CATCH_ALL])]
            self._put_ingress(account_id, tunnel, config)
        return target

    def set_catch_all(self, account_id: str, tunnel: Tunnel, service: str) -> None:
        """Service de la règle finale (sans nom d'hôte) : « http_status:404 », « http_status:503 » ou un service."""
        config = self.tunnel_config(account_id, tunnel.id)
        ingress = cast(list[dict[str, Any]], config.get("ingress") or [])
        named = [r for r in ingress if r.get("hostname")]
        rest = [r for r in ingress if not r.get("hostname")]
        final = dict(rest[-1]) if rest else {}
        final["service"] = service
        config["ingress"] = [*named, final]
        self._put_ingress(account_id, tunnel, config)

    def delete_tunnel_cname(self, account_id: str, tunnel: Tunnel, hostname: str) -> bool:
        """Supprime l'enregistrement CNAME de `hostname` s'il vise ce tunnel (et seulement dans ce cas)."""
        zone = self.zone_for_hostname(account_id, hostname)
        if zone is None:
            return False
        deleted = False
        for record in self._paged(f"/zones/{zone.id}/dns_records", {"name": hostname, "type": "CNAME"}):
            if record.get("content") == tunnel.cname_target:
                self._result("DELETE", f"/zones/{zone.id}/dns_records/{record['id']}")
                deleted = True
        return deleted

    def rename_tunnel(self, account_id: str, tunnel: Tunnel, name: str) -> Tunnel:
        result = cast(
            dict[str, Any],
            self._result("PATCH", f"/accounts/{account_id}/cfd_tunnel/{tunnel.id}", body={"name": name}),
        )
        return Tunnel(tunnel.id, str(result.get("name") or name), str(result.get("status") or tunnel.status))

    def delete_tunnel(self, account_id: str, tunnel_id: str) -> None:
        """Cloudflare refuse tant que le tunnel a des connexions actives."""
        self._result("DELETE", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}")

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
                    str(a["id"]),
                    str(a.get("name", "")),
                    str(a.get("domain", "")),
                    str(a.get("type", "")),
                    len(cast(list[Any], a["policies"])) if isinstance(a.get("policies"), list) else None,
                    str(a.get("uid") or a.get("aud") or ""),
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

    def delete_access_app(self, account_id: str, app_id: str) -> None:
        """Les politiques réutilisables qu'elle utilisait restent dans le compte."""
        self._result("DELETE", f"/accounts/{account_id}/access/apps/{app_id}")

    def allow_service_token(self, account_id: str, app_id: str, token_id: str, policy_name: str) -> str:
        """Laisse passer ce service token sur l'application (règle « Service Auth »). Renvoie l'id de la politique.

        Cloudflare n'accepte plus de politique propre à une application nouvellement créée : CMA réutilise la
        politique du compte qui autorise exactement ce token, ou la crée, puis l'attache à l'application."""
        wanted = (PolicyRule("service_token", token_id),)
        self.app_for_update(account_id, app_id)  # avant de créer : pas de politique orpheline en cas de refus
        policy = next(
            (
                p
                for p in self.list_account_policies(account_id)
                if p.decision == "non_identity" and p.include == wanted and not p.exclude and not p.require
            ),
            None,
        )
        if policy is None:
            policy = self.create_account_policy(
                account_id, AccessPolicy("", policy_name, "non_identity", wanted)
            )
        self.attach_policy(account_id, app_id, policy.id)
        return policy.id

    def list_policies(self, account_id: str, app_id: str) -> list[AccessPolicy]:
        """Politiques de l'application, dans leur ordre d'évaluation."""
        policies = [
            policy_from_api(p) for p in self._paged(f"/accounts/{account_id}/access/apps/{app_id}/policies")
        ]
        return sorted(policies, key=lambda p: (p.precedence is None, p.precedence or 0, p.name.lower()))

    def list_account_policies(self, account_id: str) -> list[AccessPolicy]:
        """Politiques réutilisables du compte, avec le nombre d'applications qui utilisent chacune."""
        policies = [
            policy_from_api({"reusable": True, **p})
            for p in self._paged(f"/accounts/{account_id}/access/policies")
        ]
        return sorted(policies, key=lambda p: p.name.lower())

    def create_account_policy(self, account_id: str, policy: AccessPolicy) -> AccessPolicy:
        body = policy_to_api(replace(policy, reusable=True))
        result = cast(
            dict[str, Any], self._result("POST", f"/accounts/{account_id}/access/policies", body=body)
        )
        return policy_from_api({"reusable": True, **result})

    def update_policy(self, account_id: str, app_id: str, policy: AccessPolicy) -> AccessPolicy:
        """Une politique réutilisable se modifie dans le compte (toutes ses applications la voient changer) ;
        une politique legacy, dans son application."""
        if policy.reusable:
            path = f"/accounts/{account_id}/access/policies/{policy.id}"
        else:
            path = f"/accounts/{account_id}/access/apps/{app_id}/policies/{policy.id}"
        result = cast(dict[str, Any], self._result("PUT", path, body=policy_to_api(policy)))
        return policy_from_api({"reusable": policy.reusable, **result})

    def delete_account_policy(self, account_id: str, policy_id: str) -> None:
        self._result("DELETE", f"/accounts/{account_id}/access/policies/{policy_id}")

    def delete_legacy_policy(self, account_id: str, app_id: str, policy_id: str) -> None:
        self._result("DELETE", f"/accounts/{account_id}/access/apps/{app_id}/policies/{policy_id}")

    def app_policy_ids(self, account_id: str, app_id: str) -> list[str]:
        """Politiques réutilisables attachées à l'application, dans leur ordre."""
        app = cast(dict[str, Any], self._result("GET", f"/accounts/{account_id}/access/apps/{app_id}"))
        links = cast(list[dict[str, Any]], app.get("policies") or [])
        links = sorted(links, key=lambda p: int(p.get("precedence") or 0))
        return [str(p["id"]) for p in links if p.get("reusable", True)]

    def set_app_policies(self, account_id: str, app_id: str, policy_ids: list[str]) -> None:
        """Remplace la liste des politiques réutilisables de l'application, dans cet ordre.

        L'API ne modifie une application que par un PUT complet : l'application est relue et renvoyée telle
        quelle, seuls ses champs calculés (id, aud, dates) étant retirés, avec la nouvelle liste."""
        app = self.app_for_update(account_id, app_id)
        body = {k: v for k, v in app.items() if k not in _APP_READ_ONLY}
        body["policies"] = [{"id": pid, "precedence": rank} for rank, pid in enumerate(policy_ids, start=1)]
        self._result("PUT", f"/accounts/{account_id}/access/apps/{app_id}", body=body)

    def access_requests(self, account_id: str, limit: int = 200) -> list[AccessRequest]:
        """Dernières connexions aux applications Access, de la plus récente à la plus ancienne. Un refus 403 dit
        quelle permission ajouter au jeton (elle n'est pas dans la liste de base)."""
        try:
            rows = cast(
                list[dict[str, Any]],
                self._result(
                    "GET",
                    f"/accounts/{account_id}/access/logs/access_requests",
                    params={"limit": limit, "direction": "desc"},
                )
                or [],
            )
        except CloudflareApiError as exc:
            if exc.status == 403:
                raise CloudflareApiError(
                    tr(
                        "Le jeton n'a pas la permission « {permission} » : ajoutez-la pour lire le journal des accès."
                    ).format(permission=AUDIT_PERMISSION),
                    status=403,
                    codes=exc.codes,
                ) from exc
            raise
        return [
            AccessRequest(
                created_at=str(row.get("created_at", "")),
                user=str(row.get("user_email") or ""),
                app_domain=str(row.get("app_domain") or ""),
                app_uid=str(row.get("app_uid") or ""),
                allowed=bool(row.get("allowed")),
                action=str(row.get("action") or ""),
                country=str(row.get("country") or ""),
                ip=str(row.get("ip_address") or ""),
                connection=str(row.get("connection") or ""),
                app_name=str(row.get("app_name") or ""),
            )
            for row in rows
        ]

    def app_settings(self, account_id: str, app_id: str) -> AppSettings:
        app = cast(dict[str, Any], self._result("GET", f"/accounts/{account_id}/access/apps/{app_id}"))
        return _settings_of(app)

    def update_app_settings(self, account_id: str, app_id: str, settings: AppSettings) -> AppSettings:
        """Change nom, durée de session, visibilité dans le lanceur et redirection automatique d'une application
        `self_hosted`, par un PUT complet de l'application relue (politiques renvoyées en liens, dans leur ordre)."""
        app = self.app_for_update(account_id, app_id)
        if app.get("type") != "self_hosted":
            raise CloudflareApiError(
                tr(
                    "Seules les applications « self-hosted » se règlent depuis CMA ({name} est de type {type})."
                ).format(name=app.get("name", app_id), type=app.get("type", "?"))
            )
        body = {k: v for k, v in app.items() if k not in _APP_READ_ONLY}
        links = cast(list[dict[str, Any]], app.get("policies") or [])
        body["policies"] = [
            {"id": link["id"], "precedence": link.get("precedence", rank)}
            for rank, link in enumerate(links, start=1)
            if link.get("id")
        ]
        body.update(
            name=settings.name,
            session_duration=settings.session_duration,
            app_launcher_visible=settings.app_launcher_visible,
            auto_redirect_to_identity=settings.auto_redirect_to_identity,
        )
        result = cast(
            dict[str, Any], self._result("PUT", f"/accounts/{account_id}/access/apps/{app_id}", body=body)
        )
        return _settings_of(result or {**app, **body})

    def app_for_update(self, account_id: str, app_id: str) -> dict[str, Any]:
        """L'application, si CMA peut changer ses politiques sans risque ; sinon une erreur qui explique pourquoi."""
        app = cast(dict[str, Any], self._result("GET", f"/accounts/{account_id}/access/apps/{app_id}"))
        links = cast(list[dict[str, Any]], app.get("policies") or [])
        if any(not p.get("reusable", True) for p in links):
            # Réutilisables et propres à l'application ne se mélangent pas dans un PUT : ne rien risquer.
            raise CloudflareApiError(
                tr(
                    "{name} a encore des politiques propres à l'application (legacy) : remplacez-les par des "
                    "politiques réutilisables dans le tableau de bord Cloudflare avant de la modifier ici."
                ).format(name=app.get("name", app_id))
            )
        return app

    def attach_policy(self, account_id: str, app_id: str, policy_id: str) -> None:
        """Ajoute la politique en dernier ; rien ne change si elle y est déjà."""
        current = self.app_policy_ids(account_id, app_id)
        if policy_id not in current:
            self.set_app_policies(account_id, app_id, [*current, policy_id])

    def detach_policy(self, account_id: str, app_id: str, policy_id: str) -> None:
        """Retire la politique de l'application ; elle reste dans le compte pour les autres."""
        current = self.app_policy_ids(account_id, app_id)
        if policy_id in current:
            self.set_app_policies(account_id, app_id, [p for p in current if p != policy_id])

    def list_access_groups(self, account_id: str) -> list[AccessGroup]:
        groups = self._paged(f"/accounts/{account_id}/access/groups")
        return sorted(
            (AccessGroup(str(g["id"]), str(g.get("name", g["id"]))) for g in groups),
            key=lambda g: g.name.lower(),
        )

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

    def delete_service_token(self, account_id: str, token_id: str) -> None:
        """Le token est révoqué aussitôt. Cloudflare refuse (code 12139) tant qu'une politique le référence."""
        self._result("DELETE", f"/accounts/{account_id}/access/service_tokens/{token_id}")

    def policies_using_token(self, account_id: str, token_id: str) -> list[AccessPolicy]:
        """Politiques du compte qui citent ce token, dans « include », « exclude » ou « require »."""
        wanted = {"service_token": {"token_id": token_id}}
        return [
            p
            for p in self.list_account_policies(account_id)
            if PolicyRule("service_token", token_id) in p.include
            or wanted in p.exclude
            or wanted in p.require
        ]

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


def _settings_of(app: dict[str, Any]) -> AppSettings:
    return AppSettings(
        name=str(app.get("name", "")),
        session_duration=str(app.get("session_duration") or "24h"),
        app_launcher_visible=bool(app.get("app_launcher_visible", True)),
        auto_redirect_to_identity=bool(app.get("auto_redirect_to_identity", False)),
        allowed_idps=tuple(str(i) for i in cast(list[Any], app.get("allowed_idps") or [])),
    )
