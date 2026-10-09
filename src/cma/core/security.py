"""Bilan de sécurité du compte Cloudflare : ce qui expose un service, ce qui traîne, ce qui est cassé.

Analyse pure des données du compte (`review`), testée sans réseau ; la lecture et les corrections passent par
`CloudflareAdmin`. Chaque constat a une gravité et, quand CMA sait le faire sans risque, une correction :
- élevée : nom d'hôte publié sans application Access (joignable par tout Internet), politique « Tout le monde »
  en « Autoriser » utilisée par une application ;
- moyenne : service token expiré ou inutilisé depuis longtemps, enregistrement DNS vers un tunnel qui n'existe
  plus, règle finale d'un tunnel qui renvoie vers un service au lieu d'une erreur ;
- faible : Access non exigé par le tunnel lui-même, politique réutilisable sans application, application sans
  politique (personne n'y entre), tunnel inactif.
Créer une application Access sans politique ferme le service à tous : c'est la correction sûre d'un nom exposé.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from cma.core.cfapi import AccessApp, IngressRule, RemoteServiceToken, Tunnel
from cma.core.policies import AccessPolicy
from cma.i18n import tr

UNUSED_AFTER = timedelta(days=90)
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class Finding:
    kind: str
    severity: str  # high, medium ou low
    target: str  # objet concerné, tel qu'affiché
    key: str = ""  # identifiant de l'objet pour la correction
    fix: str = (
        ""  # protect, require_access, delete_token, delete_dns, catch_all_404, delete_policy ; vide : rien
    )
    data: tuple[str, ...] = ()  # précisions pour la correction (tunnel, zone, chemin, audience…)

    @property
    def ident(self) -> str:
        """Identifiant stable du constat (pour « Ignorer ») : sa nature et son objet."""
        return f"{self.kind}:{self.key or self.target}"

    def title(self) -> str:
        return {
            "unprotected": tr("Nom d'hôte publié sans Access"),
            "everyone_allow": tr("Politique ouverte à tout le monde"),
            "token_expired": tr("Service token expiré"),
            "token_unused": tr("Service token inutilisé"),
            "dangling_dns": tr("DNS vers un tunnel supprimé"),
            "exposed_catch_all": tr("Règle finale ouverte"),
            "access_not_required": tr("Access non exigé par le tunnel"),
            "unused_policy": tr("Politique sans application"),
            "app_without_policy": tr("Application sans politique"),
            "inactive_tunnel": tr("Tunnel inactif"),
        }.get(self.kind, self.kind)

    def detail(self) -> str:
        return {
            "unprotected": tr(
                "{target} est joignable par tout Internet sans authentification. Le protéger crée une application "
                "Access sans politique : le service est fermé à tous jusqu'à ce qu'une politique l'ouvre."
            ),
            "everyone_allow": tr(
                "La politique « {target} » autorise n'importe qui : Access ne filtre plus rien sur les applications "
                "qui l'utilisent. À revoir dans « Politiques du compte… »."
            ),
            "token_expired": tr(
                "« {target} » a expiré : les accès qui l'utilisent sont refusés. Supprimez-le, ou créez-en un "
                "nouveau pour ces accès."
            ),
            "token_unused": tr(
                "« {target} » n'a pas servi depuis plus de 90 jours. Un secret qui ne sert plus est un risque "
                "sans contrepartie : le supprimer le révoque chez Cloudflare."
            ),
            "dangling_dns": tr(
                "{target} vise un tunnel qui n'existe plus : le nom ne mène nulle part. Supprimer l'enregistrement "
                "le retire du DNS."
            ),
            "exposed_catch_all": tr(
                "La règle finale du tunnel « {target} » renvoie vers un service : tout nom qui arrive sur le tunnel "
                "sans règle précise l'atteint. La remettre sur « erreur 404 » le ferme."
            ),
            "access_not_required": tr(
                "{target} est protégé par Access, mais le tunnel ne vérifie pas lui-même le jeton : si l'application "
                "Access disparaît, le service s'ouvre à tous. L'exiger au niveau du tunnel le garde fermé."
            ),
            "unused_policy": tr("La politique « {target} » ne sert à aucune application : elle peut partir."),
            "app_without_policy": tr(
                "L'application « {target} » n'a aucune politique : personne ne peut y entrer. Ajoutez une politique "
                "ou supprimez l'application si elle ne sert plus."
            ),
            "inactive_tunnel": tr(
                "Le tunnel « {target} » n'a plus de connecteur depuis longtemps. Supprimez-le s'il ne sert plus."
            ),
        }.get(self.kind, "").format(target=self.target)

    def fix_label(self) -> str:
        return {
            "protect": tr("Protéger par Access"),
            "require_access": tr("Exiger Access au niveau du tunnel"),
            "delete_token": tr("Supprimer le token"),
            "delete_dns": tr("Supprimer l'enregistrement DNS"),
            "catch_all_404": tr("Règle finale : erreur 404"),
            "delete_policy": tr("Supprimer la politique"),
        }.get(self.fix, "")


@dataclass(frozen=True)
class AccountData:
    tunnels: list[tuple[Tunnel, list[IngressRule], str]]  # tunnel, règles nommées, service de la règle finale
    apps: list[AccessApp]
    policies: list[AccessPolicy]
    tokens: list[RemoteServiceToken]
    records: list[tuple[str, dict[str, Any]]]  # (zone, enregistrement DNS)


def _moment(value: str) -> datetime | None:
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _access_required(rule: IngressRule) -> bool:
    access = rule.origin.get("access")
    return isinstance(access, dict) and bool(cast(dict[str, Any], access).get("required"))


def covering_app(hostname: str, apps: list[AccessApp]) -> AccessApp | None:
    """L'application Access qui protège ce nom d'hôte (domaine exact, sinon générique `*.exemple.fr`)."""
    host = hostname.lower()
    exact = next((a for a in apps if a.domain.split("/")[0].lower() == host), None)
    if exact is not None:
        return exact
    for app in apps:
        domain = app.domain.split("/")[0].lower()
        if domain.startswith("*.") and host.endswith(domain[1:]):
            return app
    return None


def review(data: AccountData, now: datetime | None = None) -> list[Finding]:
    """Tous les constats, du plus grave au moins grave."""
    moment = now or datetime.now(UTC)
    findings: list[Finding] = []
    tunnel_ids = {tunnel.id for tunnel, _rules, _catch in data.tunnels}
    for tunnel, rules, catch_all in data.tunnels:
        if tunnel.status == "inactive":
            findings.append(Finding("inactive_tunnel", "low", tunnel.name, tunnel.id))
        if not catch_all.startswith("http_status:"):
            findings.append(Finding("exposed_catch_all", "medium", tunnel.name, tunnel.id, "catch_all_404"))
        for rule in rules:
            if rule.hostname.startswith("*."):
                continue
            label = rule.hostname + rule.path
            app = covering_app(rule.hostname, data.apps)
            if app is None:
                findings.append(
                    Finding("unprotected", "high", label, rule.hostname, "protect", (tunnel.id, rule.path))
                )
            elif app.aud and not _access_required(rule):
                findings.append(
                    Finding(
                        "access_not_required",
                        "low",
                        label,
                        rule.hostname,
                        "require_access",
                        (tunnel.id, rule.path, app.aud),
                    )
                )
    for policy in data.policies:
        opened = policy.decision == "allow" and any(rule.kind == "everyone" for rule in policy.include)
        if opened and (policy.app_count or 0) > 0:
            findings.append(Finding("everyone_allow", "high", policy.name, policy.id))
        if policy.reusable and policy.app_count == 0:
            findings.append(Finding("unused_policy", "low", policy.name, policy.id, "delete_policy"))
    for app in data.apps:
        if app.policy_count == 0:
            findings.append(Finding("app_without_policy", "low", app.name, app.id))
    for token in data.tokens:
        expires = _moment(token.expires_at) if token.expires_at else None
        if expires is not None and expires < moment:
            findings.append(Finding("token_expired", "medium", token.name, token.id, "delete_token"))
            continue
        seen = _moment(token.last_seen_at) if token.last_seen_at else None
        created = _moment(token.created_at) if token.created_at else None
        # Jamais utilisé : seulement s'il existe depuis assez longtemps (un token tout neuf n'a pas encore servi).
        idle_since = seen or created
        if idle_since is not None and idle_since < moment - UNUSED_AFTER:
            findings.append(Finding("token_unused", "medium", token.name, token.id, "delete_token"))
    for zone_id, record in data.records:
        content = str(record.get("content", "")).lower()
        target = content.removesuffix(".cfargotunnel.com")
        if record.get("type") == "CNAME" and content != target and target not in tunnel_ids:
            findings.append(
                Finding(
                    "dangling_dns",
                    "medium",
                    str(record.get("name", "")),
                    str(record.get("id", "")),
                    "delete_dns",
                    (zone_id,),
                )
            )
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 3), f.title(), f.target.lower()))


def severity_label(severity: str) -> str:
    return {"high": tr("Élevée"), "medium": tr("Moyenne"), "low": tr("Faible")}.get(severity, severity)
