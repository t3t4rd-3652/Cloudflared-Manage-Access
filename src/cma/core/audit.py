"""Journal d'audit du compte Cloudflare : qui a modifié quoi, et quand (`/accounts/{id}/logs/audit`).

Distinct du journal des accès (connexions aux applications Access). Permission : « Account Settings : Read ».
Relevé sur un vrai compte : chaque entrée a une description lisible (« Delete a Cloudflare Tunnel »), un produit
(`access`, `cfd_tunnel`, `dns`…), un type de ressource, un auteur (utilisateur, jeton d'API ou Cloudflare lui-même)
et une origine (`dash`, `api_token`, `api`). La pagination se fait par curseur.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from cma.core.cfapi import CloudflareApi, CloudflareApiError
from cma.i18n import tr

AUDIT_LOG_PERMISSION = "Account Settings : Read"
PAGE_SIZE = 100


@dataclass(frozen=True)
class AuditEntry:
    time: str  # ISO 8601, UTC
    description: str
    action: str  # create, update, delete, view
    result: str  # success, failure
    product: str
    resource_type: str
    resource_id: str
    actor: str  # e-mail, nom du jeton, ou vide pour Cloudflare
    actor_type: str  # user, account, system
    context: str  # dash, api_token, api, oauth…

    @property
    def failed(self) -> bool:
        return self.result not in ("", "success")


def _entry(item: dict[str, Any]) -> AuditEntry:
    action = cast(dict[str, Any], item.get("action") or {})
    actor = cast(dict[str, Any], item.get("actor") or {})
    resource = cast(dict[str, Any], item.get("resource") or {})
    token = actor.get("token")
    token_name = str(cast(dict[str, Any], token).get("name") or "") if isinstance(token, dict) else ""
    return AuditEntry(
        time=str(action.get("time") or ""),
        description=str(action.get("description") or ""),
        action=str(action.get("type") or ""),
        result=str(action.get("result") or ""),
        product=str(resource.get("product") or ""),
        resource_type=str(resource.get("type") or ""),
        resource_id=str(resource.get("id") or ""),
        actor=str(actor.get("email") or token_name or ""),
        actor_type=str(actor.get("type") or ""),
        context=str(actor.get("context") or ""),
    )


def account_audit(
    api: CloudflareApi, account_id: str, *, days: int = 7, limit: int = 1000, now: datetime | None = None
) -> list[AuditEntry]:
    """Modifications des `days` derniers jours, de la plus récente à la plus ancienne (au plus `limit`)."""
    end = now or datetime.now(UTC)
    params: dict[str, Any] = {
        "since": (end - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "before": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "direction": "desc",
        "limit": min(PAGE_SIZE, limit),
    }
    entries: list[AuditEntry] = []
    try:
        while len(entries) < limit:
            payload = api.get(f"/accounts/{account_id}/logs/audit", params)
            items = cast(list[dict[str, Any]], payload.get("result") or [])
            entries.extend(_entry(i) for i in items)
            cursor = cast(dict[str, Any], payload.get("result_info") or {}).get("cursor")
            if not cursor or not items:
                break
            params = {**params, "cursor": cursor}
    except CloudflareApiError as exc:
        if exc.status == 403:
            raise CloudflareApiError(
                tr(
                    "Le jeton n'a pas la permission « {permission} » : ajoutez-la pour lire le journal d'audit."
                ).format(permission=AUDIT_LOG_PERMISSION),
                status=403,
                codes=exc.codes,
            ) from exc
        raise
    return entries[:limit]
