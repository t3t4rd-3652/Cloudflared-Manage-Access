"""Permissions du jeton d'API : pour chaque fonction de CMA, la permission nécessaire et si elle fonctionne.

Chaque fonction est vérifiée par une lecture (rien n'est écrit sur le compte). Une permission « Edit » ne se vérifie
donc qu'en lecture : un refus d'écriture ne se découvre qu'au moment de modifier, et CMA le dit alors.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from cma.core.audit import AUDIT_LOG_PERMISSION, account_audit
from cma.core.cfapi import ANALYTICS_PERMISSION, AUDIT_PERMISSION, CloudflareApi, CloudflareApiError
from cma.core.privnet import list_routes
from cma.core.traffic import zone_traffic
from cma.i18n import tr


@dataclass(frozen=True)
class PermissionCheck:
    feature: str
    permission: str
    state: str  # ok, denied, error, skipped
    detail: str = ""
    optional: bool = False


@dataclass(frozen=True)
class _Check:
    feature: str
    permission: str
    call: Callable[[CloudflareApi, str, str | None], Any]  # (api, compte, première zone)
    needs_zone: bool = False
    optional: bool = False


def _checks() -> list[_Check]:
    def accounts(api: CloudflareApi, _a: str, _z: str | None) -> None:
        if not api.list_accounts():
            raise CloudflareApiError(tr("liste des comptes vide"), status=403)

    return [
        _Check(tr("Lire le compte"), "Account Settings : Read", accounts),
        _Check(tr("Zones (domaines)"), "Zone : Read", lambda api, a, _z: api.list_zones(a)),
        _Check(
            tr("DNS des noms publiés"),
            "DNS : Edit",
            lambda api, _a, z: api.zone_records(z or ""),
            needs_zone=True,
        ),
        _Check(
            tr("Tunnels et noms d'hôte"), "Cloudflare Tunnel : Edit", lambda api, a, _z: api.list_tunnels(a)
        ),
        _Check(tr("Réseaux privés"), "Cloudflare Tunnel : Edit", lambda api, a, _z: list_routes(api, a)),
        _Check(
            tr("Applications et politiques Access"),
            "Access: Apps and Policies : Edit",
            lambda api, a, _z: api.list_access_apps(a),
        ),
        _Check(
            tr("Service tokens"),
            "Access: Service Tokens : Edit",
            lambda api, a, _z: api.list_service_tokens(a),
        ),
        _Check(tr("Journal des accès"), AUDIT_PERMISSION, lambda api, a, _z: api.access_requests(a, 1)),
        _Check(
            tr("Journal d'audit du compte"),
            AUDIT_LOG_PERMISSION,
            lambda api, a, _z: account_audit(api, a, days=1, limit=1),
        ),
        _Check(
            tr("Trafic par nom d'hôte"),
            ANALYTICS_PERMISSION,
            lambda api, _a, z: zone_traffic(api, z or "", hours=1),
            needs_zone=True,
            optional=True,
        ),
    ]


def check_permissions(api: CloudflareApi, account_id: str) -> list[PermissionCheck]:
    """Toutes les vérifications, en parallèle, dans l'ordre des fonctions."""
    try:
        zones = api.list_zones(account_id)
    except CloudflareApiError:
        zones = []
    zone = zones[0].id if zones else None

    def run(check: _Check) -> PermissionCheck:
        if check.needs_zone and zone is None:
            return PermissionCheck(
                check.feature,
                check.permission,
                "skipped",
                tr("aucune zone lisible pour le vérifier"),
                check.optional,
            )
        try:
            check.call(api, account_id, zone)
        except CloudflareApiError as exc:
            state = "denied" if exc.status in (401, 403) else "error"
            return PermissionCheck(check.feature, check.permission, state, str(exc), check.optional)
        return PermissionCheck(check.feature, check.permission, "ok", "", check.optional)

    checks = _checks()
    with ThreadPoolExecutor(max_workers=len(checks), thread_name_prefix="cma-perm") as pool:
        return list(pool.map(run, checks))
