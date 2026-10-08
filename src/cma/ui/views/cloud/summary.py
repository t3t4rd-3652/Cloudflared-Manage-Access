"""Chiffres du compte Cloudflare affichés par la vue (tuiles, résumé) : calculés sans interface, testés à part."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from cma.core.cfadmin import Overview
from cma.core.cfapi import AccessApp
from cma.core.tunnelwatch import severity


def protected_hosts(apps: Iterable[AccessApp]) -> set[str]:
    """Noms d'hôte protégés par une application Access (sans le chemin, en minuscules)."""
    return {app.domain.split("/")[0].lower() for app in apps}


@dataclass(frozen=True)
class AccountStats:
    tunnels: int
    # Tunnels dégradés ou hors ligne : « inactif » n'est pas une panne, comme pour la surveillance.
    troubled: int
    hostnames: int
    zones: int
    apps: int
    unprotected: int  # noms d'hôte publiés qu'aucune application Access ne protège
    tokens: int
    tokens_in_cma: int  # service tokens du compte déjà rangés dans CMA (même Client ID)


def account_stats(overview: Overview, local_client_ids: set[str]) -> AccountStats:
    published = {rule.hostname.lower() for view in overview.tunnels for rule in view.hostnames}
    return AccountStats(
        tunnels=len(overview.tunnels),
        troubled=sum(1 for view in overview.tunnels if severity(view.tunnel.status)),
        hostnames=sum(len(view.hostnames) for view in overview.tunnels),
        zones=len(overview.zones),
        apps=len(overview.apps),
        unprotected=len(published - protected_hosts(overview.apps)),
        tokens=len(overview.tokens),
        tokens_in_cma=sum(1 for token in overview.tokens if token.client_id in local_client_ids),
    )
