"""Trafic des noms d'hôte publiés : requêtes et erreurs 5xx des dernières 24 heures, par l'API GraphQL.

Une requête par zone (`httpRequestsAdaptiveGroups`, groupée par nom d'hôte et code de réponse). Permission de zone
« Analytics : Read », facultative : sans elle, CMA ne montre simplement pas de trafic. Les 5xx comptés ici sont
ceux que Cloudflare a renvoyés au visiteur (502 d'un service arrêté, 530 d'un tunnel sans connecteur…).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from cma.core.cfapi import CloudflareApi

QUERY = """
query ($zone: string!, $since: Time!, $until: Time!) {
  viewer {
    zones(filter: {zoneTag: $zone}) {
      httpRequestsAdaptiveGroups(limit: 5000, filter: {datetime_geq: $since, datetime_lt: $until}) {
        count
        dimensions { clientRequestHTTPHost edgeResponseStatus }
      }
    }
  }
}
"""


@dataclass(frozen=True)
class HostTraffic:
    requests: int = 0
    errors: int = 0  # réponses 5xx

    @property
    def error_rate(self) -> float:
        return self.errors / self.requests if self.requests else 0.0


def zone_traffic(
    api: CloudflareApi, zone_id: str, *, hours: int = 24, now: datetime | None = None
) -> dict[str, HostTraffic]:
    """Trafic par nom d'hôte (en minuscules) de la zone sur les `hours` dernières heures."""
    end = now or datetime.now(UTC)
    variables = {
        "zone": zone_id,
        "since": (end - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "until": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    data = api.graphql(QUERY, variables)
    zones = cast(list[dict[str, Any]], cast(dict[str, Any], data.get("viewer") or {}).get("zones") or [])
    totals: dict[str, list[int]] = {}
    for zone in zones:
        for group in cast(list[dict[str, Any]], zone.get("httpRequestsAdaptiveGroups") or []):
            dimensions = cast(dict[str, Any], group.get("dimensions") or {})
            host = str(dimensions.get("clientRequestHTTPHost") or "").lower()
            if not host:
                continue
            count = int(group.get("count") or 0)
            counts = totals.setdefault(host, [0, 0])
            counts[0] += count
            if int(dimensions.get("edgeResponseStatus") or 0) >= 500:
                counts[1] += count
    return {host: HostTraffic(requests, errors) for host, (requests, errors) in totals.items()}
