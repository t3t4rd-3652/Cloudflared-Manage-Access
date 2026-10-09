"""Réseaux privés d'un tunnel (WARP) : plages d'adresses routées par le tunnel, réseaux virtuels, routage WARP.

Un appareil muni du client WARP de l'organisation atteint une adresse privée (10.0.0.5, 192.168.1.0/24…) à travers
le tunnel qui route sa plage. Il faut deux choses : une route (`/teamnet/routes`, plage CIDR → tunnel, dans un réseau
virtuel) et le routage WARP activé dans la configuration du tunnel (`warp-routing.enabled`). Permission :
« Cloudflare Tunnel : Read » pour lire, « Edit » pour modifier.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, cast

from cma.core.cfapi import CloudflareApi, Tunnel
from cma.i18n import tr


@dataclass(frozen=True)
class VirtualNetwork:
    id: str
    name: str
    is_default: bool = False


@dataclass(frozen=True)
class PrivateRoute:
    id: str
    network: str
    tunnel_id: str
    virtual_network_id: str = ""
    virtual_network_name: str = ""
    comment: str = ""


def normalize_network(text: str) -> str:
    """Plage CIDR canonique : « 10.0.0.5 » → « 10.0.0.5/32 », « 192.168.1.7/24 » → « 192.168.1.0/24 ».
    ValueError (message lisible) si le texte n'est pas une adresse ou une plage."""
    value = text.strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(
            tr("« {value} » n'est ni une adresse IP ni une plage CIDR (exemple : 10.0.0.0/24).").format(
                value=value
            )
        ) from exc
    return str(network)


def is_private(network: str) -> bool:
    """Plage d'adresses privées (RFC 1918, ULA…) : une route vers une plage publique est permise mais inhabituelle."""
    return ipaddress.ip_network(network, strict=False).is_private


def _route(item: dict[str, Any]) -> PrivateRoute:
    return PrivateRoute(
        id=str(item.get("id", "")),
        network=str(item.get("network", "")),
        tunnel_id=str(item.get("tunnel_id", "")),
        virtual_network_id=str(item.get("virtual_network_id") or ""),
        virtual_network_name=str(item.get("virtual_network_name") or ""),
        comment=str(item.get("comment") or ""),
    )


def list_routes(api: CloudflareApi, account_id: str, tunnel_id: str | None = None) -> list[PrivateRoute]:
    params: dict[str, Any] = {"is_deleted": "false"}
    if tunnel_id:
        params["tunnel_id"] = tunnel_id
    routes = [_route(item) for item in api.get_list(f"/accounts/{account_id}/teamnet/routes", params)]
    return sorted(routes, key=lambda r: (r.tunnel_id, r.network))


def list_virtual_networks(api: CloudflareApi, account_id: str) -> list[VirtualNetwork]:
    items = api.get_list(f"/accounts/{account_id}/teamnet/virtual_networks", {"is_deleted": "false"})
    networks = [
        VirtualNetwork(str(i.get("id", "")), str(i.get("name", "")), bool(i.get("is_default_network")))
        for i in items
    ]
    return sorted(networks, key=lambda n: (not n.is_default, n.name.lower()))


def create_route(
    api: CloudflareApi,
    account_id: str,
    tunnel_id: str,
    network: str,
    *,
    comment: str = "",
    virtual_network_id: str | None = None,
) -> PrivateRoute:
    body: dict[str, Any] = {"network": normalize_network(network), "tunnel_id": tunnel_id, "comment": comment}
    if virtual_network_id:
        body["virtual_network_id"] = virtual_network_id
    result = cast(dict[str, Any], api.send("POST", f"/accounts/{account_id}/teamnet/routes", body) or {})
    return _route(result)


def delete_route(api: CloudflareApi, account_id: str, route_id: str) -> None:
    api.send("DELETE", f"/accounts/{account_id}/teamnet/routes/{route_id}")


def warp_routing(config: dict[str, Any]) -> bool:
    return bool(cast(dict[str, Any], config.get("warp-routing") or {}).get("enabled"))


def set_warp_routing(api: CloudflareApi, account_id: str, tunnel: Tunnel, enabled: bool) -> None:
    """Active ou coupe le routage WARP du tunnel ; le reste de la configuration (règles d'ingress) est gardé."""
    config = api.tunnel_config(account_id, tunnel.id)
    config["warp-routing"] = {**cast(dict[str, Any], config.get("warp-routing") or {}), "enabled": enabled}
    api.send("PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel.id}/configurations", {"config": config})
