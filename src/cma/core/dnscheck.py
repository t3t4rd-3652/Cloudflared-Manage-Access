"""DNS des noms d'hôte publiés : ce qui empêche un nom d'hôte de joindre son tunnel.

Un nom d'hôte publié par un tunnel a besoin d'un CNAME `<id du tunnel>.cfargotunnel.com`, proxifié par
Cloudflare. CMA le crée à la publication ; ici, on vérifie qu'il est toujours là et qu'il vise le bon tunnel.
Fonctions pures : les enregistrements sont lus ailleurs (une lecture par zone).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from cma.core.cfapi import Tunnel, Zone
from cma.i18n import tr

TUNNEL_SUFFIX = ".cfargotunnel.com"
ADDRESS_TYPES = ("A", "AAAA", "CNAME")


@dataclass(frozen=True)
class DnsCheck:
    # « ok », « missing », « other_tunnel », « not_proxied », « other_record », « no_zone » ou « unknown »
    state: str
    detail: str = ""  # tunnel visé (nom ou début d'identifiant), ou type et cible de l'enregistrement

    @property
    def ok(self) -> bool:
        """Rien à signaler : correct, ou état inconnu (DNS illisible : pas d'alerte sans certitude)."""
        return self.state in ("ok", "unknown")

    @property
    def fixable(self) -> bool:
        """Corrigeable par CMA : créer le CNAME, le faire viser ce tunnel ou le proxifier. Un enregistrement A, AAAA
        ou un CNAME vers ailleurs n'est jamais remplacé d'office."""
        return self.state in ("missing", "other_tunnel", "not_proxied")

    def label(self) -> str:
        """Texte court de la pastille."""
        return {
            "missing": tr("DNS manquant"),
            "other_tunnel": tr("DNS vers {tunnel}").format(tunnel=self.detail),
            "not_proxied": tr("DNS non proxifié"),
            "other_record": tr("DNS : {record}").format(record=self.detail),
            "no_zone": tr("Zone absente du compte"),
        }.get(self.state, "")

    def explanation(self, hostname: str) -> str:
        return {
            "missing": tr("Aucun enregistrement DNS pour {host} : le nom ne mène nulle part."),
            "other_tunnel": tr(
                "Le CNAME de {host} vise le tunnel {tunnel}, pas celui-ci : les visiteurs arrivent sur l'autre tunnel."
            ),
            "not_proxied": tr(
                "Le CNAME de {host} n'est pas proxifié par Cloudflare : il ne peut pas joindre le tunnel."
            ),
            "other_record": tr(
                "{host} a un enregistrement {tunnel} : il ne passe pas par le tunnel. Supprimez-le dans Cloudflare "
                "avant de corriger."
            ),
            "no_zone": tr("Aucune zone du compte ne contient {host}."),
        }.get(self.state, "").format(host=hostname, tunnel=self.detail)


def zone_of(hostname: str, zones: Iterable[Zone]) -> Zone | None:
    """Zone la plus précise qui contient `hostname` (app.lab.exemple.fr → lab.exemple.fr plutôt que exemple.fr)."""
    hostname = hostname.lower().rstrip(".")
    matches = [z for z in zones if hostname == z.name or hostname.endswith("." + z.name)]
    return max(matches, key=lambda z: len(z.name), default=None)


def check_hostname(
    hostname: str,
    tunnel: Tunnel,
    records: list[dict[str, Any]] | None,
    tunnel_names: dict[str, str],
) -> DnsCheck:
    """État du DNS de `hostname`, publié par `tunnel`, d'après les enregistrements de ce nom dans sa zone.

    `records` vaut None quand la zone n'a pas pu être lue (état inconnu). `tunnel_names` donne le nom des tunnels
    du compte par identifiant, pour dire vers lequel pointe un CNAME égaré.
    """
    if records is None:
        return DnsCheck("unknown")
    name = hostname.lower().rstrip(".")
    address = [
        r
        for r in records
        if str(r.get("name", "")).lower().rstrip(".") == name and r.get("type") in ADDRESS_TYPES
    ]
    if not address:
        return DnsCheck("missing")
    cname = next((r for r in address if r.get("type") == "CNAME"), None)
    if cname is None:
        return DnsCheck("other_record", str(address[0].get("type")))
    target = str(cname.get("content", "")).lower().rstrip(".")
    if target == tunnel.cname_target:
        return DnsCheck("ok") if cname.get("proxied") else DnsCheck("not_proxied")
    if target.endswith(TUNNEL_SUFFIX):
        other = target.removesuffix(TUNNEL_SUFFIX)
        return DnsCheck("other_tunnel", tunnel_names.get(other, other[:8]))
    return DnsCheck("other_record", f"CNAME → {target}")


def check_all(
    rules: Iterable[tuple[Tunnel, str]],
    zones: list[Zone],
    records_by_zone: dict[str, list[dict[str, Any]] | None],
    tunnel_names: dict[str, str],
) -> dict[str, DnsCheck]:
    """État du DNS de chaque nom d'hôte publié (clé : nom d'hôte en minuscules). Une zone absente de
    `records_by_zone` ou lue sans succès (None) donne « unknown »."""
    result: dict[str, DnsCheck] = {}
    for tunnel, hostname in rules:
        key = hostname.lower()
        if key in result:
            continue
        zone = zone_of(hostname, zones)
        if zone is None:
            result[key] = DnsCheck("no_zone")
            continue
        result[key] = check_hostname(hostname, tunnel, records_by_zone.get(zone.id), tunnel_names)
    return result
