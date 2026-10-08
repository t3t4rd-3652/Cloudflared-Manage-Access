"""Surveillance des tunnels du compte : ce qui a changé d'un relevé à l'autre.

L'API donne l'état de chaque tunnel : « healthy », « degraded » (moins de connexions que prévu), « down » (plus
aucun connecteur, après en avoir eu) et « inactive » (jamais lancé, ou sans connecteur depuis longtemps). Seuls
« degraded » et « down » méritent une alerte : un tunnel inactif est en général un tunnel de côté, pas une panne.
"""

from __future__ import annotations

from dataclasses import dataclass

from cma.core.cfapi import Tunnel
from cma.i18n import tr

# Gravité de chaque état : une alerte quand elle augmente, un message de retour quand elle revient à zéro.
SEVERITY = {"healthy": 0, "inactive": 0, "degraded": 1, "down": 2}


def severity(status: str) -> int:
    return SEVERITY.get(status, 0)


def status_label(status: str) -> str:
    """Libellé d'un état de tunnel donné par l'API (« En ligne », « Dégradé »…)."""
    return {
        "healthy": tr("En ligne"),
        "degraded": tr("Dégradé"),
        "down": tr("Hors ligne"),
        "inactive": tr("Inactif"),
    }.get(status, status)


@dataclass(frozen=True)
class TunnelChange:
    tunnel: Tunnel
    previous: str | None  # état au relevé précédent ; None si le tunnel n'avait pas encore été vu

    @property
    def recovered(self) -> bool:
        return severity(self.tunnel.status) == 0

    @property
    def level(self) -> str:
        """Niveau de la notification : « success » (rétabli), « warning » (dégradé) ou « error » (hors ligne)."""
        return {0: "success", 1: "warning"}.get(severity(self.tunnel.status), "error")

    def message(self) -> str:
        name = self.tunnel.name
        if self.recovered:
            return tr("Le tunnel « {name} » est de nouveau en ligne.").format(name=name)
        if self.tunnel.status == "down":
            return tr(
                "Le tunnel « {name} » est hors ligne : plus aucun connecteur ne le relie à Cloudflare."
            ).format(name=name)
        return tr(
            "Le tunnel « {name} » est dégradé : ses connecteurs n'ont pas toutes leurs connexions."
        ).format(name=name)


class TunnelWatch:
    """Compare les relevés successifs. Signale un tunnel qui se dégrade (ou déjà en panne au premier relevé), puis
    son rétablissement ; un tunnel stable, nouveau en bonne santé ou supprimé ne produit rien."""

    def __init__(self) -> None:
        self._last: dict[str, str] = {}
        self._tunnels: list[Tunnel] = []

    @property
    def troubled(self) -> list[Tunnel]:
        """Tunnels dégradés ou hors ligne au dernier relevé, du plus grave au moins grave."""
        bad = [t for t in self._tunnels if severity(t.status) > 0]
        return sorted(bad, key=lambda t: (-severity(t.status), t.name.lower()))

    def update(self, tunnels: list[Tunnel]) -> list[TunnelChange]:
        changes: list[TunnelChange] = []
        for tunnel in tunnels:
            previous = self._last.get(tunnel.id)
            now, before = severity(tunnel.status), severity(previous) if previous is not None else 0
            # Rétabli seulement s'il est en ligne : hors ligne → inactif est un tunnel arrêté pour de bon.
            if now > before or (tunnel.status == "healthy" and before > 0):
                changes.append(TunnelChange(tunnel, previous))
        self._last = {t.id: t.status for t in tunnels}
        self._tunnels = list(tunnels)
        return changes

    def forget(self) -> None:
        """Changement de compte ou de jeton : les relevés précédents ne valent plus rien."""
        self._last.clear()
        self._tunnels = []


def troubled_summary(tunnels: list[Tunnel]) -> str:
    """« 1 tunnel hors ligne », « 2 tunnels en panne »… ; vide si tout va bien."""
    if not tunnels:
        return ""
    if len(tunnels) == 1:
        tunnel = tunnels[0]
        if tunnel.status == "down":
            return tr("Tunnel « {name} » hors ligne").format(name=tunnel.name)
        return tr("Tunnel « {name} » dégradé").format(name=tunnel.name)
    return tr("{n} tunnels en panne").format(n=len(tunnels))
