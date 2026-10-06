"""Diagnostic d'un tunnel d'après ses connecteurs : ce qui explique un état « Dégradé » ou « Hors ligne ».

cloudflared ouvre normalement 4 connexions vers deux centres de données Cloudflare (port 7844, QUIC ou HTTP/2).
"""

from __future__ import annotations

from dataclasses import dataclass

from cma.core.cfapi import Connector
from cma.i18n import tr

EXPECTED_CONNECTIONS = 4


@dataclass(frozen=True)
class Finding:
    level: str  # « success », « info », « warning » ou « error »
    message: str


def diagnose_connectors(connectors: list[Connector]) -> list[Finding]:
    """Constats, du plus grave au plus anodin ; un seul constat « success » si tout va bien."""
    if not connectors:
        return [
            Finding(
                "error",
                tr(
                    "Aucun connecteur : cloudflared ne tourne pas sur le serveur, ou n'arrive pas à joindre "
                    "Cloudflare (port 7844 sortant)."
                ),
            )
        ]
    findings: list[Finding] = []
    for connector in connectors:
        active = [c for c in connector.connections if not c.pending_reconnect]
        where = connector.origin_ip or connector.id[:8]
        if not active:
            findings.append(
                Finding(
                    "error",
                    tr("Le connecteur {where} n'a aucune connexion active vers Cloudflare.").format(
                        where=where
                    ),
                )
            )
        elif len(active) < EXPECTED_CONNECTIONS:
            findings.append(
                Finding(
                    "warning",
                    tr(
                        "Le connecteur {where} n'a que {n} connexion(s) active(s) sur {expected} : réseau instable "
                        "ou pare-feu qui filtre le port 7844."
                    ).format(where=where, n=len(active), expected=EXPECTED_CONNECTIONS),
                )
            )
    pending = sum(1 for k in connectors for c in k.connections if c.pending_reconnect)
    if pending:
        findings.append(Finding("warning", tr("{n} connexion(s) en cours de reconnexion.").format(n=pending)))
    versions = sorted({k.version for k in connectors if k.version})
    if len(versions) > 1:
        findings.append(
            Finding(
                "info",
                tr("Les connecteurs n'ont pas tous la même version de cloudflared : {versions}.").format(
                    versions=", ".join(versions)
                ),
            )
        )
    order = {"error": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f.level])
    if not any(f.level in ("error", "warning") for f in findings):
        total = sum(len(k.connections) for k in connectors)
        findings.insert(
            0,
            Finding(
                "success",
                tr("{n} connecteur(s) en ligne, {total} connexion(s) vers Cloudflare.").format(
                    n=len(connectors), total=total
                ),
            ),
        )
    return findings
