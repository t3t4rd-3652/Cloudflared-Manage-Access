"""Diagnostic d'un tunnel d'après ses connecteurs."""

from __future__ import annotations

from cma.core.cfapi import Connector, EdgeConnection
from cma.core.tunnelhealth import diagnose_connectors


def connector(n: int, *, version: str = "2026.9.0", pending: int = 0, ip: str = "203.0.113.10") -> Connector:
    connections = tuple(EdgeConnection("cdg01", ip, "2026-10-01T08:00:01Z", i < pending) for i in range(n))
    return Connector(f"id-{ip}", version, "linux_amd64", "2026-10-01T08:00:00Z", connections)


def levels(connectors: list[Connector]) -> list[str]:
    return [f.level for f in diagnose_connectors(connectors)]


def test_no_connector_means_cloudflared_is_not_running():
    findings = diagnose_connectors([])
    assert [f.level for f in findings] == ["error"] and "Aucun connecteur" in findings[0].message


def test_healthy_tunnel():
    findings = diagnose_connectors([connector(4), connector(4, ip="203.0.113.11")])
    assert [f.level for f in findings] == ["success"]
    assert "2 connecteur(s) en ligne, 8 connexion(s)" in findings[0].message


def test_degraded_tunnel_names_the_connector():
    findings = diagnose_connectors([connector(2), connector(0, ip="198.51.100.7")])
    assert [f.level for f in findings] == ["error", "warning"]
    # Sans connexion, l'origine est inconnue : le connecteur est désigné par son identifiant.
    assert "id-198.5 n'a aucune connexion" in findings[0].message
    assert "203.0.113.10 n'a que 2 connexion(s) active(s) sur 4" in findings[1].message


def test_pending_reconnections_and_mixed_versions():
    assert levels([connector(4, pending=1)]) == ["warning", "warning"]
    mixed = diagnose_connectors([connector(4), connector(4, version="2025.1.0", ip="203.0.113.11")])
    assert [f.level for f in mixed] == ["success", "info"] and "2025.1.0, 2026.9.0" in mixed[1].message
    assert Connector("abc", "", "", "").origin_ip == ""
