"""Bilan de sécurité : chaque constat, sa gravité et sa correction, sur des données construites."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cma.core.cfapi import AccessApp, IngressRule, RemoteServiceToken, Tunnel
from cma.core.policies import AccessPolicy, PolicyRule
from cma.core.security import AccountData, covering_app, review, severity_label

NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)


def iso(delta: timedelta) -> str:
    return (NOW - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_covering_app_exact_then_wildcard():
    apps = [
        AccessApp("a1", "Tout", "*.exemple.fr", "self_hosted"),
        AccessApp("a2", "Wiki", "wiki.exemple.fr/doc", "self_hosted"),
    ]
    assert covering_app("WIKI.exemple.fr", apps).id == "a2"  # type: ignore[union-attr]
    assert covering_app("ssh.exemple.fr", apps).id == "a1"  # type: ignore[union-attr]
    assert covering_app("exemple.org", apps) is None


def test_review_finds_each_problem():
    bureau = Tunnel("t1", "bureau", "healthy")
    vieux = Tunnel("t9", "vieux", "inactive")
    data = AccountData(
        tunnels=[
            (
                bureau,
                [
                    IngressRule("ouvert.exemple.fr", "http://localhost:80"),
                    IngressRule("wiki.exemple.fr", "http://localhost:8080"),
                    IngressRule("sur.exemple.fr", "http://localhost:81", "", {"access": {"required": True}}),
                    IngressRule("*.lab.exemple.fr", "http://localhost:82"),
                ],
                "http://localhost:3000",
            ),
            (vieux, [], "http_status:404"),
        ],
        apps=[
            AccessApp("a1", "Wiki", "wiki.exemple.fr", "self_hosted", 1, aud="aud-wiki"),
            AccessApp("a2", "Sûr", "sur.exemple.fr", "self_hosted", 1, aud="aud-sur"),
            AccessApp("a3", "Vide", "vide.exemple.fr", "self_hosted", 0),
        ],
        policies=[
            AccessPolicy("p1", "Ouverte", "allow", (PolicyRule("everyone"),), reusable=True, app_count=2),
            AccessPolicy(
                "p2", "Orpheline", "allow", (PolicyRule("email", "a@x.fr"),), reusable=True, app_count=0
            ),
            AccessPolicy(
                "p3",
                "Ouverte mais inutilisée",
                "allow",
                (PolicyRule("everyone"),),
                reusable=True,
                app_count=0,
            ),
        ],
        tokens=[
            RemoteServiceToken("s1", "Expiré", "s1.access", iso(timedelta(days=1)), iso(timedelta(days=2))),
            RemoteServiceToken(
                "s2", "Oublié", "s2.access", iso(-timedelta(days=200)), iso(timedelta(days=120))
            ),
            RemoteServiceToken(
                "s3", "Jamais servi", "s3.access", iso(-timedelta(days=200)), "", iso(timedelta(days=100))
            ),
            RemoteServiceToken(
                "s4", "Tout neuf", "s4.access", iso(-timedelta(days=300)), "", iso(timedelta(days=2))
            ),
            RemoteServiceToken(
                "s5", "Actif", "s5.access", iso(-timedelta(days=300)), iso(timedelta(hours=3))
            ),
        ],
        records=[
            (
                "z1",
                {
                    "id": "r1",
                    "type": "CNAME",
                    "name": "ancien.exemple.fr",
                    "content": "t-supprime.cfargotunnel.com",
                },
            ),
            (
                "z1",
                {"id": "r2", "type": "CNAME", "name": "wiki.exemple.fr", "content": "t1.cfargotunnel.com"},
            ),
            ("z1", {"id": "r3", "type": "A", "name": "www.exemple.fr", "content": "203.0.113.1"}),
        ],
    )
    findings = review(data, NOW)
    seen = [(f.severity, f.kind, f.target, f.fix) for f in findings]
    assert seen == [
        ("high", "unprotected", "ouvert.exemple.fr", "protect"),
        ("high", "everyone_allow", "Ouverte", ""),
        ("medium", "dangling_dns", "ancien.exemple.fr", "delete_dns"),
        ("medium", "exposed_catch_all", "bureau", "catch_all_404"),
        ("medium", "token_expired", "Expiré", "delete_token"),
        ("medium", "token_unused", "Jamais servi", "delete_token"),
        ("medium", "token_unused", "Oublié", "delete_token"),
        ("low", "access_not_required", "wiki.exemple.fr", "require_access"),
        ("low", "app_without_policy", "Vide", ""),
        ("low", "unused_policy", "Orpheline", "delete_policy"),
        ("low", "unused_policy", "Ouverte mais inutilisée", "delete_policy"),
        ("low", "inactive_tunnel", "vieux", ""),
    ]
    by_kind = {f.kind: f for f in findings}
    assert by_kind["access_not_required"].data == ("t1", "", "aud-wiki")
    assert by_kind["dangling_dns"].data == ("z1",) and by_kind["dangling_dns"].key == "r1"
    assert by_kind["unprotected"].data == ("t1", "")
    for finding in findings:
        assert (finding.title() and finding.target in finding.detail()) or finding.kind == "unprotected"
    assert by_kind["unprotected"].fix_label() == "Protéger par Access"
    assert by_kind["everyone_allow"].fix_label() == ""
    assert [severity_label(s) for s in ("high", "medium", "low")] == ["Élevée", "Moyenne", "Faible"]


def test_clean_account_has_no_finding():
    tunnel = Tunnel("t1", "bureau", "healthy")
    data = AccountData(
        tunnels=[
            (
                tunnel,
                [IngressRule("app.exemple.fr", "http://x:1", "", {"access": {"required": True}})],
                "http_status:404",
            )
        ],
        apps=[AccessApp("a1", "App", "app.exemple.fr", "self_hosted", 1, aud="aud")],
        policies=[],
        tokens=[RemoteServiceToken("s1", "Actif", "s1.access", "", iso(timedelta(days=1)))],
        records=[
            ("z1", {"id": "r1", "type": "CNAME", "name": "app.exemple.fr", "content": "t1.cfargotunnel.com"})
        ],
    )
    assert review(data, NOW) == []
