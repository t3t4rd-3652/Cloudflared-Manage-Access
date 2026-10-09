"""Outils du compte Cloudflare (P10) contre le faux serveur : réseaux privés, journal d'audit, trafic, instantanés,
permissions du jeton."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cma.core.audit import account_audit
from cma.core.cfadmin import CloudflareAdmin
from cma.core.cfapi import Account, CloudflareApi, CloudflareApiError, Tunnel
from cma.core.privnet import create_route, list_routes, list_virtual_networks, set_warp_routing, warp_routing
from cma.core.snapshot import diff_snapshots, take_snapshot
from cma.core.traffic import HostTraffic, zone_traffic
from tests.fakes.fake_cfapi import TOKEN, FakeCloudflare, FakeCloudflareServer

BUREAU = Tunnel("t1", "bureau", "healthy")
ACCOUNT = Account("acc1", "Mon compte")


@pytest.fixture
def cf():
    with FakeCloudflareServer(FakeCloudflare()) as server:
        yield server


@pytest.fixture
def api(cf):
    return CloudflareApi(TOKEN, base_url=cf.base_url)


@pytest.fixture
def admin(cf, store, secrets):
    return CloudflareAdmin(store, secrets, lambda _p, _a: None, base_url=cf.base_url)


def test_private_routes_and_warp_routing(cf, api):
    assert list_virtual_networks(api, "acc1")[0].is_default
    route = create_route(api, "acc1", "t1", "10.0.0.7/24", comment="LAN bureau")
    assert (route.network, route.tunnel_id, route.virtual_network_name) == ("10.0.0.0/24", "t1", "default")
    create_route(api, "acc1", "t2", "192.168.50.23")
    assert [r.network for r in list_routes(api, "acc1", "t1")] == ["10.0.0.0/24"]
    assert len(list_routes(api, "acc1")) == 2
    with pytest.raises(CloudflareApiError, match="already exists"):
        create_route(api, "acc1", "t1", "10.0.0.0/24")
    with pytest.raises(ValueError, match="ni une adresse IP"):
        create_route(api, "acc1", "t1", "bureau")
    # Routage WARP : activé sans toucher aux règles d'ingress.
    ingress = list(cf.state.configs["t1"]["ingress"])
    assert not warp_routing(api.tunnel_config("acc1", "t1"))
    set_warp_routing(api, "acc1", BUREAU, True)
    assert cf.state.configs["t1"]["warp-routing"] == {"enabled": True}
    assert cf.state.configs["t1"]["ingress"] == ingress


async def test_admin_private_network_enables_warp_with_the_first_route(cf, admin):
    await admin.connect(TOKEN)
    view = await admin.private_network(BUREAU)
    assert view.routes == [] and not view.warp_routing and view.virtual_networks[0].name == "default"
    route = await admin.add_route(BUREAU, "10.1.0.0/16", comment="Labo")
    view = await admin.private_network(BUREAU)
    assert view.warp_routing and [r.network for r in view.routes] == ["10.1.0.0/16"]
    await admin.remove_route(route)
    assert (await admin.private_network(BUREAU)).routes == []
    await admin.set_warp_routing(BUREAU, False)
    assert not (await admin.private_network(BUREAU)).warp_routing


def test_account_audit_pages_and_permission(cf, api):
    entries = account_audit(api, "acc1", limit=10)
    assert entries[0].description == "Update a Cloudflare Tunnel configuration"
    assert [(e.actor, e.context, e.product) for e in entries] == [
        ("alice@exemple.fr", "dash", "cfd_tunnel"),
        ("", "api_token", "access"),
        ("bob@exemple.fr", "api_token", "access"),
    ]
    # Pages de 1 : le curseur suit, la limite coupe.
    assert len(account_audit(api, "acc1", limit=2)) == 2
    from cma.core import audit

    original = audit.PAGE_SIZE
    audit.PAGE_SIZE = 1
    try:
        assert len(account_audit(api, "acc1", limit=10)) == 3
    finally:
        audit.PAGE_SIZE = original
    cf.state.audit_log_allowed = False
    with pytest.raises(CloudflareApiError, match="Account Settings : Read"):
        account_audit(api, "acc1")


def test_zone_traffic_and_missing_permission(cf, api):
    traffic = zone_traffic(api, "z1", now=datetime(2026, 10, 9, tzinfo=UTC))
    assert traffic["grafana.exemple.fr"] == HostTraffic(126, 6)
    assert traffic["ssh.exemple.fr"].error_rate == 0
    assert round(traffic["grafana.exemple.fr"].error_rate, 3) == 0.048
    cf.state.analytics_allowed = False
    with pytest.raises(CloudflareApiError, match="Analytics : Read") as caught:
        zone_traffic(api, "z1")
    assert caught.value.status == 403 and "com.cloudflare.api.token" not in str(caught.value)


async def test_overview_carries_routes_and_traffic(cf, admin):
    await admin.connect(TOKEN)
    cf.state.routes.append(
        {"id": "r1", "network": "10.0.0.0/24", "tunnel_id": "t1", "virtual_network_id": "vn1"}
    )
    overview = await admin.overview(ACCOUNT)
    assert [r.network for r in overview.routes] == ["10.0.0.0/24"]
    assert overview.traffic["grafana.exemple.fr"].errors == 6 and overview.traffic_note == ""
    cf.state.analytics_allowed = False
    overview = await admin.overview(ACCOUNT)
    assert overview.traffic == {} and "Analytics : Read" in overview.traffic_note
    assert len(overview.tunnels) == 2  # le reste de la lecture n'en souffre pas


def test_snapshot_and_diff(cf, api):
    first = take_snapshot(api, ACCOUNT, now=datetime(2026, 10, 9, 8, tzinfo=UTC))
    assert first["account"] == {"id": "acc1", "name": "Mon compte"} and first["unreadable"] == []
    assert set(first["tunnels"]) == {"t1", "t2"} and "status" not in first["tunnels"]["t1"]
    assert first["tunnels"]["t1"]["config"]["ingress"][0]["hostname"] == "ssh.exemple.fr"
    # Rien n'a changé (seul l'état du tunnel bouge) : aucune différence.
    cf.state.tunnels[1]["status"] = "healthy"
    assert diff_snapshots(first, take_snapshot(api, ACCOUNT)) == []
    # Une règle modifiée dans le tableau de bord, une application supprimée, une route ajoutée.
    cf.state.configs["t1"]["ingress"][2]["service"] = "http://localhost:3001"
    cf.state.apps.clear()
    cf.state.routes.append({"id": "r1", "network": "10.0.0.0/24", "tunnel_id": "t1"})
    changes = diff_snapshots(first, take_snapshot(api, ACCOUNT))
    assert [(c.section, c.name, c.kind) for c in changes] == [
        ("tunnels", "bureau", "changed"),
        ("apps", "SSH", "removed"),
        ("routes", "10.0.0.0/24", "added"),
    ]
    assert changes[0].details == (
        "config.ingress[2].service : http://localhost:3000 → http://localhost:3001",
    )
    # Section illisible : notée, et pas comparée.
    cf.state.audit_log_allowed = False
    cf.state.zones_forbidden = True
    partial = take_snapshot(api, ACCOUNT)
    assert partial["unreadable"] == ["dns"]
    assert all(c.section != "dns" for c in diff_snapshots(first, partial))


async def test_permissions_panel(cf, admin):
    await admin.connect(TOKEN)
    checks = {c.feature: c for c in await admin.permissions()}
    assert all(c.state == "ok" for c in checks.values()), [c for c in checks.values() if c.state != "ok"]
    cf.state.analytics_allowed = False
    cf.state.audit_allowed = False
    checks = {c.feature: c for c in await admin.permissions()}
    assert checks["Trafic par nom d'hôte"].state == "denied" and checks["Trafic par nom d'hôte"].optional
    assert checks["Journal des accès"].state == "denied"
    assert checks["Tunnels et noms d'hôte"].state == "ok"
    cf.state.zones_forbidden = True
    checks = {c.feature: c for c in await admin.permissions()}
    assert checks["DNS des noms publiés"].state == "skipped" and checks["Zones (domaines)"].state == "denied"


async def test_cli_snapshot_reports_changes(cf, admin, paths, secrets, capsys):
    import asyncio

    from cma.cli import take_snapshot_cli

    def run() -> int:
        return take_snapshot_cli(paths, secrets=secrets, base_url=cf.base_url)

    assert await asyncio.to_thread(run) == 1  # sans jeton ni compte choisi
    assert "Aucun compte Cloudflare sélectionné" in capsys.readouterr().err
    await admin.connect(TOKEN)
    assert await asyncio.to_thread(run) == 0  # premier instantané
    assert "Instantané enregistré" in capsys.readouterr().out
    await asyncio.sleep(1.1)  # nom de fichier à la seconde
    assert await asyncio.to_thread(run) == 0
    assert "Aucun changement depuis le précédent." in capsys.readouterr().out
    cf.state.apps.clear()
    await asyncio.sleep(1.1)
    assert await asyncio.to_thread(run) == 2
    assert "- Applications Access · SSH" in capsys.readouterr().out
    assert len(list((paths.data_dir / "snapshots").glob("acc1-*.json"))) == 3


async def test_security_review_and_fixes(cf, admin):
    from cma.core.cfapi import IngressRule

    await admin.connect(TOKEN)
    cf.state.configs["t1"]["ingress"][-1] = {"service": "http://localhost:9999"}  # règle finale ouverte
    cf.state.dns["z1"].append(
        {
            "id": "orphelin",
            "type": "CNAME",
            "name": "ancien.exemple.fr",
            "content": "t-vieux.cfargotunnel.com",
        }
    )
    cf.state.service_tokens.append(
        {
            "id": "tok9",
            "name": "Oublié",
            "client_id": "tok9.access",
            "expires_at": "2030-01-01T00:00:00Z",
            "created_at": "2025-01-01T00:00:00Z",
            "last_seen_at": "2025-02-01T00:00:00Z",
        }
    )
    findings = await admin.security_review()
    kinds = {(f.kind, f.target) for f in findings}
    assert ("unprotected", "rdp.exemple.fr") in kinds and ("unprotected", "grafana.exemple.fr") in kinds
    assert ("access_not_required", "ssh.exemple.fr") in kinds
    assert ("exposed_catch_all", "bureau") in kinds and ("dangling_dns", "ancien.exemple.fr") in kinds
    assert ("token_unused", "Oublié") in kinds
    fixable = [f for f in findings if f.fix]
    results = await admin.fix_findings(fixable)
    assert [(f.kind, error) for f, error in results if error] == []
    assert cf.state.configs["t1"]["ingress"][-1] == {"service": "http_status:404"}
    assert all(r["id"] != "orphelin" for r in cf.state.dns["z1"])
    assert all(t["id"] != "tok9" for t in cf.state.service_tokens)
    assert {a["domain"] for a in cf.state.apps} >= {"rdp.exemple.fr", "grafana.exemple.fr"}
    ssh_rule = next(r for r in cf.state.configs["t1"]["ingress"] if r.get("hostname") == "ssh.exemple.fr")
    assert ssh_rule["originRequest"]["access"] == {
        "required": True,
        "teamName": "exemple",
        "audTag": ["aud-ssh-0123456789"],
    }
    # Refait : il ne reste que ce qui n'a pas de correction automatique (ou les nouvelles applications sans
    # politique, fermées à tous).
    assert {f.kind for f in await admin.security_review()} <= {"app_without_policy", "access_not_required"}
    # Retirer l'exigence ; sans la permission d'organisation, une erreur qui la nomme.
    rule = IngressRule("ssh.exemple.fr", "ssh://localhost:22")
    await admin.require_access(BUREAU, rule, False)
    ssh_rule = next(r for r in cf.state.configs["t1"]["ingress"] if r.get("hostname") == "ssh.exemple.fr")
    assert "originRequest" not in ssh_rule
    cf.state.organization_allowed = False
    with pytest.raises(CloudflareApiError, match="Organizations"):
        await admin.require_access(BUREAU, rule, True)
    with pytest.raises(CloudflareApiError, match="aucune application"):
        await admin.require_access(BUREAU, IngressRule("inconnu.exemple.fr", "http://x:1"), True)


async def test_watch_uses_its_own_token(cf, admin, store):
    await admin.connect(TOKEN)
    assert admin.watch_api()._token == TOKEN
    cf.state.other_tokens = ("jeton-lecture-seule-assez-long",)
    await admin.connect("jeton-lecture-seule-assez-long", "Surveillance")
    reader = next(t for t in admin.tokens() if t.name == "Surveillance")
    admin.switch_token(admin.tokens()[0].id)
    store.update(lambda c: setattr(c.settings, "watch_token_id", reader.id))
    assert admin.watch_api()._token == "jeton-lecture-seule-assez-long" and admin.api()._token == TOKEN
    assert len(await admin.tunnel_states()) == 2
    store.update(lambda c: setattr(c.settings, "watch_token_id", "disparu"))
    assert admin.watch_api()._token == TOKEN
