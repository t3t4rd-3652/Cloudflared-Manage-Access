"""API Cloudflare (cfapi) et gestion du compte (cfadmin), contre un faux serveur en mémoire."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from cma.core.cfadmin import CloudflareAdmin, PublishRequest, connector_commands
from cma.core.cfapi import (
    TOKEN_SECRET_KEY,
    AccessApp,
    Account,
    CloudflareApi,
    CloudflareApiError,
    IngressRule,
    Tunnel,
    guess_service_from_ingress,
)
from cma.core.models import AuthMode, ServiceType
from cma.core.netutil import find_free_port
from cma.core.policies import AccessGroup, AccessPolicy, PolicyRule
from cma.core.redact import redact
from tests.fakes.fake_cfapi import TOKEN, FakeCloudflare, FakeCloudflareServer


@pytest.fixture
def cf():
    with FakeCloudflareServer() as server:
        yield server


@pytest.fixture
def api(cf):
    return CloudflareApi(TOKEN, base_url=cf.base_url)


@pytest.fixture
def admin(cf, store, secrets):
    def suggest(preferred, avoid):
        return find_free_port(preferred=preferred, port_range=(31000, 31999), avoid=avoid)

    return CloudflareAdmin(store, secrets, suggest, base_url=cf.base_url)


def test_authentication_and_errors(cf):
    with pytest.raises(CloudflareApiError) as refused:
        CloudflareApi("mauvais", base_url=cf.base_url).list_accounts()
    assert refused.value.status == 401
    assert "Authentication error" in str(refused.value)
    with pytest.raises(CloudflareApiError, match="manquant"):
        CloudflareApi("  ")
    with pytest.raises(CloudflareApiError, match="injoignable"):
        CloudflareApi(TOKEN, base_url="http://127.0.0.1:9/client/v4", timeout=2).list_accounts()
    with pytest.raises(CloudflareApiError, match="No route"):
        CloudflareApi(TOKEN, base_url=cf.base_url)._call("GET", "/inconnu")
    assert "jeton" not in repr(CloudflareApi(TOKEN, base_url=cf.base_url))


def test_reading_the_account(api):
    assert [a.name for a in api.list_accounts()] == ["Mon compte"]
    assert [z.name for z in api.list_zones("acc1")] == ["exemple.fr", "lab.exemple.fr"]
    assert api.zone_for_hostname("acc1", "db.lab.exemple.fr").name == "lab.exemple.fr"
    assert api.zone_for_hostname("acc1", "autre.org") is None
    tunnels = api.list_tunnels("acc1")
    assert [(t.name, t.status) for t in tunnels] == [("bureau", "healthy"), ("labo", "down")]
    assert [r.hostname for r in api.tunnel_hostnames("acc1", "t1")] == [
        "ssh.exemple.fr",
        "rdp.exemple.fr",
        "grafana.exemple.fr",
    ]
    assert [a.domain for a in api.list_access_apps("acc1")] == ["ssh.exemple.fr"]


def test_pagination_reads_every_page(cf, api):
    cf.state.service_tokens.extend(
        {"id": f"id{i}", "name": f"T{i:03}", "client_id": f"c{i}.access"} for i in range(120)
    )
    assert len(api.list_service_tokens("acc1")) == 120
    pages = [p for m, p in cf.state.requests if p.endswith("/service_tokens")]
    assert len(pages) == 3


def test_publish_and_unpublish_a_hostname(cf, api):
    tunnel = Tunnel("t2", "labo", "down")
    api.publish_hostname("acc1", tunnel, "PG.lab.exemple.fr", "tcp://localhost:5432")
    ingress = cf.state.configs["t2"]["ingress"]
    assert ingress == [
        {"hostname": "pg.lab.exemple.fr", "service": "tcp://localhost:5432"},
        {"service": "http_status:404"},
    ]
    record = cf.state.dns["z2"][0]
    assert (record["type"], record["content"], record["proxied"]) == ("CNAME", "t2.cfargotunnel.com", True)

    # Republier met à jour le service sans dupliquer la règle ni l'enregistrement DNS.
    api.publish_hostname("acc1", tunnel, "pg.lab.exemple.fr", "tcp://localhost:5433")
    assert len(cf.state.configs["t2"]["ingress"]) == 2
    assert len(cf.state.dns["z2"]) == 1

    cf.state.dns["z1"].append({"id": "a1", "type": "A", "name": "web.exemple.fr", "content": "1.2.3.4"})
    with pytest.raises(CloudflareApiError, match="enregistrement DNS A"):
        api.publish_hostname("acc1", tunnel, "web.exemple.fr", "http://localhost:80")
    with pytest.raises(CloudflareApiError, match="Aucune zone"):
        api.publish_hostname("acc1", tunnel, "x.autre.org", "http://localhost")

    api.unpublish_hostname("acc1", tunnel, "pg.lab.exemple.fr")
    assert [r for r in cf.state.configs["t2"]["ingress"] if r.get("hostname") == "pg.lab.exemple.fr"] == []
    assert cf.state.dns["z2"] == []


def test_access_apps_policies_and_service_tokens(cf, api):
    app = api.create_access_app("acc1", "Base", "db.exemple.fr")
    with pytest.raises(CloudflareApiError, match="already exists"):
        api.create_access_app("acc1", "Base", "db.exemple.fr")
    created = api.create_service_token("acc1", "Robot")
    assert created.client_secret.startswith("secret-")
    assert created.client_secret not in repr(created)

    # Une application nouvelle n'accepte plus de politique legacy : le token passe par une politique du compte.
    policy = api.allow_service_token("acc1", app.id, created.id, "CMA - Robot")
    [shared] = cf.state.account_policies
    assert shared["id"] == policy and shared["decision"] == "non_identity"
    assert shared["include"] == [{"service_token": {"token_id": created.id}}]
    assert api.app_policy_ids("acc1", app.id) == [policy]

    # Une deuxième application réutilise la même politique ; la redemander ne change rien.
    other = api.create_access_app("acc1", "Autre", "autre.exemple.fr")
    assert api.allow_service_token("acc1", other.id, created.id, "CMA - Robot") == policy
    puts = cf.state.app_puts
    api.allow_service_token("acc1", other.id, created.id, "CMA - Robot")
    assert len(cf.state.account_policies) == 1 and cf.state.app_puts == puts
    assert [p.app_count for p in api.list_account_policies("acc1")] == [2]
    assert [t.client_id for t in api.list_service_tokens("acc1")] == [created.client_id]


def test_ingress_service_parsing():
    assert guess_service_from_ingress("ssh://localhost:22") == ("ssh", 22)
    assert guess_service_from_ingress("http_status:404") == ("http_status", None)
    assert guess_service_from_ingress("tcp://h:99999") == ("tcp", None)


async def test_admin_connect_import_and_tokens(admin, store, secrets):
    assert not admin.has_token()
    with pytest.raises(CloudflareApiError, match="connectez-vous"):
        admin.api()
    with pytest.raises(CloudflareApiError):
        await admin.connect("mauvais")
    assert secrets.get(TOKEN_SECRET_KEY) is None

    accounts = await admin.connect(TOKEN)
    assert secrets.get(TOKEN_SECRET_KEY) == TOKEN
    assert store.snapshot().settings.cloudflare_account_id == accounts[0].id == admin.account_id()

    overview = await admin.overview(accounts[0])
    bureau = overview.tunnels[0]
    created = admin.import_profiles([(bureau.tunnel, rule) for rule in bureau.hostnames])
    assert [(p.name, p.group, p.service_type) for p in created] == [
        ("ssh", "bureau", ServiceType.SSH),
        ("rdp", "bureau", ServiceType.RDP),
        ("grafana", "bureau", ServiceType.HTTP),
    ]
    ports = [p.local_port for p in created]
    assert None not in ports and len(set(ports)) == 3
    assert admin.import_profiles([(bureau.tunnel, rule) for rule in bureau.hostnames]) == []

    token = await admin.create_service_token("Robot CMA")
    config_text = store.snapshot().model_dump_json()
    secret = secrets.get(token.secret_key)
    assert secret and secret.startswith("secret-") and secret not in config_text
    policy = await admin.allow_token(overview.apps[0], token.id)
    assert policy

    admin.forget()
    assert not admin.has_token()
    assert store.snapshot().settings.cloudflare_account_id is None


async def test_admin_finds_the_account_through_zones(store, secrets):
    """Jeton sans « Account Settings : Read » : /accounts est vide, le compte vient des zones."""

    def admin_for(server):
        return CloudflareAdmin(store, secrets, lambda *_a: None, base_url=server.base_url)

    with FakeCloudflareServer(FakeCloudflare(accounts=[])) as server:
        assert CloudflareApi(TOKEN, base_url=server.base_url).accounts_from_zones() == [
            Account("acc1", "Mon compte", inferred=True)
        ]
        admin = admin_for(server)
        accounts = await admin.connect(TOKEN)
        assert [(a.id, a.inferred) for a in accounts] == [("acc1", True)]
        assert admin.account_id() == "acc1" and secrets.get(TOKEN_SECRET_KEY) == TOKEN
        assert [v.tunnel.name for v in (await admin.overview(accounts[0])).tunnels] == ["bureau", "labo"]
    admin.forget()

    # Ni compte ni zone lisible : refus, qui nomme la permission manquante, et jeton non conservé.
    for state in (FakeCloudflare(accounts=[], zones=[]), FakeCloudflare(accounts=[], zones_forbidden=True)):
        with (
            FakeCloudflareServer(state) as server,
            pytest.raises(CloudflareApiError, match="Account Settings : Read"),
        ):
            await admin_for(server).connect(TOKEN)
        assert secrets.get(TOKEN_SECRET_KEY) is None


async def test_edit_a_published_hostname(cf, api, admin, store):
    bureau = Tunnel("t1", "bureau", "healthy")
    cf.state.configs["t1"]["ingress"][2]["originRequest"] = {"noTLSVerify": True}
    rule = api.update_hostname_service("acc1", bureau, "grafana.exemple.fr", "https://localhost:3443")
    assert (rule.hostname, rule.service) == ("grafana.exemple.fr", "https://localhost:3443")
    grafana = cf.state.configs["t1"]["ingress"][2]
    assert grafana == {
        "hostname": "grafana.exemple.fr",
        "service": "https://localhost:3443",
        "originRequest": {"noTLSVerify": True},
    }
    assert len(cf.state.configs["t1"]["ingress"]) == 4  # rien d'ajouté ni de retiré
    with pytest.raises(CloudflareApiError, match="n'est pas publié"):
        api.update_hostname_service("acc1", bureau, "absent.exemple.fr", "tcp://localhost:1")

    # Le profil CMA lié suit le changement de type de service ; son port local est gardé.
    await admin.connect(TOKEN)
    [profile] = admin.import_profiles([(bureau, IngressRule("rdp.exemple.fr", "rdp://10.0.0.5:3389"))])
    assert profile.service_type == ServiceType.RDP
    await admin.edit_hostname(bureau, "rdp.exemple.fr", "ssh://10.0.0.5:22")
    edited = store.snapshot().cloudflare_profile(profile.id)
    assert edited.service_type == ServiceType.SSH and edited.local_port == profile.local_port
    await admin.edit_hostname(
        bureau, "rdp.exemple.fr", "tcp://10.0.0.5:22"
    )  # schéma sans type : profil inchangé
    assert store.snapshot().cloudflare_profile(profile.id).service_type == ServiceType.SSH


def shared_policies(cf):
    """Le cas réel : des politiques réutilisables partagées, dont une avec des règles de connexion RDP."""
    cf.state.apps.append(
        {"id": "app2", "name": "Proxy", "domain": "proxy.exemple.fr", "type": "self_hosted", "policies": []}
    )
    cf.state.account_policies.extend(
        [
            {
                "id": "p1",
                "name": "without token",
                "decision": "allow",
                "include": [{"email": {"email": "moi@exemple.fr"}}],
                "exclude": [],
                "require": [],
                "reusable": True,
            },
            {
                "id": "p2",
                "name": "RDP",
                "decision": "non_identity",
                "include": [{"service_token": {"token_id": "tok1"}}],
                "exclude": [],
                "require": [],
                "connection_rules": {"rdp": {}},
                "reusable": True,
            },
        ]
    )
    app1 = cf.state.apps[0]
    app1.update({"session_duration": "12h", "app_launcher_visible": False})
    app1["policies"] = [{"id": "p1", "precedence": 1}, {"id": "p2", "precedence": 2}]
    cf.state.apps[1]["policies"] = [{"id": "p1", "precedence": 1}]


async def test_reusable_access_policies(cf, admin):
    shared_policies(cf)
    await admin.connect(TOKEN)
    app = AccessApp("app1", "SSH", "ssh.exemple.fr", "self_hosted")
    policies, groups = await admin.policies(app)
    assert [(p.name, p.reusable, p.app_count, p.shared, p.precedence) for p in policies] == [
        ("without token", True, 2, True, 1),
        ("RDP", True, 1, False, 2),
    ]
    assert groups == [AccessGroup("g1", "Admins")]
    assert policies[1].extra == {"connection_rules": {"rdp": {}}}

    # Modifier une politique réutilisable : dans le compte, champs inconnus de CMA conservés.
    rdp = policies[1]
    await admin.save_policy(
        app, replace(rdp, name="RDP Proxmox", include=(*rdp.include, PolicyRule("group", "g1")))
    )
    stored = next(p for p in cf.state.account_policies if p["id"] == "p2")
    assert stored["name"] == "RDP Proxmox" and stored["connection_rules"] == {"rdp": {}}
    assert stored["include"] == [{"service_token": {"token_id": "tok1"}}, {"group": {"id": "g1"}}]

    # Nouvelle politique : créée dans le compte et attachée en dernier ; les réglages de l'application restent.
    team = await admin.save_policy(
        app, AccessPolicy("", "Équipe", "allow", (PolicyRule("email_domain", "exemple.fr"),))
    )
    app1 = cf.state.apps[0]
    assert [link["id"] for link in app1["policies"]] == ["p1", "p2", team.id]
    assert (app1["session_duration"], app1["app_launcher_visible"], app1["domain"]) == (
        "12h",
        False,
        "ssh.exemple.fr",
    )

    # Retirer une politique partagée : elle quitte l'application, pas le compte ni les autres applications.
    await admin.remove_policy(app, policies[0])
    assert [link["id"] for link in app1["policies"]] == ["p2", team.id]
    assert cf.state.apps[1]["policies"] == [{"id": "p1", "precedence": 1}]
    account = {p.name: p.app_count for p in await admin.account_policies()}
    assert account == {"without token": 1, "RDP Proxmox": 1, "Équipe": 1}

    # Remettre une politique existante ; supprimer seulement une politique inutilisée.
    proxy = AccessApp("app2", "Proxy", "proxy.exemple.fr", "self_hosted")
    await admin.attach_policy(proxy, team)
    assert [link["id"] for link in cf.state.apps[1]["policies"]] == ["p1", team.id]
    in_use = next(p for p in await admin.account_policies() if p.id == "p1")
    with pytest.raises(CloudflareApiError, match="sert encore"):
        await admin.delete_account_policy(in_use)
    await admin.remove_policy(proxy, in_use)
    unused = next(p for p in await admin.account_policies() if p.id == "p1")
    await admin.delete_account_policy(unused)
    assert "p1" not in {p["id"] for p in cf.state.account_policies}

    # Sans le droit de lire les groupes, les politiques restent lisibles.
    cf.state.groups_forbidden = True
    policies, groups = await admin.policies(app)
    assert len(policies) == 2 and groups == []


async def test_legacy_access_policies(cf, admin):
    await admin.connect(TOKEN)
    app = AccessApp("app1", "SSH", "ssh.exemple.fr", "self_hosted")
    cf.state.policies["app1"] = [
        {"id": "l1", "name": "Ancienne", "decision": "allow", "include": [{"everyone": {}}], "precedence": 1}
    ]
    [legacy] = (await admin.policies(app))[0]
    assert not legacy.reusable and legacy.app_count is None
    await admin.save_policy(app, replace(legacy, name="Ancienne modifiée"))
    assert cf.state.policies["app1"][0]["name"] == "Ancienne modifiée"
    assert cf.state.policies["app1"][0]["precedence"] == 1
    # Une politique legacy présente : CMA ne modifie pas la liste par un PUT de l'application.
    with pytest.raises(CloudflareApiError, match="legacy"):
        await admin.save_policy(app, AccessPolicy("", "Nouvelle", "allow", (PolicyRule("everyone"),)))
    assert cf.state.account_policies == []  # refusé avant toute création
    await admin.remove_policy(app, legacy)
    assert cf.state.policies["app1"] == []


async def test_cleanup_tunnels_apps_and_tokens(cf, admin):
    await admin.connect(TOKEN)
    bureau, labo = Tunnel("t1", "bureau", "healthy"), Tunnel("t2", "labo", "down")
    renamed = await admin.rename_tunnel(labo, "atelier")
    assert renamed.name == "atelier" and cf.state.tunnels[1]["name"] == "atelier"
    with pytest.raises(CloudflareApiError, match="already have"):
        await admin.rename_tunnel(labo, "bureau")

    # Un tunnel en service n'est pas supprimé ; un tunnel arrêté l'est, avec ses CNAME vers lui.
    with pytest.raises(CloudflareApiError, match="1 connecteur"):
        await admin.delete_tunnel(bureau, ["ssh.exemple.fr"])
    api = admin.api()
    api.publish_hostname("acc1", labo, "pg.lab.exemple.fr", "tcp://localhost:5432")
    cf.state.dns["z1"].append(
        {"id": "autre", "type": "CNAME", "name": "www.exemple.fr", "content": "ailleurs.fr"}
    )
    assert await admin.delete_tunnel(labo, ["pg.lab.exemple.fr", "www.exemple.fr"]) == 1
    assert [t["id"] for t in cf.state.tunnels] == ["t1"]
    assert cf.state.dns["z2"] == [] and len(cf.state.dns["z1"]) == 1  # le CNAME d'autrui est gardé

    app = AccessApp("app1", "SSH", "ssh.exemple.fr", "self_hosted")
    await admin.delete_app(app)
    assert cf.state.apps == []
    token = await admin.create_service_token("Robot")
    [remote] = api.list_service_tokens("acc1")
    other = api.create_access_app("acc1", "Base", "db.exemple.fr")
    await admin.allow_token(other, token.id)  # crée la politique « CMA - Robot », attachée à « Base »

    # Cité par une politique encore utilisée : Cloudflare refuserait, CMA le dit avant et ne supprime rien.
    with pytest.raises(CloudflareApiError, match="CMA - Robot"):
        await admin.delete_remote_token(remote)
    assert len(cf.state.service_tokens) == 1 and len(cf.state.account_policies) == 1
    with pytest.raises(CloudflareApiError, match="service_token_in_use"):
        api.delete_service_token("acc1", remote.id)  # le faux serveur refuse comme Cloudflare

    # Une fois l'application supprimée, la politique ne sert plus qu'au token : elle part avec lui.
    await admin.delete_app(other)
    assert await admin.delete_remote_token(remote) == ["CMA - Robot"]
    assert cf.state.service_tokens == [] and cf.state.account_policies == []
    assert admin.store.snapshot().token(token.id) is not None  # la copie dans CMA reste


async def test_create_a_tunnel(cf, admin):
    await admin.connect(TOKEN)
    created = await admin.create_tunnel("nouveau")
    assert (created.tunnel.name, created.tunnel.status) == ("nouveau", "inactive")
    assert created.token and created.token not in repr(created)
    assert redact(f"jeton {created.token}") == "jeton " + redact(created.token) != f"jeton {created.token}"
    assert ("POST", "/accounts/acc1/cfd_tunnel") in cf.state.requests
    assert [t["name"] for t in cf.state.tunnels] == ["bureau", "labo", "nouveau"]
    commands = connector_commands(created.token)
    assert len(commands) == 3 and all(created.token in command for _system, command in commands)
    with pytest.raises(CloudflareApiError, match="already have a tunnel"):
        await admin.create_tunnel("nouveau")


async def test_tunnel_connectors(api, admin):
    [healthy] = api.tunnel_connectors("acc1", "t1")
    assert (healthy.version, healthy.arch, healthy.origin_ip) == ("2026.9.0", "linux_amd64", "203.0.113.10")
    assert [c.colo for c in healthy.connections] == ["cdg01", "cdg01", "ams01", "ams01"]
    assert not any(c.pending_reconnect for c in healthy.connections)
    await admin.connect(TOKEN)
    assert await admin.connectors(Tunnel("t2", "labo", "down")) == []
    # Relevé de la surveillance : une seule lecture, les tunnels du compte choisi avec leur état.
    assert [(t.name, t.status) for t in await admin.tunnel_states()] == [
        ("bureau", "healthy"),
        ("labo", "down"),
    ]


async def test_admin_tracks_expiry_extends_and_rotates_tokens(cf, admin, store, secrets):
    await admin.connect(TOKEN)
    token = await admin.create_service_token("Robot")
    assert token.expires_at == datetime(2027, 9, 29, tzinfo=UTC)
    first_secret = secrets.get(token.secret_key)

    # La lecture du compte recopie l'échéance connue chez Cloudflare (une écriture seulement si elle change).
    cf.state.service_tokens[0]["expires_at"] = "2026-11-01T00:00:00Z"
    overview = await admin.overview((await admin.connect())[0])
    assert store.snapshot().token(token.id).expires_at == datetime(2026, 11, 1, tzinfo=UTC)
    assert admin.sync_expirations(overview.tokens) == 0

    # Prolonger : nouvelle échéance, même secret.
    assert await admin.extend_token(overview.tokens[0]) == "2028-09-29T00:00:00Z"
    assert store.snapshot().token(token.id).expires_at == datetime(2028, 9, 29, tzinfo=UTC)
    assert secrets.get(token.secret_key) == first_secret

    # Changer le secret : même client_id, nouveau secret dans le coffre, jamais dans la configuration.
    rotated = await admin.rotate_token(token.id)
    new_secret = secrets.get(token.secret_key)
    assert rotated.client_id == token.client_id
    assert new_secret and new_secret != first_secret and new_secret not in store.snapshot().model_dump_json()

    # Un token absent du compte ou de CMA est refusé avec un message clair.
    cf.state.service_tokens.clear()
    with pytest.raises(CloudflareApiError, match="n'existe pas"):
        await admin.rotate_token(token.id)
    with pytest.raises(CloudflareApiError, match="introuvable"):
        await admin.rotate_token("inconnu")


async def test_admin_publish_protects_and_creates_the_profile(cf, admin, store):
    await admin.connect(TOKEN)
    token = await admin.create_service_token("Robot")
    tunnel = Tunnel("t2", "labo", "down")
    result = await admin.publish(
        PublishRequest(tunnel, "db.lab.exemple.fr", "tcp://localhost:5432", protect=True, token_id=token.id)
    )
    assert result.app is not None and result.app.domain == "db.lab.exemple.fr"
    [policy] = cf.state.account_policies
    assert policy["decision"] == "non_identity" and policy["include"] == [
        {"service_token": {"token_id": cf.state.service_tokens[0]["id"]}}
    ]
    assert admin.api().app_policy_ids("acc1", result.app.id) == [policy["id"]]
    profile = store.snapshot().cloudflare_profile(result.profile.id)
    assert profile.auth == AuthMode.SERVICE_TOKEN and profile.token_id == token.id
    assert profile.hostname == "db.lab.exemple.fr" and profile.group == "labo"

    # Une application existante est réutilisée, et sans profil demandé rien n'est créé.
    again = await admin.publish(
        PublishRequest(tunnel, "db.lab.exemple.fr", "tcp://localhost:5432", create_profile=False)
    )
    assert again.app.id == result.app.id and again.profile is None
    await admin.unpublish(tunnel, "db.lab.exemple.fr")
    assert cf.state.dns["z2"] == []


async def test_admin_refuses_an_unknown_token(admin, store):
    await admin.connect(TOKEN)
    overview_app = (await admin.overview((await admin.connect())[0])).apps[0]
    with pytest.raises(CloudflareApiError, match="introuvable"):
        await admin.allow_token(overview_app, "absent")
    from cma.core.models import ServiceToken

    foreign = ServiceToken(name="Étranger", client_id="zzz.access")
    store.update(lambda c: c.tokens.append(foreign))
    with pytest.raises(CloudflareApiError, match="n'existe pas"):
        await admin.allow_token(overview_app, foreign.id)


def test_fake_state_is_isolated():
    assert FakeCloudflare().service_tokens == []


async def test_admin_publish_reports_each_step_and_partial_failures(cf, admin, store):
    await admin.connect(TOKEN)
    seen: list[str] = []
    result = await admin.publish(
        PublishRequest(
            Tunnel("t2", "labo", "down"), "pg.lab.exemple.fr", "tcp://localhost:5432", token_id="absent"
        ),
        progress=seen.append,
    )
    assert seen == ["Publication du nom d'hôte…", "Configuration d'Access…", "Création du profil CMA…"]
    assert [(s.name, s.ok) for s in result.steps] == [
        ("hostname", True),
        ("access", True),
        ("token", False),
        ("profile", True),
    ]
    assert not result.complete and "introuvable" in result.steps[2].detail
    assert result.profile is not None  # le nom d'hôte publié n'est pas défait par l'échec du token


async def test_cli_tunnels_reports_the_account_state(cf, admin, paths, secrets, capsys):
    """`cma tunnels` : liste lisible ou JSON, code 2 si un tunnel est en panne, 1 sans jeton."""
    import asyncio
    import json

    from cma.cli import show_tunnels

    def run(**kwargs) -> int:
        return show_tunnels(paths, secrets=secrets, base_url=cf.base_url, **kwargs)

    # Sans jeton : erreur claire, code 1 (asyncio.run exige un autre thread que la boucle des tests).
    assert await asyncio.to_thread(run, as_json=False) == 1
    assert "Aucun jeton d'API Cloudflare" in capsys.readouterr().err
    await admin.connect(TOKEN)
    assert await asyncio.to_thread(run, as_json=False) == 2  # « labo » est hors ligne dans le faux compte
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["En", "ligne", "bureau"] and lines[1].startswith("! Hors ligne")
    assert await asyncio.to_thread(run, as_json=True) == 2
    rows = json.loads(capsys.readouterr().out)
    assert [(r["name"], r["status"], r["label"]) for r in rows] == [
        ("bureau", "healthy", "En ligne"),
        ("labo", "down", "Hors ligne"),
    ]
    cf.state.tunnels[1]["status"] = "healthy"
    assert await asyncio.to_thread(run, as_json=False) == 0


def test_path_rules_order_and_catch_all(cf, api):
    """Une règle est (nom d'hôte, chemin) : les chemins d'un même nom d'hôte vivent côte à côte, et le DNS reste tant
    qu'une règle l'utilise. L'ordre se règle, la règle finale aussi, sans perdre les autres clés d'une règle."""
    tunnel = Tunnel("t2", "labo", "down")
    api.publish_hostname("acc1", tunnel, "app.lab.exemple.fr", "http://localhost:3000")
    api.publish_hostname("acc1", tunnel, "app.lab.exemple.fr", "http://localhost:8080", "/api")
    cf.state.configs["t2"]["ingress"][0]["id"] = "regle-1"  # clé inconnue de CMA : elle doit survivre
    # Republier la règle sans chemin la met à jour sur place : /api reste, la position et l'`id` aussi.
    api.publish_hostname("acc1", tunnel, "app.lab.exemple.fr", "http://localhost:3001")
    rules, catch_all = api.tunnel_ingress("acc1", "t2")
    assert [(r.hostname, r.path, r.service) for r in rules] == [
        ("app.lab.exemple.fr", "", "http://localhost:3001"),
        ("app.lab.exemple.fr", "/api", "http://localhost:8080"),
    ]
    assert catch_all == "http_status:404" and len(cf.state.dns["z2"]) == 1
    assert cf.state.configs["t2"]["ingress"][0].get("id") == "regle-1"

    # Ordre : /api passe devant (la règle la plus précise d'abord) ; aux bornes, rien ne bouge.
    assert api.move_rule("acc1", tunnel, "app.lab.exemple.fr", "/api", -1) == 0
    assert api.move_rule("acc1", tunnel, "app.lab.exemple.fr", "/api", -1) == 0
    assert [r.path for r in api.tunnel_ingress("acc1", "t2")[0]] == ["/api", ""]
    assert cf.state.configs["t2"]["ingress"][-1] == {"service": "http_status:404"}
    with pytest.raises(CloudflareApiError, match="n'est pas publié"):
        api.move_rule("acc1", tunnel, "app.lab.exemple.fr", "/absent", 1)

    # Règle finale : 503, ou un service ; les règles nommées ne bougent pas.
    api.set_catch_all("acc1", tunnel, "http_status:503")
    assert api.tunnel_ingress("acc1", "t2")[1] == "http_status:503"
    assert len(api.tunnel_ingress("acc1", "t2")[0]) == 2

    # Modifier la règle /api ne touche pas l'autre ; la clé inconnue est gardée.
    api.update_hostname_service("acc1", tunnel, "app.lab.exemple.fr", "http://localhost:9090", path="/api")
    services = {r.path: r.service for r in api.tunnel_ingress("acc1", "t2")[0]}
    assert services == {"": "http://localhost:3001", "/api": "http://localhost:9090"}
    assert any(r.get("id") == "regle-1" for r in cf.state.configs["t2"]["ingress"])

    # Retirer /api garde le DNS (la règle sans chemin l'utilise) ; retirer la dernière le supprime.
    api.unpublish_hostname("acc1", tunnel, "app.lab.exemple.fr", "/api")
    assert len(cf.state.dns["z2"]) == 1
    api.unpublish_hostname("acc1", tunnel, "app.lab.exemple.fr")
    assert cf.state.dns["z2"] == [] and api.tunnel_ingress("acc1", "t2") == ([], "http_status:503")


async def test_admin_rule_actions(cf, admin):
    await admin.connect(TOKEN)
    tunnel = Tunnel("t1", "bureau", "healthy")
    overview = await admin.overview((await admin.connect())[0])
    assert overview.tunnels[0].catch_all == "http_status:404"
    first = overview.tunnels[0].hostnames[0]
    with pytest.raises(CloudflareApiError, match="chemin"):
        await admin.add_path_rule(tunnel, first.hostname, "  ", "http://localhost:1")
    added = await admin.add_path_rule(tunnel, first.hostname, "/admin", "http://localhost:9000")
    assert (added.hostname, added.path) == (first.hostname, "/admin")
    assert await admin.move_rule(tunnel, added, -1) >= 0
    await admin.set_catch_all(tunnel, "http_status:503")
    await admin.edit_hostname(tunnel, first.hostname, "rdp://localhost:3389", path="/admin")
    await admin.unpublish(tunnel, first.hostname, "/admin")
    overview = await admin.overview((await admin.connect())[0])
    assert overview.tunnels[0].catch_all == "http_status:503"
    assert all(r.path != "/admin" for r in overview.tunnels[0].hostnames)


def test_access_app_settings(cf, api):
    """Nom, durée de session, lanceur et redirection : un PUT complet qui garde politiques et autres champs."""
    from cma.core.cfapi import AppSettings

    app = api.create_access_app("acc1", "Base", "db.exemple.fr")
    policy = api.create_account_policy(
        "acc1", AccessPolicy("", "Robots", "non_identity", (PolicyRule("any_valid_service_token"),))
    )
    api.attach_policy("acc1", app.id, policy.id)
    stored = next(a for a in cf.state.apps if a["id"] == app.id)
    stored["allowed_idps"] = ["idp-1"]
    stored["tags"] = ["prod"]
    current = api.app_settings("acc1", app.id)
    assert (current.name, current.session_duration, current.allowed_idps) == ("Base", "24h", ("idp-1",))

    saved = api.update_app_settings(
        "acc1",
        app.id,
        AppSettings("Base de prod", "15m", app_launcher_visible=False, auto_redirect_to_identity=True),
    )
    assert (
        saved.name,
        saved.session_duration,
        saved.app_launcher_visible,
        saved.auto_redirect_to_identity,
    ) == (
        "Base de prod",
        "15m",
        False,
        True,
    )
    # Ce que CMA ne règle pas est rendu tel quel : fournisseurs d'identité, étiquettes, politiques.
    assert saved.allowed_idps == ("idp-1",) and stored["tags"] == ["prod"]
    assert api.app_policy_ids("acc1", app.id) == [policy.id]
    assert next(a for a in api.list_access_apps("acc1") if a.id == app.id).policy_count == 1

    cf.state.apps.append({"id": "w1", "name": "WARP", "domain": "", "type": "warp", "policies": []})
    with pytest.raises(CloudflareApiError, match="self-hosted"):
        api.update_app_settings("acc1", "w1", saved)


async def test_access_requests_log(cf, api, admin):
    rows = api.access_requests("acc1", limit=10)
    assert [(r.user, r.app_domain, r.allowed, r.country) for r in rows] == [
        ("alice@exemple.fr", "ssh.exemple.fr", True, "FR"),
        ("robot.access", "grafana.exemple.fr", False, "US"),
    ]
    assert rows[1].connection == "nonidentity" and rows[1].app_name == "Grafana"
    assert rows[0].ip == "203.0.113.5"
    assert len(api.access_requests("acc1", limit=1)) == 1
    # Sans la permission, le message dit laquelle ajouter.
    cf.state.audit_allowed = False
    with pytest.raises(CloudflareApiError, match="Access: Audit Logs : Read") as refused:
        api.access_requests("acc1")
    assert refused.value.status == 403
    cf.state.audit_allowed = True
    await admin.connect(TOKEN)
    assert len(await admin.access_requests()) == 2


async def test_overview_checks_and_fixes_the_dns(cf, admin):
    """La lecture du compte vérifie le DNS des noms publiés ; « Corriger » crée ou redirige le CNAME, sans jamais
    remplacer un enregistrement A."""
    await admin.connect(TOKEN)
    account = (await admin.connect())[0]
    cf.state.dns["z1"] = [
        {
            "id": "r1",
            "type": "CNAME",
            "name": "ssh.exemple.fr",
            "content": "t1.cfargotunnel.com",
            "proxied": True,
        },
        {
            "id": "r2",
            "type": "CNAME",
            "name": "rdp.exemple.fr",
            "content": "t2.cfargotunnel.com",
            "proxied": True,
        },
        {"id": "r3", "type": "A", "name": "grafana.exemple.fr", "content": "192.0.2.1", "proxied": True},
    ]
    overview = await admin.overview(account)
    states = {host: (check.state, check.detail) for host, check in overview.dns.items()}
    assert states == {
        "ssh.exemple.fr": ("ok", ""),
        "rdp.exemple.fr": ("other_tunnel", "labo"),
        "grafana.exemple.fr": ("other_record", "A"),
    }
    tunnel = overview.tunnels[0].tunnel
    await admin.fix_dns(tunnel, "rdp.exemple.fr")
    with pytest.raises(CloudflareApiError, match="enregistrement DNS A"):
        await admin.fix_dns(tunnel, "grafana.exemple.fr")
    with pytest.raises(CloudflareApiError, match="Aucune zone"):
        await admin.fix_dns(tunnel, "x.autre.org")
    overview = await admin.overview(account)
    assert overview.dns["rdp.exemple.fr"].state == "ok"
    assert overview.dns["grafana.exemple.fr"].state == "other_record"


async def test_overview_calls_run_in_parallel(cf, admin, monkeypatch):
    """Tunnels, applications, tokens et zones partent en même temps : une barrière à quatre ne se lève que si les
    quatre appels sont en cours ensemble (en série, elle expirerait)."""
    import threading

    from cma.core.cfapi import CloudflareApi

    await admin.connect(TOKEN)
    account = (await admin.connect())[0]
    barrier = threading.Barrier(4, timeout=10)
    for name in ("list_tunnels", "list_access_apps", "list_service_tokens", "list_zones"):
        original = getattr(CloudflareApi, name)

        def waiting(self, *args, _original=original, **kwargs):
            barrier.wait()
            return _original(self, *args, **kwargs)

        monkeypatch.setattr(CloudflareApi, name, waiting)
    overview = await admin.overview(account)
    assert len(overview.tunnels) == 2 and overview.zones
