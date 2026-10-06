"""API Cloudflare (cfapi) et gestion du compte (cfadmin), contre un faux serveur en mémoire."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cma.core.cfadmin import CloudflareAdmin, PublishRequest
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
    policy = api.allow_service_token("acc1", app.id, created.id, "CMA - Robot")
    assert cf.state.policies[app.id][0]["id"] == policy
    assert cf.state.policies[app.id][0]["include"] == [{"service_token": {"token_id": created.id}}]
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


async def test_access_policies(cf, admin):
    await admin.connect(TOKEN)
    app = AccessApp("app1", "SSH", "ssh.exemple.fr", "self_hosted")
    policies, groups = await admin.policies(app)
    assert policies == [] and groups == [AccessGroup("g1", "Admins")]

    team = await admin.save_policy(
        app, AccessPolicy("", "Équipe", "allow", (PolicyRule("email_domain", "exemple.fr"),))
    )
    robots = await admin.save_policy(
        app, AccessPolicy("", "Robots", "non_identity", (PolicyRule("any_valid_service_token"),))
    )
    assert team.id and (team.precedence, robots.precedence) == (1, 2)
    unknown = {"github-organization": {"name": "acme"}}
    cf.state.policies["app1"][0]["include"].append(unknown)

    policies, _ = await admin.policies(app)
    assert [p.name for p in policies] == ["Équipe", "Robots"]
    edited = AccessPolicy(
        policies[0].id,
        "Équipe et Admins",
        "allow",
        (PolicyRule("group", "g1"), *[r for r in policies[0].include if not r.editable]),
        precedence=policies[0].precedence,
    )
    await admin.save_policy(app, edited)
    stored = cf.state.policies["app1"][0]
    assert stored["name"] == "Équipe et Admins"
    assert stored["include"] == [{"group": {"id": "g1"}}, unknown]  # la règle inconnue de CMA est gardée

    await admin.delete_policy(app, robots)
    assert [p["name"] for p in cf.state.policies["app1"]] == ["Équipe et Admins"]

    # Sans le droit de lire les groupes, les politiques restent lisibles.
    cf.state.groups_forbidden = True
    policies, groups = await admin.policies(app)
    assert len(policies) == 1 and groups == []


async def test_tunnel_connectors(api, admin):
    [healthy] = api.tunnel_connectors("acc1", "t1")
    assert (healthy.version, healthy.arch, healthy.origin_ip) == ("2026.9.0", "linux_amd64", "203.0.113.10")
    assert [c.colo for c in healthy.connections] == ["cdg01", "cdg01", "ams01", "ams01"]
    assert not any(c.pending_reconnect for c in healthy.connections)
    await admin.connect(TOKEN)
    assert await admin.connectors(Tunnel("t2", "labo", "down")) == []


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
    assert cf.state.policies[result.app.id][0]["decision"] == "non_identity"
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
