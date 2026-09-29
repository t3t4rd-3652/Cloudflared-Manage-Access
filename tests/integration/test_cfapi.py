"""API Cloudflare (cfapi) et gestion du compte (cfadmin), contre un faux serveur en mémoire."""

from __future__ import annotations

import pytest

from cma.core.cfadmin import CloudflareAdmin, PublishRequest
from cma.core.cfapi import (
    TOKEN_SECRET_KEY,
    CloudflareApi,
    CloudflareApiError,
    Tunnel,
    guess_service_from_ingress,
)
from cma.core.models import AuthMode, ServiceType
from cma.core.netutil import find_free_port
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
