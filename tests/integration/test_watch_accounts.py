"""Surveillance de tous les comptes (P34, ADR 0003) contre le faux serveur : deux jetons, deux comptes."""

from __future__ import annotations

from typing import Any

import pytest

from cma.core.cfadmin import CloudflareAdmin, token_secret_key
from cma.core.cfapi import CloudflareApiError, Tunnel
from cma.core.hostprobe import HostProbe
from cma.core.models import ApiToken, Config
from tests.fakes.fake_cfapi import (
    SECOND_TOKEN,
    TOKEN,
    FakeCloudflare,
    FakeCloudflareServer,
    register_two_tokens,
    two_accounts,
)


@pytest.fixture
def cf():
    with FakeCloudflareServer(two_accounts()) as server:
        yield server


@pytest.fixture
def admin(cf, store, secrets):
    return CloudflareAdmin(store, secrets, lambda _p, _a: None, base_url=cf.base_url)


@pytest.fixture
def probes(monkeypatch) -> list[str]:
    """Tests depuis Internet remplacés : app.exemple.org renvoie 502, le reste répond ; aucune requête ne sort."""
    asked: list[str] = []

    async def fake_probe(hostname: str, **_kwargs: Any) -> HostProbe:
        asked.append(hostname)
        return HostProbe("origin_down", 502) if hostname == "app.exemple.org" else HostProbe("ok", 200)

    monkeypatch.setattr("cma.core.servicewatch.probe_hostname_async", fake_probe)
    return asked


def tunnel_requests(state: FakeCloudflare) -> int:
    return sum(1 for method, path in state.requests if method == "GET" and path.endswith("/cfd_tunnel"))


async def test_every_token_is_watched_with_its_account(cf, admin, store, secrets):
    register_two_tokens(store.update, secrets)
    sweep = await admin.watch_tunnels()
    assert sweep.complete and sweep.failures == []
    # Deux comptes surveillés : le nom du compte suit celui de chaque tunnel.
    assert [(t.id, t.name, t.status) for t in sweep.tunnels] == [
        ("t1", "bureau (Compte A)", "healthy"),
        ("t2", "labo (Compte A)", "down"),
        ("t9", "api (Compte B)", "down"),
        ("t8", "web (Compte B)", "healthy"),
    ]
    assert sweep.names["t9"] == "api" and sweep.accounts["t9"].account_id == "acc2"
    assert sweep.accounts["t9"].token_name == "Travail"
    # Chaque jeton n'a lu que son compte.
    assert tunnel_requests(cf.state) == 1 and tunnel_requests(cf.state.tenants[SECOND_TOKEN]) == 1
    # Les noms des comptes sont lus une fois par jeton, puis gardés.
    await admin.watch_tunnels()
    accounts_asked = [
        p for s in (cf.state, cf.state.tenants[SECOND_TOKEN]) for m, p in s.requests if p == "/accounts"
    ]
    assert len(accounts_asked) == 2


async def test_a_refused_token_does_not_stop_the_other(cf, admin, store, secrets, caplog):
    register_two_tokens(store.update, secrets, second="jeton-api-revoque-depuis")
    sweep = await admin.watch_tunnels()
    assert not sweep.complete
    assert [t.name for t in sweep.tunnels] == ["bureau (Compte A)", "labo (Compte A)"]
    assert [(f.token_name, f.account_id) for f in sweep.failures] == [("Travail", "acc2")]
    assert "Authentication error" in sweep.failures[0].error
    assert "jeton « Travail » illisible" in caplog.text
    assert "jeton-api-revoque-depuis" not in caplog.text
    # Aucun compte lisible : le relevé échoue comme avec un seul compte.
    secrets.set(token_secret_key("principal"), "jeton-api-revoque-aussi")
    with pytest.raises(CloudflareApiError, match=r"Perso : .*Travail : "):
        await admin.watch_tunnels()


async def test_a_token_missing_from_the_vault_is_reported(admin, store, secrets):
    register_two_tokens(store.update, secrets)
    secrets.delete(token_secret_key("travail"))
    sweep = await admin.watch_tunnels()
    assert [f.error for f in sweep.failures] == ["jeton absent du coffre"]
    # Deux comptes surveillés, même si l'un n'a pas été lu : les noms gardent leur compte.
    assert [t.name for t in sweep.tunnels] == ["bureau (Compte A)", "labo (Compte A)"]
    # Ce qu'il y a à relever ne compte que les jetons présents dans le coffre.
    assert admin.watch_scope() == "principal=acc1"


async def test_setting_off_reads_only_the_chosen_account(cf, admin, store, secrets, probes):
    register_two_tokens(store.update, secrets, watch_all=False)
    sweep = await admin.watch_tunnels()
    assert sweep.complete and sweep.accounts == {} and sweep.names == {}
    assert sweep.tunnels == await admin.tunnel_states()
    assert [t.name for t in sweep.tunnels] == ["bureau", "labo"]
    assert tunnel_requests(cf.state.tenants[SECOND_TOKEN]) == 0
    services = await admin.watch_services()
    assert [(t.label, t.account_id) for t, _p in services.results] == [("grafana.exemple.fr", "")]
    assert probes == ["grafana.exemple.fr"]


async def test_services_of_every_account(cf, admin, store, secrets, probes):
    register_two_tokens(store.update, secrets)
    sweep = await admin.watch_services()
    assert sweep.complete
    found = [(t.label, t.account_id, p.state) for t, p in sweep.results]
    assert found == [
        ("grafana.exemple.fr (Compte A)", "acc1", "ok"),
        ("app.exemple.org (Compte B)", "acc2", "origin_down"),
    ]
    # La clé ne change pas : journal, sourdine et maintenance gardent leurs clés d'avant.
    assert [t.key for t, _p in sweep.results] == ["grafana.exemple.fr", "app.exemple.org"]
    assert sorted(probes) == ["app.exemple.org", "grafana.exemple.fr"]


async def test_a_hostname_declared_by_two_accounts_is_tested_once(cf, admin, store, secrets, probes):
    register_two_tokens(store.update, secrets)
    second = cf.state.tenants[SECOND_TOKEN]
    second.configs["t8"]["ingress"].insert(0, {"hostname": "grafana.exemple.fr", "service": "http://x:3000"})
    sweep = await admin.watch_services()
    assert [t.label for t, _p in sweep.results] == [
        "grafana.exemple.fr (Compte A)",
        "app.exemple.org (Compte B)",
    ]
    assert probes.count("grafana.exemple.fr") == 1


async def test_services_survive_a_refused_token(cf, admin, store, secrets, probes):
    register_two_tokens(store.update, secrets, second="jeton-api-revoque-depuis")
    sweep = await admin.watch_services()
    assert not sweep.complete and [t.label for t, _p in sweep.results] == ["grafana.exemple.fr (Compte A)"]


async def test_one_account_read_by_two_tokens_is_watched_once(cf, admin, store, secrets):
    """Le jeton de la surveillance (lecture seule) et le jeton actif voient le même compte : un seul relevé, par le
    jeton de la surveillance, et pas de nom de compte (un seul compte surveillé)."""
    readonly = "jeton-api-lecture-seule-de-test"
    cf.state.other_tokens = (readonly,)

    def apply(config: Config) -> None:
        settings = config.settings
        settings.cloudflare_tokens = [
            ApiToken(id="principal", name="Perso", account_id="acc1"),
            ApiToken(id="lecture", name="Lecture", account_id="acc1"),
        ]
        settings.cloudflare_token_id = "principal"
        settings.cloudflare_account_id = "acc1"
        settings.watch_token_id = "lecture"
        settings.watch_all_accounts = True

    store.update(apply)
    secrets.set(token_secret_key("principal"), TOKEN)
    secrets.set(token_secret_key("lecture"), readonly)
    sweep = await admin.watch_tunnels()
    assert [t.name for t in sweep.tunnels] == ["bureau", "labo"]
    assert {w.token_id for w in sweep.accounts.values()} == {"lecture"}
    assert admin.watch_scope() == "lecture=acc1"
    assert tunnel_requests(cf.state) == 1


async def test_a_token_without_chosen_account_takes_its_first(cf, admin, store, secrets):
    register_two_tokens(store.update, secrets)

    def forget_choice(config: Config) -> None:
        config.settings.cloudflare_tokens[1].account_id = None

    store.update(forget_choice)
    assert admin.watch_scope() == "principal=acc1|travail=?"
    sweep = await admin.watch_tunnels()
    assert sweep.accounts["t9"].account_id == "acc2" and sweep.accounts["t9"].name == "Compte B"
    # Un jeton qui ne mène à aucun compte est un échec, pas une erreur du relevé.
    cf.state.tenants[SECOND_TOKEN].accounts = []
    cf.state.tenants[SECOND_TOKEN].zones = []
    sweep = await admin.watch_tunnels()
    assert [f.error for f in sweep.failures] == ["Ce jeton ne donne accès à aucun compte Cloudflare."]


async def test_accounts_with_the_same_name_take_their_token_name(cf, admin, store, secrets):
    register_two_tokens(store.update, secrets)
    cf.state.tenants[SECOND_TOKEN].accounts = [{"id": "acc2", "name": "Compte A"}]
    sweep = await admin.watch_tunnels()
    assert [t.name for t in sweep.tunnels] == [
        "bureau (Perso)",
        "labo (Perso)",
        "api (Travail)",
        "web (Travail)",
    ]


async def test_unreadable_account_names_fall_back_to_the_token_name(cf, admin, store, secrets):
    """Jeton sans « Account Settings : Read » ni « Zone : Read » : son compte est connu, pas son nom."""
    register_two_tokens(store.update, secrets)
    second = cf.state.tenants[SECOND_TOKEN]
    second.accounts = []
    second.zones_forbidden = True
    sweep = await admin.watch_tunnels()
    assert sweep.complete and [t.name for t in sweep.tunnels][2:] == ["api (Travail)", "web (Travail)"]


async def test_connect_remembers_account_names(cf, admin, store, secrets):
    await admin.connect(TOKEN)
    store.update(lambda c: setattr(c.settings, "watch_all_accounts", True))
    store.update(lambda c: setattr(c.settings.cloudflare_tokens[0], "name", "Perso"))
    secrets.set(token_secret_key("travail"), SECOND_TOKEN)

    def add_second(config: Config) -> None:
        config.settings.cloudflare_tokens.append(ApiToken(id="travail", name="Travail", account_id="acc2"))

    store.update(add_second)
    await admin.watch_tunnels()
    # Le nom du premier compte vient de la connexion : seul le second jeton demande la liste des comptes.
    assert [p for _m, p in cf.state.requests].count("/accounts") == 1
    assert [p for _m, p in cf.state.tenants[SECOND_TOKEN].requests].count("/accounts") == 1


def test_names_with_their_account():
    from cma.core.servicewatch import ServiceTarget
    from cma.core.tunnelwatch import troubled_summary, with_account

    assert (
        with_account("bureau", "") == "bureau" and with_account("bureau", "Compte B") == "bureau (Compte B)"
    )
    target = ServiceTarget("App.exemple.org", "/x", "http://a", "t8", "web", "acc2", "Compte B")
    assert (target.key, target.address, target.label) == (
        "app.exemple.org/x",
        "App.exemple.org/x",
        "App.exemple.org/x (Compte B)",
    )
    assert troubled_summary([Tunnel("t9", with_account("api", "Compte B"), "down")]) == (
        "Tunnel « api (Compte B) » hors ligne"
    )
