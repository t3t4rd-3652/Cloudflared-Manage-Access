"""Repli sur un autre jeton (P38, ADR 0003) : un compte vu par plusieurs jetons reste surveillé quand le premier est
refusé ou absent du coffre ; une erreur du réseau ou de Cloudflare ne fait pas changer de jeton.

Faux serveur Cloudflare sur 127.0.0.1 (deux comptes), coffre en mémoire, tests depuis Internet remplacés. La liste des
tunnels est enveloppée pour savoir quel jeton a lu quel compte, et pour imiter une erreur 403 ou 5xx.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

import pytest

from cma.core.cfadmin import CloudflareAdmin, WatchFallback, token_refused, token_secret_key
from cma.core.cfapi import CloudflareApi, CloudflareApiError, Tunnel
from cma.core.hostprobe import HostProbe
from cma.core.models import ApiToken, Config
from tests.fakes.fake_cfapi import SECOND_TOKEN, TOKEN, FakeCloudflareServer, two_accounts

READONLY = "jeton-api-lecture-seule-de-la-surveillance"
BACKUP = "jeton-api-de-secours-du-premier-compte"
OLD = "jeton-api-ancien-du-premier-compte"
REVOKED = "jeton-api-revoque-depuis-longtemps"
NAMES = {READONLY: "Lecture", TOKEN: "Perso", BACKUP: "Secours", OLD: "Ancien", SECOND_TOKEN: "Travail"}


@pytest.fixture
def cf():
    state = two_accounts()
    state.other_tokens = (READONLY, BACKUP, OLD)  # tous voient « Compte A » ; REVOKED est refusé (401)
    with FakeCloudflareServer(state) as server:
        yield server


@pytest.fixture
def admin(cf, store, secrets):
    return CloudflareAdmin(store, secrets, lambda _p, _a: None, base_url=cf.base_url)


@pytest.fixture
def reads(monkeypatch) -> tuple[list[tuple[str, str]], dict[str, CloudflareApiError]]:
    """Chaque lecture de la liste des tunnels (nom du jeton, compte) ; `fail[secret]` y répond par cette erreur."""
    calls: list[tuple[str, str]] = []
    fail: dict[str, CloudflareApiError] = {}
    original = CloudflareApi.list_tunnels

    def list_tunnels(self: CloudflareApi, account_id: str) -> list[Tunnel]:
        token = self._token  # le jeton qui lit
        calls.append((NAMES.get(token, "révoqué"), account_id))
        if token in fail:
            raise fail[token]
        return original(self, account_id)

    monkeypatch.setattr(CloudflareApi, "list_tunnels", list_tunnels)
    return calls, fail


@pytest.fixture
def probes(monkeypatch) -> list[str]:
    asked: list[str] = []

    async def fake_probe(hostname: str, **_kwargs: Any) -> HostProbe:
        asked.append(hostname)
        return HostProbe("ok", 200)

    monkeypatch.setattr("cma.core.servicewatch.probe_hostname_async", fake_probe)
    return asked


def register(store, secrets, *, watch_all: bool = True, **values: str | None) -> None:
    """Cinq jetons : « Lecture » (jeton de la surveillance), « Perso » (jeton actif), « Secours » et « Ancien » sur
    « Compte A », « Travail » sur « Compte B ». La liste commence par « Secours » : l'ordre du repli met d'abord le jeton
    de la surveillance et le jeton actif. `values` remplace un secret (None : absent du coffre)."""

    def apply(config: Config) -> None:
        settings = config.settings
        settings.cloudflare_tokens = [
            ApiToken(id="secours", name="Secours", account_id="acc1"),
            ApiToken(id="principal", name="Perso", account_id="acc1"),
            ApiToken(id="lecture", name="Lecture", account_id="acc1"),
            ApiToken(id="ancien", name="Ancien", account_id="acc1"),
            ApiToken(id="travail", name="Travail", account_id="acc2"),
        ]
        settings.cloudflare_token_id = "principal"
        settings.cloudflare_account_id = "acc1"
        settings.watch_token_id = "lecture"
        settings.watch_all_accounts = watch_all

    store.update(apply)
    defaults = {
        "lecture": READONLY,
        "principal": TOKEN,
        "secours": BACKUP,
        "ancien": OLD,
        "travail": SECOND_TOKEN,
    }
    for token_id, value in (defaults | values).items():
        if value is not None:
            secrets.set(token_secret_key(token_id), value)


def moved(fallbacks: list[WatchFallback]) -> list[tuple[str, str, str]]:
    return [(f.token_name, f.account_id, f.used) for f in fallbacks]


@pytest.mark.parametrize("refusal", ["revoked", "forbidden"])
async def test_refused_watch_token_falls_back_to_the_active_token(
    cf, admin, store, secrets, reads, probes, caplog, refusal
):
    calls, fail = reads
    if refusal == "revoked":
        register(store, secrets, lecture=REVOKED)  # le faux serveur répond 401
    else:
        # Jeton valide, mais la permission « Cloudflare Tunnel : Read » lui a été retirée.
        register(store, secrets)
        fail[READONLY] = CloudflareApiError("Accès refusé par l'API Cloudflare (403) : -", status=403)
    sweep = await admin.watch_tunnels()
    # Le compte reste surveillé, par le jeton actif, et une seule fois : aucun tunnel en double.
    assert sweep.complete and sweep.failures == []
    assert [t.id for t in sweep.tunnels] == ["t1", "t2", "t9", "t8"]
    assert sweep.accounts["t1"].token_name == "Perso" and sweep.accounts["t9"].token_name == "Travail"
    # Le repli est porté par le relevé et journalisé, sans le secret.
    assert moved(sweep.fallbacks) == [("Lecture", "acc1", "Perso")]
    assert ("401" if refusal == "revoked" else "403") in sweep.fallbacks[0].error
    assert "jeton « Lecture » écarté" in caplog.text and "relevé avec le jeton « Perso »" in caplog.text
    assert REVOKED not in caplog.text and READONLY not in caplog.text
    # Un relevé réussi par compte ; « Secours » et « Ancien » ne sont jamais essayés.
    first = "révoqué" if refusal == "revoked" else "Lecture"
    assert Counter(calls) == Counter({(first, "acc1"): 1, ("Perso", "acc1"): 1, ("Travail", "acc2"): 1})
    # Un refus pendant le relevé ne change pas ce qui est relevé (un relevé en cours resterait valable).
    assert admin.watch_scope() == "lecture=acc1|travail=acc2"
    # Les services suivent la même règle.
    services = await admin.watch_services()
    assert services.complete and moved(services.fallbacks) == [("Lecture", "acc1", "Perso")]
    assert sorted(t.key for t, _p in services.results) == ["app.exemple.org", "grafana.exemple.fr"]


async def test_a_token_missing_from_the_vault_hands_over_to_the_next(cf, admin, store, secrets, reads):
    calls, _fail = reads
    register(store, secrets, lecture=None)
    sweep = await admin.watch_tunnels()
    assert sweep.complete and [t.id for t in sweep.tunnels] == ["t1", "t2", "t9", "t8"]
    assert [(f.token_name, f.error, f.used) for f in sweep.fallbacks] == [
        ("Lecture", "jeton absent du coffre", "Perso")
    ]
    assert ("Lecture", "acc1") not in calls
    # Ce qu'il y a à relever : le premier jeton de chaque compte présent dans le coffre.
    assert admin.watch_scope() == "principal=acc1|travail=acc2"
    # Jeton actif refusé à son tour : les autres jetons du compte, dans l'ordre de la liste.
    secrets.set(token_secret_key("principal"), REVOKED)
    calls.clear()
    sweep = await admin.watch_tunnels()
    assert moved(sweep.fallbacks) == [("Lecture", "acc1", "Secours"), ("Perso", "acc1", "Secours")]
    assert sweep.accounts["t1"].token_name == "Secours"
    assert ("Ancien", "acc1") not in calls and Counter(calls)[("Secours", "acc1")] == 1


@pytest.mark.parametrize(
    "error",
    [
        CloudflareApiError("Erreur de l'API Cloudflare (503) : -", status=503),
        CloudflareApiError("Erreur de l'API Cloudflare (500) : -", status=500),
        CloudflareApiError("API Cloudflare injoignable : timed out"),
        CloudflareApiError("Erreur de l'API Cloudflare : -", codes=(1000,)),
    ],
    ids=["503", "500", "injoignable", "sans-statut"],
)
async def test_a_server_or_network_error_does_not_switch_tokens(cf, admin, store, secrets, reads, error):
    calls, fail = reads
    register(store, secrets)
    fail[READONLY] = error
    sweep = await admin.watch_tunnels()
    # Le compte n'est pas lu (le relevé est incomplet), comme avant le repli : aucun autre jeton n'est essayé.
    assert not sweep.complete and sweep.fallbacks == []
    assert [(f.token_name, f.account_id, f.error) for f in sweep.failures] == [
        ("Lecture", "acc1", str(error))
    ]
    assert [t.id for t in sweep.tunnels] == ["t9", "t8"]
    assert Counter(account for _name, account in calls) == Counter({"acc1": 1, "acc2": 1})


async def test_every_token_refused_fails_as_before(cf, admin, store, secrets, reads):
    calls, _fail = reads
    refused = {name: f"{REVOKED}-{name}" for name in ("lecture", "principal", "secours", "ancien")}
    register(store, secrets, **refused)
    sweep = await admin.watch_tunnels()
    # Compte A illisible : incomplet, chaque jeton essayé est un échec, aucun repli ; Compte B est lu.
    assert not sweep.complete and sweep.fallbacks == []
    assert [(f.token_name, f.account_id) for f in sweep.failures] == [
        ("Lecture", "acc1"),
        ("Perso", "acc1"),
        ("Secours", "acc1"),
        ("Ancien", "acc1"),
    ]
    assert [t.name for t in sweep.tunnels] == ["api (Compte B)", "web (Compte B)"]
    assert Counter(account for _name, account in calls) == Counter({"acc1": 4, "acc2": 1})
    # Plus aucun compte lisible : le relevé échoue comme avant.
    secrets.set(token_secret_key("travail"), f"{REVOKED}-travail")
    with pytest.raises(CloudflareApiError, match=r"Lecture : .*Ancien : .*Travail : "):
        await admin.watch_tunnels()


async def test_one_account_watched_alone_falls_back_too(cf, admin, store, secrets, reads, probes, caplog):
    """Sans « Surveiller tous les comptes », même règle pour le compte choisi : le relevé porte le repli."""
    calls, _fail = reads
    register(store, secrets, watch_all=False, lecture=REVOKED)
    sweep = await admin.watch_tunnels()
    assert sweep.complete and [t.name for t in sweep.tunnels] == ["bureau", "labo"]
    assert moved(sweep.fallbacks) == [("Lecture", "acc1", "Perso")]
    assert "jeton « Lecture » écarté" in caplog.text and REVOKED not in caplog.text
    services = await admin.watch_services()
    assert moved(services.fallbacks) == [("Lecture", "acc1", "Perso")]
    assert [t.key for t, _p in services.results] == ["grafana.exemple.fr"]
    # Lu hors d'un relevé de la surveillance : le repli est seulement journalisé.
    assert len(await admin.tunnel_states()) == 2
    # Le jeton d'un autre compte n'est jamais essayé pour celui-ci.
    assert all(account == "acc1" for _name, account in calls) and ("Travail", "acc1") not in calls


async def test_one_account_watched_alone_fails_as_before(cf, admin, store, secrets, reads):
    calls, fail = reads
    refused = {name: f"{REVOKED}-{name}" for name in ("lecture", "principal", "secours", "ancien")}
    register(store, secrets, watch_all=False, **refused)
    # Tous refusés : l'erreur du jeton de la surveillance, celle qu'on avait avant le repli.
    with pytest.raises(CloudflareApiError) as caught:
        await admin.watch_tunnels()
    assert str(caught.value) == "Accès refusé par l'API Cloudflare (401) : Authentication error"
    assert caught.value.status == 401
    # Une erreur 5xx du jeton de la surveillance : pas de repli.
    register(store, secrets, watch_all=False)
    fail[READONLY] = CloudflareApiError("Erreur de l'API Cloudflare (502) : -", status=502)
    calls.clear()
    with pytest.raises(CloudflareApiError, match=r"\(502\)"):
        await admin.tunnel_states()
    assert calls == [("Lecture", "acc1")]
    # Aucun jeton dans le coffre : le message d'avant.
    for token in admin.tokens():
        secrets.delete(token_secret_key(token.id))
    with pytest.raises(CloudflareApiError, match="connectez-vous"):
        await admin.tunnel_states()


def test_only_a_refusal_of_the_token_switches():
    assert token_refused(CloudflareApiError("refusé", status=401))
    assert token_refused(CloudflareApiError("refusé", status=403))
    assert not token_refused(CloudflareApiError("introuvable", status=404))
    assert not token_refused(CloudflareApiError("panne", status=503))
    assert not token_refused(CloudflareApiError("injoignable"))
    assert not token_refused(OSError("réseau"))
