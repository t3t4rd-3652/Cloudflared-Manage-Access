"""Tâche planifiée (`cma tunnels --notify`) avec « Surveiller tous les comptes » (P34, ADR 0003).

Faux serveur Cloudflare sur 127.0.0.1, coffre en mémoire (jamais le trousseau), aucune vraie tâche planifiée ;
notification du système, tests depuis Internet et envois d'alerte remplacés.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import cma.cli as cli
from cma.core.alerts import Alert, secret_key
from cma.core.availability import AvailabilityLog
from cma.core.config_store import ConfigStore
from cma.core.hostprobe import HostProbe
from cma.core.models import AlertChannel
from cma.core.secrets import MemorySecretStore
from tests.fakes.fake_cfapi import SECOND_TOKEN, FakeCloudflareServer, register_two_tokens, two_accounts


@pytest.fixture
def cf():
    with FakeCloudflareServer(two_accounts()) as server:
        yield server


@pytest.fixture
def task(monkeypatch, paths, cf):
    """Une tâche planifiée qui voit CMA fermé : ses notifications et ses alertes sont gardées pour le test."""
    shown: list[str] = []
    sent: list[Alert] = []
    monkeypatch.setattr(
        "cma.platform.notify.system_notification", lambda _t, text: shown.append(text) or True
    )
    monkeypatch.setattr("cma.core.monitoring.send_alert", lambda _kind, _url, alert: sent.append(alert))
    monkeypatch.setattr(cli, "send_command", lambda *_a, **_k: None)

    async def fake_probe(hostname: str, **_kwargs: Any) -> HostProbe:
        return HostProbe("origin_down", 502) if hostname == "app.exemple.org" else HostProbe("ok", 200)

    monkeypatch.setattr("cma.core.servicewatch.probe_hostname_async", fake_probe)
    vault = MemorySecretStore()
    store = ConfigStore(paths)
    store.load()
    channel = AlertChannel(name="Téléphone", kind="ntfy")
    vault.set(secret_key(channel.id), "https://ntfy.exemple.fr/sujet-de-test")
    store.update(lambda c: setattr(c.settings, "alert_channels", [channel]))

    def run(**kwargs: Any) -> int:
        return cli.show_tunnels(
            paths, notify=True, secrets=vault, base_url=cf.base_url, as_json=False, **kwargs
        )

    return store, vault, run, shown, sent


def open_keys(paths) -> list[str]:
    return sorted(i.key for i in AvailabilityLog(paths.data_dir / "availability.json").incidents if i.open)


def test_scheduled_task_watches_every_account(task, paths, cf):
    store, vault, run, shown, sent = task
    register_two_tokens(store.update, vault)
    assert run() == 2
    assert shown == [
        "En panne : labo (Compte A), api (Compte B), app.exemple.org (Compte B) Ouvrez CMA pour le diagnostic."
    ]
    assert sorted(a.title for a in sent) == [
        "CMA — panne : api (Compte B)",
        "CMA — panne : app.exemple.org (Compte B)",
        "CMA — panne : labo (Compte A)",
    ]
    assert open_keys(paths) == ["service:app.exemple.org", "tunnel:t2", "tunnel:t9"]
    # Passage suivant, rien n'a changé : ni notification ni alerte.
    assert run() == 2 and len(shown) == 1 and len(sent) == 3
    # Le tunnel du compte B revient : son retour est annoncé avec le compte.
    cf.state.tenants[SECOND_TOKEN].tunnels[0]["status"] = "healthy"
    assert run() == 2
    assert shown[-1] == "Le tunnel « api (Compte B) » est de nouveau en ligne."


def test_scheduled_task_survives_a_refused_token(task, paths, cf, capsys):
    store, vault, run, shown, sent = task
    register_two_tokens(store.update, vault, second="jeton-api-revoque-depuis")
    assert run() == 2
    assert shown == [
        "Le tunnel « labo (Compte A) » est hors ligne : plus aucun connecteur ne le relie à Cloudflare. "
        "Ouvrez CMA pour le diagnostic."
    ]
    assert (
        capsys.readouterr().err.count("Jeton « Travail » illisible") == 1
    )  # tunnels et services : une ligne
    # Relevé incomplet : un incident du compte illisible n'est pas clos pour autant.
    log = AvailabilityLog(paths.data_dir / "availability.json")
    log.start("tunnel", "tunnel:t9", "api (Compte B)", "down")
    log.save()
    cf.state.tunnels[1]["status"] = "healthy"  # labo revient
    assert run() == 1  # plus de panne connue, mais un jeton illisible : la lecture a échoué en partie
    assert shown[-1] == "Le tunnel « labo (Compte A) » est de nouveau en ligne."
    assert open_keys(paths) == ["tunnel:t9"]
    # Les deux jetons refusés : la lecture échoue, rien n'est notifié.
    from cma.core.cfadmin import token_secret_key

    vault.set(token_secret_key("principal"), "jeton-api-revoque-aussi")
    assert run() == 1 and len(shown) == 2
    assert "Perso" in capsys.readouterr().err


def test_scheduled_task_without_the_setting_reads_one_account(task, paths, cf):
    store, vault, run, shown, sent = task
    register_two_tokens(store.update, vault, watch_all=False)
    assert run() == 2
    assert shown == [
        "Le tunnel « labo » est hors ligne : plus aucun connecteur ne le relie à Cloudflare. "
        "Ouvrez CMA pour le diagnostic."
    ]
    assert [a.title for a in sent] == ["CMA — panne : labo"]
    assert cf.state.tenants[SECOND_TOKEN].requests == []
    assert open_keys(paths) == ["tunnel:t2"]


def test_tunnels_json_lists_every_account(task, paths, cf, capsys, monkeypatch):
    store, vault, _run, _shown, _sent = task
    register_two_tokens(store.update, vault)
    code = cli.show_tunnels(paths, as_json=True, services=True, secrets=vault, base_url=cf.base_url)
    assert code == 2
    data = json.loads(capsys.readouterr().out)
    assert [(t["name"], t["account"]) for t in data["tunnels"]] == [
        ("bureau", "Compte A"),
        ("labo", "Compte A"),
        ("api", "Compte B"),
        ("web", "Compte B"),
    ]
    assert [(s["hostname"], s["account"], s["state"]) for s in data["services"]] == [
        ("grafana.exemple.fr", "Compte A", "ok"),
        ("app.exemple.org", "Compte B", "origin_down"),
    ]
    # Un seul compte surveillé : la sortie d'avant, sans compte.
    store.update(lambda c: setattr(c.settings, "watch_all_accounts", False))
    cli.show_tunnels(paths, as_json=True, services=True, secrets=vault, base_url=cf.base_url)
    data = json.loads(capsys.readouterr().out)
    assert all("account" not in row for row in data["tunnels"] + data["services"])
    # Sortie lisible : le compte suit le nom.
    store.update(lambda c: setattr(c.settings, "watch_all_accounts", True))
    cli.show_tunnels(paths, as_json=False, secrets=vault, base_url=cf.base_url)
    assert "api (Compte B)" in capsys.readouterr().out
