"""Surveillance des services publiés : cibles, tests en parallèle, changements d'un relevé à l'autre."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

from cma.core.cfapi import IngressRule, Tunnel
from cma.core.hostprobe import HostProbe
from cma.core.models import AuthMode, CloudflareProfile, Config, ServiceToken
from cma.core.secrets import MemorySecretStore
from cma.core.servicewatch import (
    ServiceTarget,
    ServiceWatch,
    probe_targets,
    probe_token,
    targets_of,
    troubled_services_summary,
)

BUREAU = Tunnel("t1", "bureau", "healthy")
LABO = Tunnel("t2", "labo", "inactive")
RULES = [
    IngressRule("app.exemple.fr", "http://localhost:3000"),
    IngressRule("app.exemple.fr", "http://localhost:8080", "/api"),
    IngressRule("ssh.exemple.fr", "ssh://localhost:22"),
    IngressRule("*.exemple.fr", "https://localhost:8443"),
]


def target(
    host: str = "app.exemple.fr", path: str = "", service: str = "http://localhost:3000"
) -> ServiceTarget:
    return ServiceTarget(host, path, service, "t1", "bureau")


def test_targets_skip_wildcards_inactive_tunnels_and_non_http_services():
    found = targets_of([(BUREAU, RULES), (LABO, [IngressRule("old.exemple.fr", "http://x:1")])])
    assert [t.label for t in found] == ["app.exemple.fr", "app.exemple.fr/api"]
    # « Tester tous les noms d'hôte » prend aussi SSH et le tunnel arrêté.
    everything = targets_of(
        [(BUREAU, RULES), (LABO, [IngressRule("old.exemple.fr", "http://x:1")])],
        web_only=False,
        active_only=False,
    )
    assert [t.label for t in everything] == [
        "app.exemple.fr",
        "app.exemple.fr/api",
        "ssh.exemple.fr",
        "old.exemple.fr",
    ]
    assert not everything[2].web and everything[3].tunnel_name == "labo"


def test_probe_path_keeps_only_plain_paths():
    assert target(path="/api").probe_path == "/api"
    assert target(path="^/api$").probe_path == "/api"
    assert target(path="/static/.*").probe_path == "/"
    assert target(path="").probe_path == "/"


def test_probe_token_comes_from_the_cma_profile():
    token = ServiceToken(name="robot", client_id="robot.access")
    config = Config(
        tokens=[token],
        cloudflare_profiles=[
            CloudflareProfile(
                name="App", hostname="APP.exemple.fr", auth=AuthMode.SERVICE_TOKEN, token_id=token.id
            ),
            CloudflareProfile(name="Web", hostname="web.exemple.fr"),
        ],
    )
    secrets = MemorySecretStore()
    assert probe_token(config, secrets, "app.exemple.fr") is None  # secret absent du coffre
    secrets.set(token.secret_key, "secret-de-test-assez-long")
    assert probe_token(config, secrets, "app.exemple.fr") == ("robot.access", "secret-de-test-assez-long")
    assert probe_token(config, secrets, "web.exemple.fr") is None  # connexion par navigateur


def test_probe_targets_runs_in_parallel_with_tokens_for_web_services_only():
    calls: list[tuple[str, object, str]] = []
    running = {"now": 0, "max": 0}

    async def prober(hostname: str, *, token: object, path: str) -> HostProbe:
        running["now"] += 1
        running["max"] = max(running["max"], running["now"])
        await asyncio.sleep(0.01)
        running["now"] -= 1
        calls.append((hostname, token, path))
        return HostProbe("ok", 200)

    targets = [target(), target(path="/api"), target("ssh.exemple.fr", service="ssh://localhost:22")]
    results = asyncio.run(probe_targets(targets, lambda _h: ("id", "secret"), concurrency=2, prober=prober))
    assert [t for t, _p in results] == targets and running["max"] == 2
    assert sorted(calls) == [
        ("app.exemple.fr", ("id", "secret"), "/"),
        ("app.exemple.fr", ("id", "secret"), "/api"),
        ("ssh.exemple.fr", None, "/"),
    ]


def test_watch_reports_failures_once_then_recovery():
    watch = ServiceWatch()
    app, api = target(), target(path="/api")
    start = datetime.now() - timedelta(minutes=30)
    # Premier relevé : seul le service déjà en panne est signalé.
    first = watch.update([(app, HostProbe("ok", 200)), (api, HostProbe("origin_down", 502))], start)
    assert [(c.target.label, c.level, c.previous) for c in first] == [("app.exemple.fr/api", "warning", None)]
    assert (
        first[0].message()
        == "app.exemple.fr/api : le tunnel répond, mais pas le service derrière lui (erreur 502)."
    )
    # Toujours en panne : rien de nouveau. Plus grave (1033) : nouvelle alerte, en erreur.
    assert watch.update([(app, HostProbe("ok", 200)), (api, HostProbe("origin_down", 502))]) == []
    worse = watch.update([(app, HostProbe("ok", 200)), (api, HostProbe("no_connector", 530))])
    assert [c.level for c in worse] == ["error"]
    assert [r.target.label for r in watch.troubled] == ["app.exemple.fr/api"]
    assert troubled_services_summary(watch.troubled) == "app.exemple.fr/api ne répond plus"
    # Sans réponse (réseau du poste coupé) : l'état connu reste, aucune alerte, aucun retour.
    assert (
        watch.update([(app, HostProbe("unreachable", detail="timed out")), (api, HostProbe("unreachable"))])
        == []
    )
    assert watch.result("APP.exemple.fr", "/api").probe.state == "no_connector"  # type: ignore[union-attr]
    # Retour : un message de succès.
    back = watch.update([(app, HostProbe("ok", 200)), (api, HostProbe("ok", 200))])
    assert [(c.level, c.message()) for c in back] == [("success", "app.exemple.fr/api répond de nouveau.")]
    assert watch.troubled == []


def test_record_keeps_other_results_and_update_forgets_removed_names():
    watch = ServiceWatch()
    app, other = target(), target("web.exemple.fr")
    watch.update([(app, HostProbe("ok", 200)), (other, HostProbe("not_found"))])
    assert troubled_services_summary(watch.troubled) == "web.exemple.fr ne répond plus"
    watch.record([(app, HostProbe("access", 302))])  # test d'un seul nom : l'autre reste
    assert watch.result("web.exemple.fr") is not None
    watch.update([(app, HostProbe("ok", 200))])  # relevé complet sans « web » : il est oublié
    assert watch.result("web.exemple.fr") is None
    watch.update([(app, HostProbe("not_found")), (other, HostProbe("origin_down", 502))])
    assert troubled_services_summary(watch.troubled) == "2 services en panne"
    assert [r.probe.state for r in watch.troubled] == [
        "not_found",
        "origin_down",
    ]  # du plus grave au moins grave
    watch.forget()
    assert watch.troubled == [] and troubled_services_summary([]) == ""


def test_advice_for_each_problem():
    assert "Bot Fight Mode" in HostProbe("challenge", 403).advice()
    assert "cloudflared" in HostProbe("no_connector", 530).advice()
    assert "Modifier le service" in HostProbe("origin_down", 502).advice()
    assert "Corriger le DNS" in HostProbe("not_found").advice()
    assert "Autoriser un service token" in HostProbe("refused", 403).advice()
    assert HostProbe("ok", 200).advice() == ""
