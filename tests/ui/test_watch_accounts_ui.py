"""Surveillance de tous les comptes (P34, ADR 0003) côté interface : `Monitor`, zone de notification, Paramètres.

Faux serveur Cloudflare sur 127.0.0.1, deux jetons et deux comptes ; les tests depuis Internet et les envois d'alerte
sont remplacés.
"""

from __future__ import annotations

from typing import Any

import pytest

from cma.core.alerts import Alert, secret_key
from cma.core.hostprobe import HostProbe
from cma.core.models import AlertChannel
from cma.ui.monitor import Monitor
from tests.fakes.fake_cfapi import SECOND_TOKEN, FakeCloudflareServer, register_two_tokens, two_accounts


@pytest.fixture
def cf():
    with FakeCloudflareServer(two_accounts()) as server:
        yield server


@pytest.fixture
def probes(monkeypatch) -> list[str]:
    asked: list[str] = []

    async def fake_probe(hostname: str, **_kwargs: Any) -> HostProbe:
        asked.append(hostname)
        return (
            HostProbe("origin_down", 502, ms=30.0) if hostname == "app.exemple.org" else HostProbe("ok", 200)
        )

    monkeypatch.setattr("cma.core.servicewatch.probe_hostname_async", fake_probe)
    return asked


@pytest.fixture
def sent(monkeypatch) -> list[Alert]:
    """Envois vers les canaux d'alerte remplacés (aucune requête ne sort)."""
    alerts: list[Alert] = []
    monkeypatch.setattr("cma.core.monitoring.send_alert", lambda _kind, _url, alert: alerts.append(alert))
    return alerts


def watched_monitor(ctx, cf, *, second: str = SECOND_TOKEN, watch_all: bool = True):
    admin = ctx.manager.cloudflare
    admin.base_url = cf.base_url  # faux serveur local, jamais l'API réelle
    register_two_tokens(ctx.update_config, admin.secrets, second=second, watch_all=watch_all)
    channel = AlertChannel(name="Téléphone", kind="ntfy")
    admin.secrets.set(secret_key(channel.id), "https://ntfy.exemple.fr/sujet-de-test")
    ctx.update_config(lambda c: setattr(c.settings, "alert_channels", [channel]))
    opened: list[tuple[object, bool]] = []
    monitor = Monitor(ctx, None, open_tunnel=lambda t, d: opened.append((t, d)), start=False)
    notices: list[tuple[str, str, object]] = []
    troubles: list[tuple[list[Any], list[Any]]] = []
    checked: list[bool] = []
    monitor.notice.connect(lambda level, text, action: notices.append((level, text, action)))
    monitor.troubled.connect(lambda tunnels, services: troubles.append((tunnels, services)))
    monitor.services_checked.connect(lambda: checked.append(True))
    return monitor, notices, troubles, checked, opened


def run_tunnels(qtbot, monitor, troubles) -> None:
    troubles.clear()
    assert monitor.check_tunnels() is True
    qtbot.waitUntil(lambda: not monitor.tunnel_check_running and bool(troubles), timeout=15000)


def test_monitor_watches_every_account(qtbot, gui_context, cf, probes, sent):
    ctx = gui_context
    monitor, notices, troubles, checked, opened = watched_monitor(ctx, cf)
    run_tunnels(qtbot, monitor, troubles)
    # Les pannes des deux comptes, avec le nom du compte.
    texts = [text for _level, text, _action in notices]
    assert "Le tunnel « labo (Compte A) » est hors ligne" in texts[0]
    assert "Le tunnel « api (Compte B) » est hors ligne" in texts[1]
    assert [t.name for t in troubles[-1][0]] == ["api (Compte B)", "labo (Compte A)"]
    # « Diagnostiquer… » seulement pour le compte de la vue Cloudflare (l'autre n'y est pas affiché).
    actions = [action for _level, _text, action in notices]
    assert isinstance(actions[0], tuple) and actions[0][0] == "Diagnostiquer…" and actions[1] is None
    # Journal : les clés restent celles d'avant ; le libellé porte le compte.
    incident = monitor.availability.open_incident("tunnel", "tunnel:t9")
    assert incident is not None and incident.label == "api (Compte B)"
    # Alertes vers les canaux : le compte est dans le titre.
    qtbot.waitUntil(lambda: len(sent) == 2, timeout=10000)
    assert sorted(a.title for a in sent) == ["CMA — panne : api (Compte B)", "CMA — panne : labo (Compte A)"]

    # Services : ceux des deux comptes, le compte dans le libellé.
    notices.clear()
    assert monitor.check_services() is True
    qtbot.waitUntil(lambda: bool(checked), timeout=15000)
    assert sorted(probes) == ["app.exemple.org", "grafana.exemple.fr"]
    assert [r.target.label for r in troubles[-1][1]] == ["app.exemple.org (Compte B)"]
    assert [text for _l, text, _a in notices] == [
        "app.exemple.org (Compte B) : le tunnel répond, mais pas le service derrière lui (erreur 502)."
    ]
    assert notices[0][2] is None  # service d'un autre compte : pas de « Voir… »
    assert monitor.availability.open_incident("service", "service:app.exemple.org") is not None


def test_a_refused_token_does_not_stop_the_monitor(qtbot, gui_context, cf, probes, sent):
    ctx = gui_context
    monitor, notices, troubles, checked, _opened = watched_monitor(ctx, cf)
    run_tunnels(qtbot, monitor, troubles)
    assert len(notices) == 2
    # Le jeton du compte B est révoqué : le compte A est toujours relevé, et ce qu'on savait du compte B reste (pas de
    # retour annoncé, pas d'incident clos, pas de nouvelle alerte quand il revient).
    second = cf.state.tenants.pop(SECOND_TOKEN)
    cf.state.tunnels[1]["status"] = "healthy"  # labo revient
    notices.clear()
    run_tunnels(qtbot, monitor, troubles)
    assert [text for _l, text, _a in notices] == ["Le tunnel « labo (Compte A) » est de nouveau en ligne."]
    assert [t.name for t in troubles[-1][0]] == ["api (Compte B)"]
    assert monitor.availability.open_incident("tunnel", "tunnel:t9") is not None
    cf.state.tenants[SECOND_TOKEN] = second
    notices.clear()
    run_tunnels(qtbot, monitor, troubles)
    assert notices == [] and [t.name for t in troubles[-1][0]] == ["api (Compte B)"]

    # Services : un compte illisible garde ses résultats et ne ferme rien.
    assert monitor.check_services() is True
    qtbot.waitUntil(lambda: bool(checked), timeout=15000)
    cf.state.tenants.pop(SECOND_TOKEN)
    checked.clear()
    notices.clear()
    assert monitor.check_services() is True
    qtbot.waitUntil(lambda: bool(checked), timeout=15000)
    assert notices == [] and [r.target.label for r in troubles[-1][1]] == ["app.exemple.org (Compte B)"]
    assert monitor.availability.open_incident("service", "service:app.exemple.org") is not None


def test_monitor_without_the_setting_watches_one_account(qtbot, gui_context, cf, probes, sent):
    ctx = gui_context
    monitor, notices, troubles, checked, _opened = watched_monitor(ctx, cf, watch_all=False)
    run_tunnels(qtbot, monitor, troubles)
    assert [text for _l, text, _a in notices] == [
        "Le tunnel « labo » est hors ligne : plus aucun connecteur ne le relie à Cloudflare."
    ]
    assert [t.name for t in troubles[-1][0]] == ["labo"]
    assert cf.state.tenants[SECOND_TOKEN].requests == []
    assert monitor.check_services() is True
    qtbot.waitUntil(lambda: bool(checked), timeout=15000)
    assert probes == ["grafana.exemple.fr"] and troubles[-1][1] == []

    # Activer le réglage : le compte B arrive, sans annoncer une seconde fois la panne déjà connue du compte A.
    ctx.update_config(lambda c: setattr(c.settings, "watch_all_accounts", True))
    notices.clear()
    run_tunnels(qtbot, monitor, troubles)
    assert [text for _l, text, _a in notices] == [
        "Le tunnel « api (Compte B) » est hors ligne : plus aucun connecteur ne le relie à Cloudflare."
    ]


def test_a_survey_finished_after_a_scope_change_is_ignored(qtbot, gui_context, cf):
    ctx = gui_context
    monitor, notices, troubles, _checked, _opened = watched_monitor(ctx, cf)
    assert monitor.check_tunnels() is True
    # Pendant le relevé, le jeton du compte B est oublié : son résultat ne vaut plus.
    ctx.update_config(lambda c: setattr(c.settings, "cloudflare_tokens", c.settings.cloudflare_tokens[:1]))
    qtbot.waitUntil(lambda: not monitor.tunnel_check_running, timeout=15000)
    assert notices == [] and troubles == []


def test_tray_and_health_labels_carry_the_account(qtbot, gui, cf, probes, sent):
    """Sous-menu « Pannes » et carte « Santé du compte » : le compte suit chaque nom."""
    from cma.ui.tray import Tray

    ctx, window = gui
    window.monitor.ctx.manager.cloudflare.base_url = cf.base_url
    register_two_tokens(ctx.update_config, ctx.manager.cloudflare.secrets)
    tray = Tray(ctx, window)
    assert window.monitor.check_tunnels() is True
    qtbot.waitUntil(lambda: len(tray.troubled) == 2, timeout=15000)
    menu = tray._build_health_submenu()
    assert menu is not None
    titles = [action.text() for action in menu.actions() if action.text()]
    assert titles[:2] == ["Tunnel « api (Compte B) » — Hors ligne", "Tunnel « labo (Compte A) » — Hors ligne"]
    health = window.dashboard.health
    assert "2 tunnels en panne" in health.detail.text()
    # Un seul tunnel en panne : son nom et son compte sur la carte.
    cf.state.tunnels[1]["status"] = "healthy"
    assert window.monitor.check_tunnels() is True
    qtbot.waitUntil(lambda: len(tray.troubled) == 1, timeout=15000)
    assert health.detail.text() == "Tunnel « api (Compte B) » hors ligne"
    assert "api (Compte B)" in tray.icon.toolTip()


def test_settings_checkbox(qtbot, gui):
    ctx, window = gui
    view = window.settings
    view.load()
    box = view.watch_all_accounts
    assert not box.isChecked() and not box.isEnabled()  # un seul jeton : rien à choisir
    register_two_tokens(ctx.update_config, ctx.manager.cloudflare.secrets, watch_all=False)
    view.load()
    assert box.isEnabled() and not box.isChecked()
    box.setChecked(True)
    assert ctx.config().settings.watch_all_accounts is True
    box.setChecked(False)
    assert ctx.config().settings.watch_all_accounts is False
