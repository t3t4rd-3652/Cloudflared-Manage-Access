"""Surveillance des services dans l'interface : relevé, alertes, pastilles des cartes, test de tous les noms, reprise
après la veille ou le retour du réseau."""

from __future__ import annotations

from datetime import datetime

import pytest

import cma.ui.views.cloud.cards as cards_module
import cma.ui.views.cloud.tunnels_tab as tunnels_module
from cma.core.hostprobe import HostProbe
from cma.core.servicewatch import ServiceResult, ServiceTarget
from cma.ui.views.cloud.cards import SERVICE_ROLE
from cma.ui.views.cloud.services import ServiceTestsDialog, service_badge, service_tooltip
from cma.ui.wake import WakeWatcher
from tests.fakes.fake_cfapi import TOKEN, FakeCloudflare, FakeCloudflareServer

GRAFANA = ServiceTarget("grafana.exemple.fr", "", "http://localhost:3000", "t1", "bureau")


@pytest.fixture
def cf():
    with FakeCloudflareServer(FakeCloudflare()) as server:
        yield server


def test_main_window_reports_services_and_marks_navigation(qtbot, gui, monkeypatch):
    ctx, window = gui
    notes: list[tuple[str, str]] = []
    window.banners.show_message = lambda level, text, **_k: notes.append((level, text))  # type: ignore[method-assign]
    admin = ctx.manager.cloudflare
    readings = [
        [(GRAFANA, HostProbe("origin_down", 502))],
        [(GRAFANA, HostProbe("origin_down", 502))],
        [(GRAFANA, HostProbe("ok", 200))],
    ]

    async def check_services() -> list[tuple[ServiceTarget, HostProbe]]:
        return readings.pop(0)

    monkeypatch.setattr(admin, "has_token", lambda: True)
    monkeypatch.setattr(admin, "check_services", check_services)
    window.show()
    assert window.check_services() is False  # aucun compte choisi
    ctx.update_config(lambda c: setattr(c.settings, "cloudflare_account_id", "acc1"))
    emitted: list[list[ServiceResult]] = []
    window.services_troubled.connect(emitted.append)

    assert window.check_services() is True
    qtbot.waitUntil(lambda: notes != [], timeout=5000)
    assert notes == [
        ("warning", "grafana.exemple.fr : le tunnel répond, mais pas le service derrière lui (erreur 502).")
    ]
    nav = window._nav_items["cloud"]
    assert nav.text().endswith("· 1 !") and "grafana.exemple.fr ne répond plus" in nav.toolTip()
    assert [r.target.hostname for r in emitted[-1]] == ["grafana.exemple.fr"]
    # Toujours en panne : pas de nouvelle alerte.
    window.check_services()
    qtbot.waitUntil(lambda: len(readings) == 1 and not window._service_check_running, timeout=5000)
    assert len(notes) == 1
    # Retour : un succès, et la navigation redevient normale.
    window.check_services()
    qtbot.waitUntil(lambda: len(notes) == 2, timeout=5000)
    assert notes[-1] == ("success", "grafana.exemple.fr répond de nouveau.")
    assert not nav.text().endswith("!")
    # Réglage coupé : rien n'est testé, l'ancien relevé est oublié.
    ctx.update_config(lambda c: setattr(c.settings, "watch_services", False))
    assert window.check_services() is False and ctx.services.troubled == []


def test_cards_show_the_last_test_and_test_all(qtbot, gui, cf, monkeypatch):
    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    view = window.cloud
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=10000)
    bureau = view.tree.topLevelItem(0)
    rows = {bureau.child(i).data(0, cards_module.RULE_ROLE).hostname: bureau.child(i) for i in range(3)}
    assert rows["grafana.exemple.fr"].data(0, SERVICE_ROLE) is None
    assert view.test_all_button.isEnabled()

    tested: list[list[str]] = []
    shown: list[int] = []

    async def probe_services(targets: list[ServiceTarget]) -> list[tuple[ServiceTarget, HostProbe]]:
        tested.append([t.label for t in targets])
        return [(t, HostProbe("origin_down", 502) if t.web else HostProbe("access", 302)) for t in targets]

    monkeypatch.setattr(view.admin, "probe_services", probe_services)
    monkeypatch.setattr(tunnels_module, "show_service_tests", lambda _p, results: shown.append(len(results)))
    view.test_all_hostnames()
    qtbot.waitUntil(lambda: shown == [3], timeout=5000)
    assert tested == [["ssh.exemple.fr", "rdp.exemple.fr", "grafana.exemple.fr"]]
    grafana = rows["grafana.exemple.fr"].data(0, SERVICE_ROLE)
    assert isinstance(grafana, ServiceResult) and grafana.probe.state == "origin_down"
    assert "Modifier le service" in rows["grafana.exemple.fr"].toolTip(0)
    assert service_badge(rows["ssh.exemple.fr"].data(0, SERVICE_ROLE)) is None  # la carte dit déjà « Access »

    # Un relevé de la surveillance se reporte sur les cartes sans relire le compte.
    ctx.services.record([(GRAFANA, HostProbe("ok", 200))])
    view.show_service_results()
    assert service_badge(rows["grafana.exemple.fr"].data(0, SERVICE_ROLE)) == (
        "Répond",
        "circle-check",
        "success",
    )


def test_service_tests_dialog_lists_failures_first(qtbot):
    ssh = ServiceTarget("ssh.exemple.fr", "", "ssh://localhost:22", "t1", "bureau")
    web = ServiceTarget("web.exemple.fr", "", "https://localhost", "t2", "labo")
    dialog = ServiceTestsDialog(
        None,
        [
            (ssh, HostProbe("access", 302)),
            (GRAFANA, HostProbe("ok", 200)),
            (web, HostProbe("challenge", 403)),
        ],
    )
    qtbot.addWidget(dialog)
    dialog.results = sorted(dialog.results, key=lambda r: r[0].label)  # ordre stable pour la suite
    dialog._fill()
    table = dialog.table
    assert [table.item(r, 0).text() for r in range(3)] == [
        "grafana.exemple.fr",
        "ssh.exemple.fr",
        "web.exemple.fr",
    ]
    table.selectRow(1)
    assert "Service non HTTP" in dialog.advice.text()
    table.selectRow(2)
    assert (
        "Bot Fight Mode" in dialog.advice.text() and table.item(2, 2).text() == "Vérification de navigateur"
    )

    failing = ServiceTestsDialog(
        None, [(GRAFANA, HostProbe("ok", 200)), (web, HostProbe("no_connector", 530))]
    )
    qtbot.addWidget(failing)
    assert failing.table.item(0, 0).text() == "web.exemple.fr"  # les pannes d'abord


def test_service_tooltip_and_badges():
    result = ServiceResult(GRAFANA, HostProbe("no_connector", 530), datetime(2026, 10, 9, 14, 5))
    text = service_tooltip(result)
    assert "erreur 1033" in text and "relancez le service cloudflared" in text and "14:05" in text
    assert service_badge(result) == ("Aucun connecteur", "plug-connected-x", "danger")
    assert service_badge(None) is None


def test_wake_watcher_detects_sleep_and_network_return(qtbot):
    now = {"t": 1000.0}
    watcher = WakeWatcher(clock=lambda: now["t"])
    reasons: list[str] = []
    watcher.resumed.connect(reasons.append)
    now["t"] += 30
    watcher.tick()
    assert reasons == []  # tic ordinaire
    now["t"] += 600
    watcher.tick()
    assert reasons == ["sleep"]
    # Le réseau revient juste après le réveil : un seul signal.
    watcher.network_changed(False)
    watcher.network_changed(True)
    assert reasons == ["sleep"]
    now["t"] += 60
    watcher.network_changed(False)
    watcher.network_changed(True)
    assert reasons == ["sleep", "network"]
    watcher.network_changed(True)  # déjà en ligne : rien
    assert reasons == ["sleep", "network"]


def test_resume_sessions_notifies_when_something_restarts(qtbot, gui, monkeypatch):
    ctx, window = gui
    notes: list[str] = []
    window.banners.show_message = lambda _level, text, **_k: notes.append(text)  # type: ignore[method-assign]
    counts = [2, 0]

    async def resume() -> int:
        return counts.pop(0)

    monkeypatch.setattr(ctx.manager, "resume_after_network", resume)
    window.show()
    window.resume_sessions("network")
    qtbot.waitUntil(lambda: notes != [], timeout=5000)
    assert notes == ["Réseau revenu : 2 connexion(s) relancée(s)."]
    window.resume_sessions("sleep")
    qtbot.waitUntil(lambda: counts == [], timeout=5000)
    assert len(notes) == 1  # rien relancé, rien à dire
