"""Disponibilité et alertes dans l'interface (P14) : canaux d'alerte, sourdine, boîte Disponibilité, journal tenu
par la fenêtre principale."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

import cma.ui.views.cloud.tunnels_tab as tunnels_module
import cma.ui.views.settings_alerts as alerts_module
from cma.core.alerts import Alert, AlertError
from cma.core.availability import AvailabilityLog
from cma.core.cfapi import Tunnel
from cma.core.hostprobe import HostProbe
from cma.core.models import AlertChannel
from cma.core.servicewatch import ServiceTarget
from cma.ui.views.cloud.availability import AvailabilityDialog, duration_text, percent
from cma.ui.views.cloud.cards import MUTED_ROLE
from tests.fakes.fake_cfapi import TOKEN, FakeCloudflare, FakeCloudflareServer

GRAFANA = ServiceTarget("grafana.exemple.fr", "", "http://localhost:3000", "t1", "bureau")


@pytest.fixture
def cf():
    with FakeCloudflareServer(FakeCloudflare()) as server:
        yield server


def test_alert_channels_in_settings(qtbot, gui, monkeypatch):
    ctx, window = gui
    section = window.settings.alerts
    assert section.table.rowCount() == 0 and not section.test_button.isEnabled()
    channel = AlertChannel(name="Téléphone", kind="ntfy")
    monkeypatch.setattr(alerts_module, "ask_channel", lambda _p: (channel, "https://ntfy.sh/sujet-secret"))
    section.add()
    assert [c.name for c in ctx.config().settings.alert_channels] == ["Téléphone"]
    assert ctx.core.secrets.get(f"alert:{channel.id}") == "https://ntfy.sh/sujet-secret"
    assert "sujet-secret" not in ctx.config().model_dump_json()  # l'adresse reste dans le coffre
    section.table.selectRow(0)
    sent: list[tuple[str, str, str]] = []

    def fake_send(kind: str, url: str, alert: Alert) -> None:
        sent.append((kind, url, alert.title))
        if len(sent) > 1:
            raise AlertError("Le canal a refusé l'alerte (403).")

    monkeypatch.setattr(alerts_module, "send_alert", fake_send)
    section.send_test()
    qtbot.waitUntil(lambda: section.status.text() == "Test envoyé à « Téléphone ».", timeout=5000)
    assert sent == [("ntfy", "https://ntfy.sh/sujet-secret", "CMA — test d'alerte")]
    section.send_test()
    qtbot.waitUntil(lambda: section.status.text().startswith("Échec du test"), timeout=5000)
    section.toggle_enabled()
    assert not ctx.config().settings.alert_channels[0].enabled
    assert section.table.item(0, 3).text() == "Suspendu"
    monkeypatch.setattr(alerts_module, "confirm", lambda *_a: True)
    section.table.selectRow(0)
    section.remove()
    assert ctx.config().settings.alert_channels == [] and ctx.core.secrets.get(f"alert:{channel.id}") is None


def test_channel_dialog_validates(qtbot):
    dialog = alerts_module.ChannelDialog(None)
    qtbot.addWidget(dialog)
    dialog._accept()
    assert dialog.error.text() == "Donnez un nom au canal."
    dialog.name.setText("Équipe")
    dialog.kind.setCurrentIndex(dialog.kind.findData("slack"))
    dialog.url.set_text("pas une adresse")
    dialog._accept()
    assert "https://" in dialog.error.text() and "hooks.slack.com" in dialog.hint.text()
    dialog.url.set_text("https://hooks.slack.com/services/x")
    dialog.recoveries.setChecked(False)
    channel, url = dialog.values()
    assert (channel.kind, channel.recoveries, url) == ("slack", False, "https://hooks.slack.com/services/x")


def test_mute_from_the_tunnel_menu(qtbot, gui, cf):
    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    view = window.cloud
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=10000)

    def grafana():
        top = view.tree.topLevelItem(0)
        return next(
            top.child(i) for i in range(top.childCount()) if top.child(i).text(0) == "grafana.exemple.fr"
        )

    menu = view.tree_menu(grafana())
    sub = next(a.menu() for a in menu.actions() if a.text() == "Mettre en sourdine")
    assert [a.text() for a in sub.actions()] == ["1 heure", "4 heures", "Jusqu'à demain 8 h", "1 semaine"]
    sub.actions()[1].trigger()
    assert set(ctx.config().settings.muted) == {"service:grafana.exemple.fr"}
    qtbot.waitUntil(lambda: bool(grafana().data(0, MUTED_ROLE)), timeout=10000)
    unmute = next(
        a for a in view.tree_menu(grafana()).actions() if a.text().startswith("Réactiver les alertes")
    )
    unmute.trigger()
    assert ctx.config().settings.muted == {}
    # Sourdine d'un tunnel : son résumé le dit, ses noms d'hôte aussi.
    tunnel_menu = view.tree_menu(view.tree.topLevelItem(0))
    next(a.menu() for a in tunnel_menu.actions() if a.text() == "Mettre en sourdine").actions()[0].trigger()
    qtbot.waitUntil(lambda: "sourdine" in view.tree.topLevelItem(0).text(1), timeout=10000)
    assert grafana().data(0, MUTED_ROLE)
    choices = tunnels_module.mute_choices(datetime(2026, 10, 9, 22, 30))
    assert choices[2][1] == timedelta(hours=9, minutes=30)


def test_main_window_records_and_alerts_but_respects_mute(qtbot, gui, monkeypatch):
    ctx, window = gui
    notes: list[str] = []
    window.banners.show_message = lambda _level, text, **_k: notes.append(text)  # type: ignore[method-assign]
    channel = AlertChannel(name="Téléphone", kind="ntfy")
    ctx.core.secrets.set(f"alert:{channel.id}", "https://ntfy.sh/x")
    ctx.update_config(lambda c: c.settings.alert_channels.append(channel))
    sent: list[str] = []
    monkeypatch.setattr("cma.core.monitoring.send_alert", lambda _k, _u, alert: sent.append(alert.title))
    admin = ctx.manager.cloudflare
    readings = [
        [Tunnel("t1", "bureau", "down")],
        [Tunnel("t1", "bureau", "healthy")],
    ]

    async def states() -> list[Tunnel]:
        return readings.pop(0)

    monkeypatch.setattr(admin, "has_token", lambda: True)
    monkeypatch.setattr(admin, "tunnel_states", states)
    ctx.update_config(lambda c: setattr(c.settings, "cloudflare_account_id", "acc1"))
    window.show()
    window.check_tunnels()
    qtbot.waitUntil(lambda: sent == ["CMA — panne : bureau"], timeout=5000)
    assert any("hors ligne" in n for n in notes)
    assert window.availability.open_incident("tunnel", "tunnel:t1") is not None
    window.check_tunnels()
    qtbot.waitUntil(lambda: len(sent) == 2, timeout=5000)
    assert sent[-1] == "CMA — bureau rétabli"
    assert AvailabilityLog(ctx.paths.data_dir / "availability.json").incidents[0].ended is not None

    # En sourdine : relevé et journalisé, mais ni notification ni alerte, ni badge de navigation.
    from cma.core.monitoring import mute, service_key

    ctx.update_config(lambda c: mute(c, service_key(GRAFANA), timedelta(hours=1)))
    before = len(notes)

    async def check_services() -> list[tuple[ServiceTarget, HostProbe]]:
        return [(GRAFANA, HostProbe("origin_down", 502, ms=80.0))]

    monkeypatch.setattr(admin, "check_services", check_services)
    window.check_services()
    qtbot.waitUntil(lambda: not window._service_check_running, timeout=5000)
    assert len(notes) == before and len(sent) == 2
    assert not window._nav_items["cloud"].text().endswith("!")
    assert window.availability.open_incident("service", "service:grafana.exemple.fr") is not None


def test_availability_dialog(qtbot, tmp_path):
    path = tmp_path / "availability.json"
    log = AvailabilityLog(path)
    now = datetime.now(UTC)
    for hours in range(10):
        log.record_check("service:wiki", "wiki.exemple.fr", hours != 3, 120.0, now - timedelta(hours=hours))
    log.record_check("tunnel:t1", "bureau", True, None, now)
    log.start("service", "service:wiki", "wiki.exemple.fr", "origin_down", now - timedelta(hours=3))
    log.end("service", "service:wiki", now - timedelta(hours=2, minutes=45))
    log.start("tunnel", "tunnel:t1", "bureau", "down", now - timedelta(minutes=10))
    log.save()
    dialog = AvailabilityDialog(None, path)
    qtbot.addWidget(dialog)
    rows = {dialog.table.item(r, 0).text(): r for r in range(dialog.table.rowCount())}
    wiki = rows["wiki.exemple.fr"]
    assert dialog.table.item(wiki, 2).text() == "90 %" or dialog.table.item(wiki, 2).text() == "90.00 %"
    assert dialog.table.item(wiki, 4).text() == "120 ms" and dialog.table.item(wiki, 5).text() == "1"
    assert dialog.incidents.rowCount() == 2 and dialog.incidents.item(0, 1).text() == "en cours"
    dialog.table.selectRow(wiki)
    assert dialog.incidents.rowCount() == 1 and dialog.incidents.item(0, 2).text() == "15 min"
    assert dialog.incidents.item(0, 3).text() == "Service injoignable"
    assert (
        duration_text(timedelta(hours=50)) == "2 j 2 h"
        and duration_text(timedelta(hours=3, minutes=5)) == "3 h 05"
    )
    empty = AvailabilityDialog(None, tmp_path / "absent.json")
    qtbot.addWidget(empty)
    assert empty.table.isHidden() and not empty.empty.isHidden()
    from cma.core.availability import Stats

    assert percent(Stats(None, None, None, 0)) == "—" and percent(Stats(1.0, None, None, 3)) == "100 %"
