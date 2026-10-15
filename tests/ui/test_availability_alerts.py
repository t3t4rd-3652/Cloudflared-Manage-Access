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
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=45000)

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
    qtbot.waitUntil(lambda: bool(grafana().data(0, MUTED_ROLE)), timeout=45000)
    unmute = next(
        a for a in view.tree_menu(grafana()).actions() if a.text().startswith("Réactiver les alertes")
    )
    unmute.trigger()
    assert ctx.config().settings.muted == {}
    # Sourdine d'un tunnel : son résumé le dit, ses noms d'hôte aussi.
    tunnel_menu = view.tree_menu(view.tree.topLevelItem(0))
    next(a.menu() for a in tunnel_menu.actions() if a.text() == "Mettre en sourdine").actions()[0].trigger()
    qtbot.waitUntil(lambda: "sourdine" in view.tree.topLevelItem(0).text(1), timeout=45000)
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


def test_availability_chart_and_export(qtbot, tmp_path, monkeypatch):
    import cma.ui.views.cloud.availability as availability_module

    path = tmp_path / "availability.json"
    log = AvailabilityLog(path)
    now = datetime.now(UTC)
    for hours in range(30):
        log.record_check("service:wiki", "wiki.exemple.fr", hours != 2, 150.0, now - timedelta(hours=hours))
    log.save()
    dialog = AvailabilityDialog(None, path)
    qtbot.addWidget(dialog)
    dialog.show()
    assert dialog.chart.isHidden() and "Choisissez" in dialog.chart_title.text()
    dialog.table.selectRow(0)
    assert dialog.chart.isVisible() and len(dialog.chart.series) == 30
    assert "wiki.exemple.fr" in dialog.chart_title.text()
    assert "jours relevés" in dialog.chart.accessibleDescription()
    dialog.period.setCurrentIndex(2)
    assert len(dialog.chart.series) == 90
    dialog.chart.grab()  # le dessin ne lève rien
    from PySide6.QtCore import QPoint
    from PySide6.QtTest import QTest

    QTest.mouseMove(dialog.chart, QPoint(dialog.chart.width() - 3, 30))
    # Survol : le dernier jour (aujourd'hui) a ses tests ; hors des barres, rien.
    chart = dialog.chart
    last = chart.text_at(chart.width() - 3)
    assert last is not None and "tests" in last and "%" in last
    assert chart.text_at(chart.width() + 50) is None
    from PySide6.QtCore import QPointF, Qt
    from PySide6.QtGui import QMouseEvent

    event = QMouseEvent(
        QMouseEvent.Type.MouseMove,
        QPointF(chart.width() - 3, 30),
        QPointF(chart.mapToGlobal(QPoint(chart.width() - 3, 30))),
        Qt.MouseButton.NoButton,
        Qt.MouseButton.NoButton,
        Qt.KeyboardModifier.NoModifier,
    )
    chart.mouseMoveEvent(event)  # l'info-bulle s'affiche sans erreur

    html_path = tmp_path / "rapport.html"
    monkeypatch.setattr(availability_module, "ask_report_path", lambda _p, _d: html_path)
    dialog.export_report()
    assert html_path.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert dialog.export_note.text() == "Rapport enregistré : rapport.html"
    csv_path = tmp_path / "rapport.csv"
    monkeypatch.setattr(availability_module, "ask_report_path", lambda _p, _d: csv_path)
    dialog.export_report()
    assert csv_path.read_text(encoding="utf-8-sig").startswith("Objet;Type")


def test_maintenance_badge_on_cards(qtbot, gui, cf):
    """Pastille « Maintenance » (P29) : un tunnel et ses noms d'hôte en maintenance la portent avec la fin et le
    libellé en info-bulle ; elle disparaît hors fenêtre ; une maintenance de tout le compte couvre tout."""
    from cma.core.models import MaintenanceWindow
    from cma.ui.views.cloud.cards import MAINTENANCE_ROLE, TUNNEL_ROLE

    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    window.show()
    view = window.cloud
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=45000)
    first, second = view.tree.topLevelItem(0), view.tree.topLevelItem(1)
    assert first.childCount() >= 1
    first_id = first.data(0, TUNNEL_ROLE).id

    def covered(item) -> bool:
        return bool(item.data(0, MAINTENANCE_ROLE))

    def anywhere() -> bool:
        return any(
            covered(item)
            for top in (first, second)
            for item in [top, *(top.child(i) for i in range(top.childCount()))]
        )

    assert not anywhere()
    today = datetime.now().astimezone().weekday()
    # Une journée entière, aujourd'hui, sur le premier tunnel : lui et ses noms d'hôte, pas l'autre.
    ctx.update_config(
        lambda c: c.settings.maintenance_windows.append(
            MaintenanceWindow(
                weekday=today, start="00:00", end="00:00", target=f"tunnel:{first_id}", label="Mises à jour"
            )
        )
    )
    view.show_maintenance()
    assert covered(first) and all(covered(first.child(i)) for i in range(first.childCount()))
    assert not covered(second) and not any(covered(second.child(i)) for i in range(second.childCount()))
    tip = first.toolTip(0)
    assert "Maintenance en cours jusqu'à " in tip and "Mises à jour" in tip and "Tunnel " in tip
    assert "Mises à jour" in first.child(0).toolTip(0) and "→" in first.child(0).toolTip(0)
    # Les pastilles sont bien peintes : la carte change.
    covered_image = view.tree.grab().toImage()
    ctx.update_config(lambda c: setattr(c.settings, "maintenance_windows", []))
    view.show_maintenance()
    assert not anywhere() and "Maintenance" not in first.toolTip(0)
    assert view.tree.grab().toImage() != covered_image
    # Une fenêtre un autre jour ne couvre rien.
    ctx.update_config(
        lambda c: c.settings.maintenance_windows.append(
            MaintenanceWindow(weekday=(today + 3) % 7, start="00:00", end="00:00")
        )
    )
    view.show_maintenance()
    assert not anywhere()
    # Tout le compte, vu par un relevé de la surveillance (Monitor.refresh) sans relire le compte.
    ctx.update_config(
        lambda c: setattr(
            c.settings, "maintenance_windows", [MaintenanceWindow(weekday=today, start="00:00", end="00:00")]
        )
    )
    window.monitor.refresh()
    assert covered(first) and covered(second) and covered(second.child(0))
    assert (
        "Maintenance en cours jusqu'à " in second.toolTip(0)
        and ":" not in second.toolTip(0).split("à ")[-1][5:]
    )


def test_maintenance_badge_after_a_reread(qtbot, gui, cf):
    """La pastille se pose aussi quand le compte est relu (`fill`), sans relevé de la surveillance."""
    from cma.core.models import MaintenanceWindow
    from cma.ui.views.cloud.cards import MAINTENANCE_ROLE

    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    view = window.cloud
    ctx.update_config(
        lambda c: c.settings.maintenance_windows.append(
            MaintenanceWindow(weekday=datetime.now().astimezone().weekday(), start="00:00", end="00:00")
        )
    )
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=45000)
    first = view.tree.topLevelItem(0)
    assert first.data(0, MAINTENANCE_ROLE) and first.child(0).data(0, MAINTENANCE_ROLE)
    # Sans libellé : l'info-bulle ne garde que la fin.
    assert first.data(0, MAINTENANCE_ROLE).startswith("Maintenance en cours jusqu'à ")
    assert ":" not in first.data(0, MAINTENANCE_ROLE).split(" : ")[-1][-1:]
