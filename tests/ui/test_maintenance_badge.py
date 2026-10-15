"""Pastille « Maintenance » des cartes de la vue Cloudflare et sous-menu « Pannes » de l'icône (P29)."""

from __future__ import annotations

from datetime import datetime

import pytest

from cma.core.cfapi import Tunnel
from cma.core.hostprobe import HostProbe
from cma.core.models import MaintenanceWindow
from cma.core.servicewatch import ServiceTarget
from cma.ui.tray import Tray
from cma.ui.views.cloud.cards import MAINTENANCE_ROLE, TUNNEL_ROLE
from tests.fakes.fake_cfapi import TOKEN, FakeCloudflare, FakeCloudflareServer


@pytest.fixture
def cf():
    with FakeCloudflareServer(FakeCloudflare()) as server:
        yield server


def today() -> int:
    return datetime.now().astimezone().weekday()


def whole_day(**kwargs: str) -> MaintenanceWindow:
    """Aujourd'hui, de 0 h à 0 h le lendemain (début = fin : la journée entière)."""
    return MaintenanceWindow(weekday=today(), start="00:00", end="00:00", **kwargs)


def covered(item) -> bool:
    return bool(item.data(0, MAINTENANCE_ROLE))


def items_of(top):
    return [top, *(top.child(i) for i in range(top.childCount()))]


def open_cards(qtbot, gui, cf):
    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    window.show()
    view = window.cloud
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=45000)
    return ctx, window, view


def test_maintenance_badge_follows_the_window(qtbot, gui, cf):
    """Un tunnel en maintenance et ses noms d'hôte portent la pastille, avec la fin et le libellé en info-bulle ;
    elle disparaît hors fenêtre ; l'autre tunnel n'est pas touché ; une maintenance de tout le compte couvre tout."""
    ctx, window, view = open_cards(qtbot, gui, cf)
    first, second = view.tree.topLevelItem(0), view.tree.topLevelItem(1)
    assert first.childCount() >= 1  # le second tunnel n'a aucun nom d'hôte
    assert not any(covered(i) for top in (first, second) for i in items_of(top))
    assert "Maintenance" not in first.toolTip(0)
    plain_image = view.tree.grab().toImage()

    ctx.update_config(
        lambda c: c.settings.maintenance_windows.append(
            whole_day(target=f"tunnel:{first.data(0, TUNNEL_ROLE).id}", label="Mises à jour")
        )
    )
    view.show_maintenance()
    assert all(covered(i) for i in items_of(first))  # un nom d'hôte suit son tunnel
    assert not any(covered(i) for i in items_of(second))
    assert first.data(0, MAINTENANCE_ROLE).startswith("Maintenance en cours jusqu'à ")
    assert first.data(0, MAINTENANCE_ROLE).endswith(" : Mises à jour")
    assert first.data(0, MAINTENANCE_ROLE) in first.toolTip(0) and "Tunnel " in first.toolTip(0)
    assert first.data(0, MAINTENANCE_ROLE) in first.child(0).toolTip(0) and "→" in first.child(0).toolTip(0)
    # Les pastilles sont bien peintes : la carte change.
    assert view.tree.grab().toImage() != plain_image

    # Plus de fenêtre : la pastille et l'info-bulle disparaissent.
    ctx.update_config(lambda c: setattr(c.settings, "maintenance_windows", []))
    view.show_maintenance()
    assert not any(covered(i) for top in (first, second) for i in items_of(top))
    assert "Maintenance" not in first.toolTip(0) and "Maintenance" not in first.child(0).toolTip(0)
    assert view.tree.grab().toImage() == plain_image

    # Une fenêtre un autre jour ne couvre rien.
    ctx.update_config(
        lambda c: c.settings.maintenance_windows.append(
            MaintenanceWindow(weekday=(today() + 3) % 7, start="00:00", end="00:00")
        )
    )
    view.show_maintenance()
    assert not any(covered(i) for top in (first, second) for i in items_of(top))

    # Tout le compte, vu par un relevé de la surveillance (Monitor.refresh), sans relire le compte.
    ctx.update_config(lambda c: setattr(c.settings, "maintenance_windows", [whole_day()]))
    window.monitor.refresh()
    assert all(covered(i) for top in (first, second) for i in items_of(top))
    # Sans libellé : la fin seulement.
    assert second.data(0, MAINTENANCE_ROLE).startswith("Maintenance en cours jusqu'à ")
    assert " : " not in second.data(0, MAINTENANCE_ROLE)


def test_maintenance_badge_is_set_when_the_account_is_reread(qtbot, gui, cf):
    """La pastille se pose aussi à la lecture du compte, sans relevé de la surveillance."""
    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    view = window.cloud
    ctx.update_config(lambda c: c.settings.maintenance_windows.append(whole_day(label="Nuit")))
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=45000)
    assert all(
        covered(i) for top in (view.tree.topLevelItem(0), view.tree.topLevelItem(1)) for i in items_of(top)
    )
    assert "Nuit" in view.tree.topLevelItem(1).toolTip(0)
    ctx.update_config(lambda c: setattr(c.settings, "maintenance_windows", []))
    view.refresh()
    qtbot.waitUntil(lambda: not covered(view.tree.topLevelItem(0)), timeout=45000)
    assert not covered(view.tree.topLevelItem(0).child(0))


def test_tray_hides_objects_under_maintenance(qtbot, gui):
    """Un tunnel et un nom d'hôte en maintenance ne sont pas listés dans « Pannes » de l'icône : le Monitor les filtre
    comme la sourdine."""
    ctx, window = gui
    window.show()
    tray = Tray(ctx, window)
    target = ServiceTarget("wiki.exemple.fr", "", "http://localhost:8080", "t1", "bureau")
    window.monitor.tunnel_watch.update([Tunnel("t1", "bureau", "down"), Tunnel("t2", "labo", "degraded")])
    window.ctx.services.update([(target, HostProbe("origin_down", 502, ms=5.0))])
    window.monitor.refresh()
    menu = tray._build_health_submenu()
    assert menu is not None and "Pannes (3)" in menu.title()
    # Maintenance du tunnel t1 : lui et son nom d'hôte disparaissent, le tunnel t2 reste.
    ctx.update_config(
        lambda c: c.settings.maintenance_windows.append(whole_day(target="tunnel:t1", label="Mises à jour"))
    )
    window.monitor.refresh()
    assert [t.id for t in tray.troubled] == ["t2"] and tray.services == []
    menu = tray._build_health_submenu()
    assert menu is not None and "Pannes (1)" in menu.title()
    assert [a.text() for a in menu.actions() if a.menu() is not None] == ["Tunnel « labo » — Dégradé"]
    # Tout le compte en maintenance : plus de sous-menu.
    ctx.update_config(lambda c: setattr(c.settings, "maintenance_windows", [whole_day()]))
    window.monitor.refresh()
    assert tray._build_health_submenu() is None
    # Fin de la maintenance : tout revient.
    ctx.update_config(lambda c: setattr(c.settings, "maintenance_windows", []))
    window.monitor.refresh()
    menu = tray._build_health_submenu()
    assert menu is not None and "Pannes (3)" in menu.title()
