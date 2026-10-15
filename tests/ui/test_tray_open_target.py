"""« Ouvrir » du sous-menu Pannes de l'icône : la vue Cloudflare s'ouvre sur l'objet en panne, relu puis sélectionné."""

from __future__ import annotations

from datetime import datetime

import pytest

from cma.core.cfapi import IngressRule, Tunnel
from cma.core.hostprobe import HostProbe
from cma.core.servicewatch import ServiceResult, ServiceTarget
from cma.ui.tray import Tray
from cma.ui.views.cloud.cards import RULE_ROLE, TUNNEL_ROLE
from tests.fakes.fake_cfapi import TOKEN, FakeCloudflare, FakeCloudflareServer


@pytest.fixture
def cf():
    with FakeCloudflareServer(FakeCloudflare()) as server:
        yield server


def _connect(qtbot, window, cf):
    window.ctx.core.manager.cloudflare.base_url = cf.base_url
    view = window.cloud
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=45000)
    return view


def _selected(view):
    item = view.tree.currentItem()
    assert item is not None, "rien n'est sélectionné"
    parent = item.parent() or item
    rule = item.data(0, RULE_ROLE) if item.parent() is not None else None
    tunnel = parent.data(0, TUNNEL_ROLE)
    return tunnel.id, rule


def test_open_tunnel_selects_it_after_the_account_is_read(qtbot, gui, cf):
    ctx, window = gui
    window.show()
    view = _connect(qtbot, window, cf)
    tray = Tray(ctx, window)
    view.tree.setCurrentItem(view.tree.topLevelItem(0))  # « bureau » : ce n'est pas le tunnel visé
    assert _selected(view)[0] == "t1"
    window.show_view("dashboard")

    tray._open_tunnel_from_health(Tunnel("t2", "labo", "down"))

    assert window.stack.currentWidget() is window.cloud
    # La sélection se fait après la relecture : on attend qu'elle ait eu lieu, pas seulement que la vue soit affichée.
    qtbot.waitUntil(lambda: _selected(view) == ("t2", None), timeout=45000)


def test_open_service_selects_its_rule(qtbot, gui, cf):
    ctx, window = gui
    window.show()
    view = _connect(qtbot, window, cf)
    tray = Tray(ctx, window)
    view.tree.setCurrentItem(view.tree.topLevelItem(1))  # « labo » : pas le tunnel du service
    window.show_view("dashboard")
    target = ServiceTarget("rdp.exemple.fr", "", "rdp://10.0.0.5:3389", "t1", "bureau")

    tray._open_cloud_from_health(ServiceResult(target, HostProbe("origin_down", 502), datetime.now()))

    assert window.stack.currentWidget() is window.cloud
    expected = ("t1", IngressRule("rdp.exemple.fr", "rdp://10.0.0.5:3389"))
    qtbot.waitUntil(lambda: _selected(view) == expected, timeout=45000)


def test_open_service_unknown_hostname_keeps_the_view_usable(qtbot, gui, cf):
    ctx, window = gui
    window.show()
    view = _connect(qtbot, window, cf)
    target = ServiceTarget("disparu.exemple.fr", "", "http://localhost:1", "t1", "bureau")

    window.open_service(target.hostname, target.path)

    qtbot.waitUntil(lambda: view.read_at is not None and not view._loading, timeout=45000)  # type: ignore[reportPrivateUsage]
    assert window.stack.currentWidget() is window.cloud
