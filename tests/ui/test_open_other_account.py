"""« Ouvrir » sur la panne d'un autre compte (P39, ADR 0003) : la vue Cloudflare bascule sur un jeton qui voit ce compte,
relit, puis sélectionne l'objet. Faux serveur Cloudflare à deux comptes et deux jetons ; rien ne sort vers le réseau."""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

import pytest

from cma.core.cfadmin import token_secret_key
from cma.core.cfapi import IngressRule
from cma.core.hostprobe import HostProbe
from cma.core.servicewatch import ServiceChange, ServiceResult, ServiceTarget
from cma.ui.tray import Tray
from cma.ui.views.cloud.cards import RULE_ROLE, TUNNEL_ROLE
from tests.fakes.fake_cfapi import SECOND_TOKEN, FakeCloudflareServer, register_two_tokens, two_accounts

NO_TOKEN = (
    "Aucun jeton d'API enregistré ne donne accès à ce compte Cloudflare : l'objet ne peut pas être ouvert."
)
APP_B = ServiceTarget(
    "app.exemple.org",
    "",
    "http://localhost:8080",
    "t8",
    "web (Compte B)",
    account_id="acc2",
    account="Compte B",
)


@pytest.fixture
def cf():
    with FakeCloudflareServer(two_accounts()) as server:
        yield server


@pytest.fixture
def watched(qtbot, gui, cf, monkeypatch):
    """Fenêtre sur le compte A (jeton « Perso »), deux comptes surveillés, pannes des deux relevées. `notices` : ce que
    la fenêtre a affiché (niveau, texte, action)."""
    ctx, window = gui
    admin = ctx.manager.cloudflare
    admin.base_url = cf.base_url  # faux serveur local, jamais l'API réelle
    register_two_tokens(ctx.update_config, admin.secrets)
    notices: list[tuple[str, str, object]] = []
    real_add = window.notices.add

    def add(level, text, action=None, at=None):
        notices.append((level, text, action))
        return real_add(level, text, action, at)

    monkeypatch.setattr(window.notices, "add", add)
    window.show()
    view = window.cloud
    view.connect_account(use_saved=True)
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=45000)
    assert window.monitor.check_tunnels() is True
    qtbot.waitUntil(
        lambda: not window.monitor.tunnel_check_running and len(window.monitor.tunnel_watch.troubled) == 2,
        timeout=45000,
    )
    window.show_view("dashboard")
    return SimpleNamespace(ctx=ctx, window=window, view=view, tray=Tray(ctx, window), notices=notices)


def trouble(window, name: str):
    return next(t for t in window.monitor.tunnel_watch.troubled if t.name.startswith(name))


def selected(view):
    item = view.tree.currentItem()
    if item is None:
        return None
    parent = item.parent() or item
    rule = item.data(0, RULE_ROLE) if item.parent() is not None else None
    return parent.data(0, TUNNEL_ROLE).id, rule


def active(ctx) -> tuple[str | None, str | None]:
    settings = ctx.config().settings
    return settings.cloudflare_token_id, settings.cloudflare_account_id


def test_open_a_tunnel_of_another_account_switches_token_and_account(qtbot, watched):
    ctx, window, view, tray = watched.ctx, watched.window, watched.view, watched.tray
    api = trouble(window, "api")  # compte B, que le jeton actif ne voit pas
    assert window.monitor.tunnel_account(api.id) == "acc2" and window.monitor.other_account("acc2")
    assert ctx.config().settings.watch_token_id is None

    tray._open_tunnel_from_health(api)

    assert window.stack.currentWidget() is window.cloud
    qtbot.waitUntil(lambda: selected(view) == ("t9", None), timeout=45000)
    assert active(ctx) == ("travail", "acc2")
    assert view.overview is not None and view.overview.account.id == "acc2"
    assert view.account.currentData().id == "acc2"
    assert ctx.config().settings.watch_token_id is None  # le jeton de la surveillance n'est pas touché
    # Le compte A est maintenant « l'autre » : « Ouvrir » y revient.
    tray._open_tunnel_from_health(trouble(window, "labo"))
    qtbot.waitUntil(lambda: selected(view) == ("t2", None), timeout=45000)
    assert active(ctx) == ("principal", "acc1")


def test_open_a_tunnel_of_the_active_account_keeps_token_and_account(qtbot, watched):
    ctx, window, view, tray = watched.ctx, watched.window, watched.view, watched.tray
    assert active(ctx) == ("principal", "acc1")

    tray._open_tunnel_from_health(trouble(window, "labo"))

    qtbot.waitUntil(lambda: selected(view) == ("t2", None), timeout=45000)
    assert active(ctx) == ("principal", "acc1")
    assert [t.id for t in ctx.config().settings.cloudflare_tokens] == ["principal", "travail"]


def test_open_a_service_of_another_account_selects_its_rule(qtbot, watched):
    ctx, view, tray = watched.ctx, watched.view, watched.tray

    tray._open_cloud_from_health(ServiceResult(APP_B, HostProbe("origin_down", 502), datetime.now()))

    expected = ("t8", IngressRule("app.exemple.org", "http://localhost:8080"))
    qtbot.waitUntil(lambda: selected(view) == expected, timeout=45000)
    assert active(ctx) == ("travail", "acc2")


def test_no_token_sees_the_account(qtbot, watched):
    ctx, window, tray = watched.ctx, watched.window, watched.tray
    api = trouble(window, "api")
    # Le jeton du compte B est oublié depuis le relevé.
    ctx.manager.cloudflare.secrets.delete(token_secret_key("travail"))
    assert window.monitor.token_for_account("acc2") is None and not window.monitor.can_open("acc2")
    watched.notices.clear()

    tray._open_tunnel_from_health(api)
    tray._open_cloud_from_health(ServiceResult(APP_B, HostProbe("origin_down", 502), datetime.now()))

    assert [(level, text) for level, text, _action in watched.notices] == [("warning", NO_TOKEN)] * 2
    assert window.stack.currentWidget() is not window.cloud  # rien n'a bougé
    assert active(ctx) == ("principal", "acc1")


def test_a_token_that_lost_the_account_opens_nothing(qtbot, watched, cf):
    window, view, tray = watched.window, watched.view, watched.tray
    api = trouble(window, "api")
    # Depuis le relevé, le jeton « Travail » ne donne plus le compte B (permissions retirées, compte quitté).
    cf.state.tenants[SECOND_TOKEN].accounts = [{"id": "acc9", "name": "Autre compte"}]
    watched.notices.clear()

    tray._open_tunnel_from_health(api)

    qtbot.waitUntil(lambda: any(text == NO_TOKEN for _l, text, _a in watched.notices), timeout=45000)
    qtbot.waitUntil(lambda: not view._loading, timeout=45000)  # type: ignore[reportPrivateUsage]
    assert selected(view) is None or selected(view)[0] != "t9"


def test_notification_actions_for_another_account(qtbot, watched, monkeypatch):
    ctx, window, view = watched.ctx, watched.window, watched.view
    api = trouble(window, "api")
    # « Diagnostiquer… » est proposée pour le compte B (lecture seule : les connecteurs) tant qu'un jeton le donne.
    actions = {text: action for _l, text, action in watched.notices}
    api_action = next(action for text, action in actions.items() if "api (Compte B)" in text)
    assert isinstance(api_action, tuple) and api_action[0] == "Diagnostiquer…"
    shown: list[str] = []
    monkeypatch.setattr(
        "cma.ui.views.cloud.tunnels_tab.show_connectors", lambda _tab, tunnel, _conns: shown.append(tunnel.id)
    )

    api_action[1]()

    qtbot.waitUntil(lambda: shown == ["t9"], timeout=45000)
    assert active(ctx) == ("travail", "acc2") and selected(view) == ("t9", None)

    # Services : « Voir… » ouvre le compte B sur le nom d'hôte.
    window.show_view("dashboard")
    change = ServiceChange(APP_B, HostProbe("origin_down", 502), None)
    watched.notices.clear()
    ctx.manager.cloudflare.switch_token("principal")
    window.monitor.report_service_changes([change])
    action = watched.notices[-1][2]
    assert isinstance(action, tuple) and action[0] == "Voir…"
    action[1]()
    expected = ("t8", IngressRule("app.exemple.org", "http://localhost:8080"))
    qtbot.waitUntil(lambda: selected(view) == expected, timeout=45000)

    # Sans jeton qui donne le compte B : aucune action proposée.
    ctx.manager.cloudflare.secrets.delete(token_secret_key("travail"))
    ctx.manager.cloudflare.switch_token("principal")
    watched.notices.clear()
    window.monitor.report_service_changes([change])
    assert watched.notices[-1][2] is None
    assert api.id in {t.id for t in window.monitor.tunnel_watch.troubled}


def test_a_reading_in_progress_is_abandoned_not_mixed(qtbot, watched, cf):
    window, view, tray = watched.window, watched.view, watched.tray
    api = trouble(window, "api")
    cf.state.delay = 0.4  # le compte A est lent à lire
    view.refresh()  # lecture du compte A en cours
    assert view._loading  # type: ignore[reportPrivateUsage]

    tray._open_tunnel_from_health(api)

    qtbot.waitUntil(lambda: selected(view) == ("t9", None), timeout=45000)
    qtbot.wait(1500)  # la réponse tardive du compte A ne doit rien changer
    assert view.overview is not None and view.overview.account.id == "acc2"
    assert selected(view) == ("t9", None)
    ids = sorted(
        view.tree.topLevelItem(i).data(0, TUNNEL_ROLE).id for i in range(view.tree.topLevelItemCount())
    )
    assert ids == ["t8", "t9"]
    assert not view._loading  # type: ignore[reportPrivateUsage]
