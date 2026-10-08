"""Surveillance des tunnels dans l'interface : relevés, alertes, diagnostic et réglage."""

from __future__ import annotations

from cma.core.cfapi import Tunnel


def test_main_window_warns_when_a_tunnel_falls_and_recovers(qtbot, gui, monkeypatch):
    ctx, window = gui
    notes: list[tuple[str, str, object]] = []
    window.banners.show_message = lambda level, text, action=None, **_k: notes.append(  # type: ignore[method-assign]
        (level, text, action)
    )
    admin = ctx.manager.cloudflare
    readings: list[list[Tunnel]] = [
        [Tunnel("t1", "bureau", "healthy"), Tunnel("t2", "labo", "inactive")],
        [Tunnel("t1", "bureau", "down"), Tunnel("t2", "labo", "inactive")],
        [Tunnel("t1", "bureau", "healthy"), Tunnel("t2", "labo", "inactive")],
    ]

    async def tunnel_states() -> list[Tunnel]:
        return readings.pop(0)

    monkeypatch.setattr(admin, "has_token", lambda: True)
    monkeypatch.setattr(admin, "tunnel_states", tunnel_states)
    window.show()

    # Sans compte choisi, rien n'est relevé.
    assert window.check_tunnels() is False
    ctx.update_config(lambda c: setattr(c.settings, "cloudflare_account_id", "acc1"))

    # Premier relevé : tout va bien, aucun message.
    assert window.check_tunnels() is True
    qtbot.waitUntil(lambda: len(readings) == 2 and not window._tunnel_check_running, timeout=5000)
    assert notes == []

    # Le tunnel tombe : une erreur, avec « Diagnostiquer… » qui ouvre l'état de ses connecteurs.
    window.check_tunnels()
    qtbot.waitUntil(lambda: len(notes) == 1, timeout=5000)
    level, text, action = notes[0]
    assert level == "error" and "« bureau » est hors ligne" in text
    diagnosed: list[str] = []
    monkeypatch.setattr(window.cloud, "refresh", lambda: None)
    monkeypatch.setattr(window.cloud, "check_connectors", lambda tunnel: diagnosed.append(tunnel.id))
    assert isinstance(action, tuple) and action[0] == "Diagnostiquer…"
    action[1]()
    assert diagnosed == ["t1"] and window.stack.currentWidget() is window.cloud
    assert window.cloud.tabs.currentIndex() == 0

    # Il revient : un message de succès, sans action.
    window.check_tunnels()
    qtbot.waitUntil(lambda: any(level == "success" for level, _t, _a in notes), timeout=5000)
    assert [(level, action) for level, text, action in notes if "tunnel" in text][-1] == ("success", None)

    # Surveillance désactivée dans les paramètres : plus aucun relevé.
    ctx.update_config(lambda c: setattr(c.settings, "watch_tunnels", False))
    assert window.check_tunnels() is False


def test_failed_reading_stays_quiet(qtbot, gui, monkeypatch):
    ctx, window = gui
    notes: list[str] = []
    window.banners.show_message = lambda level, text, **_k: notes.append(text)  # type: ignore[method-assign]
    admin = ctx.manager.cloudflare

    async def offline() -> list[Tunnel]:
        raise OSError("réseau injoignable")

    monkeypatch.setattr(admin, "has_token", lambda: True)
    monkeypatch.setattr(admin, "tunnel_states", offline)
    ctx.update_config(lambda c: setattr(c.settings, "cloudflare_account_id", "acc1"))
    assert window.check_tunnels() is True
    qtbot.waitUntil(lambda: not window._tunnel_check_running, timeout=5000)
    assert notes == []


def test_settings_toggle_the_watch(qtbot, gui):
    ctx, window = gui
    window.show_view("settings")
    checkbox = window.settings.watch_tunnels
    assert checkbox.isChecked() and ctx.config().settings.watch_tunnels
    checkbox.setChecked(False)
    assert ctx.config().settings.watch_tunnels is False
    checkbox.setChecked(True)
    assert ctx.config().settings.watch_tunnels is True


def test_troubled_tunnels_stay_visible_in_navigation_and_tray(qtbot, gui, monkeypatch):
    from cma.ui.tray import Tray

    ctx, window = gui
    window.banners.show_message = lambda *_a, **_k: None  # type: ignore[method-assign]
    admin = ctx.manager.cloudflare
    readings = [[Tunnel("t1", "bureau", "down")], [Tunnel("t1", "bureau", "degraded")]]

    async def tunnel_states() -> list[Tunnel]:
        return readings.pop(0)

    monkeypatch.setattr(admin, "has_token", lambda: True)
    monkeypatch.setattr(admin, "tunnel_states", tunnel_states)
    ctx.update_config(lambda c: setattr(c.settings, "cloudflare_account_id", "acc1"))
    tray = Tray(ctx, window)
    item = window._nav_items["cloud"]

    window.check_tunnels()
    qtbot.waitUntil(lambda: item.text().endswith("· 1 !"), timeout=5000)
    assert item.toolTip() == "Tunnel « bureau » hors ligne"
    assert tray.global_state()[1] == "error"
    assert tray.icon.toolTip() == "CMA : 0 session en cours · Tunnel « bureau » hors ligne"

    window.check_tunnels()
    qtbot.waitUntil(lambda: tray.global_state()[1] == "warn", timeout=5000)

    # Surveillance coupée : l'ancien relevé disparaît de partout.
    ctx.update_config(lambda c: setattr(c.settings, "watch_tunnels", False))
    assert window.check_tunnels() is False
    assert not item.text().endswith("!") and tray.global_state() == (None, None)


def test_settings_schedule_the_closed_watch(qtbot, gui, monkeypatch):
    from cma.platform import schedule

    ctx, window = gui
    notes: list[tuple[str, str]] = []
    monkeypatch.setattr(ctx, "notify", lambda level, text, **_k: notes.append((level, text)))
    calls: list[bool] = []
    monkeypatch.setattr(schedule, "set_enabled", calls.append)
    box = window.settings.watch_closed
    box.setChecked(not box.isChecked())
    assert calls == [box.isChecked()] and notes[-1][0] == "success"

    def refuse(_enabled: bool) -> None:
        raise OSError("Accès refusé.")

    monkeypatch.setattr(schedule, "set_enabled", refuse)
    before = box.isChecked()
    box.setChecked(not before)
    assert box.isChecked() == before  # remis comme avant
    assert notes[-1][0] == "error" and "Accès refusé" in notes[-1][1]
