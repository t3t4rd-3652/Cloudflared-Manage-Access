"""Sous-menu des pannes (tunnels et services) dans la zone de notification."""

from __future__ import annotations

from datetime import datetime

from cma.core.cfapi import Tunnel
from cma.core.hostprobe import HostProbe
from cma.core.servicewatch import ServiceResult, ServiceTarget
from cma.ui.tray import Tray


def test_health_submenu_appears_when_tunnel_is_down(qtbot, gui, monkeypatch):
    """Le sous-menu Pannes apparaît quand un tunnel est en panne (down ou degraded)."""
    ctx, window = gui
    window.show()
    tray = Tray(ctx, window)

    # Simuler un tunnel en panne
    troubled_tunnel = Tunnel("t1", "test", "down")
    tray._on_tunnels([troubled_tunnel])
    qtbot.wait(100)

    # Construire le menu sans l'afficher
    menu = tray._build_health_submenu()

    assert menu is not None, "Le sous-menu de santé devrait exister avec un tunnel en panne"
    assert "Pannes" in menu.title()


def test_health_submenu_appears_when_service_is_down(qtbot, gui, monkeypatch):
    """Le sous-menu Pannes apparaît quand un service est en panne."""
    ctx, window = gui
    window.show()
    tray = Tray(ctx, window)

    # Simuler un service en panne
    target = ServiceTarget(
        hostname="example.com",
        path="/app",
        service="https://localhost:8080",
        tunnel_id="t1",
        tunnel_name="test",
    )
    probe = HostProbe(state="origin_down", status=502)
    service_result = ServiceResult(target, probe, datetime.now())
    tray._on_services([service_result])
    qtbot.wait(100)

    # Construire le menu sans l'afficher
    menu = tray._build_health_submenu()

    assert menu is not None, "Le sous-menu de santé devrait exister avec un service en panne"
    assert "Pannes" in menu.title()


def test_health_submenu_absent_when_all_healthy(qtbot, gui):
    """Le sous-menu Pannes est absent quand tout va bien."""
    ctx, window = gui
    window.show()
    tray = Tray(ctx, window)

    # Pas de pannes
    tray._on_tunnels([])
    tray._on_services([])
    qtbot.wait(100)

    # Construire le menu
    menu = tray._build_health_submenu()

    assert menu is None, "Le sous-menu de santé devrait être absent quand tout va bien"


def test_health_submenu_lists_both_tunnel_and_service(qtbot, gui):
    """Le sous-menu liste un tunnel ET un service en panne."""
    ctx, window = gui
    window.show()
    tray = Tray(ctx, window)

    # Un tunnel en panne
    troubled_tunnel = Tunnel("t1", "bureau", "degraded")
    tray._on_tunnels([troubled_tunnel])

    # Un service en panne
    target = ServiceTarget(
        hostname="api.example.com",
        path="/health",
        service="https://localhost:9000",
        tunnel_id="t1",
        tunnel_name="bureau",
    )
    probe = HostProbe(state="no_connector", status=1033)
    service_result = ServiceResult(target, probe, datetime.now())
    tray._on_services([service_result])
    qtbot.wait(100)

    # Construire le menu
    menu = tray._build_health_submenu()

    assert menu is not None
    assert "Pannes (2)" in menu.title()


def test_health_submenu_mute_updates_config(qtbot, gui, monkeypatch):
    """Mettre en sourdine 1 h écrit dans Settings.muted."""
    ctx, window = gui
    window.show()
    tray = Tray(ctx, window)

    # Un tunnel en panne
    troubled_tunnel = Tunnel("t1", "test", "down")
    tray._on_tunnels([troubled_tunnel])
    qtbot.wait(100)

    # Imiter l'action Mettre en sourdine
    settings_before = ctx.config().settings.muted.copy()

    tray._mute_tunnel_for_one_hour(troubled_tunnel)
    qtbot.wait(100)

    # Verifier que les parametres ont change
    settings_after = ctx.config().settings.muted
    assert settings_after != settings_before, "Les parametres muted devraient avoir change"
    assert "tunnel:t1" in settings_after, "La cle du tunnel devrait etre dans muted"


def test_health_menu_entries_are_wired(qtbot, gui, monkeypatch):
    """Les entrées du vrai menu de l'icône déclenchent les bonnes actions (sans afficher le menu)."""
    ctx, window = gui
    tray = Tray(ctx, window)
    opened: list[object] = []
    monkeypatch.setattr(window, "open_tunnel", lambda t, **_kw: opened.append(t))
    monkeypatch.setattr(window, "open_service", lambda host, path="": opened.append((host, path)))
    target = ServiceTarget("wiki.exemple.fr", "", "http://localhost:8080", "t1", "bureau")
    tray._on_tunnels([Tunnel("t2", "labo", "down")])
    tray._on_services([ServiceResult(target, HostProbe("origin_down", 502), datetime.now())])
    health = next(a.menu() for a in tray.menu.actions() if a.menu() is not None and "Pannes" in a.text())
    entries = {a.text(): a.menu() for a in health.actions() if a.menu() is not None}
    assert set(entries) == {"Tunnel « labo » — Hors ligne", "wiki.exemple.fr — Service injoignable"}

    def trigger(menu, text):
        next(a for a in menu.actions() if a.text() == text).trigger()

    trigger(entries["wiki.exemple.fr — Service injoignable"], "Ouvrir")
    trigger(entries["Tunnel « labo » — Hors ligne"], "Ouvrir")
    assert opened[0] == ("wiki.exemple.fr", "") and getattr(opened[1], "id", None) == "t2"
    trigger(entries["wiki.exemple.fr — Service injoignable"], "Mettre en sourdine 1 h")
    assert any(key.startswith("service:wiki.exemple.fr") for key in ctx.config().settings.muted)
    # Reconstruit sans panne : le sous-menu disparaît.
    tray._on_tunnels([])
    tray._on_services([])
    assert not any("Pannes" in a.text() for a in tray.menu.actions())


def test_health_submenu_open_tunnel_calls_window_method(qtbot, gui, monkeypatch):
    """Ouvrir pour un tunnel appelle window.open_tunnel."""
    ctx, window = gui
    window.show()
    tray = Tray(ctx, window)

    tunnel_opened: list[str] = []
    monkeypatch.setattr(window, "open_tunnel", lambda t, **kw: tunnel_opened.append(t.id))

    troubled_tunnel = Tunnel("t1", "test", "down")
    tray._on_tunnels([troubled_tunnel])
    qtbot.wait(100)

    # Appeler l'action Ouvrir
    tray._open_tunnel_from_health(troubled_tunnel)
    qtbot.wait(100)

    assert tunnel_opened == ["t1"], (
        f"window.open_tunnel devrait avoir ete appelee avec t1, got {tunnel_opened}"
    )


def test_health_submenu_check_health_now(qtbot, gui, monkeypatch):
    """Relever maintenant appelle check_tunnels et check_services."""
    ctx, window = gui
    window.show()
    tray = Tray(ctx, window)

    calls: list[str] = []
    monkeypatch.setattr(window.monitor, "check_tunnels", lambda: calls.append("check_tunnels") or True)
    monkeypatch.setattr(window.monitor, "check_services", lambda: calls.append("check_services") or True)

    tray._check_health_now()
    qtbot.wait(100)

    assert calls == ["check_tunnels", "check_services"], (
        f"Les deux verifications devraient etre appelees, got {calls}"
    )
