"""Surveillance sans fenêtre (ADR 0001) : relevés, signaux, sourdine, journal."""

from __future__ import annotations

from datetime import timedelta

from PySide6.QtWidgets import QApplication

from cma.core.cfapi import Tunnel
from cma.core.hostprobe import HostProbe
from cma.core.monitoring import mute, tunnel_key
from cma.core.servicewatch import ServiceTarget
from cma.ui.monitor import Monitor


def test_monitor_alone(qtbot, gui_context, monkeypatch):
    ctx = gui_context
    from cma.ui.main_window import MainWindow

    # Aucune fenêtre principale : le Monitor se suffit à lui-même (ADR 0001).
    assert not any(isinstance(w, MainWindow) for w in QApplication.topLevelWidgets())
    opened: list[tuple[object, bool]] = []
    monitor = Monitor(
        ctx, None, open_tunnel=lambda tunnel, diagnose: opened.append((tunnel, diagnose)), start=False
    )
    notices: list[tuple[str, str, object]] = []
    troubles: list[tuple[list[Tunnel], list[object]]] = []
    checked: list[bool] = []
    monitor.notice.connect(lambda level, text, action: notices.append((level, text, action)))
    monitor.troubled.connect(lambda tunnels, services: troubles.append((tunnels, services)))
    monitor.services_checked.connect(lambda: checked.append(True))

    admin = ctx.manager.cloudflare
    assert monitor.check_tunnels() is False  # ni jeton ni compte

    async def states() -> list[Tunnel]:
        return [Tunnel("t1", "bureau", "down")]

    target = ServiceTarget("wiki.exemple.fr", "", "http://x:1", "t1", "bureau")

    async def services() -> list[tuple[ServiceTarget, HostProbe]]:
        return [(target, HostProbe("origin_down", 502, ms=40.0))]

    monkeypatch.setattr(admin, "has_token", lambda: True)
    monkeypatch.setattr(admin, "tunnel_states", states)
    monkeypatch.setattr(admin, "check_services", services)
    ctx.update_config(lambda c: setattr(c.settings, "cloudflare_account_id", "acc1"))

    assert monitor.check_tunnels() is True
    qtbot.waitUntil(lambda: not monitor.tunnel_check_running and bool(troubles), timeout=5000)
    level, text, action = notices[-1]
    assert level == "error" and "« bureau » est hors ligne" in text
    assert isinstance(action, tuple) and action[0] == "Diagnostiquer…"
    action[1]()
    assert opened == [(Tunnel("t1", "bureau", "down"), True)]
    assert [t.name for t in troubles[-1][0]] == ["bureau"]
    assert monitor.availability.open_incident("tunnel", "tunnel:t1") is not None

    assert monitor.check_services() is True
    qtbot.waitUntil(lambda: bool(checked), timeout=5000)
    assert [r.target.hostname for r in troubles[-1][1]] == ["wiki.exemple.fr"]

    # En sourdine, le tunnel et ses noms ne comptent plus comme des pannes à signaler.
    ctx.update_config(lambda c: mute(c, tunnel_key("t1"), timedelta(hours=1)))
    monitor.refresh()
    assert troubles[-1] == ([], [])
    assert monitor.current_troubles() == ([], [])

    # Un relevé réussi où le nom n'apparaît plus (règle retirée) clôt son incident : plus de rappel sans fin.
    service_key = "service:wiki.exemple.fr"
    assert monitor.availability.open_incident("service", service_key) is not None

    async def no_services() -> list[tuple[ServiceTarget, HostProbe]]:
        return []

    monkeypatch.setattr(admin, "check_services", no_services)
    checked.clear()
    assert monitor.check_services() is True
    qtbot.waitUntil(lambda: bool(checked), timeout=5000)
    assert monitor.availability.open_incident("service", service_key) is None


def test_monitor_closes_incidents_of_a_switched_off_watch(qtbot, gui_context):
    """Surveillance coupée dans les Paramètres (P29) : à la vérification suivante, les incidents ouverts de ce type
    sont clos et enregistrés, sans notification ; l'autre type n'est pas touché."""
    from cma.core.availability import AvailabilityLog

    ctx = gui_context
    monitor = Monitor(ctx, None, start=False)
    notices: list[tuple[str, str, object]] = []
    monitor.notice.connect(lambda level, text, action: notices.append((level, text, action)))
    monitor.availability.start("tunnel", "tunnel:t1", "bureau", "down")
    monitor.availability.start("service", "service:wiki.exemple.fr", "wiki.exemple.fr", "origin_down")
    monitor.availability.save()
    path = ctx.paths.data_dir / "availability.json"

    def saved(kind: str, key: str):
        return AvailabilityLog(path).open_incident(kind, key)

    # Tout est surveillé (ni compte ni jeton : rien à relever) : rien n'est clos.
    assert monitor.check_tunnels() is False and monitor.check_services() is False
    assert saved("tunnel", "tunnel:t1") and saved("service", "service:wiki.exemple.fr")

    ctx.update_config(lambda c: setattr(c.settings, "watch_services", False))
    assert monitor.check_services() is False
    assert saved("service", "service:wiki.exemple.fr") is None
    assert saved("tunnel", "tunnel:t1") is not None  # les tunnels sont toujours surveillés
    assert monitor.availability.open_incident("service", "service:wiki.exemple.fr") is None

    ctx.update_config(lambda c: setattr(c.settings, "watch_tunnels", False))
    assert monitor.check_tunnels() is False
    assert saved("tunnel", "tunnel:t1") is None
    assert notices == []
