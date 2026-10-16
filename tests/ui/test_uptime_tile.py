"""Tuile « Disponibilité » de la page Sessions (P35) et ouverture de la boîte positionnée sur un objet."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from PySide6.QtWidgets import QDialog

import cma.ui.main_window as main_window_module
import cma.ui.views.uptime_tile as tile_module
from cma.core.availability import AvailabilityLog
from cma.core.cfapi import Tunnel
from cma.core.hostprobe import HostProbe
from cma.core.servicewatch import ServiceTarget
from cma.ui.a11y import accessible_name
from cma.ui.views.cloud.availability import AvailabilityDialog, percent, uptime_tone
from cma.ui.views.health import HealthCard
from cma.ui.views.uptime_tile import (
    UptimeTile,
    percent_text,
    select_key,
    show_availability_on,
    summarize,
    tone_of,
)
from tests.ui.test_a11y_recent import verify_tab_order


def _ago(**delta: float) -> datetime:
    """Date relative à maintenant : un journal d'exemple ne vieillit pas."""
    return datetime.now(UTC) - timedelta(**delta)


def fill(log: AvailabilityLog, key: str, label: str, ok: int, failed: int, days: int = 1) -> None:
    for index in range(ok + failed):
        log.record_check(key, label, index < ok, 120.0 if index < ok else None, _ago(days=days))


def sample_log(path: Path | None = None) -> AvailabilityLog:
    """Deux objets : « wiki » à 80 % (8 tests sur 10), « bureau » à 100 % ; un incident récent et un ancien."""
    log = AvailabilityLog(path or Path("absent.json"))
    fill(log, "service:wiki.exemple.fr", "wiki.exemple.fr", 8, 2)
    fill(log, "tunnel:t1", "bureau", 10, 0)
    log.start("service", "service:wiki.exemple.fr", "wiki.exemple.fr", "origin_down", _ago(days=2))
    log.end("service", "service:wiki.exemple.fr", _ago(days=2) + timedelta(minutes=30))
    log.start("tunnel", "tunnel:t1", "bureau", "down", _ago(days=30))  # hors de la période de 7 jours
    log.end("tunnel", "tunnel:t1", _ago(days=30) + timedelta(hours=1))
    return log


# --- Calcul ----------------------------------------------------------------------------------------


def test_summary_values():
    summary = summarize(sample_log())
    assert summary is not None
    assert (
        summary.checks == 20 and abs(summary.uptime - 0.9) < 1e-9
    )  # 18 réussis sur 20, tous objets confondus
    assert summary.incidents == 1  # l'incident d'il y a 30 jours n'est pas compté
    assert summary.worst_key == "service:wiki.exemple.fr" and summary.worst_label == "wiki.exemple.fr"
    assert summary.worst_uptime == 0.8


def test_summary_without_checks_or_without_failure():
    assert summarize(AvailabilityLog(Path("absent.json"))) is None
    old = AvailabilityLog(Path("absent.json"))
    fill(old, "tunnel:t1", "bureau", 5, 0, days=20)  # relevé hors de la période
    assert summarize(old) is None
    perfect = AvailabilityLog(Path("absent.json"))
    fill(perfect, "tunnel:t1", "bureau", 5, 0)
    summary = summarize(perfect)
    assert summary is not None and summary.uptime == 1 and summary.incidents == 0
    assert summary.worst_key is None  # aucun objet en échec : pas d'objet « le moins disponible »


def test_summary_worst_is_the_lowest_rate():
    log = sample_log()
    fill(log, "service:grafana.exemple.fr", "grafana.exemple.fr", 5, 5)  # 50 %
    summary = summarize(log)
    assert summary is not None and summary.worst_key == "service:grafana.exemple.fr"


def test_formats_match_the_availability_dialog():
    from cma.core.availability import Stats

    for value in (0.0, 0.5, 0.9, 0.98, 0.9987, 0.999, 1.0):
        stats = Stats(value, None, None, 1)
        assert percent_text(value) == percent(stats)
        assert tone_of(value) == uptime_tone(stats)


# --- Tuile sur la page Sessions --------------------------------------------------------------------


def test_tile_hidden_without_checks_then_follows_the_monitor(qtbot, gui):
    ctx, window = gui
    tile = window.dashboard.uptime
    window._on_troubled([], [])
    assert tile.isHidden()  # aucun relevé
    fill(window.availability, "service:wiki.exemple.fr", "wiki.exemple.fr", 8, 2)
    window._on_troubled([], [])  # chaque relevé de la surveillance passe par là
    assert tile.isVisible()
    assert "80.00 %" in tile.heading.text()
    assert "Aucun incident" in tile.detail.text()
    assert "Moins disponible : wiki.exemple.fr (80.00 %)" in tile.detail.text()
    # Un incident de plus et des tests réussis : la tuile est recalculée au relevé suivant.
    window.availability.start("service", "service:wiki.exemple.fr", "wiki.exemple.fr", "origin_down")
    fill(window.availability, "service:wiki.exemple.fr", "wiki.exemple.fr", 10, 0)
    window.monitor.refresh()
    assert "90.00 %" in tile.heading.text() and "1 incident" in tile.detail.text()


def test_tile_refreshes_when_the_page_opens(qtbot, gui):
    ctx, window = gui
    tile = window.dashboard.uptime
    window.show_view("profiles")
    fill(window.availability, "tunnel:t1", "bureau", 10, 0)
    window.show_view("dashboard")
    qtbot.waitUntil(tile.isVisible, timeout=3000)
    assert "100 %" in tile.heading.text()


def test_tile_opens_the_dialog_on_the_least_available_object(qtbot, gui, monkeypatch):
    ctx, window = gui
    fill(window.availability, "service:wiki.exemple.fr", "wiki.exemple.fr", 8, 2)
    fill(window.availability, "tunnel:t1", "bureau", 10, 0)
    window._on_troubled([], [])
    calls: list[tuple[object, Path, str | None]] = []
    monkeypatch.setattr(
        main_window_module,
        "show_availability_on",
        lambda parent, path, key: calls.append((parent, path, key)),
    )
    window.dashboard.uptime.action.click()
    assert calls == [(window, ctx.paths.data_dir / "availability.json", "service:wiki.exemple.fr")]


def test_health_card_opens_the_dialog_on_the_first_object_down(qtbot, gui, monkeypatch):
    ctx, window = gui
    health = window.dashboard.health
    opened: list[str | None] = []
    monkeypatch.setattr(
        main_window_module, "show_availability_on", lambda _parent, _path, key: opened.append(key)
    )
    # Tunnel hors ligne : la boîte s'ouvre sur lui (les tunnels passent avant les services).
    window.tunnel_watch.update([Tunnel("t1", "bureau", "down")])
    target = ServiceTarget("wiki.exemple.fr", "", "http://x:1", "t1", "bureau")
    ctx.services.update([(target, HostProbe("origin_down", 502))])
    window._show_troubled_tunnels()
    assert health.availability.isVisible()
    health.availability.click()
    # Le tunnel revient, le service reste en panne : la boîte s'ouvre sur le service.
    window.tunnel_watch.update([Tunnel("t1", "bureau", "healthy")])
    window._show_troubled_tunnels()
    health.availability.click()
    assert opened == ["tunnel:t1", "service:wiki.exemple.fr"]
    # Plus rien en panne : la carte est cachée.
    ctx.services.update([(target, HostProbe("ok", 200))])
    window._show_troubled_tunnels()
    assert health.isHidden()


def test_health_card_tokens_only_has_no_availability_link(qtbot):
    from cma.core.expiry import TokenExpiry
    from cma.core.models import ServiceToken

    card = HealthCard(lambda: None, lambda: None)
    qtbot.addWidget(card)
    token = ServiceToken(name="Robot", client_id="robot.access", expires_at=_ago(days=-3))
    card.update_state([], [], [TokenExpiry(token, 3)])
    card.show()
    assert card.isVisible() and card.availability.isHidden() and card.first_key is None


# --- Ouverture de la boîte sur un objet -------------------------------------------------------------


def test_dialog_is_positioned_on_the_object(qtbot, tmp_path, monkeypatch):
    path = tmp_path / "availability.json"
    log = sample_log(path)
    fill(log, "service:zeta.exemple.fr", "zeta.exemple.fr", 3, 0)
    log.save()
    dialog = AvailabilityDialog(None, path)
    qtbot.addWidget(dialog)
    for key in ("service:wiki.exemple.fr", "service:zeta.exemple.fr", "tunnel:t1"):
        assert select_key(dialog, key)
        row = dialog.keys.index(key)
        assert dialog.table.currentRow() == row and dialog.table.item(row, 0).isSelected()
        assert dialog.log.label(key) in dialog.chart_title.text()
    assert not select_key(dialog, "service:inconnu") and not select_key(dialog, None)
    # La fonction de module construit la boîte, la positionne puis l'affiche.
    shown: list[AvailabilityDialog] = []
    monkeypatch.setattr(
        AvailabilityDialog, "exec", lambda self: shown.append(self) or QDialog.DialogCode.Accepted
    )
    show_availability_on(None, path, "service:wiki.exemple.fr")
    assert len(shown) == 1
    assert shown[0].keys[shown[0].table.currentRow()] == "service:wiki.exemple.fr"
    qtbot.addWidget(shown[0])


def test_dialog_without_key_keeps_no_selection(qtbot, tmp_path, monkeypatch):
    path = tmp_path / "availability.json"
    sample_log(path).save()
    shown: list[AvailabilityDialog] = []
    monkeypatch.setattr(
        AvailabilityDialog, "exec", lambda self: shown.append(self) or QDialog.DialogCode.Accepted
    )
    show_availability_on(None, path, None)
    qtbot.addWidget(shown[0])
    assert shown[0].table.currentRow() < 0 or not shown[0].table.selectedItems()


# --- Accessibilité ----------------------------------------------------------------------------------


def test_tile_accessibility(qtbot):
    tile = UptimeTile()
    qtbot.addWidget(tile)
    tile.log_source = lambda: sample_log()
    tile.refresh()
    tile.show()
    assert tile.isVisible()
    assert accessible_name(tile).startswith("Disponibilité sur 7 jours : 90.00 %")
    assert "wiki.exemple.fr" in accessible_name(tile)
    assert accessible_name(tile.action) == "Ouvrir la disponibilité : wiki.exemple.fr"
    assert tile.action.toolTip() == accessible_name(tile.action)
    verify_tab_order(tile, min_controls=1)  # vrais appuis sur Tab et Maj+Tab


def test_health_card_accessibility(qtbot):
    card = HealthCard(lambda: None, lambda: None)
    qtbot.addWidget(card)
    card.update_state([Tunnel("t1", "bureau", "down")], [], [])
    assert accessible_name(card.availability) == "Ouvrir la disponibilité : bureau"
    verify_tab_order(card, min_controls=2)  # « Disponibilité » et « Voir »


def test_tile_module_is_light_at_import():
    """La boîte et ses dépendances (rapport, tableaux) ne sont importées qu'à l'ouverture."""
    import subprocess
    import sys

    code = (
        "import sys, cma.ui.views.uptime_tile;"
        "sys.exit(1 if 'cma.ui.views.cloud.availability' in sys.modules else 0)"
    )
    assert tile_module.__file__
    result = subprocess.run([sys.executable, "-c", code], check=False, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr.decode(errors="replace")


def test_dialog_opened_from_the_window_gets_its_context(qtbot, gui, tmp_path, monkeypatch):
    """Ouverte depuis la tuile ou la carte « Santé » (parent : la fenêtre), la boîte reçoit le contexte : objectifs
    affichés et boutons « Définir l'objectif… » et « Objectif par défaut… » actifs."""
    _ctx, window = gui
    path = tmp_path / "availability.json"
    sample_log(path).save()
    shown: list[AvailabilityDialog] = []
    monkeypatch.setattr(
        AvailabilityDialog, "exec", lambda self: shown.append(self) or QDialog.DialogCode.Accepted
    )
    show_availability_on(window, path, "service:wiki.exemple.fr")
    dialog = shown[0]
    qtbot.addWidget(dialog)
    assert dialog.ctx is window.ctx
    assert dialog.default_button.isEnabled() and dialog.target_button.isEnabled()
