"""Historique des sessions dans l'interface : résumé, détail, période, effacement et points d'entrée."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

import cma.ui.dialogs.history as history_module
import cma.ui.views.logs as logs_module
from cma.core.history import ProfileStats, SessionRecord
from cma.core.models import ServiceType
from cma.core.sessions import SessionInfo, SessionKind, SessionState
from cma.ui.dialogs.history import HistoryDialog, availability_text, availability_tone, end_label


def session_info(sid: str, profile: str, state: SessionState, started: datetime, **extra) -> SessionInfo:
    base = SessionInfo(
        id=sid,
        kind=SessionKind.CLOUDFLARE,
        profile_id=profile,
        forward_id=None,
        name=f"Accès {profile}",
        subtitle="",
        local_host="127.0.0.1",
        local_port=22022,
        state=state,
        message="",
        started_at=started,
        listening_since=None,
        service_type=ServiceType.SSH,
        scheme=None,
        service_user="",
        connections=0,
        bytes_up=0,
        bytes_down=0,
        reconnect_in=None,
        attempts=0,
    )
    return replace(base, **extra)


def fill(history, clock: list[datetime]) -> None:
    """« stable » : une session sans incident ; « fragile » : une reconnexion puis une erreur."""
    start = clock[0]

    def at(seconds: float, item: SessionInfo) -> None:
        clock[0] = start + timedelta(seconds=seconds)
        history.track(item)

    at(0, session_info("a", "stable", SessionState.STARTING, start))
    at(1, session_info("a", "stable", SessionState.LISTENING, start))
    at(100, session_info("a", "stable", SessionState.STOPPED, start))
    at(200, session_info("b", "fragile", SessionState.STARTING, start))
    at(201, session_info("b", "fragile", SessionState.LISTENING, start))
    at(250, session_info("b", "fragile", SessionState.RECONNECTING, start, message="Connexion perdue"))
    at(300, session_info("b", "fragile", SessionState.ERROR, start, message="Abandon après 10 essais"))


def test_history_dialog(qtbot, gui, monkeypatch):
    ctx, window = gui
    history = ctx.manager.history
    clock = [datetime.now() - timedelta(hours=1)]
    monkeypatch.setattr(history, "_now", lambda: clock[0])
    fill(history, clock)

    dialog = HistoryDialog(window, ctx)
    qtbot.addWidget(dialog)
    assert dialog.summary.rowCount() == 2 and dialog.empty.isHidden()
    assert dialog.summary.item(0, 0).text() == "Accès fragile"  # le plus instable en tête
    assert [dialog.summary.item(0, c).text() for c in (1, 4, 5)] == ["1", "1", "1"]
    assert dialog.summary.item(0, 7).text() == "Abandon après 10 essais"
    assert dialog.summary.item(1, 3).text() == "99,0 %"
    assert dialog.sessions.rowCount() == 0  # rien de sélectionné

    dialog.summary.selectRow(0)
    assert dialog.sessions.rowCount() == 1
    assert dialog.sessions.item(0, 3).text() == "Erreur"
    assert dialog.sessions.item(0, 5).text() == "Connexion perdue · Abandon après 10 essais"

    preselected = HistoryDialog(window, ctx, ("stable", None))
    qtbot.addWidget(preselected)
    assert preselected.selected_key() == ("stable", None) and preselected.sessions.rowCount() == 1

    # Une semaine plus tard, la période « 7 derniers jours » est vide ; « tout » garde tout.
    clock[0] = datetime.now() + timedelta(days=8)
    dialog.period.setCurrentIndex(0)
    assert dialog.summary.rowCount() == 0 and not dialog.empty.isHidden()
    dialog.period.setCurrentIndex(2)
    assert dialog.summary.rowCount() == 2

    monkeypatch.setattr(history_module, "confirm", lambda *_a: False)
    dialog.clear()
    assert len(history.records()) == 2
    monkeypatch.setattr(history_module, "confirm", lambda *_a: True)
    dialog.clear()
    assert history.records() == [] and dialog.summary.rowCount() == 0
    assert not dialog.clear_button.isEnabled()


def test_history_texts():
    stats = ProfileStats(("p", None), "A", seconds=100, listening_seconds=100)
    assert (availability_text(stats), availability_tone(stats)) == ("100,0 %", None)
    assert availability_tone(replace(stats, listening_seconds=95)) == "warning"
    assert availability_tone(replace(stats, reconnects=1)) == "warning"
    assert availability_tone(replace(stats, listening_seconds=50)) == "danger"
    assert availability_tone(replace(stats, errors=1)) == "danger"
    assert availability_text(ProfileStats(("p", None), "B")) == "—"
    now = datetime.now()
    assert end_label(SessionRecord("p", None, "cloudflare", "A", now, now, "error")) == "Erreur"
    assert end_label(SessionRecord("p", None, "cloudflare", "A", now, now, "stopped")) == "Arrêtée"


def test_history_entry_points(qtbot, gui, monkeypatch):
    ctx, window = gui
    opened: list[tuple] = []
    monkeypatch.setattr(logs_module, "show_history", lambda *args: opened.append(args))
    window.show_view("logs")
    history_button = next(
        b for b in window.logs.findChildren(type(window.logs.copy_button)) if "Historique" in b.text()
    )
    history_button.click()
    assert opened and opened[0][1] is ctx

    labels = [entry.text for entry in window.palette_entries()]
    assert "Historique des sessions…" in labels
