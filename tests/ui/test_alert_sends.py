"""Journal des envois dans l'interface (P31) : boîte « Envois récents », bouton des Paramètres, test d'un canal et
envois du `Monitor` notés."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import cma.ui.dialogs.sends as sends_module
import cma.ui.views.settings_alerts as alerts_module
from cma.core.alertlog import AlertLog, log_path
from cma.core.alerts import Alert, AlertError
from cma.core.cfapi import Tunnel
from cma.core.models import AlertChannel
from cma.ui.dialogs.sends import SendsDialog
from cma.ui.theme import current_tokens, status_colors
from tests.ui.test_alerts_maintenance import watched_monitor


def filled_log(tmp_path) -> AlertLog:
    journal = AlertLog(tmp_path / "alert_log.json")
    start = datetime(2026, 10, 15, 8, 0, tzinfo=UTC)
    journal.note(channel="Téléphone", kind="ntfy", nature="alert", subject="bureau", at=start)
    journal.note(
        channel="Équipe",
        kind="slack",
        nature="reminder",
        subject="wiki.exemple.fr",
        error="Le canal a refusé l'alerte (403).",
        at=start + timedelta(minutes=5),
    )
    journal.note(channel="Équipe", kind="slack", nature="digest", at=start + timedelta(minutes=9))
    return journal


def cells(dialog: SendsDialog, row: int) -> list[str]:
    return [dialog.table.item(row, column).text() for column in range(dialog.table.columnCount())]


def test_dialog_lists_sends_latest_first_with_failure_tint(qtbot, tmp_path):
    dialog = SendsDialog(None, filled_log(tmp_path))
    qtbot.addWidget(dialog)
    assert dialog.table.rowCount() == 3 and dialog.empty.isHidden()
    assert [dialog.table.horizontalHeaderItem(c).text() for c in range(5)] == [
        "Date",
        "Canal",
        "Nature",
        "Objet",
        "Résultat",
    ]
    digest, reminder, alert = (cells(dialog, row) for row in range(3))
    assert digest[1:] == ["Équipe (Slack)", "Résumé", "—", "Réussi"]
    assert reminder[1:] == [
        "Équipe (Slack)",
        "Rappel",
        "wiki.exemple.fr",
        "Échec : Le canal a refusé l'alerte (403).",
    ]
    assert alert[1:] == ["Téléphone (ntfy)", "Panne", "bureau", "Réussi"]
    assert alert[0] == datetime(2026, 10, 15, 8, 0, tzinfo=UTC).astimezone().strftime("%d/%m/%Y %H:%M:%S")
    danger = status_colors("danger", current_tokens())[0].lower()
    assert dialog.table.item(1, 4).foreground().color().name().lower() == danger
    assert dialog.table.item(0, 4).foreground().color().name().lower() != danger
    assert dialog.table.item(1, 4).toolTip() == reminder[4]


def test_dialog_clear_asks_confirmation_and_refills(qtbot, tmp_path, monkeypatch):
    journal = filled_log(tmp_path)
    dialog = SendsDialog(None, journal)
    qtbot.addWidget(dialog)
    asked: list[bool] = []
    answers = [False, True]
    monkeypatch.setattr(sends_module, "ask_clear", lambda _parent: asked.append(True) or answers.pop(0))
    dialog.clear()  # refusé : rien ne change
    assert asked == [True] and dialog.table.rowCount() == 3 and len(journal.entries()) == 3
    dialog.clear()  # confirmé
    assert len(asked) == 2 and journal.entries() == []
    assert dialog.table.rowCount() == 0 and dialog.table.isHidden() and not dialog.empty.isHidden()
    assert not dialog.clear_button.isEnabled()
    # Remplie plusieurs fois (clear_items) : le nouveau contenu remplace l'ancien.
    journal.note(channel="Téléphone", kind="ntfy", nature="test")
    dialog._fill()
    dialog._fill()
    assert dialog.table.rowCount() == 1 and cells(dialog, 0)[2:4] == ["Test", "—"]


def test_confirmation_box_is_a_replaceable_module_function(qtbot, monkeypatch):
    seen: list[tuple[str, str | None]] = []
    monkeypatch.setattr(
        sends_module, "confirm", lambda _p, heading, text, action=None: seen.append((heading, action)) or True
    )
    assert sends_module.ask_clear(None) is True  # type: ignore[arg-type]
    assert seen == [("Effacer le journal des envois ?", "Effacer")]


def test_settings_button_opens_the_dialog_on_the_journal(qtbot, gui, monkeypatch):
    ctx, window = gui
    section = window.settings.alerts
    assert section.sends_button.text() == "Envois récents…" and section.sends_button.isEnabled()
    opened: list[tuple[object, AlertLog]] = []
    monkeypatch.setattr(alerts_module, "show_recent_sends", lambda parent, log: opened.append((parent, log)))
    section.sends_button.click()
    ((parent, journal),) = opened
    assert parent is window.settings and journal.path == log_path(ctx.paths.data_dir)
    # La vraie fonction de module ouvre bien la boîte (exec remplacé : pas de boîte modale).
    shown: list[SendsDialog] = []
    monkeypatch.setattr(SendsDialog, "exec", lambda self: shown.append(self) or 0)
    sends_module.show_recent_sends(window, journal)
    assert len(shown) == 1 and shown[0].table.rowCount() == 0


def test_settings_test_notes_success_and_failure(qtbot, gui, monkeypatch):
    ctx, window = gui
    section = window.settings.alerts
    channel = AlertChannel(name="Téléphone", kind="ntfy")
    monkeypatch.setattr(
        alerts_module, "ask_channel", lambda _p: (channel, "https://ntfy.sh/sujet-tres-secret")
    )
    section.add()
    section.table.selectRow(0)
    calls: list[str] = []

    def fake_send(_kind: str, url: str, _alert: Alert) -> None:
        calls.append(url)
        if len(calls) > 1:
            raise AlertError(f"Le canal a refusé l'alerte (403) pour {url}.")

    monkeypatch.setattr(alerts_module, "send_alert", fake_send)
    journal = AlertLog(log_path(ctx.paths.data_dir))
    section.send_test()
    qtbot.waitUntil(lambda: section.status.text().startswith("Test envoyé"), timeout=5000)
    section.send_test()
    qtbot.waitUntil(lambda: section.status.text().startswith("Échec du test"), timeout=5000)
    ok, failed = journal.entries()
    assert (ok.channel, ok.kind, ok.nature, ok.ok) == ("Téléphone", "ntfy", "test", True)
    assert (failed.nature, failed.ok) == ("test", False)
    assert "sujet-tres-secret" not in failed.error and "ntfy.sh" not in failed.error
    assert "sujet-tres-secret" not in log_path(ctx.paths.data_dir).read_text(encoding="utf-8")


def test_monitor_notes_its_sends_from_the_sending_thread(qtbot, gui_context, monkeypatch):
    ctx = gui_context
    monitor, sent = watched_monitor(ctx, monkeypatch, [[Tunnel("t1", "bureau", "down")]])
    monitor.availability.start(
        "tunnel", "tunnel:t1", "bureau", "down", datetime.now(UTC) - timedelta(hours=3)
    )
    assert monitor.check_tunnels() is True
    qtbot.waitUntil(lambda: sent == ["CMA — toujours en panne : bureau"], timeout=5000)
    qtbot.waitUntil(lambda: not monitor._follow_up_running, timeout=5000)
    assert monitor.alert_log.path == log_path(ctx.paths.data_dir)
    entries = AlertLog(log_path(ctx.paths.data_dir)).entries()
    assert [(e.channel, e.kind, e.nature, e.subject, e.ok) for e in entries] == [
        ("Téléphone", "ntfy", "reminder", "bureau", True)
    ]


def test_monitor_notes_new_outages_and_failures(qtbot, gui_context, monkeypatch):
    ctx = gui_context
    monitor, _sent = watched_monitor(ctx, monkeypatch, [[Tunnel("t1", "bureau", "down")]], repeat=0)

    def refuse(_kind: str, url: str, _alert: Alert) -> None:
        raise AlertError(f"Canal injoignable : {url}")

    monkeypatch.setattr("cma.core.monitoring.send_alert", refuse)
    assert monitor.check_tunnels() is True
    journal = AlertLog(log_path(ctx.paths.data_dir))
    qtbot.waitUntil(lambda: len(journal.entries()) == 1, timeout=5000)
    (entry,) = journal.entries()
    assert (entry.nature, entry.subject, entry.ok) == ("alert", "bureau", False)
    assert "ntfy.sh" not in log_path(ctx.paths.data_dir).read_text(encoding="utf-8")
