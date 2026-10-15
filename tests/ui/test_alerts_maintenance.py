"""Maintenance, rappels et résumé dans l'interface (P24, P25) : section Alertes des Paramètres, boîte d'ajout,
rappels et résumé envoyés par le `Monitor`."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import cma.ui.views.settings_alerts as alerts_module
from cma.core.alertstate import AlertState, state_path
from cma.core.cfapi import Tunnel
from cma.core.hostprobe import HostProbe
from cma.core.models import AlertChannel, MaintenanceWindow
from cma.core.servicewatch import ServiceTarget
from cma.ui.monitor import Monitor


def test_settings_section_loads_and_saves(qtbot, gui):
    ctx, window = gui
    section = window.settings.alerts
    assert section.repeat.value() == 0 and section.repeat.text() == "Jamais"
    assert not section.digest.isChecked() and section.window_table.rowCount() == 0
    assert not section.remove_window_button.isEnabled()
    section.repeat.setValue(6)
    section.digest.setChecked(True)
    settings = ctx.config().settings
    assert settings.alert_repeat_hours == 6 and settings.weekly_digest is True
    # Rechargé depuis la configuration : les valeurs reviennent.
    ctx.update_config(lambda c: setattr(c.settings, "alert_repeat_hours", 12))
    window.settings.load()
    assert section.repeat.value() == 12 and section.digest.isChecked()
    # Le chargement n'écrit rien lui-même.
    before = ctx.config().settings.model_dump_json()
    window.settings.load()
    assert ctx.config().settings.model_dump_json() == before
    section.digest.setChecked(False)
    assert ctx.config().settings.weekly_digest is False


def test_add_and_remove_maintenance_windows(qtbot, gui, monkeypatch):
    ctx, window = gui
    section = window.settings.alerts
    seen: list[list[tuple[str, str]]] = []
    answers = [
        MaintenanceWindow(weekday=6, start="02:00", end="04:00", label="Mises à jour"),
        MaintenanceWindow(weekday=5, start="23:00", end="01:00", target="tunnel:t1"),
        None,
    ]

    def fake_ask(_parent, objects):
        seen.append(objects)
        return answers.pop(0)

    monkeypatch.setattr(alerts_module, "ask_maintenance", fake_ask)
    window.monitor.tunnel_watch.update([Tunnel("t1", "bureau", "healthy")])
    section.add_window()
    section.add_window()
    section.add_window()  # annulée
    assert seen[0] == [("tunnel:t1", "bureau")]
    windows = ctx.config().settings.maintenance_windows
    assert [(w.weekday, w.start, w.end, w.target) for w in windows] == [
        (6, "02:00", "04:00", ""),
        (5, "23:00", "01:00", "tunnel:t1"),
    ]
    table = section.window_table
    assert table.rowCount() == 2
    assert [table.item(0, c).text() for c in range(5)] == [
        "Dimanche",
        "02:00",
        "04:00",
        "Tout le compte",
        "Mises à jour",
    ]
    assert table.item(1, 3).text() == "Tunnel « bureau »"
    assert "Maintenance du samedi de 23:00 à 01:00 ajoutée." in section.status.text()
    table.selectRow(0)
    assert section.remove_window_button.isEnabled()
    section.remove_window()
    assert [w.target for w in ctx.config().settings.maintenance_windows] == ["tunnel:t1"]
    assert section.window_table.rowCount() == 1 and not section.remove_window_button.isEnabled()
    section.remove_window()  # rien de sélectionné : sans effet
    assert len(ctx.config().settings.maintenance_windows) == 1


def test_maintenance_dialog(qtbot):
    objects = [("tunnel:t1", "bureau"), ("service:wiki.exemple.fr", "wiki.exemple.fr")]
    dialog = alerts_module.MaintenanceDialog(None, objects)
    qtbot.addWidget(dialog)
    assert [dialog.target.itemText(i) for i in range(dialog.target.count())] == [
        "Tout le compte",
        "Tunnel « bureau »",
        "wiki.exemple.fr",
    ]
    assert dialog.day.count() == 7 and dialog.day.itemText(0) == "Lundi"
    default = dialog.values()
    assert (default.weekday, default.start, default.end, default.target) == (0, "02:00", "04:00", "")
    dialog.day.setCurrentIndex(4)
    dialog.start.setTime(dialog.start.time().fromString("23:30", "HH:mm"))
    dialog.end.setTime(dialog.end.time().fromString("01:15", "HH:mm"))
    dialog.target.setCurrentIndex(2)
    dialog.name.setText("  Sauvegarde  ")
    chosen = dialog.values()
    assert (chosen.weekday, chosen.start, chosen.end, chosen.target, chosen.label) == (
        4,
        "23:30",
        "01:15",
        "service:wiki.exemple.fr",
        "Sauvegarde",
    )
    # L'aide dit les deux cas particuliers : fin avant le début (passe minuit), fin égale au début (journée entière).
    assert "avant le début" in dialog.hint.text() and "égale au début" in dialog.hint.text()
    assert alerts_module.target_text("service:inconnu.fr", []) == "inconnu.fr"
    assert alerts_module.target_text("tunnel:t9", []) == "Tunnel « t9 »"


def test_ask_maintenance_uses_the_dialog(qtbot, monkeypatch):
    from PySide6.QtWidgets import QDialog

    monkeypatch.setattr(QDialog, "exec", lambda _self: QDialog.DialogCode.Accepted)
    window = alerts_module.ask_maintenance(None, [])  # type: ignore[arg-type]
    assert window is not None and window.target == ""
    monkeypatch.setattr(QDialog, "exec", lambda _self: QDialog.DialogCode.Rejected)
    assert alerts_module.ask_maintenance(None, []) is None  # type: ignore[arg-type]


# --- Monitor : rappels et résumé ---------------------------------------------------------------------------------


def watched_monitor(ctx, monkeypatch, tunnels, repeat=1, digest=False):
    channel = AlertChannel(name="Téléphone", kind="ntfy")
    ctx.core.secrets.set(f"alert:{channel.id}", "https://ntfy.sh/x")
    ctx.update_config(lambda c: c.settings.alert_channels.append(channel))
    ctx.update_config(lambda c: setattr(c.settings, "alert_repeat_hours", repeat))
    ctx.update_config(lambda c: setattr(c.settings, "weekly_digest", digest))
    ctx.update_config(lambda c: setattr(c.settings, "cloudflare_account_id", "acc1"))
    sent: list[str] = []
    monkeypatch.setattr("cma.core.monitoring.send_alert", lambda _k, _u, alert: sent.append(alert.title))
    admin = ctx.manager.cloudflare
    readings = list(tunnels)

    async def states() -> list[Tunnel]:
        return readings[0]

    monkeypatch.setattr(admin, "has_token", lambda: True)
    monkeypatch.setattr(admin, "tunnel_states", states)
    return Monitor(ctx, None, start=False), sent


def test_monitor_sends_reminders_once_per_period(qtbot, gui_context, monkeypatch):
    ctx = gui_context
    monitor, sent = watched_monitor(ctx, monkeypatch, [[Tunnel("t1", "bureau", "down")]])
    monitor.availability.start(
        "tunnel", "tunnel:t1", "bureau", "down", datetime.now(UTC) - timedelta(hours=3)
    )
    assert monitor.check_tunnels() is True
    qtbot.waitUntil(lambda: sent == ["CMA — toujours en panne : bureau"], timeout=5000)
    qtbot.waitUntil(lambda: not monitor._follow_up_running, timeout=5000)
    path = state_path(ctx.paths.data_dir)
    assert "tunnel:t1" in json.loads(path.read_text(encoding="utf-8"))["reminders"]
    # Relevé suivant : pas de second rappel avant une heure de plus.
    monitor.check_tunnels()
    qtbot.waitUntil(lambda: not monitor.tunnel_check_running, timeout=5000)
    # Le rappel ou le résumé est décidé dans le rappel de fin de relevé : une fois celui-ci passé, plus rien ne part
    # que par l'envoi en cours, que l'on attend (au lieu d'un délai fixe qu'une machine chargée dépasse).
    qtbot.waitUntil(lambda: not monitor._follow_up_running, timeout=45000)
    assert sent == ["CMA — toujours en panne : bureau"]
    # En maintenance (tout le compte, toute la semaine) : plus de rappel même après une heure.
    state = AlertState(path)
    state.mark_reminder("tunnel:t1", datetime.now(UTC) - timedelta(hours=2))
    state.save()
    ctx.update_config(
        lambda c: c.settings.maintenance_windows.extend(
            MaintenanceWindow(weekday=d, start="00:00", end="00:00") for d in range(7)
        )
    )
    monitor.check_tunnels()
    qtbot.waitUntil(lambda: not monitor.tunnel_check_running, timeout=5000)
    # Le rappel ou le résumé est décidé dans le rappel de fin de relevé : une fois celui-ci passé, plus rien ne part
    # que par l'envoi en cours, que l'on attend (au lieu d'un délai fixe qu'une machine chargée dépasse).
    qtbot.waitUntil(lambda: not monitor._follow_up_running, timeout=45000)
    assert sent == ["CMA — toujours en panne : bureau"]


def test_monitor_without_reminder_setting_sends_nothing(qtbot, gui_context, monkeypatch):
    ctx = gui_context
    monitor, sent = watched_monitor(ctx, monkeypatch, [[Tunnel("t1", "bureau", "down")]], repeat=0)
    monitor.availability.start("tunnel", "tunnel:t1", "bureau", "down", datetime.now(UTC) - timedelta(days=2))
    monitor.check_tunnels()
    qtbot.waitUntil(lambda: not monitor.tunnel_check_running, timeout=5000)
    # Le rappel ou le résumé est décidé dans le rappel de fin de relevé : une fois celui-ci passé, plus rien ne part
    # que par l'envoi en cours, que l'on attend (au lieu d'un délai fixe qu'une machine chargée dépasse).
    qtbot.waitUntil(lambda: not monitor._follow_up_running, timeout=45000)
    assert sent == [] and not state_path(ctx.paths.data_dir).exists()


def test_monitor_digest_only_after_tunnel_checks(qtbot, gui_context, monkeypatch):
    import cma.core.monitoring as monitoring

    ctx = gui_context
    monitor, sent = watched_monitor(
        ctx, monkeypatch, [[Tunnel("t1", "bureau", "healthy")]], repeat=0, digest=True
    )
    monday = datetime(2026, 10, 12, 9, 30, tzinfo=UTC)
    real_due = monitoring.digest_due
    monkeypatch.setattr(
        monitoring, "digest_due", lambda c, s, _now=None, _tz=None: real_due(c, s, monday, UTC)
    )
    monkeypatch.setattr(monitoring, "week_id", lambda _local: "2026-W42")
    target = ServiceTarget("wiki.exemple.fr", "", "http://x:1", "t1", "bureau")

    async def services() -> list[tuple[ServiceTarget, HostProbe]]:
        return [(target, HostProbe("ok", 200, ms=30.0))]

    monkeypatch.setattr(ctx.manager.cloudflare, "check_services", services)
    # Le relevé des services ne déclenche pas le résumé.
    assert monitor.check_services() is True
    qtbot.waitUntil(lambda: not monitor.service_check_running, timeout=5000)
    # Le rappel ou le résumé est décidé dans le rappel de fin de relevé : une fois celui-ci passé, plus rien ne part
    # que par l'envoi en cours, que l'on attend (au lieu d'un délai fixe qu'une machine chargée dépasse).
    qtbot.waitUntil(lambda: not monitor._follow_up_running, timeout=45000)
    assert sent == []
    # Celui des tunnels, si : une seule fois.
    monitor.check_tunnels()
    qtbot.waitUntil(lambda: len(sent) == 1, timeout=5000)
    qtbot.waitUntil(lambda: not monitor._follow_up_running, timeout=5000)
    assert sent[0].startswith("CMA — les 7 derniers jours, au ")
    assert AlertState(state_path(ctx.paths.data_dir)).digest_week == "2026-W42"
    monitor.check_tunnels()
    qtbot.waitUntil(lambda: not monitor.tunnel_check_running, timeout=5000)
    # Le rappel ou le résumé est décidé dans le rappel de fin de relevé : une fois celui-ci passé, plus rien ne part
    # que par l'envoi en cours, que l'on attend (au lieu d'un délai fixe qu'une machine chargée dépasse).
    qtbot.waitUntil(lambda: not monitor._follow_up_running, timeout=45000)
    assert len(sent) == 1
    # Les objets connus au dernier relevé servent à viser une maintenance.
    assert monitor.known_objects() == [
        ("tunnel:t1", "bureau"),
        ("service:wiki.exemple.fr", "wiki.exemple.fr"),
    ]
