"""Vues SSH et Paramètres, zone de notification, actions rapides, fenêtre principale, démarrage complet."""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime
from pathlib import Path

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox

import cma.ui.views.settings as settings_view
from cma.core.cloudflared.binary import ReleaseInfo
from cma.core.models import CloudflareProfile, ServiceType, SshProfile, Theme
from cma.core.sessions import SessionInfo, SessionKind, SessionState
from cma.core.updates import UpdateInfo
from cma.platform import launchers
from cma.ui import actions
from cma.ui.dialogs.redirect import RedirectDialog
from cma.ui.tray import Tray
from tests.integration.test_ssh import PASSWORD, ScriptedPrompter, create_test_server
from tests.ui.conftest import build_gui, close_gui


def fake_info(**overrides) -> SessionInfo:
    values = {
        "id": "s1",
        "kind": SessionKind.CLOUDFLARE,
        "profile_id": "p1",
        "forward_id": None,
        "name": "Démo",
        "subtitle": "app.ex.fr",
        "local_host": "127.0.0.1",
        "local_port": 2222,
        "state": SessionState.LISTENING,
        "message": "",
        "started_at": datetime.now(),
        "listening_since": datetime.now(),
        "service_type": ServiceType.GENERIC,
        "scheme": None,
        "service_user": "admin",
        "connections": 0,
        "bytes_up": 0,
        "bytes_down": 0,
        "reconnect_in": None,
        "attempts": 0,
    }
    values.update(overrides)
    return SessionInfo(**values)


# --- Vue SSH de bout en bout -----------------------------------------------------------------------


@pytest.fixture
def ssh_gui(qapp, paths):
    ctx, window = build_gui(qapp, paths, ScriptedPrompter(passwords=[PASSWORD] * 10))
    yield ctx, window
    close_gui(ctx, window)


@pytest.fixture
def threaded_ssh_server(tmp_path):
    """Le serveur SSH tourne dans sa propre boucle : un test d'interface synchrone ne fait pas tourner celle de pytest."""
    import threading

    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    info = asyncio.run_coroutine_threadsafe(create_test_server(tmp_path), loop).result(10)
    yield info
    loop.call_soon_threadsafe(info["server"].close)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(5)


def test_ssh_view_full_flow(qtbot, ssh_gui, threaded_ssh_server, monkeypatch):
    ssh_server = threaded_ssh_server
    ctx, window = ssh_gui
    window.show_view("ssh")
    view = window.ssh
    view.new_profile()
    settings = view.panel.settings_tab
    settings.name.setText("Serveur test")
    settings.host.setText("127.0.0.1")
    settings.port.setText(str(ssh_server["port"]))
    settings.user.setText("admin")
    settings.name.textEdited.emit("x")
    assert settings.save()
    profile_id = view.panel.profile.id

    view.panel._toggle_connection()
    qtbot.waitUntil(
        lambda: (
            view.ssh_states.get(profile_id) is not None and view.ssh_states[profile_id].state == "connected"
        ),
        timeout=15000,
    )
    assert "Connecté" in view.panel.pill.text()

    ports = view.panel.ports_tab
    ports.refresh()
    qtbot.waitUntil(lambda: ports.model.rowCount() == 1, timeout=15000)
    assert "ports-report 2.0.0" in ports.status.text()

    monkeypatch.setattr(RedirectDialog, "exec", lambda self: (self._accept(), self.result())[1])
    ports.table.selectRow(0)
    ports.redirect_selected()
    qtbot.waitUntil(lambda: bool(view.panel.profile.saved_forwards), timeout=5000)
    forwards = view.panel.forwards_tab
    qtbot.waitUntil(
        lambda: any(s.state == SessionState.LISTENING for s in view.sessions.values()), timeout=15000
    )
    forwards.reload()
    forwards.table.selectRow(0)
    forwards._toggle()
    qtbot.waitUntil(lambda: not any(s.state.active for s in view.sessions.values()), timeout=10000)
    forwards._start_all()
    qtbot.waitUntil(
        lambda: any(s.state == SessionState.LISTENING for s in view.sessions.values()), timeout=15000
    )
    forwards._stop_all()
    forwards.table.selectRow(0)
    forwards._edit()
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    forwards._remove()
    qtbot.waitUntil(lambda: not ctx.config().ssh_profile(profile_id).saved_forwards, timeout=5000)

    view.duplicate()
    assert len(ctx.config().ssh_profiles) == 2
    view.list.select(profile_id)
    view.panel._toggle_connection()
    qtbot.waitUntil(lambda: view.ssh_states[profile_id].state == "disconnected", timeout=10000)
    view.delete()
    assert ctx.config().ssh_profile(profile_id) is None


def test_ssh_settings_validation(qtbot, gui):
    ctx, window = gui
    view = window.ssh
    view.new_profile()
    settings = view.panel.settings_tab
    settings.user.setText("nom invalide")
    settings.user.textEdited.emit("x")
    assert not settings.save()
    assert settings.errors["user"].text()
    settings.user.setText("ok")
    settings.auth_key.setChecked(True)
    assert not settings.save()
    assert settings.errors["key_path"].text()


# --- Paramètres ------------------------------------------------------------------------------------


def test_settings_view(qtbot, gui, monkeypatch, tmp_path):
    ctx, window = gui
    view = window.settings
    view.theme.setCurrentIndex(view.theme.findData(Theme.DARK))
    assert ctx.config().settings.theme == Theme.DARK
    assert ctx.theme.tokens.dark
    view.theme.setCurrentIndex(view.theme.findData(Theme.LIGHT))
    view.language.setCurrentIndex(view.language.findData("en"))
    assert ctx.config().settings.language == "en"
    view.close_to_tray.setChecked(False)
    assert not ctx.config().settings.close_to_tray
    view.port_min.setValue(21000)
    view.port_max.setValue(22000)
    view._ports_changed()
    assert ctx.config().settings.auto_port_min == 21000
    view.port_min.setValue(30000)
    view._ports_changed()
    assert ctx.config().settings.auto_port_min == 21000

    enabled: list[bool] = []
    monkeypatch.setattr(settings_view.autostart, "set_enabled", enabled.append)
    view.start_with_system.setChecked(not view.start_with_system.isChecked())
    assert enabled

    view.cf_path.setText(str(tmp_path / "absent.exe"))
    view._save_path()
    fake = tmp_path / "cloudflared.exe"
    fake.write_bytes(b"x")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(fake), ""))
    view._browse()
    assert ctx.config().settings.cloudflared_path == str(fake)
    view._detect()
    assert ctx.config().settings.cloudflared_path is None

    release = ReleaseInfo("2099.1.1", "", ())
    monkeypatch.setattr(settings_view, "fetch_latest_release", lambda *a, **k: release)
    view._installed_version = "2026.1.1"
    view.check_cloudflared_release()
    qtbot.waitUntil(lambda: view._release is release, timeout=5000)
    assert "2099.1.1" in view.release_label.text()
    assert view.download_button.isEnabled()

    installed = tmp_path / "cloudflared-2099.1.1.exe"
    installed.write_bytes(b"x")

    def fake_download(_release, _dir, *, progress=None, cancel=None):
        progress(50, 100)
        progress(100, None)
        return installed

    monkeypatch.setattr(settings_view, "download_release_binary", fake_download)
    view._download()
    qtbot.waitUntil(lambda: ctx.config().settings.cloudflared_path == str(installed), timeout=5000)

    monkeypatch.setattr(settings_view, "check_for_update", lambda: UpdateInfo("2.0.0", "9.9.9", "https://x"))
    view.check_cma_update()
    qtbot.waitUntil(lambda: "9.9.9" in view.cma_update_label.text(), timeout=5000)
    monkeypatch.setattr(settings_view, "check_for_update", lambda: UpdateInfo("2.0.0", None, None))
    view.check_cma_update()
    qtbot.waitUntil(lambda: "Aucune version" in view.cma_update_label.text(), timeout=5000)

    opened: list[object] = []
    monkeypatch.setattr(settings_view.QDesktopServices, "openUrl", opened.append)
    view._diagnostic()
    qtbot.waitUntil(lambda: any((ctx.paths.data_dir / "diagnostics").glob("*.zip")), timeout=10000)
    view._open(ctx.paths.backups_dir)
    assert opened


# --- Zone de notification, actions, fenêtre ------------------------------------------------------------


def test_tray_menu_and_state(qtbot, gui):
    ctx, window = gui
    profile = CloudflareProfile(name="Fav", hostname="f.ex.fr", local_port=2222, favorite=True)
    ssh = SshProfile(name="FavSSH", host="h", user="u", favorite=True)
    ctx.update_config(lambda c: (c.cloudflare_profiles.append(profile), c.ssh_profiles.append(ssh)))
    tray = Tray(ctx, window)
    tray.notify("error", "t", "m")
    tray.notify("info", "t", "m")
    for state in (SessionState.ERROR, SessionState.DEGRADED, SessionState.LISTENING):
        tray._on_session(fake_info(profile_id=profile.id, state=state))
    labels = [a.text() for a in tray.menu.actions()]
    assert "Fav" in labels and "FavSSH" in labels
    tray._on_removed("s1")
    tray._toggle(profile, False)
    tray._toggle(ssh, True)
    from PySide6.QtWidgets import QSystemTrayIcon

    tray._activated(QSystemTrayIcon.ActivationReason.Trigger)
    assert not window.isVisible()
    tray._activated(QSystemTrayIcon.ActivationReason.Trigger)
    assert window.isVisible()


def test_quick_actions(qtbot, monkeypatch, tmp_path):
    calls: list[list[str]] = []
    monkeypatch.setattr(launchers, "_spawn", lambda args, new_console=False: calls.append(args))
    monkeypatch.setattr(actions, "open_ssh_terminal", lambda *a: calls.append(["ssh", *map(str, a)]))
    monkeypatch.setattr(actions, "open_rdp", lambda *a: calls.append(["rdp", *map(str, a)]))
    monkeypatch.setattr(actions, "rdp_available", lambda: True)
    compass = tmp_path / "Compass.exe"
    compass.write_bytes(b"")
    monkeypatch.setattr(actions, "find_mongodb_compass", lambda: compass)
    monkeypatch.setattr(actions, "open_mongodb_compass", lambda uri: calls.append(["compass", uri]))
    opened: list[object] = []
    monkeypatch.setattr(actions.QDesktopServices, "openUrl", opened.append)
    messages: list[tuple] = []

    def notify(*args, **kwargs):
        messages.append(args)

    for service in ServiceType:
        info = fake_info(service_type=service, scheme="https" if service == ServiceType.HTTPS else None)
        for action in actions.quick_actions(info):
            actions.run_action(action, notify)
    assert opened
    assert any(c[0] == "ssh" for c in calls)
    assert any(c[0] == "rdp" for c in calls)
    assert any(c[0] == "compass" for c in calls)
    assert any("copiée" in m[1] for m in messages)

    def failing():
        raise launchers.LaunchError("échec")

    actions.run_action(actions.QuickAction("x", "copy", failing), notify)
    assert messages[-1] == ("error", "échec")


def test_main_window_behaviour(qtbot, gui, monkeypatch):
    ctx, window = gui
    shown: list[tuple] = []
    window.tray_notify = lambda *a: shown.append(a)
    window.tray_available = True
    event = QCloseEvent()
    window.closeEvent(event)
    assert not event.isAccepted()
    assert not window.isVisible()
    window.notify("info", "en arrière-plan")
    assert shown
    window.bring_to_front()
    assert window.isVisible()
    window._on_session(fake_info(state=SessionState.ERROR, message="panne"))
    window._on_session_removed("s1")
    window.open_logs_for("s1")
    assert window.current_view_key() == "logs"
    profile = CloudflareProfile(name="Ouvrir", hostname="o.ex.fr", local_port=2223)
    ctx.update_config(lambda c: c.cloudflare_profiles.append(profile))
    window.open_profile(profile.id)
    assert window.current_view_key() == "profiles"
    window.profiles.editor.name.setText("Modifié")
    window.profiles.editor.name.textEdited.emit("x")
    assert window.has_unsaved_changes()
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.No)
    window.request_quit()
    assert not window.quitting
    window.profiles.editor.load(window.profiles.editor.profile)
    ctx.update_config(lambda c: setattr(c.settings, "close_to_tray", False))
    window._on_session(fake_info(id="s2", state=SessionState.LISTENING))
    window.closeEvent(QCloseEvent())
    assert not window.quitting


def test_full_application_start_and_stop(qtbot, qapp, paths, monkeypatch):
    """run_gui de bout en bout : migration v1, instance unique, moteur, fenêtre, arrêt propre."""
    import cma.ui.app as app_module
    from cma.core.instance import send_command
    from tests.conftest import PersistentMemoryStore

    (paths.data_dir / "cloudflared_ssh_redir.json").write_text(
        '{"NAS": {"host": "nas", "port": "22", "user": "u"}}', encoding="utf-8"
    )
    monkeypatch.setattr(app_module, "_open_secret_store", lambda _p: PersistentMemoryStore())
    reports: list[object] = []
    import cma.ui.dialogs.misc as misc

    monkeypatch.setattr(misc, "show_migration_report", lambda ctx, parent, report: reports.append(report))
    monkeypatch.setattr(qapp, "exec", lambda: 0)
    monkeypatch.setattr(settings_view, "fetch_latest_release", lambda *a, **k: ReleaseInfo("1.0.0", "", ()))
    monkeypatch.setattr(settings_view, "check_for_update", lambda: UpdateInfo("2.0.0", None, None))
    args = argparse.Namespace(data_dir=str(paths.data_dir), debug=True, minimized=False)

    def check_and_quit() -> None:
        reports.append(send_command(paths, {"cmd": "show"}, timeout=5))

    QTimer.singleShot(0, check_and_quit)
    assert app_module.run_gui(args) == 0
    qtbot.wait(500)
    assert (paths.data_dir / "config.json").exists()
    log = (paths.logs_dir / "cma.log").read_text(encoding="utf-8")
    assert "Interface prête" in log
    assert "Arrêt terminé" in log
    assert QApplication.instance() is qapp
    assert asyncio
    assert Path(paths.lock_file).exists()
