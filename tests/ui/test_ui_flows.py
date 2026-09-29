"""Parcours principaux de l'interface (pytest-qt, plateforme « offscreen »)."""

from __future__ import annotations

import os
import sys
import time

from PySide6.QtCore import Qt

from cma.core.cloudflared.command import CommandSpec
from cma.core.models import AuthMode, CloudflareProfile, Theme
from cma.core.netutil import find_free_port
from cma.core.sessions import SessionState
from tests.conftest import FAKE_CLOUDFLARED


def wait_until(qtbot, predicate, timeout=10000):
    qtbot.waitUntil(predicate, timeout=timeout)


def test_create_profile_with_live_validation(qtbot, gui):
    ctx, window = gui
    window.show_view("profiles")
    view = window.profiles
    view.new_profile()
    editor = view.editor
    assert editor.profile is not None
    assert editor.name.text() == "Nouveau profil"

    editor.hostname.setText("avec espace.fr")
    editor.hostname.textEdited.emit("avec espace.fr")
    assert editor.save() is False
    assert editor.errors["hostname"].isVisible()

    editor.hostname.setText("https://ssh.exemple.fr/")
    editor.hostname.textEdited.emit("x")
    editor.name.setText("SSH prod")
    editor.name.textEdited.emit("SSH prod")
    assert editor.is_dirty()
    assert editor.save() is True
    saved = ctx.config().cloudflare_profiles[0]
    assert saved.name == "SSH prod"
    assert saved.hostname == "ssh.exemple.fr"
    assert saved.local_port is not None
    assert not editor.is_dirty()


def test_duplicate_names_are_refused(qtbot, gui):
    ctx, window = gui
    view = window.profiles
    view.new_profile()
    view.new_profile()
    editor = view.editor
    editor.name.setText("Nouveau profil")
    editor.name.textEdited.emit("x")
    assert editor.save() is False
    assert "déjà ce nom" in editor.errors["name"].text()


def test_token_secret_goes_to_the_vault(qtbot, gui):
    ctx, window = gui
    window.show_view("tokens")
    view = window.tokens
    view.new_token()
    editor = view.editor
    editor.client_id.setText("abc.access")
    editor.client_id.textEdited.emit("x")
    editor.secret.edit.setText("tres-secret")
    editor.secret.changed.emit()
    assert editor.save()
    token = ctx.config().tokens[0]
    assert token.client_id == "abc.access"
    assert ctx.core.secrets.get(token.secret_key) == "tres-secret"
    assert "tres-secret" not in ctx.store.path.read_text(encoding="utf-8")


def test_dashboard_follows_a_real_session(qtbot, gui, monkeypatch):
    ctx, window = gui
    port = find_free_port(port_range=(27000, 27999))
    profile = CloudflareProfile(
        name="Démo", hostname="app.exemple.fr", local_port=port, auth=AuthMode.BROWSER
    )
    ctx.update_config(lambda c: c.cloudflare_profiles.append(profile))

    def fake_command(p):
        args = (
            sys.executable,
            str(FAKE_CLOUDFLARED),
            "access",
            "tcp",
            "--hostname",
            p.hostname,
            "--url",
            f"127.0.0.1:{p.local_port}",
        )
        return CommandSpec(args, {**os.environ, "FAKE_CF_MODE": "ok"})

    monkeypatch.setattr(ctx.manager, "_cloudflared_command", fake_command)
    window.show_view("dashboard")
    window.dashboard.start_cloudflare(profile.id)
    wait_until(
        qtbot, lambda: any(c.info.state == SessionState.LISTENING for c in window.dashboard.cards.values())
    )
    card = next(iter(window.dashboard.cards.values()))
    assert card.address.text() == f"127.0.0.1:{port}"
    assert "1 session(s) active(s)" in window.status_sessions.text()

    card._stop()
    wait_until(qtbot, lambda: not window.dashboard.cards)
    assert window.dashboard.empty.isVisible()


def test_failed_start_shows_a_banner(qtbot, gui):
    ctx, window = gui
    profile = CloudflareProfile(name="Incomplet", hostname="", local_port=None)
    ctx.update_config(lambda c: c.cloudflare_profiles.append(profile))
    window.dashboard.start_cloudflare(profile.id)
    from PySide6.QtWidgets import QLabel

    from cma.ui.widgets import Banner

    wait_until(qtbot, lambda: any(not b.isHidden() for b in window.banners.findChildren(Banner)))
    texts = [lbl.text() for b in window.banners.findChildren(Banner) for lbl in b.findChildren(QLabel)]
    assert any("incomplet" in text for text in texts)


def test_theme_switch_and_navigation_shortcuts(qtbot, gui):
    ctx, window = gui
    ctx.theme.set_theme(Theme.DARK)
    assert ctx.theme.tokens.dark
    qtbot.keyClick(window, Qt.Key.Key_5, Qt.KeyboardModifier.ControlModifier)
    assert window.current_view_key() == "cloud"
    qtbot.keyClick(window, Qt.Key.Key_6, Qt.KeyboardModifier.ControlModifier)
    assert window.current_view_key() == "logs"
    qtbot.keyClick(window, Qt.Key.Key_1, Qt.KeyboardModifier.ControlModifier)
    assert window.current_view_key() == "dashboard"
    ctx.theme.set_theme(Theme.LIGHT)


def test_ui_never_blocks_during_a_slow_engine_task(qtbot, gui):
    """Une opération lente du moteur ne doit pas geler le thread de l'interface."""
    ctx, window = gui
    import asyncio

    finished = []

    async def slow() -> str:
        await asyncio.sleep(1.0)
        return "fini"

    started = time.monotonic()
    ctx.run(slow(), finished.append)
    returned_after = time.monotonic() - started
    assert returned_after < 0.05
    wait_until(qtbot, lambda: finished == ["fini"], timeout=5000)


def test_groups_delete_key_and_access_token_status(qtbot, gui, monkeypatch):
    from PySide6.QtGui import QKeySequence, QShortcut
    from PySide6.QtWidgets import QMenu

    import cma.ui.views.profiles as profiles_module
    from cma.core.models import CloudflareProfile

    ctx, window = gui
    manager = ctx.core.manager
    calls: list[tuple[str, str]] = []

    async def fake_start_group(group):
        calls.append(("start", group))
        return []

    async def fake_stop_group(group):
        calls.append(("stop", group))

    async def fake_token(profile_id):
        calls.append(("token", profile_id))
        return True

    monkeypatch.setattr(manager, "start_group", fake_start_group)
    monkeypatch.setattr(manager, "stop_group", fake_stop_group)
    monkeypatch.setattr(manager, "access_token_valid", fake_token)
    first = CloudflareProfile(name="A", group="Prod", hostname="a.ex.fr", local_port=31001)
    second = CloudflareProfile(name="B", group="Prod", hostname="b.ex.fr", local_port=31002)
    ctx.update_config(lambda c: c.cloudflare_profiles.extend([first, second]))

    # Tableau de bord : le menu « Connecter » propose le groupe entier.
    group_action = next(a for a in window.dashboard.connect_menu.actions() if "Prod (2)" in a.text())
    group_action.trigger()
    qtbot.waitUntil(lambda: ("start", "Prod") in calls)

    # Vue Profils : clic droit sur le titre du groupe.
    view = window.profiles
    window.show_view("profiles")
    tree = view.list.tree
    group_item = tree.topLevelItem(0)
    assert group_item is not None and group_item.text(0) == "Prod"
    menu = view.list.group_menu(tree.visualItemRect(group_item).center())
    assert isinstance(menu, QMenu)
    assert [a.text() for a in menu.actions()] == ["Connecter le groupe", "Déconnecter le groupe"]
    menu.actions()[1].trigger()
    qtbot.waitUntil(lambda: ("stop", "Prod") in calls)
    profile_item = group_item.child(0)
    assert view.list.group_menu(tree.visualItemRect(profile_item).center()) is None

    # État du jeton Access d'un profil en authentification navigateur.
    view.select_profile(first.id)
    editor = view.editor
    assert editor.auth_form.isRowVisible(editor.access_host)
    assert "non vérifié" in editor.access_status.text()
    editor.access_check.click()
    qtbot.waitUntil(lambda: "valide" in editor.access_status.text())
    assert editor.access_status.property("role") == "success"

    # Touche Suppr : même action que la corbeille.
    monkeypatch.setattr(profiles_module, "confirm", lambda *_a: True)
    shortcut = tree.findChild(QShortcut)
    assert shortcut is not None and shortcut.key() == QKeySequence(QKeySequence.StandardKey.Delete)
    shortcut.activated.emit()
    assert [p.name for p in ctx.config().cloudflare_profiles] == ["B"]
