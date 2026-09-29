"""Parcours secondaires des éditeurs : modifications non enregistrées, erreurs du coffre, actions distantes."""

from __future__ import annotations

import pytest

import cma.ui.views.profiles as profiles_module
import cma.ui.views.tokens as tokens_module
from cma.core.models import AuthMode, CloudflareProfile, ServiceToken, SshProfile
from cma.core.secrets import SecretStoreError
from tests.ui.test_views import fake_info


@pytest.fixture
def notes(gui):
    ctx, _window = gui
    received: list[tuple[str, str]] = []
    ctx._notifier = lambda level, text, **_k: received.append((level, text))
    return received


def add_profiles(ctx):
    token = ServiceToken(name="Prod", client_id="abc.access")
    first = CloudflareProfile(name="A", hostname="a.exemple.fr", local_port=31501)
    second = CloudflareProfile(
        name="B", hostname="b.exemple.fr", local_port=31502, auth=AuthMode.SERVICE_TOKEN, token_id=token.id
    )
    via = SshProfile(name="Via A", host="srv", user="u", via_cloudflare_profile=first.id)
    ctx.update_config(
        lambda c: (
            c.tokens.append(token),
            c.cloudflare_profiles.extend([first, second]),
            c.ssh_profiles.append(via),
        )
    )
    return token, first, second, via


def test_profile_remote_actions(qtbot, gui, notes, monkeypatch):
    ctx, window = gui
    _token, first, second, _via = add_profiles(ctx)
    manager = ctx.core.manager
    calls: list[str] = []

    async def fake_test(profile_id):
        calls.append("test")
        return False, "refusé par Access"

    async def fake_login(profile_id):
        calls.append("login")
        return "ok"

    async def fake_token(profile_id):
        calls.append("token")
        return False

    async def fake_ssh_config(profile_id):
        calls.append("ssh-config")
        return "Host a.exemple.fr"

    async def failing(*_a):
        raise RuntimeError("panne")

    monkeypatch.setattr(manager, "test_cloudflare_profile", fake_test)
    monkeypatch.setattr(manager, "access_login", fake_login)
    monkeypatch.setattr(manager, "access_token_valid", fake_token)
    monkeypatch.setattr(manager, "ssh_config_snippet", fake_ssh_config)
    shown: list[str] = []
    monkeypatch.setattr(profiles_module, "show_text", lambda *a: shown.append(a[-1]))

    window.show_view("profiles")
    view = window.profiles
    view.select_profile(second.id)
    editor = view.editor
    editor._test()
    qtbot.waitUntil(lambda: ("error", "refusé par Access") in notes, timeout=5000)
    assert editor.test_button.isEnabled()

    view.select_profile(first.id)
    editor._login()
    qtbot.waitUntil(lambda: "token" in calls, timeout=5000)
    qtbot.waitUntil(lambda: "Aucun jeton" in editor.access_status.text(), timeout=5000)
    assert editor.access_status.property("role") == "warning"
    editor._ssh_config()
    qtbot.waitUntil(lambda: shown == ["Host a.exemple.fr"], timeout=5000)

    monkeypatch.setattr(manager, "access_token_valid", failing)
    monkeypatch.setattr(manager, "test_cloudflare_profile", failing)
    editor._check_access_token()
    qtbot.waitUntil(lambda: ("error", "panne") in notes, timeout=5000)
    assert editor.access_check.isEnabled()
    view.select_profile(second.id)
    editor._test()
    qtbot.waitUntil(lambda: notes.count(("error", "panne")) == 2, timeout=5000)


def test_profile_sessions_toggle_and_unsaved_changes(qtbot, gui, notes, monkeypatch):
    ctx, window = gui
    _token, first, second, via = add_profiles(ctx)
    manager = ctx.core.manager
    stopped: list[str] = []

    async def fake_stop(profile_id):
        stopped.append(profile_id)

    monkeypatch.setattr(manager, "stop_profile", fake_stop)
    window.show_view("profiles")
    view = window.profiles
    view.select_profile(first.id)
    info = fake_info(profile_id=first.id, name="A", local_port=31501)
    ctx.bridge.session_changed.emit(info)
    assert view.editor.connect_button.text() == "Déconnecter"
    view.editor._toggle_connection()
    qtbot.waitUntil(lambda: stopped == [first.id], timeout=5000)
    ctx.bridge.session_removed.emit("s1")
    assert view.editor.connect_button.text() == "Connecter"

    # Modification en cours, puis changement de profil : « Annuler » garde la sélection.
    view.editor.name.setText("A modifié")
    view.editor.name.textEdited.emit("x")
    monkeypatch.setattr(profiles_module, "ask_unsaved", lambda *_a: "cancel")
    view._on_select(second.id)
    assert view.editor.profile.id == first.id
    monkeypatch.setattr(profiles_module, "ask_unsaved", lambda *_a: "discard")
    view._on_select(second.id)
    assert view.editor.profile.id == second.id
    view.editor.name.setText("B renommé")
    view.editor.name.textEdited.emit("x")
    monkeypatch.setattr(profiles_module, "ask_unsaved", lambda *_a: "save")
    view._on_select(first.id)
    assert ctx.config().cloudflare_profile(second.id).name == "B renommé"

    # Un profil invalide ne se lance pas : l'enregistrement échoue d'abord.
    view.editor.hostname.setText("pas valide")
    view.editor.hostname.textEdited.emit("x")
    view.editor._toggle_connection()
    assert view.editor.errors["hostname"].isVisible()

    # Duplication puis suppression d'un profil dont dépend un profil SSH.
    view.editor.load(ctx.config().cloudflare_profile(first.id))
    view.duplicate()
    assert any(p.name.startswith("A (copie)") for p in ctx.config().cloudflare_profiles)
    view.select_profile(first.id)
    view._show(first.id)
    texts: list[str] = []
    monkeypatch.setattr(profiles_module, "confirm", lambda _p, _h, text: texts.append(text) or True)
    view.delete()
    assert "Via A" in texts[0]
    assert ctx.config().ssh_profile(via.id).via_cloudflare_profile is None
    assert ctx.config().cloudflare_profile(first.id) is None


def test_token_editor_errors_and_navigation(qtbot, gui, notes, monkeypatch):
    ctx, window = gui
    token, _first, second, _via = add_profiles(ctx)
    other = ServiceToken(name="Labo", client_id="xyz.access")
    ctx.update_config(lambda c: c.tokens.append(other))
    ctx.core.secrets.set(token.secret_key, "s3cret")
    window.show_view("tokens")
    view = window.tokens
    view.list.select(token.id)
    editor = view.editor
    assert editor.secret.text() == "s3cret"
    assert editor.users.item(0).text() == "B"

    # Nom déjà pris, puis ID client invalide.
    editor.name.setText("labo")
    editor._changed()
    assert editor.save() is False and "déjà ce nom" in editor.name_error.text()
    editor.name.setText("Prod")
    editor.client_id.setText("")
    assert editor.save() is False and editor.client_error.text()
    editor.client_id.setText("abc.access")

    # Le coffre refuse le secret.
    editor.secret.set_text("nouveau")
    original_set = ctx.core.secrets.set

    def refuse(*_a):
        raise SecretStoreError("verrouillé")

    monkeypatch.setattr(ctx.core.secrets, "set", refuse)
    assert editor.save() is False
    assert any("refusé le secret" in text for _level, text in notes)
    monkeypatch.setattr(ctx.core.secrets, "set", original_set)

    # Changements non enregistrés en changeant de token.
    monkeypatch.setattr(tokens_module, "ask_unsaved", lambda *_a: "cancel")
    view._on_select(other.id)
    assert editor.token.id == token.id
    monkeypatch.setattr(tokens_module, "ask_unsaved", lambda *_a: "save")
    view._on_select(other.id)
    assert ctx.core.secrets.get(token.secret_key) == "nouveau"
    assert editor.token.id == other.id

    # Secret vidé : il est retiré du coffre.
    view._on_select(token.id)
    editor.secret.set_text("")
    assert editor.save() is True
    assert ctx.core.secrets.get(token.secret_key) is None

    # Coffre illisible au chargement.
    def unreadable(*_a):
        raise SecretStoreError("illisible")

    monkeypatch.setattr(ctx.core.secrets, "get", unreadable)
    editor.load(ctx.config().token(token.id))
    assert any("Coffre illisible" in text for _level, text in notes)
    monkeypatch.undo()

    # Suppression : les profils qui l'utilisaient repassent au navigateur, le secret part du coffre.
    ctx._notifier = lambda level, text, **_k: notes.append((level, text))
    monkeypatch.setattr(tokens_module, "confirm", lambda *_a: True)
    view._show(token.id)
    monkeypatch.setattr(ctx.core.secrets, "delete", refuse)
    view.delete()
    assert ctx.config().token(token.id) is None
    assert ctx.config().cloudflare_profile(second.id).auth == AuthMode.BROWSER
    assert any(level == "warning" for level, _text in notes)
