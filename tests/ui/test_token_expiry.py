"""Échéance des service tokens dans l'interface : alertes, éditeur et textes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cma.core.expiry import TokenExpiry
from cma.core.models import ServiceToken
from cma.ui.format import expiry_alert, token_expiry

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


def test_expiry_texts():
    assert token_expiry(None)[1] == "muted"
    assert token_expiry(NOW + timedelta(days=200), NOW) == ("Expire le 24/04/2027", "muted")
    text, role = token_expiry(NOW + timedelta(days=12, hours=1), NOW)
    assert role == "warning" and "dans 12 j" in text
    assert token_expiry(NOW - timedelta(days=1), NOW)[1] == "error"
    token = ServiceToken(name="Robot", client_id="robot.access")
    assert "a expiré" in expiry_alert(TokenExpiry(token, -3))
    assert "aujourd'hui" in expiry_alert(TokenExpiry(token, 0))
    assert "dans 5 jours" in expiry_alert(TokenExpiry(token, 5))


def test_main_window_warns_once_per_token(qtbot, gui):
    ctx, window = gui
    notes: list[tuple[str, str]] = []
    window.banners.show_message = lambda level, text, **_k: notes.append((level, text))  # type: ignore[method-assign]
    soon = ServiceToken(
        name="Bientôt", client_id="b.access", expires_at=datetime.now(UTC) + timedelta(days=5)
    )
    gone = ServiceToken(name="Fini", client_id="f.access", expires_at=datetime.now(UTC) - timedelta(days=2))
    later = ServiceToken(name="Tard", client_id="t.access", expires_at=datetime.now(UTC) + timedelta(days=90))
    ctx.update_config(lambda c: c.tokens.extend([soon, gone, later]))
    window.show()

    assert [item.token.name for item in window.check_token_expiry()] == ["Fini", "Bientôt"]
    assert [level for level, _ in notes] == ["error", "warning"]
    assert window.check_token_expiry() == []  # une seule alerte par token et par session
    window.open_cloud_tokens()
    assert window.stack.currentWidget() is window.cloud and window.cloud.tabs.currentIndex() == 2


def test_token_editor_shows_the_expiry(qtbot, gui):
    ctx, window = gui
    token = ServiceToken(name="Robot", client_id="r.access", expires_at=datetime.now(UTC) + timedelta(days=3))
    ctx.update_config(lambda c: c.tokens.append(token))
    window.show_view("tokens")
    window.tokens.list.select(token.id)
    editor = window.tokens.editor
    assert editor.expiry.text().startswith("Expire le") and editor.expiry.property("role") == "warning"
