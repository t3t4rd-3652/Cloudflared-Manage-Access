"""Vue « Compte Cloudflare » contre le faux serveur d'API : connexion, import, tokens, publication."""

from __future__ import annotations

import pytest

import cma.ui.views.cloud as cloud_module
from cma.core.cfadmin import PublishRequest
from cma.core.cfapi import TOKEN_SECRET_KEY, Tunnel
from cma.core.models import AuthMode
from cma.ui.views.cloud import AllowDialog, CloudView, CreateTokenDialog, ProtectDialog, PublishDialog
from tests.fakes.fake_cfapi import TOKEN, FakeCloudflareServer


@pytest.fixture
def cf():
    with FakeCloudflareServer() as server:
        yield server


def names(ctx) -> list[str]:
    return sorted(p.hostname for p in ctx.config().cloudflare_profiles)


def test_cloud_view_full_flow(qtbot, gui, cf, monkeypatch):
    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    view = window.cloud
    assert view.stack.currentIndex() == 0

    view.connect_account()  # champ vide : rien n'est envoyé
    assert cf.state.requests == []
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=10000)
    assert view.stack.currentIndex() == 1
    assert ctx.core.secrets.get(TOKEN_SECRET_KEY) == TOKEN
    assert view.token_field.text() == ""
    assert "3 noms d'hôte" in view.status.text()
    assert view.read_label.text().startswith("Dernière lecture")

    # Import d'un nom d'hôte sélectionné, puis de tout le reste.
    bureau = view.tree.topLevelItem(0)
    bureau.child(2).setSelected(True)
    view.import_selected()
    assert names(ctx) == ["grafana.exemple.fr"]
    view.tree.clearSelection()
    view.import_selected()
    assert names(ctx) == ["grafana.exemple.fr", "rdp.exemple.fr", "ssh.exemple.fr"]
    view.import_selected()  # déjà importés : rien de plus
    assert len(ctx.config().cloudflare_profiles) == 3

    # Service token créé chez Cloudflare et rangé dans le coffre.
    monkeypatch.setattr(cloud_module, "ask_create_token", lambda *_a: ("Robot", "17520h"))
    view.create_token()
    qtbot.waitUntil(lambda: view.remote_tokens.rowCount() == 1, timeout=10000)
    assert cf.state.service_tokens[0]["duration"] == "17520h"
    token = ctx.config().tokens[0]
    assert ctx.core.secrets.get(token.secret_key).startswith("secret-")
    assert view.remote_tokens.item(0, 3).text() == "Oui"

    # Autorisation du token sur l'application Access existante.
    view.apps.selectRow(0)
    monkeypatch.setattr(cloud_module, "ask_allow", lambda _p, _app, tokens: tokens[0])
    view.allow_token()
    qtbot.waitUntil(lambda: bool(cf.state.policies), timeout=10000)

    # Protection d'un nouveau nom d'hôte.
    monkeypatch.setattr(cloud_module, "ask_protect", lambda *_a: "DB.exemple.fr")
    view.protect_hostname()
    qtbot.waitUntil(lambda: view.apps.rowCount() == 2, timeout=10000)

    # Publication d'un service sur le second tunnel, avec profil et token.
    request = PublishRequest(
        Tunnel("t2", "labo", "down"), "pg.lab.exemple.fr", "tcp://localhost:5432", token_id=token.id
    )
    monkeypatch.setattr(view, "ask_publish", lambda: request)
    view.publish()
    qtbot.waitUntil(lambda: "pg.lab.exemple.fr" in names(ctx), timeout=10000)
    profile = next(p for p in ctx.config().cloudflare_profiles if p.hostname == "pg.lab.exemple.fr")
    assert profile.auth == AuthMode.SERVICE_TOKEN and profile.token_id == token.id
    qtbot.waitUntil(lambda: view.tree.topLevelItem(1).childCount() == 1, timeout=10000)

    # Retrait du nom d'hôte publié.
    monkeypatch.setattr(cloud_module, "confirm", lambda *_a: True)
    view.tree.clearSelection()
    view.unpublish_selected()  # rien de sélectionné : refus
    view.tree.topLevelItem(1).child(0).setSelected(True)
    view.unpublish_selected()
    qtbot.waitUntil(lambda: view.tree.topLevelItem(1).childCount() == 0, timeout=10000)
    assert cf.state.dns["z2"] == []

    # Une nouvelle vue se reconnecte seule avec le jeton du coffre.
    fresh = CloudView(ctx)
    qtbot.addWidget(fresh)
    fresh.show()
    qtbot.waitUntil(lambda: fresh.overview is not None, timeout=10000)

    view.forget()
    assert view.stack.currentIndex() == 0
    assert ctx.core.secrets.get(TOKEN_SECRET_KEY) is None


def test_cloud_view_reports_api_errors(qtbot, gui, cf):
    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    notes: list[tuple[str, str]] = []
    ctx._notifier = lambda level, text, **_k: notes.append((level, text))
    view = window.cloud
    view.token_field.set_text("mauvais")
    view.connect_account()
    qtbot.waitUntil(lambda: bool(notes), timeout=10000)
    assert notes[0][0] == "error" and "401" in notes[0][1]
    assert view.stack.currentIndex() == 0
    assert view.connect_button.isEnabled()
    view.allow_token()  # aucune application sélectionnée
    view.import_selected()  # rien à importer
    assert [level for level, _ in notes[1:]] == ["info", "info"]


def test_publish_dialog_validation(qtbot, gui, cf):
    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    ctx.core.secrets.set(TOKEN_SECRET_KEY, TOKEN)
    accounts = ctx.engine.run_sync(ctx.core.manager.cloudflare.connect(), timeout=10)
    overview = ctx.engine.run_sync(ctx.core.manager.cloudflare.overview(accounts[0]), timeout=10)
    dialog = PublishDialog(window, overview, [])
    qtbot.addWidget(dialog)
    assert dialog.request() is None and "Nom d'hôte invalide" in dialog.error.text()
    dialog.hostname.setText("app.exemple.fr")
    dialog.service.setText("localhost:22")
    assert dialog.request() is None and "schéma" in dialog.error.text()
    dialog.service.setText("tcp://localhost:22")
    dialog.protect.setChecked(False)
    request = dialog.request()
    assert request is not None and request.tunnel.name == "bureau" and request.token_id is None
    dialog._accept()
    assert dialog.result() == dialog.DialogCode.Accepted

    empty = PublishDialog(window, overview.__class__(account=overview.account), [])
    qtbot.addWidget(empty)
    assert empty.request() is None and "aucun tunnel" in empty.error.text().lower()


def test_publish_dialog_splits_pasted_hostname(qtbot, gui, cf):
    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    ctx.core.secrets.set(TOKEN_SECRET_KEY, TOKEN)
    accounts = ctx.engine.run_sync(ctx.core.manager.cloudflare.connect(), timeout=10)
    overview = ctx.engine.run_sync(ctx.core.manager.cloudflare.overview(accounts[0]), timeout=10)
    dialog = PublishDialog(window, overview, [])
    qtbot.addWidget(dialog)
    assert not dialog.ok_button.isEnabled()
    dialog.hostname.textEdited.emit("pg.lab.exemple.fr")
    assert dialog.hostname.text() == "pg" and dialog.zone.currentData() == "lab.exemple.fr"
    dialog.service.setText("tcp://localhost:5432")
    assert dialog.ok_button.isEnabled()
    assert "pg.lab.exemple.fr → tcp://localhost:5432 via bureau" in dialog.summary.text()


def test_cloud_secondary_dialogs(qtbot, gui):
    from cma.core.cfapi import AccessApp
    from cma.core.models import ServiceToken

    _ctx, window = gui
    protect = ProtectDialog(window, ["ssh.exemple.fr"])
    qtbot.addWidget(protect)
    assert not protect.ok_button.isEnabled()
    protect.hostname.setText("  DB.Exemple.fr ")
    assert protect.ok_button.isEnabled() and protect.value() == "db.exemple.fr"
    assert "db.exemple.fr" in protect.app_name.text()

    app = AccessApp("a1", "SSH", "ssh.exemple.fr", "self_hosted")
    empty = AllowDialog(window, app, [])
    qtbot.addWidget(empty)
    assert not empty.ok_button.isEnabled() and empty.value() is None
    token = ServiceToken(name="Robot", client_id="abc.access")
    allow = AllowDialog(window, app, [token])
    qtbot.addWidget(allow)
    assert allow.ok_button.isEnabled() and allow.value() == token

    create = CreateTokenDialog(window, "Mon compte", persistent=False)
    qtbot.addWidget(create)
    assert not create.ok_button.isEnabled()
    create.name.setText(" Robot ")
    create.duration.setCurrentIndex(create.duration.findData("17520h"))
    assert create.ok_button.isEnabled() and create.value() == ("Robot", "17520h")


def test_publish_summary_lists_each_step():
    from cma.core.cfadmin import PublishResult, PublishStep
    from cma.core.cfapi import IngressRule

    result = PublishResult(
        IngressRule("a.exemple.fr", "tcp://localhost:22"),
        None,
        None,
        (
            PublishStep("hostname", True),
            PublishStep("access", False, "refusé"),
            PublishStep("profile", False),
        ),
    )
    assert cloud_module.publish_summary(result) == (
        "Nom d'hôte publié ; protection Access non créée ; profil CMA non créé.\nrefusé"
    )
