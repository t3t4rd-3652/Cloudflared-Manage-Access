"""Vue « Compte Cloudflare » contre le faux serveur d'API : connexion, import, tokens, publication."""

from __future__ import annotations

from dataclasses import replace

import pytest

import cma.ui.views.cloud.helpers as cloud_helpers
import cma.ui.views.cloud.tokens_tab as tokens_module
import cma.ui.views.cloud.view as cloud_module
from cma.core.cfadmin import NewTunnel, PublishRequest
from cma.core.cfapi import TOKEN_SECRET_KEY, Tunnel
from cma.core.models import AuthMode
from cma.core.policies import AccessGroup, AccessPolicy, PolicyRule
from cma.ui.views.cloud import (
    AllowDialog,
    CloudView,
    ConnectorsDialog,
    CreateTokenDialog,
    EditServiceDialog,
    ProtectDialog,
    PublishDialog,
)
from cma.ui.views.cloud.policies import AccountPoliciesDialog, PoliciesDialog, PolicyEditDialog
from cma.ui.views.cloud.tunnel_create import MASK, CreateTunnelDialog, NewTunnelDialog
from tests.fakes.fake_cfapi import TOKEN, FakeCloudflare, FakeCloudflareServer


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
    assert view.stat_hostnames.value.text() == "3" and view.stat_tunnels.value.text() == "2"
    assert view.account_name.text() and view.stat_tunnels.detail.text()
    assert not view.permission_hint.isVisible()
    view.stat_apps.clicked.emit()
    assert view.tabs.currentIndex() == 1
    view.tabs.setCurrentIndex(0)
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
    monkeypatch.setattr(tokens_module, "ask_create_token", lambda *_a: ("Robot", "17520h"))
    view.create_token()
    qtbot.waitUntil(lambda: view.remote_tokens.rowCount() == 1, timeout=10000)
    assert cf.state.service_tokens[0]["duration"] == "17520h"
    token = ctx.config().tokens[0]
    assert ctx.core.secrets.get(token.secret_key).startswith("secret-")
    assert view.remote_tokens.item(0, 3).text() == "Oui"

    # Prolonger, puis changer le secret du token sélectionné.
    assert not view.extend_button.isEnabled() and not view.rotate_button.isEnabled()
    view.remote_tokens.selectRow(0)
    assert view.extend_button.isEnabled() and view.rotate_button.isEnabled()
    view.extend_selected_token()
    qtbot.waitUntil(lambda: ctx.config().tokens[0].expires_at.year == 2028, timeout=10000)
    old_secret = ctx.core.secrets.get(token.secret_key)
    monkeypatch.setattr(tokens_module, "confirm", lambda *_a: False)
    view.remote_tokens.selectRow(0)
    view.rotate_selected_token()  # refusé : rien ne change
    assert ctx.core.secrets.get(token.secret_key) == old_secret
    monkeypatch.setattr(tokens_module, "confirm", lambda *_a: True)
    view.rotate_selected_token()
    qtbot.waitUntil(lambda: ctx.core.secrets.get(token.secret_key) != old_secret, timeout=10000)
    qtbot.waitUntil(lambda: view.remote_tokens.rowCount() == 1, timeout=10000)

    # Autorisation du token sur l'application Access existante.
    view.apps.selectRow(0)
    monkeypatch.setattr(cloud_module, "ask_allow", lambda _p, _app, tokens: tokens[0])
    view.allow_token()
    qtbot.waitUntil(lambda: bool(cf.state.account_policies), timeout=10000)

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


def test_cloud_view_checks_tunnel_connectors(qtbot, gui, cf, monkeypatch):
    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    view = window.cloud
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=10000)
    shown: list[tuple[str, int]] = []
    monkeypatch.setattr(
        cloud_module,
        "show_connectors",
        lambda _p, tunnel, connectors: shown.append((tunnel.name, len(connectors))),
    )
    for index in (0, 1):
        view.check_connectors(view.tree.topLevelItem(index).data(0, cloud_module.TUNNEL_ROLE))
    qtbot.waitUntil(lambda: len(shown) == 2, timeout=10000)
    assert sorted(shown) == [("bureau", 1), ("labo", 0)]

    tunnel = view.tree.topLevelItem(0).data(0, cloud_module.TUNNEL_ROLE)
    healthy = ConnectorsDialog(
        view, tunnel, ctx.core.manager.cloudflare.api().tunnel_connectors("acc1", "t1")
    )
    assert healthy.table.rowCount() == 4 and [f.level for f in healthy.findings] == ["success"]
    assert healthy.table.item(0, 4).text() == "CDG01"
    empty = ConnectorsDialog(view, tunnel, [])
    assert empty.table.isHidden() and empty.findings[0].level == "error"


def connected_view(qtbot, gui, cf):
    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    view = window.cloud
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=10000)
    return ctx, view


def test_cloud_view_edits_a_published_service(qtbot, gui, cf, monkeypatch):
    _ctx, view = connected_view(qtbot, gui, cf)
    bureau = view.tree.topLevelItem(0)
    tunnel = bureau.data(0, cloud_module.TUNNEL_ROLE)
    rule = bureau.child(0).data(0, cloud_module.RULE_ROLE)
    assert rule.hostname == "ssh.exemple.fr"

    monkeypatch.setattr(cloud_module, "ask_service", lambda *_a: None)
    view.edit_service(tunnel, rule)  # annulé : rien n'est envoyé
    assert not any(method == "PUT" for method, _ in cf.state.requests)
    origin = {"noTLSVerify": True, "httpHostHeader": "pve.local", "originServerName": ""}
    monkeypatch.setattr(cloud_module, "ask_service", lambda *_a: ("https://localhost:8006", origin))
    view.edit_service(tunnel, rule)
    qtbot.waitUntil(
        lambda: cf.state.configs["t1"]["ingress"][0]["service"] == "https://localhost:8006", timeout=10000
    )
    assert cf.state.configs["t1"]["ingress"][0]["originRequest"] == {
        "noTLSVerify": True,
        "httpHostHeader": "pve.local",
    }

    dialog = EditServiceDialog(view, tunnel, rule)
    assert not dialog.ok_button.isEnabled()  # rien de changé
    dialog.no_tls_verify.setChecked(True)
    assert dialog.ok_button.isEnabled()  # une option d'origine suffit
    dialog.no_tls_verify.setChecked(False)
    dialog.service.setText("localhost:22")
    assert dialog.ok_button.isEnabled()
    dialog._accept()
    assert "schéma" in dialog.error.text() and dialog.result() == 0
    dialog.service.setText("tcp://localhost:22")
    dialog._accept()
    assert dialog.result() == 1 and dialog.value() == "tcp://localhost:22"
    assert dialog.origin() == {"noTLSVerify": False, "httpHostHeader": "", "originServerName": ""}
    with_origin = EditServiceDialog(
        view, tunnel, cloud_module.IngressRule("a.fr", "https://x", origin={"noTLSVerify": True})
    )
    assert with_origin.no_tls_verify.isChecked() and not with_origin.ok_button.isEnabled()


def test_cloud_view_manages_shared_access_policies(qtbot, gui, cf, monkeypatch):
    import cma.ui.views.cloud.policies as policies_module

    cf.state.apps.append(
        {"id": "app2", "name": "Proxy", "domain": "proxy.exemple.fr", "type": "self_hosted", "policies": []}
    )
    cf.state.account_policies.append(
        {
            "id": "p1",
            "name": "without token",
            "decision": "allow",
            "include": [{"email": {"email": "moi@exemple.fr"}}],
            "exclude": [],
            "require": [],
            "connection_rules": {"rdp": {}},
            "reusable": True,
        }
    )
    cf.state.apps[0]["policies"] = [{"id": "p1", "precedence": 1}]
    cf.state.apps[1]["policies"] = [{"id": "p1", "precedence": 1}]
    _ctx, view = connected_view(qtbot, gui, cf)
    qtbot.waitUntil(lambda: view.apps.rowCount() == 2, timeout=10000)
    view.tabs.setCurrentIndex(1)
    assert not view.policies_button.isEnabled() and not view.delete_app_button.isEnabled()
    row = next(r for r in range(view.apps.rowCount()) if view.apps.item(r, 0).text() == "SSH")
    view.apps.selectRow(row)
    assert view.policies_button.isEnabled() and view.delete_app_button.isEnabled()

    opened: list[PoliciesDialog] = []
    monkeypatch.setattr(cloud_module, "show_policies", opened.append)
    view.manage_policies()
    qtbot.waitUntil(lambda: bool(opened), timeout=10000)
    dialog = opened[0]
    assert dialog.table.rowCount() == 1 and dialog.table.item(0, 3).text() == "Partagée : 2 applications"
    assert dialog.groups == [AccessGroup("g1", "Admins")]

    # Nouvelle politique : créée dans le compte et attachée à l'application.
    team = AccessPolicy("", "Équipe", "allow", (PolicyRule("email_domain", "exemple.fr"),), reusable=True)
    monkeypatch.setattr(policies_module, "ask_policy", lambda *_a: team)
    dialog.add_policy()
    qtbot.waitUntil(lambda: dialog.table.rowCount() == 2 and dialog.isEnabled(), timeout=10000)
    assert (
        dialog.table.item(1, 2).text() == "@exemple.fr"
        and dialog.table.item(1, 3).text() == "Une seule application"
    )

    # Modifier la politique partagée : dans le compte, règles RDP conservées.
    dialog.table.selectRow(0)
    shared = dialog.policies[0]
    monkeypatch.setattr(policies_module, "ask_policy", lambda *_a: replace(shared, name="Moi"))
    dialog.edit_policy(dialog.save)
    qtbot.waitUntil(lambda: dialog.table.item(0, 0).text() == "Moi", timeout=10000)
    stored = cf.state.account_policies[0]
    assert stored["name"] == "Moi" and stored["connection_rules"] == {"rdp": {}}

    # Retirer la politique partagée : l'autre application la garde.
    dialog.table.selectRow(0)
    monkeypatch.setattr(policies_module, "confirm", lambda *_a: True)
    dialog.remove_policy()
    qtbot.waitUntil(lambda: dialog.table.rowCount() == 1 and dialog.isEnabled(), timeout=10000)
    assert cf.state.apps[1]["policies"] == [{"id": "p1", "precedence": 1}]

    # Ajouter une politique existante du compte.
    monkeypatch.setattr(policies_module, "ask_existing_policy", lambda _p, candidates, *_a: candidates[0])
    dialog.add_existing()
    qtbot.waitUntil(lambda: dialog.table.rowCount() == 2 and dialog.isEnabled(), timeout=10000)
    assert [link["id"] for link in cf.state.apps[0]["policies"]][-1] == "p1"

    # Une erreur de l'API réactive la boîte de dialogue.
    ghost = AccessPolicy("disparue", "Fantôme", "allow", (PolicyRule("everyone"),), reusable=True)
    dialog.policies = [ghost]
    dialog.table.selectRow(0)
    monkeypatch.setattr(policies_module, "ask_policy", lambda *_a: ghost)
    dialog.edit_policy(dialog.save)
    qtbot.waitUntil(dialog.isEnabled, timeout=10000)


def test_cloud_view_account_policies_and_cleanup(qtbot, gui, cf, monkeypatch):
    import cma.ui.views.cloud.policies as policies_module

    cf.state.account_policies.append(
        {
            "id": "p9",
            "name": "Oubliée",
            "decision": "allow",
            "include": [{"everyone": {}}],
            "exclude": [],
            "require": [],
        }
    )
    ctx, view = connected_view(qtbot, gui, cf)
    opened: list[AccountPoliciesDialog] = []
    monkeypatch.setattr(cloud_module, "show_policies", opened.append)
    view.manage_account_policies()
    qtbot.waitUntil(lambda: bool(opened), timeout=10000)
    dialog = opened[0]
    assert (
        dialog.table.item(0, 3).text() == "Inutilisée"
        and "1 politique(s) inutilisée(s)" in dialog.status.text()
    )
    dialog.table.selectRow(0)
    assert dialog.delete_button.isEnabled()
    monkeypatch.setattr(policies_module, "confirm", lambda *_a: True)
    dialog.delete_policy()
    qtbot.waitUntil(lambda: dialog.table.rowCount() == 0 and dialog.isEnabled(), timeout=10000)
    assert cf.state.account_policies == []

    # Ménage : renommer et supprimer un tunnel arrêté, supprimer une application et un token.
    monkeypatch.setattr(cloud_module, "confirm", lambda *_a: True)
    monkeypatch.setattr(tokens_module, "confirm", lambda *_a: True)
    labo = view.tree.topLevelItem(1).data(0, cloud_module.TUNNEL_ROLE)
    monkeypatch.setattr(cloud_module, "ask_tunnel_name", lambda _p, _existing, current: current + "-2")
    view.rename_tunnel(labo)
    qtbot.waitUntil(lambda: cf.state.tunnels[1]["name"] == "labo-2", timeout=10000)
    view.delete_tunnel(labo)
    qtbot.waitUntil(lambda: len(cf.state.tunnels) == 1, timeout=10000)
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 1, timeout=10000)
    notes: list[tuple[str, str]] = []
    ctx._notifier = lambda level, text, **_k: notes.append((level, text))
    view.delete_tunnel(
        view.tree.topLevelItem(0).data(0, cloud_module.TUNNEL_ROLE)
    )  # connecteur actif : refus
    qtbot.waitUntil(lambda: any(level == "error" for level, _ in notes), timeout=10000)
    assert len(cf.state.tunnels) == 1

    view.tabs.setCurrentIndex(1)
    view.apps.selectRow(0)
    view.delete_selected_app()
    qtbot.waitUntil(lambda: cf.state.apps == [], timeout=10000)
    cf.state.service_tokens.append(
        {"id": "tk", "name": "Vieux", "client_id": "vieux.access", "expires_at": ""}
    )
    view.refresh()
    qtbot.waitUntil(lambda: view.remote_tokens.rowCount() == 1, timeout=10000)
    view.remote_tokens.selectRow(0)
    assert view.delete_token_button.isEnabled()
    view.delete_selected_token()
    qtbot.waitUntil(lambda: cf.state.service_tokens == [], timeout=10000)


def test_policy_editor_validates_the_rules(qtbot, gui):
    _ctx, window = gui
    groups = [AccessGroup("g1", "Admins")]
    unknown = PolicyRule("raw", raw={"github-organization": {"name": "acme"}})
    existing = AccessPolicy("p1", "Équipe", "allow", (PolicyRule("email", "a@b.fr"), unknown), precedence=3)
    dialog = PolicyEditDialog(window, existing, groups, {"Robot": "tok1"})
    assert dialog.rules.toPlainText() == "a@b.fr"
    assert dialog.warning.isHidden()
    dialog.rules.setPlainText("a@b.fr\ntout le monde")
    assert not dialog.warning.isHidden()
    dialog.rules.setPlainText("a@b.fr\nn'importe quoi")
    assert dialog.value() is None and "Ligne 2" in dialog.error.text()
    dialog.rules.setPlainText("groupe : Admins\ntoken : Robot")
    dialog.decision.setCurrentIndex(2)
    value = dialog.value()
    assert (
        value is not None and value.id == "p1" and value.decision == "non_identity" and value.precedence == 3
    )
    assert value.include == (PolicyRule("group", "g1"), PolicyRule("service_token", "tok1"), unknown)

    shared = AccessPolicy(
        "p2",
        "Partagée",
        "allow",
        (PolicyRule("email", "a@b.fr"),),
        reusable=True,
        app_count=3,
        extra={"connection_rules": {"rdp": {}}},
    )
    edited = PolicyEditDialog(window, shared, groups, {})
    kept = edited.value()
    assert kept is not None and kept.reusable and kept.extra == {"connection_rules": {"rdp": {}}}
    assert edited.findChildren(type(edited.warning))  # avertissement de partage affiché

    fresh = PolicyEditDialog(window, None, groups, {})
    assert fresh.value() is None and "nom" in fresh.error.text()
    fresh.name.setText("Vide")
    assert fresh.value() is None and "au moins une règle" in fresh.error.text()


def test_cloud_view_creates_a_tunnel(qtbot, gui, cf, monkeypatch):
    import cma.ui.views.cloud.tunnel_create as create_module

    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    view = window.cloud
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=10000)

    asked: list[list[str]] = []
    created: list[NewTunnel] = []
    monkeypatch.setattr(cloud_module, "ask_tunnel_name", lambda _p, existing: asked.append(existing))
    view.create_tunnel()  # annulé
    assert asked == [["bureau", "labo"]] and len(cf.state.tunnels) == 2
    monkeypatch.setattr(cloud_module, "ask_tunnel_name", lambda *_a: "nouveau")
    monkeypatch.setattr(cloud_module, "show_new_tunnel", lambda _p, result: created.append(result))
    view.create_tunnel()
    qtbot.waitUntil(lambda: bool(created) and view.tree.topLevelItemCount() == 3, timeout=10000)

    # La commande affichée masque le jeton ; « Copier » donne la commande complète.
    copied: list[str] = []
    monkeypatch.setattr(create_module, "copy_to_clipboard", copied.append)
    dialog = NewTunnelDialog(view, created[0])
    token = created[0].token
    assert all(token not in field.text() and MASK in field.text() for field in dialog.fields)
    dialog._copy(dialog.commands[0][1], dialog.commands[0][0])
    assert copied == [f"sudo cloudflared service install {token}"] and "Linux" in dialog.copied.text()

    ask = CreateTunnelDialog(view, ["bureau"])
    assert not ask.ok_button.isEnabled()
    ask.name.setText("Bureau")
    assert not ask.ok_button.isEnabled() and not ask.error.isHidden()
    ask.name.setText("  atelier ")
    assert ask.ok_button.isEnabled() and ask.value() == "atelier"


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


def test_cloud_view_explains_an_account_found_through_zones(qtbot, gui):
    ctx, window = gui
    with FakeCloudflareServer(FakeCloudflare(accounts=[])) as server:
        ctx.core.manager.cloudflare.base_url = server.base_url
        window.show_view("cloud")
        view = window.cloud
        view.token_field.set_text(TOKEN)
        view.connect_account()
        qtbot.waitUntil(lambda: view.overview is not None, timeout=10000)
        assert view.account_name.text() == "Mon compte"
        assert view.permission_hint.isVisible()
        assert "Account Settings : Read" in view.permission_hint.text()


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


def test_cloud_presentation_helpers():
    from datetime import datetime, timedelta

    assert cloud_module.service_icon("ssh://localhost:22") == "terminal-2"
    assert cloud_module.service_icon("tcp://localhost:27017") == "database"
    assert cloud_module.service_icon("tcp://localhost:9000") == "plug-connected"
    assert cloud_module.service_icon("https://intranet") == "world-www"
    assert cloud_module.service_icon("http_status:404") == "link"
    soon = (datetime.now() + timedelta(days=10)).strftime("%Y-%m-%d")
    past = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    later = (datetime.now() + timedelta(days=400)).strftime("%Y-%m-%d")
    assert cloud_helpers.expiry_status(soon) == "warning"
    assert cloud_helpers.expiry_status(past) == "danger"
    assert cloud_helpers.expiry_status(later) is None and cloud_helpers.expiry_status("") is None


def test_app_and_token_cards():
    from cma.core.cfapi import AccessApp, RemoteServiceToken
    from cma.ui.views.cloud.cards import app_card, token_card

    open_app = app_card(AccessApp("a", "Grafana", "grafana.exemple.fr", "self_hosted", 2))
    assert (open_app.icon, open_app.tone, open_app.subtitle) == ("shield-check", None, "grafana.exemple.fr")
    assert [b[0] for b in open_app.badges] == ["Self-hosted", "2 politiques"]
    closed = app_card(AccessApp("b", "Vide", "vide.exemple.fr", "self_hosted", 0))
    assert closed.tone == "warning" and closed.badges[-1][:1] == ("Aucune politique",)
    assert app_card(AccessApp("c", "WARP", "", "warp")).icon == "world"
    expired = token_card(
        RemoteServiceToken("t", "Robot", "r.access", "2020-01-01T00:00:00Z"), ("Oui", "success")
    )
    assert expired.tone == "danger"
    assert [b[0] for b in expired.badges] == ["Expire le 01/01/2020", "Dans CMA"]
    unknown = token_card(RemoteServiceToken("u", "Autre", "a.access"), ("Secret indisponible", "warning"))
    assert [b[0] for b in unknown.badges] == ["Échéance inconnue", "Secret indisponible"]
    assert (
        token_card(RemoteServiceToken("v", "Ailleurs", "x.access"), None).badges[-1][0] == "Échéance inconnue"
    )


def test_ingress_rules_from_the_tunnel_menu(qtbot, gui, cf, monkeypatch):
    """Règle avec chemin, ordre et règle finale depuis le menu d'un tunnel ou d'une règle."""
    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    view = window.cloud
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=10000)
    bureau = view.tree.topLevelItem(0)
    first = bureau.child(0)
    host = first.data(0, cloud_module.RULE_ROLE).hostname

    # Menu d'une règle : les actions de règle, « Monter » désactivé pour la première.
    actions = {a.text(): a for a in view.tree_menu(first).actions() if a.text()}
    assert {"Modifier le service…", "Ajouter une règle avec chemin…", "Monter", "Descendre"} <= set(actions)
    assert not actions["Monter"].isEnabled() and actions["Descendre"].isEnabled()
    assert "Règle finale…" in [a.text() for a in view.tree_menu(bureau).actions()]

    def cnames() -> int:
        return sum(1 for records in cf.state.dns.values() for r in records if r.get("name") == host)

    # Ajouter /api sur le même nom d'hôte : une règle de plus, un seul enregistrement DNS pour ce nom.
    monkeypatch.setattr(cloud_module, "ask_path_rule", lambda *_a: ("/api", "http://localhost:8080"))
    actions["Ajouter une règle avec chemin…"].trigger()
    qtbot.waitUntil(lambda: view.tree.topLevelItem(0).childCount() == 4, timeout=10000)
    assert cnames() == 1
    bureau = view.tree.topLevelItem(0)
    added = bureau.child(3)
    assert added.text(0) == host + "/api"

    # La faire passer devant la règle du nom d'hôte seul.
    for _ in range(3):
        view.move_rule(bureau.data(0, cloud_module.TUNNEL_ROLE), added.data(0, cloud_module.RULE_ROLE), -1)
        qtbot.wait(50)
    qtbot.waitUntil(lambda: view.tree.topLevelItem(0).child(0).text(0) == host + "/api", timeout=10000)

    # Règle finale : 503.
    monkeypatch.setattr(cloud_module, "ask_catch_all", lambda *_a: "http_status:503")
    view.edit_catch_all(view.tree.topLevelItem(0).data(0, cloud_module.TUNNEL_ROLE))
    qtbot.waitUntil(
        lambda: cf.state.configs["t1"]["ingress"][-1]["service"] == "http_status:503", timeout=10000
    )

    # Retirer la règle /api : le nom d'hôte reste publié (son DNS aussi), la confirmation le dit.
    view.tree.topLevelItem(0).child(0).setSelected(True)
    told: list[str] = []
    monkeypatch.setattr(cloud_module, "confirm", lambda _p, _h, text, *_a: told.append(text) or True)
    view.unpublish_selected()
    qtbot.waitUntil(lambda: view.tree.topLevelItem(0).childCount() == 3, timeout=10000)
    assert "reste publié" in told[0]
    assert cnames() == 1


def test_path_rule_and_catch_all_dialogs(qtbot):
    from cma.ui.views.cloud.dialogs import CatchAllDialog, PathRuleDialog

    tunnel = Tunnel("t1", "bureau", "healthy")
    dialog = PathRuleDialog(None, tunnel, "app.exemple.fr")
    qtbot.addWidget(dialog)
    assert not dialog.ok_button.isEnabled()
    dialog.path.setText("api")
    dialog.service.setText("http://localhost:8080")
    assert not dialog.ok_button.isEnabled() and "commence par /" in dialog.error.text()
    dialog.path.setText("/api")
    assert dialog.ok_button.isEnabled() and dialog.value() == ("/api", "http://localhost:8080")
    dialog.service.setText("localhost:8080")
    assert not dialog.ok_button.isEnabled()

    final = CatchAllDialog(None, tunnel, "http_status:404")
    qtbot.addWidget(final)
    assert final.value() == "http_status:404" and final.service.isHidden()
    final.choice.setCurrentIndex(2)
    assert not final.ok_button.isEnabled()
    final.service.setText("http://localhost:9000")
    assert final.ok_button.isEnabled() and final.value() == "http://localhost:9000"
    custom = CatchAllDialog(None, tunnel, "http://localhost:1234")
    qtbot.addWidget(custom)
    assert custom.choice.currentIndex() == 2 and custom.value() == "http://localhost:1234"


def test_app_settings_from_the_apps_tab(qtbot, gui, cf, monkeypatch):
    from dataclasses import replace as replaced

    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    view = window.cloud
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.apps.rowCount() > 0, timeout=10000)
    assert not view.app_settings_button.isEnabled()
    view.apps.selectRow(0)
    assert view.app_settings_button.isEnabled()
    app = view._selected_app()
    shown: list[object] = []

    def answer(_parent, _app, settings):
        shown.append(settings)
        return replaced(settings, name="Renommée", session_duration="15m")

    monkeypatch.setattr(cloud_module, "ask_app_settings", answer)
    view.edit_app_settings()
    stored = next(a for a in cf.state.apps if a["id"] == app.id)
    qtbot.waitUntil(lambda: stored.get("name") == "Renommée", timeout=10000)
    assert stored["session_duration"] == "15m" and shown


def test_app_settings_dialog(qtbot):
    from cma.core.cfapi import AccessApp, AppSettings
    from cma.ui.views.cloud.dialogs import AppSettingsDialog, session_duration_label

    app = AccessApp("a", "Grafana", "grafana.exemple.fr", "self_hosted")
    dialog = AppSettingsDialog(None, app, AppSettings("Grafana", "0s", True, False, ("idp-1", "idp-2")))
    qtbot.addWidget(dialog)
    assert dialog.duration.currentText() == "Expire aussitôt"
    assert not dialog.redirect.isEnabled()  # deux fournisseurs : pas de redirection automatique
    dialog.duration.setCurrentIndex(dialog.duration.findData("168h"))
    dialog.launcher.setChecked(False)
    assert dialog.value() == AppSettings("Grafana", "168h", False, False, ("idp-1", "idp-2"))
    dialog.name.setText("  ")
    assert not dialog.ok_button.isEnabled()
    odd = AppSettingsDialog(None, app, AppSettings("X", "45m", True, False, ("idp-1",)))
    qtbot.addWidget(odd)
    assert odd.duration.currentData() == "45m" and odd.redirect.isEnabled()
    assert session_duration_label("730h") == "1 mois"


def test_access_log(qtbot, gui, cf, monkeypatch):
    from cma.core.cfapi import AccessApp, AccessRequest
    from cma.ui.views.cloud.access_log import AccessLogDialog, request_time, request_user

    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    view = window.cloud
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=10000)
    opened: list[tuple[int, object]] = []
    monkeypatch.setattr(
        cloud_module,
        "show_access_log",
        lambda _p, requests, _apps, selected, _names: opened.append((len(requests), selected)),
    )
    view.open_access_log()
    qtbot.waitUntil(lambda: bool(opened), timeout=10000)
    assert opened[0] == (2, None)

    # Sans la permission : l'erreur dit laquelle ajouter.
    cf.state.audit_allowed = False
    errors: list[str] = []
    monkeypatch.setattr(view.ctx, "notify", lambda level, text, **_k: errors.append(text))
    view.open_access_log()
    qtbot.waitUntil(lambda: any("Audit Logs" in e for e in errors), timeout=10000)

    # La boîte : filtre par application (identifiant, sinon nom d'hôte), refus comptés.
    requests = [
        AccessRequest("2026-10-08T09:12:00Z", "alice@exemple.fr", "ssh.exemple.fr", "uid-ssh", True, "login"),
        AccessRequest(
            "2026-10-08T09:10:00Z",
            "robot.access",
            "grafana.exemple.fr",
            "",
            False,
            "login",
            connection="nonidentity",
            app_name="Grafana",
        ),
    ]
    apps = [
        AccessApp("a1", "SSH", "ssh.exemple.fr", "self_hosted", uid="uid-ssh"),
        AccessApp("a2", "Grafana", "grafana.exemple.fr/", "self_hosted"),
    ]
    dialog = AccessLogDialog(None, requests, apps, token_names={"robot.access": "Robot"})
    qtbot.addWidget(dialog)
    assert dialog.table.rowCount() == 2 and dialog.summary.text() == "2 connexions · 1 refusée"
    dialog.app_filter.setCurrentIndex(dialog.app_filter.findData(apps[1]))
    assert [r.app_domain for r in dialog.shown()] == ["grafana.exemple.fr"]
    assert dialog.table.item(0, 1).text() == "Service token « Robot »"
    assert (
        dialog.table.item(0, 2).text() == "Grafana"
        and dialog.table.item(0, 2).toolTip() == "grafana.exemple.fr"
    )
    assert dialog.table.item(0, 3).text() == "Refusé"
    focused = AccessLogDialog(None, requests, apps, apps[0])
    qtbot.addWidget(focused)
    assert [r.user for r in focused.shown()] == ["alice@exemple.fr"]
    assert request_time("pas une date") == "pas une date" and request_time("") == "—"
    assert request_user(AccessRequest("", "", "", "", True, "")) == "—"
    assert (
        request_user(AccessRequest("", "x.access", "", "", True, "", connection="nonidentity")) == "x.access"
    )
    assert request_user(AccessRequest("", "", "", "", True, "", connection="nonidentity")) == "Service token"
