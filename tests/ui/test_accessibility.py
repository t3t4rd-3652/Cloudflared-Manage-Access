"""Chaque contrôle atteignable au clavier doit avoir un nom pour les lecteurs d'écran (NVDA, Narrateur)."""

from __future__ import annotations

from cma.core.models import CloudflareProfile, ServiceToken, SshProfile
from cma.ui.a11y import accessible_name, apply_accessible_names, missing_accessible_names
from cma.ui.dialogs import misc, transfer
from cma.ui.dialogs.onboarding import OnboardingWizard
from cma.ui.dialogs.redirect import RedirectDialog


def describe(widgets) -> list[str]:
    return [f"{type(w).__name__} dans {type(w.parent()).__name__}" for w in widgets]


def test_main_window_has_no_unnamed_control(qtbot, gui):
    ctx, window = gui
    token = ServiceToken(name="Prod", client_id="abc.access")
    ctx.update_config(
        lambda c: (
            c.tokens.append(token),
            c.cloudflare_profiles.append(
                CloudflareProfile(name="A", group="G", hostname="a.fr", local_port=31000)
            ),
            c.ssh_profiles.append(SshProfile(name="S", host="h", user="u")),
        )
    )
    config = ctx.config()
    window.profiles.select_profile(config.cloudflare_profiles[0].id)
    window.ssh.list.select(config.ssh_profiles[0].id)
    window.tokens.list.select(token.id)
    assert describe(missing_accessible_names(window)) == []
    # Les champs enveloppés (message d'erreur sous le champ) reprennent le libellé de leur ligne.
    assert accessible_name(window.profiles.editor.hostname) == "Nom d'hôte"
    assert accessible_name(window.profiles.list.tree) == "Profils Cloudflare"


def test_dialogs_have_no_unnamed_control(qtbot, gui, tmp_path):
    from cma.core.cfadmin import NewTunnel, Overview, TunnelView
    from cma.core.cfapi import AccessApp, Account, Connector, EdgeConnection, IngressRule, Tunnel, Zone
    from cma.core.policies import AccessGroup, AccessPolicy, PolicyRule
    from cma.core.transfer import build_export, plan_import
    from cma.ui.views import cloud
    from cma.ui.views.cloud.policies import PoliciesDialog, PolicyEditDialog
    from cma.ui.views.cloud.tunnel_create import CreateTunnelDialog, NewTunnelDialog

    ctx, window = gui
    token = ServiceToken(name="Prod", client_id="abc.access")
    ctx.update_config(lambda c: c.tokens.append(token))
    plan = plan_import(build_export(ctx.config(), ctx.core.secrets), ctx.config())
    tunnel = Tunnel("t1", "bureau", "healthy")
    overview = Overview(
        Account("a1", "Compte"),
        tunnels=[TunnelView(tunnel, [IngressRule("a.exemple.fr", "tcp://localhost:22")])],
        zones=[Zone("z1", "exemple.fr")],
    )
    app = AccessApp("app1", "A", "a.exemple.fr", "self_hosted")
    dialogs = [
        misc.KnownHostsDialog(window, ctx),
        misc.KeysDialog(window, ctx),
        RedirectDialog(window, ctx),
        transfer.ExportDialog(window, ctx),
        OnboardingWizard(window, ctx, None),
        misc.GenerateKeyDialog(window),
        misc.SecretStoreDialog(window, tmp_path / "coffre.json"),
        misc.SecretStoreDialog(window, tmp_path / "coffre.json", portable=True),
        transfer.ImportDialog(window, plan, tmp_path / "export.json", {}),
        cloud.PublishDialog(window, overview, [token]),
        cloud.ProtectDialog(window, ["a.exemple.fr"]),
        cloud.AllowDialog(window, app, [token]),
        cloud.CreateTokenDialog(window, "Compte", persistent=True),
        cloud.EditServiceDialog(window, tunnel, IngressRule("a.exemple.fr", "tcp://localhost:22")),
        PolicyEditDialog(window, None, [AccessGroup("g1", "Admins")], {"Robot": "tok1"}),
        PoliciesDialog(
            window,
            app,
            [AccessPolicy("p1", "Équipe", "allow", (PolicyRule("email_domain", "exemple.fr"),))],
            [],
            {},
            save=lambda *_a: None,
            delete=lambda *_a: None,
        ),
        CreateTunnelDialog(window, ["bureau"]),
        NewTunnelDialog(window, NewTunnel(tunnel, "jeton-de-connecteur-assez-long")),
        cloud.ConnectorsDialog(
            window,
            tunnel,
            [Connector("c1", "2026.9.0", "linux_amd64", "", (EdgeConnection("cdg01", "203.0.113.10", ""),))],
        ),
    ]
    for dialog in dialogs:
        apply_accessible_names(dialog)
        assert describe(missing_accessible_names(dialog)) == [], type(dialog).__name__
        dialog.deleteLater()
