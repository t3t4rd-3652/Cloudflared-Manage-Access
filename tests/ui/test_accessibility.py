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
    from cma.ui.dialogs.history import HistoryDialog
    from cma.ui.views import cloud
    from cma.ui.views.cloud.policies import (
        AccountPoliciesDialog,
        ChoosePolicyDialog,
        PoliciesDialog,
        PolicyEditDialog,
    )
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
            [],
            save=lambda *_a: None,
            remove=lambda *_a: None,
            attach=lambda *_a: None,
        ),
        AccountPoliciesDialog(window, [], [], {}, save=lambda *_a: None, delete=lambda *_a: None),
        ChoosePolicyDialog(
            window, [AccessPolicy("p1", "Équipe", "allow", reusable=True, app_count=2)], [], {}
        ),
        CreateTunnelDialog(window, ["bureau"]),
        HistoryDialog(window, ctx),
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


def test_recent_dialogs_have_no_unnamed_control(qtbot, gui, tmp_path):
    """Boîtes ajoutées depuis la 2.9 : notifications, tests depuis Internet, réseaux privés, outils du compte,
    bilan de sécurité, disponibilité, alertes, partage, import de ~/.ssh/config."""
    from types import SimpleNamespace

    from cma.core.audit import AuditEntry
    from cma.core.cfapi import Account, Tunnel
    from cma.core.hostprobe import HostProbe
    from cma.core.servicewatch import ServiceTarget
    from cma.ui.dialogs.links import ShareDialog
    from cma.ui.dialogs.notifications import NotificationsDialog
    from cma.ui.views.cloud.audit_log import AuditLogDialog
    from cma.ui.views.cloud.availability import AvailabilityDialog
    from cma.ui.views.cloud.permissions import PermissionsDialog
    from cma.ui.views.cloud.private_network import PrivateNetworkDialog
    from cma.ui.views.cloud.security_review import SecurityReviewDialog
    from cma.ui.views.cloud.services import ServiceTestsDialog
    from cma.ui.views.cloud.snapshots import SnapshotsDialog
    from cma.ui.views.settings_alerts import ChannelDialog
    from cma.ui.views.ssh.import_config import SshConfigImportDialog

    ctx, window = gui
    profile = CloudflareProfile(name="NAS", hostname="nas.exemple.fr", local_port=24445)
    ctx.update_config(lambda c: c.cloudflare_profiles.append(profile))
    # Façades inertes : les boîtes qui lisent le compte à l'ouverture n'appellent rien.
    admin = SimpleNamespace(
        private_network=lambda _t: None,
        snapshot=lambda _a: None,
        permissions=lambda: None,
        security_review=lambda: None,
    )
    quiet = SimpleNamespace(
        run=lambda *_a, **_k: None,
        notify=lambda *_a, **_k: None,
        paths=ctx.paths,
        config=ctx.config,
        update_config=ctx.update_config,
        core=ctx.core,
    )
    target = ServiceTarget("wiki.exemple.fr", "", "http://localhost:8080", "t1", "bureau")
    (tmp_path / "config").write_text("Host nas\n  HostName 192.168.1.2\n", encoding="utf-8")
    dialogs = [
        NotificationsDialog(window, window.notices),
        ServiceTestsDialog(window, [(target, HostProbe("origin_down", 502))]),
        PrivateNetworkDialog(window, quiet, admin, Tunnel("t1", "bureau", "healthy")),  # type: ignore[arg-type]
        AuditLogDialog(
            window,
            [
                AuditEntry(
                    "2026-10-09T08:00:00Z",
                    "x",
                    "update",
                    "success",
                    "dns",
                    "record",
                    "r1",
                    "a@x.fr",
                    "user",
                    "dash",
                )
            ],
        ),
        SnapshotsDialog(window, quiet, admin, Account("acc", "Compte")),  # type: ignore[arg-type]
        PermissionsDialog(window, quiet, admin),  # type: ignore[arg-type]
        SecurityReviewDialog(window, quiet, admin),  # type: ignore[arg-type]
        AvailabilityDialog(window, tmp_path / "availability.json"),
        ShareDialog(window, ctx, profile),
        ChannelDialog(window),
        SshConfigImportDialog(window, ctx, tmp_path / "config"),
    ]
    for dialog in dialogs:
        apply_accessible_names(dialog)
        assert describe(missing_accessible_names(dialog)) == [], type(dialog).__name__
        dialog.deleteLater()
