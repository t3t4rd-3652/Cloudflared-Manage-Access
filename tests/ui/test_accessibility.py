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


def test_dialogs_have_no_unnamed_control(qtbot, gui):
    ctx, window = gui
    dialogs = [
        misc.KnownHostsDialog(window, ctx),
        misc.KeysDialog(window, ctx),
        RedirectDialog(window, ctx),
        transfer.ExportDialog(window, ctx),
        OnboardingWizard(window, ctx, None),
    ]
    for dialog in dialogs:
        apply_accessible_names(dialog)
        assert describe(missing_accessible_names(dialog)) == [], type(dialog).__name__
        dialog.deleteLater()
