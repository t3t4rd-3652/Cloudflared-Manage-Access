"""Test d'accessibilité des boîtes de dialogue récentes : vérifier qu'elles sont utilisables au clavier et aux lecteurs d'écran."""

from __future__ import annotations

from cma.core.cfapi import IngressRule
from cma.core.changelog import Release
from cma.core.models import ServiceToken
from cma.ui.a11y import accessible_name, apply_accessible_names, missing_accessible_names
from cma.ui.dialogs.shortcuts import ShortcutsDialog
from cma.ui.dialogs.whatsnew import WhatsNewDialog
from cma.ui.views.cloud.dialogs import PublishDialog


def describe(widgets) -> list[str]:
    return [f"{type(w).__name__} dans {type(w.parent()).__name__}" for w in widgets]


def test_whats_new_dialog_accessibility(qtbot, gui):
    """« Quoi de neuf » : notes de version avec titres, texte et boutons."""
    ctx, window = gui
    releases = [
        Release("2.11.0", "2026-10-09", "## Nouvelles features\n\n- Dialogue accessible\n- Tests améliorés"),
        Release("2.10.0", "2026-10-08", "## Bilan de sécurité\n\n- Sécurité renforcée"),
    ]
    dialog = WhatsNewDialog(window, releases)
    dialog.show()
    apply_accessible_names(dialog)
    assert describe(missing_accessible_names(dialog)) == []
    assert dialog.windowTitle()
    # Vérifier que le titre du navigateur a un nom accessible.
    assert accessible_name(dialog.browser) == "Notes de version"
    dialog.deleteLater()


def test_shortcuts_dialog_accessibility(qtbot, gui):
    """Raccourcis clavier : tableau des raccourcis disponibles avec touches et descriptions."""
    ctx, window = gui
    pages = ["Accès Cloudflare", "SSH", "Cloudflare", "Paramètres", "Aide"]
    dialog = ShortcutsDialog(window, pages)
    dialog.show()
    apply_accessible_names(dialog)
    assert describe(missing_accessible_names(dialog)) == []
    assert dialog.windowTitle()
    assert accessible_name(dialog.table) == "Raccourcis clavier"
    dialog.deleteLater()


def test_publish_dialog_with_prefilled_values_accessibility(qtbot, gui):
    """Publication d'un service avec valeurs pré-remplies (hostname, service, note).

    Scénario : publication depuis un port découvert sur un serveur SSH, où le nom d'hôte,
    le service et une note explicative sont proposés."""
    from cma.core.cfadmin import Overview, TunnelView
    from cma.core.cfapi import Account, Tunnel, Zone

    ctx, window = gui
    token = ServiceToken(name="Prod", client_id="abc.access")
    ctx.update_config(lambda c: c.tokens.append(token))

    # Compte Cloudflare fictif pour la publication.
    tunnel = Tunnel("t1", "bureau", "healthy")
    overview = Overview(
        account=Account("acc", "Exemple SAS"),
        tunnels=[TunnelView(tunnel, [IngressRule("wiki.exemple.fr", "http://localhost:8080")])],
        zones=[Zone("z1", "exemple.fr")],
    )

    # Pré-remplissage depuis une découverte SSH.
    dialog = PublishDialog(
        window,
        overview,
        [token],
        tunnel=tunnel,
        hostname="wiki",
        service="http://localhost:8080",
        note="Découvert depuis le serveur SSH 'bureau' : port 8080.",
    )
    dialog.show()
    apply_accessible_names(dialog)
    assert describe(missing_accessible_names(dialog)) == []
    assert dialog.windowTitle()
    assert accessible_name(dialog.hostname) == "Nom d'hôte"
    assert accessible_name(dialog.service) == "Service"
    assert accessible_name(dialog.tunnel) == "Tunnel"
    assert accessible_name(dialog.zone) == "Domaine"
    dialog.deleteLater()


def test_publish_dialog_empty_overview_accessibility(qtbot, gui):
    """Publication d'un service quand aucun tunnel ou domaine n'est disponible.

    Scénario de dégradation : le compte n'a pas de tunnel configuré.
    La boîte doit rester accessible même si elle signale l'impossibilité."""
    from cma.core.cfadmin import Overview
    from cma.core.cfapi import Account

    ctx, window = gui
    token = ServiceToken(name="Prod", client_id="abc.access")
    ctx.update_config(lambda c: c.tokens.append(token))

    overview = Overview(account=Account("acc", "Exemple SAS"), tunnels=[], zones=[])
    dialog = PublishDialog(window, overview, [token])
    dialog.show()
    apply_accessible_names(dialog)
    assert describe(missing_accessible_names(dialog)) == []
    assert dialog.windowTitle()
    dialog.deleteLater()


def test_whats_new_dialog_language_variants(qtbot, gui):
    """Tester « Quoi de neuf » avec des variantes de langue (en, de, es)."""
    ctx, window = gui
    releases = [Release("2.11.0", "2026-10-09", "Nouvelles fonctionnalités.")]

    for lang in ["en", "de", "es"]:
        dialog = WhatsNewDialog(window, releases, language=lang)
        dialog.show()
        apply_accessible_names(dialog)
        assert describe(missing_accessible_names(dialog)) == [], f"Langue {lang}"
        dialog.deleteLater()
