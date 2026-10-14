"""Test d'accessibilité des boîtes de dialogue récentes : vérifier qu'elles sont utilisables au clavier et aux lecteurs d'écran."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QWidget

from cma.core.availability import AvailabilityLog
from cma.core.cfapi import IngressRule
from cma.core.changelog import Release
from cma.core.models import ServiceToken
from cma.core.security import Finding
from cma.ui.a11y import accessible_name, apply_accessible_names, missing_accessible_names
from cma.ui.dialogs.shortcuts import ShortcutsDialog
from cma.ui.dialogs.whatsnew import WhatsNewDialog
from cma.ui.views.cloud.availability import AvailabilityDialog
from cma.ui.views.cloud.dialogs import PublishDialog
from cma.ui.views.cloud.security_review import SecurityReviewDialog


def describe(widgets) -> list[str]:
    return [f"{type(w).__name__} dans {type(w.parent()).__name__}" for w in widgets]


def verify_tab_order(dialog: QWidget, min_controls: int = 2) -> None:
    """Vérifier que la tabulation parcourt au moins min_controls distincts sans sortir de la boîte.

    - Donne le focus au premier contrôle interactif
    - Appelle focusNextChild() jusqu'à max_steps fois
    - Vérifie que le focus a visité au moins min_controls distincts
    - Vérifie que le focus ne sort jamais de la boîte (reste sur les enfants)
    """
    dialog.setFocus()
    dialog.show()
    QApplication.processEvents()

    # Trouver le premier contrôle interactif
    initial_widget = None
    for child in dialog.findChildren(QWidget):
        if child.focusPolicy() != Qt.FocusPolicy.NoFocus and child.isVisible():
            child.setFocus()
            initial_widget = child
            QApplication.processEvents()
            break

    if initial_widget is None:
        # Pas de contrôle interactif trouvé, c'est acceptable pour certaines boîtes
        return

    visited_widgets = set()
    current = QApplication.focusWidget()
    if current is not None and current != dialog:
        visited_widgets.add(id(current))

    max_steps = 30  # Assez pour parcourir tous les contrôles + redondance
    for _ in range(max_steps):
        # Appeler focusNextChild pour passer au suivant
        dialog.focusNextChild()
        QApplication.processEvents()

        current = QApplication.focusWidget()
        if current is None:
            break

        # Vérifier que le focus ne sort pas de la boîte
        if not (current == dialog or current in dialog.findChildren(QWidget)):
            raise AssertionError(f"Focus sorti de la boîte : {type(current).__name__}")

        visited_widgets.add(id(current))

        # Si on est revenu au premier widget, on a fait une boucle complète
        if current == initial_widget and len(visited_widgets) > 1:
            break

    # Vérifier qu'on a visité au moins min_controls distincts
    if len(visited_widgets) < min_controls:
        raise AssertionError(
            f"Tabulation insuffisante : {len(visited_widgets)} contrôles visités, minimum {min_controls} attendus"
        )


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
    assert accessible_name(dialog.browser) == "Notes de version"
    verify_tab_order(dialog, min_controls=2)
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
    verify_tab_order(dialog, min_controls=2)
    dialog.deleteLater()


def test_security_review_dialog_accessibility(qtbot, gui):
    """Bilan de sécurité du compte : constats de sécurité avec corrections possibles."""
    ctx, window = gui
    # Façade inerte pour éviter les appels d'API
    admin = SimpleNamespace(security_review=lambda: None)
    quiet_ctx = SimpleNamespace(
        run=lambda *_a, **_k: None,
        notify=lambda *_a, **_k: None,
        paths=ctx.paths,
        config=ctx.config,
        update_config=ctx.update_config,
        core=ctx.core,
    )

    dialog = SecurityReviewDialog(window, quiet_ctx, admin)  # type: ignore[arg-type]
    # Montrer quelques constats sans appeler l'API
    dialog.show_findings(
        [
            Finding("unprotected", "high", "wiki.exemple.fr", "wiki.exemple.fr", "protect", ("t1", "")),
            Finding("dangling_dns", "medium", "ancien.exemple.fr", "d1", "delete_dns", ("z1",)),
            Finding("inactive_tunnel", "low", "ancien-nas", "t9"),  # Pas de correction possible
        ]
    )
    apply_accessible_names(dialog)
    assert describe(missing_accessible_names(dialog)) == []
    assert dialog.windowTitle()
    verify_tab_order(dialog, min_controls=2)
    dialog.deleteLater()


def test_availability_dialog_accessibility(qtbot, gui, tmp_path):
    """Disponibilité des tunnels et des services sur 90 jours avec graphique et incidents."""
    ctx, window = gui

    # Créer un journal de disponibilité fictif
    log = AvailabilityLog(tmp_path / "availability.json")
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)

    # Quelques objets avec des incidents
    objects = (
        ("service:wiki.exemple.fr", "wiki.exemple.fr", "service", 160, {(1, 9), (1, 10)}),
        ("tunnel:t1", "bureau", "tunnel", 0, {(1, 8), (1, 9)}),
    )

    for key, name, kind, base_ms, outages in objects:
        down_since = None
        for hours in range(7 * 24, -1, -1):  # 7 jours pour la démo
            at = now - timedelta(hours=hours)
            day, hour = divmod(hours, 24)
            ok = (day, hour) not in outages
            ms = float(base_ms + (hours * 37) % 90) if base_ms and ok else None
            log.record_check(key, name, ok, ms, at)
            if not ok and down_since is None:
                down_since = at
                log.start(kind, key, name, "origin_down" if kind == "service" else "down", at)
            if ok and down_since is not None:
                log.end(kind, key, at)
                down_since = None

    log.save()

    dialog = AvailabilityDialog(window, tmp_path / "availability.json")
    dialog.show()
    # Sélectionner une ligne pour afficher les incidents
    if dialog.keys:
        dialog.table.selectRow(0)
    apply_accessible_names(dialog)
    assert describe(missing_accessible_names(dialog)) == []
    assert dialog.windowTitle()
    verify_tab_order(dialog, min_controls=2)
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
    verify_tab_order(dialog, min_controls=2)
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
    verify_tab_order(dialog, min_controls=2)
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
        verify_tab_order(dialog, min_controls=2)
        dialog.deleteLater()
