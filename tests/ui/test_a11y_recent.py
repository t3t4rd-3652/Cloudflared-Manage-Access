"""Test d'accessibilité des boîtes de dialogue récentes : vérifier qu'elles sont utilisables au clavier et aux lecteurs d'écran."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QAbstractButton, QApplication, QWidget

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


def _focusable(dialog: QWidget) -> list[QWidget]:
    """Contrôles que le clavier doit pouvoir atteindre : visibles, activés et acceptant le focus."""
    return [
        w
        for w in dialog.findChildren(QWidget)
        if w.focusPolicy() != Qt.FocusPolicy.NoFocus and w.isVisible() and w.isEnabled()
    ]


def verify_tab_order(dialog: QWidget, min_controls: int = 2) -> None:
    """Vérifier, avec de vrais appuis sur Tab puis Maj+Tab, que le clavier atteint tous les boutons de la boîte.

    - Le focus part du premier contrôle ; on appuie sur la touche au plus « contrôles + 2 » fois ;
    - le focus ne sort jamais de la boîte ;
    - chaque bouton visible et activé reçoit le focus (un tableau qui garde Tab pour passer de case en case
      empêcherait d'atteindre les boutons qui le suivent) ;
    - même exigence avec Maj+Tab.

    `focusNextChild()` ne convient pas : il ne passe pas par la gestion de Tab du widget qui a le focus.
    """
    dialog.show()
    QApplication.processEvents()
    controls = _focusable(dialog)
    if not controls:
        return  # pas de contrôle interactif : acceptable pour certaines boîtes
    buttons = [w for w in controls if isinstance(w, QAbstractButton)]
    inside = set(dialog.findChildren(QWidget))

    for label, key, modifier in (
        ("Tab", Qt.Key.Key_Tab, Qt.KeyboardModifier.NoModifier),
        ("Maj+Tab", Qt.Key.Key_Backtab, Qt.KeyboardModifier.ShiftModifier),
    ):
        controls[0].setFocus()
        QApplication.processEvents()
        visited: set[QWidget] = set()
        current = QApplication.focusWidget()
        if current is not None:
            visited.add(current)
        for _ in range(len(controls) + 2):
            current = QApplication.focusWidget()
            assert current is not None, f"{label} : le focus a été perdu"
            QTest.keyClick(current, key, modifier)
            QApplication.processEvents()
            current = QApplication.focusWidget()
            assert current is not None, f"{label} : le focus a été perdu"
            assert current in inside, f"{label} : focus sorti de la boîte ({type(current).__name__})"
            visited.add(current)
        assert len(visited) >= min_controls, (
            f"{label} : {len(visited)} contrôles visités, {min_controls} attendus"
        )
        missed = [b.text() or type(b).__name__ for b in buttons if b not in visited]
        assert missed == [], f"{label} n'atteint pas les boutons {missed}"


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


def test_recent_sends_dialog_accessibility(qtbot, gui, tmp_path):
    """Envois récents : tableau du journal des envois d'alertes, effacement et fermeture au clavier."""
    from cma.core.alertlog import AlertLog
    from cma.ui.dialogs.sends import SendsDialog

    ctx, window = gui
    journal = AlertLog(tmp_path / "alert_log.json")
    journal.note(channel="Téléphone", kind="ntfy", nature="alert", subject="bureau")
    journal.note(channel="Équipe", kind="slack", nature="digest", error="Le canal a refusé l'alerte (403).")

    dialog = SendsDialog(window, journal)
    dialog.show()
    apply_accessible_names(dialog)
    assert describe(missing_accessible_names(dialog)) == []
    assert dialog.windowTitle()
    assert accessible_name(dialog.table) == "Envois récents"
    assert not dialog.table.tabKeyNavigation()  # Tab quitte le tableau au lieu de passer de case en case
    verify_tab_order(dialog, min_controls=2)
    dialog.deleteLater()

    # Journal vide : seuls les boutons restent, et le clavier atteint « Fermer ».
    empty = SendsDialog(window, AlertLog(tmp_path / "vide.json"))
    empty.show()
    apply_accessible_names(empty)
    assert describe(missing_accessible_names(empty)) == []
    verify_tab_order(empty, min_controls=1)
    empty.deleteLater()


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
    # Listes non modifiables : sous Linux et macOS, Qt annonce le texte affiché ; le nom posé est vérifié tel quel.
    assert dialog.tunnel.accessibleName() == "Tunnel" and accessible_name(dialog.tunnel)
    assert dialog.zone.accessibleName() == "Domaine" and accessible_name(dialog.zone)
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

    from cma.i18n import get_language, set_language

    previous = get_language()
    try:
        for lang in ["en", "de", "es"]:
            set_language(lang)  # l'interface elle-même change de langue, pas seulement la note de la boîte
            dialog = WhatsNewDialog(window, releases, language=lang)
            dialog.show()
            assert dialog.windowTitle() != "Quoi de neuf dans CMA", f"Langue {lang} : titre non traduit"
            apply_accessible_names(dialog)
            assert describe(missing_accessible_names(dialog)) == [], f"Langue {lang}"
            verify_tab_order(dialog, min_controls=2)
            dialog.deleteLater()
    finally:
        set_language(previous)


def test_alert_dialogs_accessibility(qtbot, gui):
    """Boîtes des canaux d'alerte et des maintenances : noms accessibles et vraie tabulation."""
    from cma.ui.views.settings_alerts import ChannelDialog, MaintenanceDialog

    _ctx, window = gui
    for dialog in (ChannelDialog(window), MaintenanceDialog(window, [("tunnel:t1", "Tunnel « bureau »")])):
        dialog.show()
        apply_accessible_names(dialog)
        assert dialog.windowTitle()
        assert describe(missing_accessible_names(dialog)) == []
        verify_tab_order(dialog, min_controls=2)
        dialog.deleteLater()
