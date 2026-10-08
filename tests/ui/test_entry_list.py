"""Listes en cartes et en-têtes d'objet des vues Accès Cloudflare, Service tokens et Serveurs SSH."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QMouseEvent, QPixmap
from PySide6.QtWidgets import QPushButton

from cma.core.models import AuthMode, CloudflareProfile, ServiceToken, ServiceType, SshProfile
from cma.ui.views.common import ENTRY_ROLE, ListEntry, ObjectHeader, ProfileList
from tests.ui.test_views import fake_info


def entries_in(tree) -> list[str]:
    """Textes des lignes dans l'ordre d'affichage (intertitres compris)."""
    found = []
    for i in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(i)
        found.append(item.text(0))
        found.extend(item.child(j).text(0) for j in range(item.childCount()))
    return found


def test_loose_entries_first_and_collapsed_groups_stay_collapsed(qtbot):
    view = ProfileList("Rechercher", [], name="Liste")
    qtbot.addWidget(view)
    view.resize(320, 500)
    view.show()
    view.set_entries(
        [
            ListEntry("1", "Zeta", "Prod"),
            ListEntry("2", "Alpha", "Prod", favorite=True),
            ListEntry("3", "Sans groupe"),
            ListEntry("4", "Labo 1", "Labo", tone="success", status_text="À l'écoute", icon="database"),
        ]
    )
    # Les objets sans groupe viennent avant les intertitres : sinon ils sembleraient appartenir au dernier groupe.
    assert entries_in(view.tree) == ["Sans groupe", "Prod (2)", "★ Alpha", "Zeta", "Labo (1)", "Labo 1"]
    prod = view.tree.topLevelItem(1)
    rect = view.tree.visualItemRect(prod)
    press = QMouseEvent(
        QMouseEvent.Type.MouseButtonPress,
        rect.center().toPointF(),
        rect.center().toPointF(),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    view.tree.mousePressEvent(press)
    assert not prod.isExpanded()
    # Une mise à jour (état d'une session) garde le groupe replié ; une recherche le rouvre.
    view.set_entries(list(view._entries))
    assert not view.tree.topLevelItem(1).isExpanded()
    view.search.setText("zeta")
    assert view.tree.topLevelItem(0).isExpanded()
    view.search.clear()
    # Le rendu des cartes ne lève rien, quelle que soit la ligne (intertitre, objet sélectionné, vide).
    view.select("4")
    assert view.current_id() == "4"
    assert isinstance(view.tree.currentItem().data(0, ENTRY_ROLE), ListEntry)
    pixmap = QPixmap(view.tree.viewport().size())
    view.tree.viewport().render(pixmap, QPoint())
    view.search.setText("aucun objet ne correspond")
    assert entries_in(view.tree) == ["Aucun résultat pour cette recherche."]
    view.tree.viewport().render(pixmap, QPoint())


def test_header_puts_actions_below_when_narrow(qtbot):
    header = ObjectHeader("server")
    qtbot.addWidget(header)
    header.title.setText("Un serveur au nom assez long")
    header.subtitle.setText("administrateur@serveur.exemple.fr:22")
    buttons = [QPushButton(text) for text in ("Tester", "Connexion Access", "Déconnecter")]
    for widget in buttons:
        header.add_action(widget)
    header.show()
    # Les seuils sont calculés, pas écrits en dur : ils dépendent des polices et du style de l'application.
    three = header.needed_width()
    header.resize(three + 40, 140)
    qtbot.waitUntil(lambda: header._stacked is False)
    header.resize(three - 40, 160)
    qtbot.waitUntil(lambda: header._stacked is True)
    # Moins de boutons visibles : la place revient à droite du texte, dès le changement d'état suivant.
    buttons[1].hide()
    buttons[2].hide()
    one = header.needed_width()
    assert one < three - 40
    header.set_tone("info")
    assert header._stacked is False
    header.set_tone("success")
    assert header.tile.property("status") == "success"
    header.set_tone(None)
    assert header.tile.property("status") == "idle"


def test_views_fill_cards_and_headers(qtbot, gui):
    ctx, window = gui
    soon = ServiceToken(
        name="Labo", client_id="labo.access", expires_at=datetime.now(UTC) + timedelta(days=5)
    )
    later = ServiceToken(
        name="Prod", client_id="prod.access", expires_at=datetime.now(UTC) + timedelta(days=200)
    )
    profile = CloudflareProfile(
        name="Base",
        group="Prod",
        hostname="db.exemple.fr",
        local_port=31555,
        service_type=ServiceType.MONGODB,
        auth=AuthMode.SERVICE_TOKEN,
        token_id=later.id,
    )
    via = SshProfile(name="Bastion", user="admin", via_cloudflare_profile=profile.id)
    ctx.update_config(
        lambda c: (
            c.tokens.extend([soon, later]),
            c.cloudflare_profiles.append(profile),
            c.ssh_profiles.append(via),
        )
    )

    # Accès Cloudflare : pictogramme du service, nom public → adresse locale, contexte lisible.
    window.show_view("profiles")
    window.profiles.select_profile(profile.id)
    editor = window.profiles.editor
    assert editor.header.subtitle.text() == "db.exemple.fr  →  127.0.0.1:31555"
    assert editor.header.context.text() == "MongoDB · Service token : Prod · Groupe : Prod"
    assert editor.header.tile.property("status") == "idle"
    session = fake_info(profile_id=profile.id, name="Base", local_port=31555)
    window.profiles._on_session(session)
    assert editor.header.tile.property("status") == "success"
    entry = window.profiles.list.tree.topLevelItem(0).child(0).data(0, ENTRY_ROLE)
    assert (entry.icon, entry.tone, entry.status_text) == ("database", "success", "À l'écoute")

    # Service tokens : l'échéance proche teinte la ligne et l'en-tête.
    window.show_view("tokens")
    window.tokens.list.select(soon.id)
    tokens_editor = window.tokens.editor
    assert tokens_editor.header.subtitle.text() == "labo.access"
    assert tokens_editor.header.tile.property("status") == "warning"
    assert tokens_editor.header.pill.text().startswith("! Expire le")
    assert tokens_editor.header.context.text() == "Aucun profil n'utilise ce token."
    rows = {
        item.data(0, ENTRY_ROLE).name: item.data(0, ENTRY_ROLE)
        for item in (window.tokens.list.tree.topLevelItem(i) for i in range(2))
    }
    assert rows["Labo"].tone == "warning" and rows["Prod"].tone is None
    window.tokens.list.select(later.id)
    assert tokens_editor.header.context.text() == "Utilisé par 1 profil"
    assert tokens_editor.header.pill.text().startswith("✓ Expire le")

    # Serveurs SSH : un serveur joint par Cloudflare montre le nom public et le pictogramme du nuage.
    window.show_view("ssh")
    ssh_entry = window.ssh.list.tree.topLevelItem(0).data(0, ENTRY_ROLE)
    assert (ssh_entry.icon, ssh_entry.detail) == ("cloud", "admin@db.exemple.fr")
    window.ssh.list.select(via.id)
    assert window.ssh.panel.route.text() == "Via Cloudflare : Base"
