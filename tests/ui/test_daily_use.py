"""Usage quotidien (P11) : liens cma://, partage d'un profil, objets Cloudflare dans la palette, plusieurs jetons
d'API."""

from __future__ import annotations

import pytest

import cma.ui.dialogs.links as links_dialogs
import cma.ui.main_window as main_module
from cma.core.cfadmin import LEGACY_TOKEN_ID, token_secret_key
from cma.core.cfapi import TOKEN_SECRET_KEY
from cma.core.links import connect_link, share_file_text, share_link
from cma.core.models import AuthMode, CloudflareProfile, ServiceToken
from cma.ui.dialogs.links import ShareDialog
from cma.ui.views.cloud.cards import RULE_ROLE
from tests.fakes.fake_cfapi import TOKEN, FakeCloudflare, FakeCloudflareServer

OTHER_TOKEN = "jeton-api-du-client-x-assez-long"


@pytest.fixture
def cf():
    with FakeCloudflareServer(FakeCloudflare(other_tokens=(OTHER_TOKEN,))) as server:
        yield server


def add_profile(ctx, **fields) -> CloudflareProfile:
    profile = CloudflareProfile(name="NAS", hostname="nas.exemple.fr", local_port=24445, **fields)
    ctx.update_config(lambda c: c.cloudflare_profiles.append(profile))
    return profile


def test_connect_link_asks_once_then_trusts(qtbot, gui, monkeypatch):
    ctx, window = gui
    notes: list[tuple[str, str]] = []
    window.banners.show_message = lambda level, text, **_k: notes.append((level, text))  # type: ignore[method-assign]
    profile = add_profile(ctx)
    asked: list[str] = []
    answers = [(False, False), (True, True)]
    monkeypatch.setattr(main_module, "ask_link_connect", lambda _w, p: asked.append(p.name) or answers.pop(0))
    sent: list[dict[str, object]] = []

    async def execute(_manager, message):
        sent.append(message)
        return {"ok": False, "error": "port occupé"}

    monkeypatch.setattr(main_module, "execute", execute)
    window.handle_link(connect_link("nas"))
    assert asked == ["NAS"] and sent == []  # refusé : rien n'est lancé
    window.handle_link(connect_link("NAS"))
    qtbot.waitUntil(lambda: sent != [], timeout=5000)
    assert sent == [{"cmd": "connect", "profile": profile.id}]
    assert ctx.config().cloudflare_profile(profile.id).link_trusted
    qtbot.waitUntil(lambda: ("error", "port occupé") in notes, timeout=5000)
    # Profil marqué sûr : plus de question.
    window.handle_link(connect_link("NAS"))
    qtbot.waitUntil(lambda: len(sent) == 2, timeout=5000)
    assert asked == ["NAS", "NAS"]
    # Profil inconnu, lien invalide : une erreur claire.
    window.handle_link(connect_link("Inconnu"))
    window.handle_link("cma://effacer/tout")
    assert notes[-2][1] == "Lien CMA : aucun profil « Inconnu »." and "Action inconnue" in notes[-1][1]


def test_import_from_link_and_file(qtbot, gui, monkeypatch, tmp_path):
    ctx, window = gui
    notes: list[tuple[str, str]] = []
    window.banners.show_message = lambda level, text, **_k: notes.append((level, text))  # type: ignore[method-assign]
    token = ServiceToken(name="Robot", client_id="robot.access")
    source_config = ctx.config().model_copy(update={"tokens": [token]})
    shared = CloudflareProfile(
        name="Grafana", hostname="grafana.exemple.fr", auth=AuthMode.SERVICE_TOKEN, token_id=token.id
    )
    previews: list[str] = []
    monkeypatch.setattr(
        main_module, "ask_import_shared", lambda _w, s: previews.append(s.profile.name) or True
    )
    window.handle_link(share_link(shared, source_config))
    profiles = ctx.config().cloudflare_profiles
    assert previews == ["Grafana"] and [p.name for p in profiles] == ["Grafana"]
    assert notes[-1][0] == "warning" and "Client ID robot.access" in notes[-1][1]
    assert window.stack.currentWidget() is window.profiles
    # Fichier .cma (double-clic) : même chemin, nom rendu unique.
    path = tmp_path / "grafana.cma"
    path.write_text(share_file_text(shared, source_config), encoding="utf-8")
    window.handle_link(str(path))
    assert [p.name for p in ctx.config().cloudflare_profiles] == ["Grafana", "Grafana (2)"]
    window.handle_link(str(tmp_path / "absent.cma"))
    assert notes[-1][0] == "error"


def test_share_dialog(qtbot, gui, monkeypatch, tmp_path):
    ctx, window = gui
    profile = add_profile(ctx)
    monkeypatch.setattr(links_dialogs.platform_links, "is_registered", lambda: True)
    dialog = ShareDialog(window, ctx, profile)
    qtbot.addWidget(dialog)
    assert dialog.connect_field.text() == "cma://connect/NAS"
    assert dialog.share_field.text().startswith("cma://import?p=")
    target = tmp_path / "NAS.cma"
    monkeypatch.setattr(links_dialogs, "ask_share_path", lambda _p, _n: target)
    dialog.save_file()
    assert '"hostname": "nas.exemple.fr"' in target.read_text(encoding="utf-8")
    assert dialog.status.text() == "Profil enregistré : NAS.cma"
    # Le menu d'un profil propose le partage.
    actions = [text for _icon, text, _run in window.profiles._item_actions(profile.id)]
    assert "Partager…" in actions


def test_palette_finds_cloudflare_objects(qtbot, gui, cf):
    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    view = window.cloud
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=10000)
    window.show_view("dashboard")
    entries = {e.text: e for e in window.palette_entries() if e.section == "Compte Cloudflare"}
    assert {"Tunnel « bureau »", "grafana.exemple.fr", "Application Access « SSH »"} <= set(entries)
    entries["grafana.exemple.fr"].run()
    assert window.stack.currentWidget() is window.cloud and view.tabs.currentIndex() == 0
    assert view.tree.currentItem().data(0, RULE_ROLE).hostname == "grafana.exemple.fr"
    entries["Application Access « SSH »"].run()
    assert view.tabs.currentIndex() == 1 and view.apps_tab.selected_app().name == "SSH"


async def test_named_tokens(cf, store, secrets):
    from cma.core.cfadmin import CloudflareAdmin

    admin = CloudflareAdmin(store, secrets, lambda _p, _a: None, base_url=cf.base_url)
    assert admin.tokens() == [] and not admin.has_token()
    await admin.connect(TOKEN)
    # Premier jeton : rangé sous l'ancienne clé, comme avant les jetons nommés.
    assert secrets.get(TOKEN_SECRET_KEY) == TOKEN and admin.active_token().id == LEGACY_TOKEN_ID
    assert [t.name for t in admin.tokens()] == ["Mon compte"]
    admin.select_account("acc1")
    await admin.connect(OTHER_TOKEN, "Client X")
    tokens = admin.tokens()
    assert [t.name for t in tokens] == ["Mon compte", "Client X"] and admin.active_token().name == "Client X"
    assert secrets.get(token_secret_key(tokens[1].id)) == OTHER_TOKEN
    assert admin.api()._token == OTHER_TOKEN
    admin.switch_token(LEGACY_TOKEN_ID)
    assert store.snapshot().settings.cloudflare_account_id == "acc1" and admin.api()._token == TOKEN
    admin.forget()
    assert (
        secrets.get(TOKEN_SECRET_KEY) is None
        and admin.active_token().name == "Client X"
        and admin.has_token()
    )
    admin.forget()
    assert admin.tokens() == [] and not admin.has_token()


def test_token_switcher_in_the_view(qtbot, gui, cf):
    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    view = window.cloud
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=10000)
    assert [view.token_choice.itemText(i) for i in range(view.token_choice.count())] == [
        "Mon compte",
        "Ajouter un jeton…",
    ]
    # « Ajouter un jeton… » : page de connexion, avec retour possible.
    view.token_choice.setCurrentIndex(1)
    view._token_chosen(1)
    assert view.stack.currentIndex() == 0 and view.cancel_add.isVisibleTo(view)
    view.cancel_add.click()
    assert view.stack.currentIndex() == 1
    view._token_chosen(1)
    view.token_field.set_text(OTHER_TOKEN)
    view.token_name.setText("Client X")
    view.connect_account()
    qtbot.waitUntil(lambda: view.token_choice.count() == 3 and view.stack.currentIndex() == 1, timeout=10000)
    assert view.token_choice.currentText() == "Client X"
    # Retour au premier jeton : relu aussitôt.
    view.token_choice.setCurrentIndex(0)
    view._token_chosen(0)
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=10000)
    assert view.admin.active_token().name == "Mon compte"
