"""Aide (P21) : « Quoi de neuf » une fois par mise à jour, « Raccourcis clavier » (F1, palette, Paramètres)."""

from __future__ import annotations

from PySide6.QtCore import Qt

import cma.ui.dialogs.shortcuts as shortcuts_module
import cma.ui.dialogs.whatsnew as whatsnew_module
from cma import __version__
from cma.core.changelog import Release
from cma.ui.dialogs.shortcuts import ShortcutsDialog, shortcut_rows
from cma.ui.dialogs.whatsnew import (
    WhatsNewDialog,
    announce_update,
    release_markdown,
    releases_to_announce,
)

NOTES = [Release("2.11.0", "2026-10-10", "### Ajouté\n- **Quoi de neuf** après une mise à jour.")]


def set_seen(ctx, version):
    ctx.update_config(lambda c: setattr(c.settings, "last_seen_version", version))


def test_releases_to_announce(gui):
    ctx, _window = gui
    # Première installation : rien à montrer, la version est seulement notée.
    assert releases_to_announce(ctx, fresh=True) == []
    assert ctx.config().settings.last_seen_version == __version__
    assert releases_to_announce(ctx, fresh=False) == []  # même version : rien
    # Mise à jour depuis une version qui ne notait rien : la section de la version courante.
    set_seen(ctx, None)
    assert [r.version for r in releases_to_announce(ctx, fresh=False)] == [__version__]
    assert releases_to_announce(ctx, fresh=False) == []  # une seule fois
    # Mise à jour depuis une version ancienne : toutes les versions intermédiaires, la plus récente d'abord.
    set_seen(ctx, "2.8.0")
    versions = [r.version for r in releases_to_announce(ctx, fresh=False)]
    assert versions[0] == __version__ and "2.8.0" not in versions and "2.9.0" in versions
    # Retour à une version plus ancienne : rien, mais la version est notée.
    set_seen(ctx, "99.0.0")
    assert releases_to_announce(ctx, fresh=False) == []
    assert ctx.config().settings.last_seen_version == __version__


def test_whats_new_dialog(gui):
    _ctx, window = gui
    dialog = WhatsNewDialog(window, NOTES, "en")
    text = dialog.browser.toPlainText()
    assert "2.11.0" in text and "Quoi de neuf après une mise à jour." in text
    assert "**" not in text  # Markdown rendu
    assert "2.11.0 · 2026-10-10" in release_markdown(NOTES)
    empty = WhatsNewDialog(window, [])
    assert empty.browser.isHidden()


def test_announce_update_dialog_or_notice(gui, monkeypatch):
    _ctx, window = gui
    shown: list[list[Release]] = []
    monkeypatch.setattr(
        whatsnew_module, "show_whats_new", lambda _p, releases, _lang="fr": shown.append(releases)
    )
    announce_update(window, [])
    assert shown == []
    # Fenêtre cachée (démarrage dans la zone de notification) : une notification dont l'action ouvre la boîte.
    window.hide()
    announce_update(window, NOTES)
    assert shown == []
    notice = window.notices.latest()[0]
    assert __version__ in notice.text and notice.action is not None
    notice.action[1]()
    assert shown == [NOTES]
    window.show()
    announce_update(window, NOTES)
    assert shown == [NOTES, NOTES]


def test_shortcuts_everywhere(gui, qtbot, monkeypatch):
    _ctx, window = gui
    opened: list[list[str]] = []
    monkeypatch.setattr(shortcuts_module, "show_shortcuts", lambda _p, pages: opened.append(pages))
    window.show()
    qtbot.waitExposed(window)
    window.activateWindow()
    qtbot.keyClick(window, Qt.Key.Key_F1)
    assert len(opened) == 1 and opened[0][0] == window._nav_items["dashboard"].text()
    entries = {e.text: e for e in window.palette_entries()}
    entries["Raccourcis clavier…"].run()
    assert len(opened) == 2
    news: list[str] = []
    monkeypatch.setattr(whatsnew_module, "show_whats_new", lambda _p, releases, lang="fr": news.append(lang))
    entries["Quoi de neuf dans CMA…"].run()
    window.settings.whats_new_button.click()
    window.settings.shortcuts_button.click()
    assert news == ["fr", "fr"] and len(opened) == 3


def test_shortcut_rows_and_dialog(gui):
    _ctx, window = gui
    rows = shortcut_rows(["Sessions", "Accès"])
    actions = [action for _where, _keys, action in rows]
    assert "Aller à « Accès »" in actions and "Raccourcis clavier" in actions
    keys = {action: k for _where, k, action in rows}
    assert keys["Aller à « Sessions »"] in ("Ctrl+1", "⌘1")
    assert all(k for _w, k, _a in rows)
    dialog = ShortcutsDialog(window, ["Sessions"])
    assert dialog.table.rowCount() == len(shortcut_rows(["Sessions"]))
