"""Historique des notifications dans l'interface : bouton de la barre d'état, boîte et action différée."""

from __future__ import annotations

from cma.ui.dialogs.notifications import NotificationsDialog


def test_status_bar_counts_unread_alerts_and_opens_history(qtbot, gui, monkeypatch):
    _ctx, window = gui
    window.banners.show_message = lambda *_a, **_k: None  # type: ignore[method-assign]
    assert window.status_notices.text() == "Notifications"

    window.notify("info", "Profil enregistré.")
    window.notify("error", "Tunnel « bureau » hors ligne.")
    window.notify("warning", "Jeton bientôt expiré.")
    assert window.status_notices.text() == "Notifications · 2 !"

    opened: list[int] = []
    monkeypatch.setattr("cma.ui.main_window.show_notifications", lambda _parent, log: opened.append(len(log)))
    window.open_notifications()
    assert opened == [3]
    assert window.status_notices.text() == "Notifications"


def test_dialog_lists_newest_first_and_runs_the_action(qtbot, gui):
    _ctx, window = gui
    window.banners.show_message = lambda *_a, **_k: None  # type: ignore[method-assign]
    ran: list[str] = []
    window.notify("error", "Session « nas » en erreur.", action=("Journal", lambda: ran.append("journal")))
    window.notify("success", "Tunnel « bureau » de nouveau en ligne.")

    dialog = NotificationsDialog(window, window.notices)
    qtbot.addWidget(dialog)
    table = dialog.table
    assert table.rowCount() == 2
    assert [table.item(r, 2).text() for r in range(2)] == [
        "Tunnel « bureau » de nouveau en ligne.",
        "Session « nas » en erreur.",
    ]
    assert table.item(0, 1).text() == "Réussite" and table.item(1, 1).text() == "Erreur"

    # Pas d'action pour la première, « Journal » pour la seconde.
    table.selectRow(0)
    assert not dialog.action_button.isEnabled()
    table.selectRow(1)
    assert dialog.action_button.isEnabled() and dialog.action_button.text() == "Journal"
    dialog.run_action()
    assert ran == ["journal"]

    # Effacer vide l'historique et affiche le message d'attente.
    dialog.clear()
    assert len(window.notices) == 0 and dialog.table.rowCount() == 0
    assert not dialog.clear_button.isEnabled()
