"""P30 : boîtes d'import et d'export de la configuration avec les canaux d'alerte et les maintenances."""

import json

import pytest
from PySide6.QtWidgets import QFileDialog

from cma.core.alerts import secret_key as alert_secret_key
from cma.core.models import AlertChannel, MaintenanceWindow
from cma.core.transfer import build_export, plan_import
from cma.ui.a11y import accessible_name, apply_accessible_names, missing_accessible_names
from cma.ui.dialogs import transfer
from tests.ui.test_a11y_recent import describe, verify_tab_order

ADDRESS = "https://hooks.slack.com/services/T0ABCDEF/B0GHIJKL/Zq8RsTuVwXyz1234"
PHRASE = "phrase-longue-1"


def _fill(ctx) -> AlertChannel:
    channel = AlertChannel(name="Équipe", kind="slack")

    def fill(config):
        config.settings.alert_channels.append(channel)
        config.settings.alert_channels.append(AlertChannel(name="Astreinte", kind="ntfy"))
        config.settings.maintenance_windows.append(
            MaintenanceWindow(weekday=1, start="02:00", end="04:00", label="Sauvegardes")
        )
        config.settings.alert_repeat_hours = 6
        config.settings.weekly_digest = True

    ctx.update_config(fill)
    ctx.core.secrets.set(alert_secret_key(channel.id), ADDRESS)
    return channel


def _empty_config_plan(ctx, data):
    """Plan d'un import dans une installation qui n'a ni canal ni maintenance."""
    from cma.core.models import Config

    return plan_import(data, Config())


def test_import_dialog_lists_alerts_and_waiting_channels(qtbot, gui):
    ctx, window = gui
    _fill(ctx)
    plan = _empty_config_plan(ctx, build_export(ctx.config(), ctx.core.secrets))
    dialog = transfer.ImportDialog(window, plan, None, {})
    qtbot.addWidget(dialog)
    dialog.show()
    assert dialog.alerts_title.isVisible()
    summary = dialog.alerts_summary.text()
    assert "Équipe (Slack)" in summary and "Astreinte (ntfy)" in summary
    assert "Maintenances à ajouter : 1" in summary
    waiting = dialog.alerts_waiting.text()
    assert dialog.alerts_waiting.isVisible()
    assert "Équipe" in waiting and "Astreinte" in waiting
    assert "Paramètres › Général › Alertes" in waiting
    # Les réglages globaux ne sont repris que sur demande.
    assert dialog.import_settings.isVisible() and not dialog.import_settings.isChecked()
    assert "rappel toutes les 6 h" in dialog.settings_detail.text()
    assert dialog.ok_button.isEnabled()
    assert dialog.ok_button.text() == "Importer 3 éléments"
    dialog.import_settings.setChecked(True)
    assert plan.apply_alert_settings
    assert dialog.ok_button.text() == "Importer 4 éléments"
    dialog.import_settings.setChecked(False)
    assert not plan.apply_alert_settings


def test_import_dialog_encrypted_explains_the_passphrase(qtbot, gui):
    ctx, window = gui
    _fill(ctx)
    plan = _empty_config_plan(ctx, build_export(ctx.config(), ctx.core.secrets, passphrase=PHRASE))
    dialog = transfer.ImportDialog(window, plan, None, {})
    qtbot.addWidget(dialog)
    dialog.show()
    assert "Sans phrase de passe" in dialog.alerts_waiting.text()
    dialog.passphrase.setText(PHRASE)
    assert "reprises avec la phrase de passe" in dialog.alerts_waiting.text()
    dialog._accept()
    # Déchiffré : seul le canal qui n'avait pas d'adresse dans le coffre d'origine reste en attente.
    assert plan.secrets is not None
    assert [c.name for c in plan.channels_waiting] == ["Astreinte"]


def test_import_dialog_reports_what_is_already_here(qtbot, gui):
    ctx, window = gui
    _fill(ctx)
    plan = plan_import(build_export(ctx.config(), ctx.core.secrets), ctx.config())
    dialog = transfer.ImportDialog(window, plan, None, {})
    qtbot.addWidget(dialog)
    dialog.show()
    assert "Aucun canal ni aucune maintenance à ajouter." in dialog.alerts_summary.text()
    assert "2 canal(aux), 1 maintenance(s)" in dialog.alerts_summary.text()
    assert not dialog.alerts_waiting.isVisible()
    assert not dialog.ok_button.isEnabled()  # rien à ajouter : rien à importer


def test_import_dialog_without_alerts_shows_nothing_about_them(qtbot, gui):
    ctx, window = gui
    from cma.core.models import ServiceToken

    ctx.update_config(lambda c: c.tokens.append(ServiceToken(name="T", client_id="t")))
    data = build_export(ctx.config(), ctx.core.secrets)
    plan = _empty_config_plan(ctx, data)
    dialog = transfer.ImportDialog(window, plan, None, {})
    qtbot.addWidget(dialog)
    dialog.show()
    for widget in (dialog.alerts_title, dialog.alerts_summary, dialog.alerts_waiting, dialog.import_settings):
        assert not widget.isVisible()
    assert dialog.ok_button.isEnabled()


@pytest.mark.parametrize("encrypted", [False, True])
def test_import_dialog_accessibility(qtbot, gui, encrypted):
    ctx, window = gui
    _fill(ctx)
    data = build_export(ctx.config(), ctx.core.secrets, passphrase=PHRASE if encrypted else None)
    plan = _empty_config_plan(ctx, data)
    dialog = transfer.ImportDialog(window, plan, None, {})
    qtbot.addWidget(dialog)
    dialog.show()
    apply_accessible_names(dialog)
    assert describe(missing_accessible_names(dialog)) == []
    assert accessible_name(dialog.import_settings) == "Reprendre les réglages des rappels et du résumé"
    verify_tab_order(dialog, min_controls=3)


def test_export_dialog_alerts_checkbox(qtbot, gui):
    ctx, window = gui
    empty = transfer.ExportDialog(window, ctx)
    qtbot.addWidget(empty)
    empty.show()
    assert not empty.with_alerts.isVisible() and not empty.alerts_included()
    assert not empty.ok_button.isEnabled()
    assert empty.empty.isVisible()

    _fill(ctx)
    dialog = transfer.ExportDialog(window, ctx)
    qtbot.addWidget(dialog)
    dialog.show()
    assert dialog.with_alerts.isVisible() and dialog.with_alerts.isChecked()
    assert not dialog.empty.isVisible()
    assert dialog.ok_button.isEnabled()  # seuls les canaux et les maintenances : déjà exportable
    assert "adresses des canaux d'alerte ne sont pas exportées" in dialog.secrets_hint.text()
    dialog.with_secrets.setChecked(True)
    dialog.passphrase.setText(PHRASE)
    dialog.confirmation.setText(PHRASE)
    assert "adresses des canaux d'alerte ne sont pas exportées" not in dialog.secrets_hint.text()
    dialog.with_alerts.setChecked(False)
    assert not dialog.alerts_included() and not dialog.ok_button.isEnabled()
    assert accessible_name(dialog.with_alerts) == "Inclure les canaux d'alerte et les maintenances"
    verify_tab_order(dialog, min_controls=3)


def test_export_then_import_through_the_dialogs(qtbot, gui, accept_dialogs, monkeypatch, tmp_path):
    ctx, window = gui
    channel = _fill(ctx)
    target = tmp_path / "export.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(target), ""))
    transfer.run_export(ctx, window)
    written = target.read_text(encoding="utf-8")
    assert "Zq8RsTuVwXyz1234" not in written and "hooks.slack.com" not in written
    assert [c["name"] for c in json.loads(written)["alert_channels"]] == ["Équipe", "Astreinte"]

    # Import sur une installation vide : canaux désactivés, réglages des rappels repris seulement si cochés.
    def clear(config):
        config.settings.alert_channels.clear()
        config.settings.maintenance_windows.clear()
        config.settings.alert_repeat_hours = 0
        config.settings.weekly_digest = False

    ctx.update_config(clear)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(target), ""))
    transfer.run_import(ctx, window)
    settings = ctx.config().settings
    assert [(c.name, c.enabled) for c in settings.alert_channels] == [("Équipe", False), ("Astreinte", False)]
    assert len(settings.maintenance_windows) == 1
    assert (settings.alert_repeat_hours, settings.weekly_digest) == (0, False)

    ctx.update_config(clear)
    accept_dialogs.append(
        lambda d: d.import_settings.setChecked(True) if isinstance(d, transfer.ImportDialog) else None
    )
    transfer.run_import(ctx, window)
    settings = ctx.config().settings
    assert (settings.alert_repeat_hours, settings.weekly_digest) == (6, True)
    assert ctx.core.secrets.get(alert_secret_key(channel.id)) == ADDRESS  # l'ancienne adresse est inchangée


def test_encrypted_export_then_import_restores_the_address(qtbot, gui, accept_dialogs, monkeypatch, tmp_path):
    ctx, window = gui
    _fill(ctx)
    target = tmp_path / "export.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(target), ""))

    def fill_export(dialog):
        if isinstance(dialog, transfer.ExportDialog):
            dialog.with_secrets.setChecked(True)
            dialog.passphrase.setText(PHRASE)
            dialog.confirmation.setText(PHRASE)

    accept_dialogs.append(fill_export)
    transfer.run_export(ctx, window)
    assert "Zq8RsTuVwXyz1234" not in target.read_text(encoding="utf-8")

    ctx.update_config(lambda c: (c.settings.alert_channels.clear(), c.settings.maintenance_windows.clear()))
    accept_dialogs.clear()
    accept_dialogs.append(
        lambda d: d.passphrase.setText(PHRASE) if isinstance(d, transfer.ImportDialog) else None
    )
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(target), ""))
    transfer.run_import(ctx, window)
    restored = next(c for c in ctx.config().settings.alert_channels if c.name == "Équipe")
    assert restored.enabled
    assert ctx.core.secrets.get(alert_secret_key(restored.id)) == ADDRESS
