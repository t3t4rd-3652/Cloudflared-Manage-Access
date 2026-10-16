"""Boîte Disponibilité (P33) : colonne « Objectif », teinte sous l'objectif, saisie, accessibilité, clavier."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QDialog, QWidget

import cma.ui.views.cloud.availability as availability_module
from cma.core.alertlog import AlertLog
from cma.core.availability import AvailabilityLog
from cma.core.models import Theme
from cma.core.slo import set_target
from cma.ui.a11y import accessible_name, apply_accessible_names, missing_accessible_names
from cma.ui.dialogs.sends import SendsDialog, nature_label
from cma.ui.theme import current_tokens, status_colors
from cma.ui.views.cloud.availability import (
    TARGET_COLUMN,
    AvailabilityDialog,
    TargetChoice,
    TargetDialog,
    ask_target,
)
from tests.ui.test_a11y_recent import describe, verify_tab_order

WIKI = "service:wiki.exemple.fr"
BUREAU = "tunnel:t1"


def make_log(tmp_path: Path) -> Path:
    """wiki : 27 tests sur 30 réussis (90 %) ; bureau : 100 % ; grafana : 100 %."""
    path = tmp_path / "availability.json"
    log = AvailabilityLog(path)
    now = datetime.now(UTC)
    for offset in range(30):
        at = now - timedelta(hours=offset)
        log.record_check(WIKI, "wiki.exemple.fr", offset >= 3, 120.0, at)
        log.record_check(BUREAU, "bureau", True, None, at)
        log.record_check("service:grafana.exemple.fr", "grafana.exemple.fr", True, 30.0, at)
    log.save()
    return path


def rows_of(dialog: AvailabilityDialog) -> dict[str, int]:
    return {dialog.table.item(r, 0).text(): r for r in range(dialog.table.rowCount())}


def color_of(item) -> str:
    return QColor(item.foreground().color()).name().lower()


def test_target_column_shows_value_and_alert_tint(qtbot, gui_context, tmp_path):
    ctx = gui_context
    ctx.update_config(lambda c: set_target(c, WIKI, 99.9))
    ctx.update_config(lambda c: set_target(c, BUREAU, 99.0))
    dialog = AvailabilityDialog(None, make_log(tmp_path), ctx)
    qtbot.addWidget(dialog)
    header = dialog.table.horizontalHeaderItem(TARGET_COLUMN).text()
    assert header == "Objectif" and dialog.table.columnCount() == 7
    rows = rows_of(dialog)
    wiki, bureau, grafana = rows["wiki.exemple.fr"], rows["bureau"], rows["grafana.exemple.fr"]
    # Colonnes d'avant inchangées : le temps moyen et le nombre d'incidents gardent leur place.
    assert dialog.table.item(wiki, 4).text() == "120 ms" and dialog.table.item(wiki, 5).text() == "0"
    # Sous l'objectif : ▼, teinte d'alerte sur l'objectif et sur le taux de 30 jours, info-bulle explicite.
    target = dialog.table.item(wiki, TARGET_COLUMN)
    assert target.text() == "▼ 99.9 %"
    danger = status_colors("danger", current_tokens())[0].lower()
    assert color_of(target) == danger and color_of(dialog.table.item(wiki, 3)) == danger
    assert "Sous l'objectif" in target.toolTip() and "90.00 %" in target.toolTip()
    assert "sous l'objectif" in target.data(availability_module.Qt.ItemDataRole.AccessibleTextRole)
    # Objectif tenu : la valeur seule, sans teinte d'alerte ; sans objectif : « — ».
    assert dialog.table.item(bureau, TARGET_COLUMN).text() == "99 %"
    assert (
        dialog.table.item(bureau, TARGET_COLUMN).foreground().style()
        == availability_module.Qt.BrushStyle.NoBrush
    )
    assert dialog.table.item(grafana, TARGET_COLUMN).text() == "—"


def test_default_target_is_shown_for_objects_without_one(qtbot, gui_context, tmp_path):
    ctx = gui_context
    ctx.update_config(lambda c: setattr(c.settings, "default_availability_target", 95.0))
    dialog = AvailabilityDialog(None, make_log(tmp_path), ctx)
    qtbot.addWidget(dialog)
    rows = rows_of(dialog)
    assert dialog.table.item(rows["bureau"], TARGET_COLUMN).text() == "95 %"
    assert dialog.table.item(rows["wiki.exemple.fr"], TARGET_COLUMN).text() == "▼ 95 %"  # 90 % : sous 95 %


@pytest.mark.parametrize("theme", [Theme.LIGHT, Theme.DARK])
def test_alert_tint_in_both_themes(qtbot, gui_context, tmp_path, theme):
    ctx = gui_context
    ctx.theme.set_theme(theme)
    ctx.update_config(lambda c: set_target(c, WIKI, 99.9))
    dialog = AvailabilityDialog(None, make_log(tmp_path), ctx)
    qtbot.addWidget(dialog)
    wiki = rows_of(dialog)["wiki.exemple.fr"]
    assert (
        color_of(dialog.table.item(wiki, TARGET_COLUMN))
        == status_colors("danger", current_tokens())[0].lower()
    )
    dialog.grab()  # le dessin ne lève rien dans ce thème


def test_dialog_without_context_is_read_only(qtbot, tmp_path):
    dialog = AvailabilityDialog(None, make_log(tmp_path))
    qtbot.addWidget(dialog)
    dialog.show()
    assert dialog.table.item(0, TARGET_COLUMN).text() == "—"
    dialog.table.selectRow(0)
    assert not dialog.target_button.isEnabled() and not dialog.default_button.isEnabled()
    dialog.define_target()  # sans contexte : rien ne se passe
    dialog.define_default_target()


def test_define_target_sets_changes_and_removes(qtbot, gui_context, tmp_path, monkeypatch):
    ctx = gui_context
    dialog = AvailabilityDialog(None, make_log(tmp_path), ctx)
    qtbot.addWidget(dialog)
    dialog.show()
    assert not dialog.target_button.isEnabled() and dialog.default_button.isEnabled()  # rien de choisi
    asked: list[tuple[str, float | None]] = []
    answers: list[TargetChoice | None] = [TargetChoice(99.9), None, TargetChoice(80.0), TargetChoice(None)]

    def fake_ask(parent, name, current, *, for_default=False):
        asked.append((name, current))
        return answers.pop(0)

    monkeypatch.setattr(availability_module, "ask_target", fake_ask)
    wiki = rows_of(dialog)["wiki.exemple.fr"]
    dialog.table.selectRow(wiki)
    assert dialog.target_button.isEnabled()
    dialog.target_button.click()
    assert asked == [("wiki.exemple.fr", None)]
    assert ctx.config().settings.availability_targets == {WIKI: 99.9}
    assert dialog.table.item(wiki, TARGET_COLUMN).text() == "▼ 99.9 %"
    assert dialog.table.currentRow() == wiki  # la sélection est gardée
    dialog.define_target()  # annulé : rien ne change
    assert asked[-1] == ("wiki.exemple.fr", 99.9) and ctx.config().settings.availability_targets == {
        WIKI: 99.9
    }
    dialog.define_target()
    assert dialog.table.item(wiki, TARGET_COLUMN).text() == "80 %"  # 90 % : au-dessus, plus de ▼
    dialog.define_target()  # retire l'objectif
    assert ctx.config().settings.availability_targets == {}
    assert dialog.table.item(wiki, TARGET_COLUMN).text() == "—"


def test_define_default_target(qtbot, gui_context, tmp_path, monkeypatch):
    ctx = gui_context
    dialog = AvailabilityDialog(None, make_log(tmp_path), ctx)
    qtbot.addWidget(dialog)
    calls: list[tuple[float | None, bool]] = []
    margins: list[float | None] = []
    answers: list[TargetChoice | None] = [TargetChoice(97.0), None, TargetChoice(None)]

    def fake_ask(parent, name, current, *, for_default=False, margin=None):
        calls.append((current, for_default))
        margins.append(margin)
        return answers.pop(0)

    monkeypatch.setattr(availability_module, "ask_target", fake_ask)
    dialog.define_default_target()
    assert ctx.config().settings.default_availability_target == 97.0
    assert dialog.table.item(rows_of(dialog)["bureau"], TARGET_COLUMN).text() == "97 %"
    dialog.define_default_target()  # annulé
    assert ctx.config().settings.default_availability_target == 97.0
    dialog.define_default_target()
    assert ctx.config().settings.default_availability_target is None
    assert calls == [(None, True), (97.0, True), (97.0, True)]
    assert margins == [0.05, 0.05, 0.05]  # la marge actuelle est proposée à la boîte
    assert ctx.config().settings.availability_margin == 0.05  # une réponse sans marge ne la touche pas


def test_define_default_target_saves_the_margin(qtbot, gui_context, tmp_path, monkeypatch):
    ctx = gui_context
    dialog = AvailabilityDialog(None, make_log(tmp_path), ctx)
    qtbot.addWidget(dialog)
    asked: list[float | None] = []
    answers = [TargetChoice(99.5, 0.2), TargetChoice(None, 0.0)]

    def fake_ask(parent, name, current, *, for_default=False, margin=None):
        asked.append(margin)
        return answers.pop(0)

    monkeypatch.setattr(availability_module, "ask_target", fake_ask)
    dialog.define_default_target()
    settings = ctx.config().settings
    assert settings.default_availability_target == 99.5 and settings.availability_margin == 0.2
    dialog.define_default_target()  # retirer l'objectif par défaut garde le réglage de la marge choisi
    settings = ctx.config().settings
    assert settings.default_availability_target is None and settings.availability_margin == 0.0
    assert asked == [0.05, 0.2]


def test_refused_update_keeps_the_table(qtbot, gui_context, tmp_path, monkeypatch):
    ctx = gui_context
    dialog = AvailabilityDialog(None, make_log(tmp_path), ctx)
    qtbot.addWidget(dialog)
    dialog.table.selectRow(rows_of(dialog)["wiki.exemple.fr"])
    monkeypatch.setattr(availability_module, "ask_target", lambda *_a, **_k: TargetChoice(99.0))
    monkeypatch.setattr(ctx, "update_config", lambda _mutator: False)  # enregistrement refusé
    dialog.define_target()
    assert dialog.table.item(dialog.table.currentRow(), TARGET_COLUMN).text() == "—"


def test_target_dialog_fields(qtbot):
    dialog = TargetDialog(None, "wiki", None, for_default=False)
    qtbot.addWidget(dialog)
    assert dialog.spin.minimum() == 50.0 and dialog.spin.maximum() == 100.0
    assert (
        dialog.spin.value() == 99.9 and not dialog.remove_button.isEnabled()
    )  # valeur proposée, rien à retirer
    dialog.spin.setValue(10.0)
    assert dialog.spin.value() == 50.0  # borné
    dialog.spin.setValue(250.0)
    assert dialog.spin.value() == 100.0
    dialog.spin.setValue(98.25)
    assert dialog.value() == TargetChoice(98.25)
    assert accessible_name(dialog.spin) == "Objectif de disponibilité (%)"
    current = TargetDialog(None, "wiki", 97.5, for_default=True)
    qtbot.addWidget(current)
    assert current.spin.value() == 97.5 and current.remove_button.isEnabled()
    current.remove_button.click()
    assert current.result() == QDialog.DialogCode.Accepted and current.value() == TargetChoice(None)


def test_target_dialog_margin_field(qtbot):
    plain = TargetDialog(None, "wiki", 99.0, for_default=False)
    qtbot.addWidget(plain)
    assert plain.margin_spin is None and plain.value().margin is None  # la marge est un réglage commun
    dialog = TargetDialog(None, "tous", 99.0, for_default=True, margin=0.05)
    qtbot.addWidget(dialog)
    spin = dialog.margin_spin
    assert spin is not None and spin.decimals() == 2
    assert spin.minimum() == 0.0 and spin.maximum() == 1.0 and spin.value() == 0.05
    assert accessible_name(spin) == "Marge de retour (points de pourcentage)"
    spin.setValue(5.0)
    assert spin.value() == 1.0  # borné
    spin.setValue(-1.0)
    assert spin.value() == 0.0
    spin.setValue(0.126)  # deux décimales
    assert dialog.value() == TargetChoice(99.0, 0.13)
    spin.setValue(0.3)
    assert dialog.value() == TargetChoice(99.0, 0.3)
    dialog.remove_button.click()
    assert dialog.value() == TargetChoice(None, 0.3)  # retirer l'objectif garde la marge choisie
    apply_accessible_names(dialog)
    assert describe(missing_accessible_names(dialog)) == []
    verify_tab_order(dialog, min_controls=4)  # objectif, marge, Annuler, Enregistrer, Retirer


def test_ask_target_passes_the_margin(qtbot, monkeypatch):
    monkeypatch.setattr(QDialog, "exec", lambda self: QDialog.DialogCode.Accepted)
    parent = QWidget()
    qtbot.addWidget(parent)
    assert ask_target(parent, "tous", 96.0, for_default=True, margin=0.4) == TargetChoice(96.0, 0.4)


def test_ask_target_module_function(qtbot, monkeypatch):
    monkeypatch.setattr(QDialog, "exec", lambda self: QDialog.DialogCode.Accepted)
    parent = QWidget()
    qtbot.addWidget(parent)
    assert ask_target(parent, "wiki", 96.0) == TargetChoice(96.0)
    monkeypatch.setattr(QDialog, "exec", lambda self: QDialog.DialogCode.Rejected)
    assert ask_target(parent, "wiki", 96.0, for_default=True) is None


def test_show_availability_passes_the_context_of_the_view(qtbot, gui_context, monkeypatch, tmp_path):
    seen: list[object] = []
    monkeypatch.setattr(AvailabilityDialog, "exec", lambda self: seen.append(self.ctx) or 0)
    parent = QWidget()
    parent.ctx = gui_context  # type: ignore[attr-defined]
    qtbot.addWidget(parent)
    availability_module.show_availability(parent, make_log(tmp_path))
    availability_module.show_availability(QWidget(), make_log(tmp_path))
    assert seen == [gui_context, None]


def test_dialogs_are_accessible_with_real_tabbing(qtbot, gui_context, tmp_path):
    ctx = gui_context
    ctx.update_config(lambda c: set_target(c, WIKI, 99.9))
    dialog = AvailabilityDialog(None, make_log(tmp_path), ctx)
    qtbot.addWidget(dialog)
    dialog.show()
    dialog.table.selectRow(rows_of(dialog)["wiki.exemple.fr"])
    apply_accessible_names(dialog)
    assert describe(missing_accessible_names(dialog)) == []
    assert accessible_name(dialog.table) == "Disponibilité par objet"
    assert (
        not dialog.table.tabKeyNavigation() and not dialog.incidents.tabKeyNavigation()
    )  # Tab quitte le tableau
    assert dialog.target_button.isEnabled() and dialog.default_button.isEnabled()
    verify_tab_order(
        dialog, min_controls=4
    )  # tableaux, boutons « Définir l'objectif… » et « Objectif par défaut… »

    target = TargetDialog(None, "wiki", 99.0, for_default=False)
    qtbot.addWidget(target)
    apply_accessible_names(target)
    assert describe(missing_accessible_names(target)) == []
    verify_tab_order(target, min_controls=3)  # valeur, Annuler, Enregistrer, Retirer


def test_sends_dialog_labels_the_slo_nature(qtbot, tmp_path):
    assert nature_label("slo") == "Objectif"
    journal = AlertLog(tmp_path / "alert_log.json")
    journal.note(channel="Équipe", kind="slack", nature="slo", subject="wiki.exemple.fr")
    dialog = SendsDialog(None, journal)
    qtbot.addWidget(dialog)
    assert "Objectif" in [dialog.table.item(0, c).text() for c in range(dialog.table.columnCount())]
