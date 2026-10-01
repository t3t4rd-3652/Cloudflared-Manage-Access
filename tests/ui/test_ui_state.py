"""Largeurs de colonnes mémorisées d'un lancement à l'autre."""

from __future__ import annotations

from PySide6.QtWidgets import QTableWidget

from cma.ui import state


def test_header_widths_survive_a_restart(qtbot, tmp_path):
    state.configure(tmp_path / "ui-state.ini")
    try:
        first = QTableWidget(0, 3)
        qtbot.addWidget(first)
        state.remember_header(first.horizontalHeader(), "essai")
        first.horizontalHeader().resizeSection(0, 222)
        qtbot.wait(600)

        second = QTableWidget(0, 3)
        qtbot.addWidget(second)
        state.remember_header(second.horizontalHeader(), "essai")
        assert second.horizontalHeader().sectionSize(0) == 222
    finally:
        state.configure(None)


def test_disabled_state_is_a_no_op(qtbot):
    state.configure(None)
    table = QTableWidget(0, 2)
    qtbot.addWidget(table)
    state.remember_header(table.horizontalHeader(), "essai")
    table.horizontalHeader().resizeSection(0, 150)
    assert table.horizontalHeader().sectionSize(0) == 150
