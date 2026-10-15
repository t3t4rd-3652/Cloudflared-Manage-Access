"""Mise en page en allemand et en espagnol : les libellés les plus longs ne sont pas rognés (P36)."""

from __future__ import annotations

import pytest

from cma.core.alertlog import AlertLog
from cma.i18n import set_language
from cma.ui.dialogs.sends import SendsDialog, nature_label
from cma.ui.views.cloud.cards import StatTile

NATURES = ("alert", "recovery", "reminder", "digest", "test")


@pytest.mark.parametrize("language", ["de", "es"])
def test_send_natures_fit_their_column(qtbot, tmp_path, language):
    """« Zusammenfassung » et « Wiederherstellung » étaient coupés à 80 px dans la boîte « Envois récents »."""
    set_language(language)
    try:
        dialog = SendsDialog(None, AlertLog(tmp_path / "envois.json"))
        qtbot.addWidget(dialog)
        width = dialog.table.horizontalHeader().sectionSize(2)
        for nature in NATURES:
            text = nature_label(nature)
            # En « offscreen » il n'y a pas de vraie police : les mesures de `QFontMetrics` ne valent rien. On compte
            # donc 8 px par lettre (la police de l'interface fait environ 7 px), ce que les captures ont confirmé.
            assert len(text) * 8 <= width, (language, text, width)
    finally:
        set_language("fr")


@pytest.mark.parametrize("language", ["de", "es"])
def test_stat_tile_caption_wraps_instead_of_clipping(qtbot, language):
    """« Nombres de host publicados » perdait son « s » dans une tuile étroite : la légende passe à la ligne."""
    set_language(language)
    try:
        tile = StatTile("world-www", "Nombres de host publicados")
        qtbot.addWidget(tile)
        assert tile.caption.wordWrap()
        assert tile.caption.minimumWidth() > 0
    finally:
        set_language("fr")
