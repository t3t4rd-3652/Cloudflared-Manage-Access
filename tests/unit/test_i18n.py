"""Chaque texte tr("…") du code a sa traduction anglaise, avec les mêmes variables {…}."""

import ast
import string
from pathlib import Path

from cma.i18n import get_language, set_language, tr
from cma.i18n_en import CATALOG

SOURCE = Path(__file__).resolve().parents[2] / "src" / "cma"


def translatable_strings() -> dict[str, str]:
    found: dict[str, str] = {}
    for path in SOURCE.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "tr" and node.args:
                argument = node.args[0]
                assert isinstance(argument, ast.Constant) and isinstance(argument.value, str), (
                    f"{path.name}:{node.lineno} : tr() doit recevoir un texte littéral"
                )
                found.setdefault(argument.value, f"{path.name}:{node.lineno}")
    return found


def fields(text: str) -> set[str]:
    return {name for _literal, name, _spec, _conv in string.Formatter().parse(text) if name}


def test_every_text_has_an_english_translation():
    missing = {text: where for text, where in translatable_strings().items() if text not in CATALOG}
    assert not missing, f"{len(missing)} texte(s) sans traduction : {list(missing.items())[:10]}"


def test_placeholders_match():
    wrong = [text for text, english in CATALOG.items() if fields(text) != fields(english)]
    assert not wrong, wrong


def test_no_stale_translations():
    stale = set(CATALOG) - set(translatable_strings())
    assert not stale, sorted(stale)[:10]


def test_language_switch():
    previous = get_language()
    try:
        set_language("en")
        assert tr("Journaux") == "Logs"
        assert tr("texte inconnu") == "texte inconnu"
        set_language("xx")
        assert get_language() == "fr"
    finally:
        set_language(previous)
