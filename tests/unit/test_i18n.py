"""Chaque texte tr("…") du code a sa traduction dans chaque langue, avec les mêmes variables {…}."""

import ast
import string
from pathlib import Path

import pytest

from cma.i18n import SUPPORTED_LANGUAGES, catalog, get_language, set_language, tr
from cma.i18n_en import CATALOG

LANGUAGES = [code for code in SUPPORTED_LANGUAGES if code != "fr"]

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


@pytest.mark.parametrize("language", LANGUAGES)
def test_every_text_is_translated(language):
    translations = catalog(language)
    missing = {text: where for text, where in translatable_strings().items() if text not in translations}
    assert not missing, f"{language} : {len(missing)} texte(s) sans traduction : {list(missing.items())[:10]}"


@pytest.mark.parametrize("language", LANGUAGES)
def test_placeholders_match(language):
    wrong = [text for text, value in catalog(language).items() if fields(text) != fields(value)]
    assert not wrong, wrong


@pytest.mark.parametrize("language", LANGUAGES)
def test_no_stale_translations(language):
    stale = set(catalog(language)) - set(translatable_strings())
    assert not stale, sorted(stale)[:10]


def test_catalogs_cover_the_same_texts():
    for language in LANGUAGES:
        assert set(catalog(language)) == set(CATALOG), language


def test_language_switch():
    previous = get_language()
    try:
        set_language("en")
        assert tr("Journaux") == "Logs"
        assert tr("texte inconnu") == "texte inconnu"
        set_language("de")
        assert tr("Journaux") != "Journaux"
        set_language("es")
        assert tr("Journaux") != "Journaux"
        assert catalog("fr") == {} and catalog("xx") == {}
        set_language("xx")
        assert get_language() == "fr"
    finally:
        set_language(previous)


def test_settings_accept_only_known_languages():
    from cma.core.models import Settings

    assert Settings(language="de").language == "de" and Settings(language="es").language == "es"
    assert (
        Settings(language="xx").language == "fr"
    )  # configuration d'une version plus récente ou faute de frappe
    assert Settings.model_validate({"language": None}).language == "fr"
