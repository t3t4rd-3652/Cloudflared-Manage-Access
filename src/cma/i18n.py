"""Traduction de l'interface.

Les textes sources sont en français. `tr()` renvoie la traduction de la langue active ; si elle manque, la
traduction anglaise, puis le texte source. Les textes à variables utilisent `str.format` :
`tr("{n} sessions").format(n=3)`.

Ajouter une langue revient à fournir un catalogue `cma/i18n_<code>.py` (dictionnaire `CATALOG`, mêmes clés que
le catalogue anglais) et à l'inscrire dans `SUPPORTED_LANGUAGES`. Le test tests/unit/test_i18n.py vérifie, pour
chaque catalogue, qu'aucun texte du code ne manque et que les variables {…} sont les mêmes.
"""

from __future__ import annotations

import importlib

SUPPORTED_LANGUAGES = {"fr": "Français", "en": "English", "de": "Deutsch", "es": "Español"}

_language = "fr"
_catalogs: dict[str, dict[str, str]] = {}


def set_language(language: str) -> None:
    global _language
    _language = language if language in SUPPORTED_LANGUAGES else "fr"


def get_language() -> str:
    return _language


def catalog(language: str) -> dict[str, str]:
    """Catalogue d'une langue (chargé à la première demande) ; vide pour le français, langue des sources."""
    if language == "fr" or language not in SUPPORTED_LANGUAGES:
        return {}
    if language not in _catalogs:
        module = importlib.import_module(f"cma.i18n_{language}")
        _catalogs[language] = module.CATALOG
    return _catalogs[language]


def tr(text: str) -> str:
    if _language == "fr":
        return text
    value = catalog(_language).get(text)
    if value is None and _language != "en":
        value = catalog("en").get(text)
    return text if value is None else value
