"""Traduction de l'interface.

Les textes sources sont en français. `tr()` renvoie la traduction de la langue active,
ou le texte source si la langue est le français ou si la traduction manque.
Les textes à variables utilisent `str.format` : `tr("{n} sessions").format(n=3)`.
Le test tests/unit/test_i18n.py vérifie que chaque `tr("...")` du code a sa traduction anglaise.
"""

from __future__ import annotations

SUPPORTED_LANGUAGES = {"fr": "Français", "en": "English"}

_language = "fr"


def set_language(language: str) -> None:
    global _language
    _language = language if language in SUPPORTED_LANGUAGES else "fr"


def get_language() -> str:
    return _language


def tr(text: str) -> str:
    if _language == "fr":
        return text
    from cma.i18n_en import CATALOG

    return CATALOG.get(text, text)
