"""Contrastes des jetons de couleur (WCAG 2.x) : texte 4,5:1 minimum, limites de contrôle et focus 3:1."""

from __future__ import annotations

import pytest

from cma.ui.theme import DARK, LIGHT, Tokens

SURFACES = ("window", "surface", "sidebar", "hover", "pressed", "selected")
TEXT_PAIRS = [
    *[(fg, bg) for fg in ("text", "muted") for bg in SURFACES],
    *[("on_accent", bg) for bg in ("accent", "primary_hover", "primary_pressed")],
    *[(fg, f"{fg}_bg") for fg in ("success", "warning", "danger", "info", "neutral")],
    ("disabled", "disabled_bg"),
    *[(fg, bg) for fg in ("accent", "danger") for bg in ("surface", "window", "hover", "pressed")],
    *[("text", f"{tone}_bg") for tone in ("success", "warning", "danger", "info")],
]
UI_PAIRS = [(fg, bg) for fg in ("control", "focus") for bg in ("window", "surface", "sidebar")]


def luminance(color: str) -> float:
    channels = [int(color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def ratio(first: str, second: str) -> float:
    dark, light = sorted((luminance(first), luminance(second)))
    return (light + 0.05) / (dark + 0.05)


@pytest.mark.parametrize("tokens", [LIGHT, DARK], ids=["clair", "sombre"])
def test_text_pairs_reach_4_5(tokens: Tokens) -> None:
    low = {
        (fg, bg): round(value, 2)
        for fg, bg in TEXT_PAIRS
        if (value := ratio(getattr(tokens, fg), getattr(tokens, bg))) < 4.5
    }
    assert not low


@pytest.mark.parametrize("tokens", [LIGHT, DARK], ids=["clair", "sombre"])
def test_controls_and_focus_reach_3(tokens: Tokens) -> None:
    low = {
        (fg, bg): round(value, 2)
        for fg, bg in UI_PAIRS
        if (value := ratio(getattr(tokens, fg), getattr(tokens, bg))) < 3
    }
    assert not low
