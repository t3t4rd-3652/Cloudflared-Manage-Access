"""Marge de retour des objectifs de disponibilité (P40) : hystérésis, bornes, réglages anciens ou abîmés.

Le passage sous l'objectif est annoncé tout de suite ; le retour attend objectif + marge (100 % au plus). Les
disponibilités sont posées directement dans le journal (un jour, 100 000 tests) : aucune dépendance au fuseau du poste.
"""

from __future__ import annotations

import json
import math
from datetime import UTC, timedelta
from pathlib import Path

import pytest

from cma.core.alertstate import AlertState
from cma.core.availability import AvailabilityLog
from cma.core.models import DEFAULT_MARGIN, Config
from cma.core.slo import crossings, is_recovered, recovery_level
from tests.unit.test_slo import KEY, NOW, Run, channel_setup, config_with

TOTAL = 100_000


def log_at(path: Path, percent: float) -> AvailabilityLog:
    """Un journal dont la disponibilité sur 30 jours est `percent` (précision de 0,001 point)."""
    log = AvailabilityLog(path)
    day = NOW.astimezone(UTC).date().isoformat()
    log.days[KEY] = {day: [float(round(percent * TOTAL / 100)), float(TOTAL), 0.0, 0.0, 0]}
    log.labels[KEY] = "wiki.exemple.fr"
    return log


def titles(run: Run) -> list[str]:
    return [a.title.split(" : ")[0] for a in run.sent]


# --- Réglage ---------------------------------------------------------------------------------------------------------


def test_margin_default_bounds_and_old_files():
    assert Config().settings.availability_margin == DEFAULT_MARGIN == 0.05
    # Une configuration d'avant P40, ou sans réglages du tout, garde la valeur par défaut.
    old = Config.model_validate({"settings": {"alert_repeat_hours": 6, "default_availability_target": 99}})
    assert old.settings.availability_margin == 0.05
    assert Config.model_validate({}).settings.availability_margin == 0.05
    given = Config.model_validate({"settings": {"availability_margin": 0.2}})
    assert given.settings.availability_margin == 0.2
    assert (
        Config.model_validate({"settings": {"availability_margin": "0.3"}}).settings.availability_margin
        == 0.3
    )
    # Bornée de 0 à 1.
    for raw, expected in ((-3, 0.0), (0, 0.0), (1, 1.0), (7.5, 1.0), (math.inf, 1.0), (-math.inf, 0.0)):
        assert (
            Config.model_validate({"settings": {"availability_margin": raw}}).settings.availability_margin
            == expected
        )
    # Illisible : retour à la valeur par défaut, jamais une erreur qui ferait perdre la configuration.
    for bad in (None, "abc", "", [], {}, True, math.nan, "nan"):
        loaded = Config.model_validate({"settings": {"availability_margin": bad, "alert_repeat_hours": 4}})
        assert loaded.settings.availability_margin == 0.05 and loaded.settings.alert_repeat_hours == 4, bad
    # Une affectation est bornée aussi, et la marge fait l'aller-retour par JSON.
    config = Config()
    config.settings.availability_margin = 4.0
    assert config.settings.availability_margin == 1.0
    config.settings.availability_margin = 0.12
    again = Config.model_validate_json(config.model_dump_json())
    assert again.settings.availability_margin == 0.12
    assert json.loads(config.model_dump_json())["settings"]["availability_margin"] == 0.12


def test_recovery_level_is_capped_at_100():
    assert recovery_level(99.9, 0.05) == pytest.approx(99.95)
    assert recovery_level(99.9, 0.0) == 99.9
    assert recovery_level(99.98, 0.05) == 100.0 and recovery_level(100.0, 0.05) == 100.0
    assert is_recovered(99.95, 99.9, 0.05) and not is_recovered(99.94, 99.9, 0.05)
    assert is_recovered(100.0, 100.0, 0.5) and not is_recovered(99.99, 100.0, 0.5)
    assert not is_recovered(None, 99.9, 0.05) and not is_recovered(99.99, None, 0.05)


# --- Franchissements -------------------------------------------------------------------------------------------------


def test_oscillation_gives_one_alert_and_one_recovery(tmp_path: Path):
    config = config_with(99.9)  # marge par défaut : 0,05 point, retour à 99,95 %
    run = Run(tmp_path, config, channel_setup(config))
    at = NOW
    steps = [
        (99.90, []),  # à l'objectif : correct
        (99.93, []),  # au-dessus de l'objectif, sous le niveau de retour : rien
        (99.89, ["CMA — objectif manqué"]),  # sous l'objectif : l'alerte
        (99.93, []),  # entre l'objectif et objectif + marge : toujours « sous l'objectif », rien d'annoncé
        (99.89, []),  # il redescend : pas de seconde alerte
        (99.91, []),
        (99.96, ["CMA — objectif retrouvé"]),  # objectif + marge atteint : le retour, une fois
        (99.93, []),  # correct entre les deux : pas de nouvelle alerte
        (99.95, []),
    ]
    for hours, (percent, expected) in enumerate(steps):
        before = len(run.sent)
        run(log_at(tmp_path / "availability.json", percent), at + timedelta(hours=hours))
        assert titles(run)[before:] == expected, (hours, percent)
    assert len(run.sent) == 2
    assert not AlertState(run.state_path).slo_below(KEY)


def test_state_between_target_and_margin_survives_a_restart(tmp_path: Path):
    config = config_with(99.9)
    run = Run(tmp_path, config, channel_setup(config))
    run(log_at(tmp_path / "a.json", 99.80), NOW)
    assert AlertState(run.state_path).slo_below(KEY) and len(run.sent) == 1
    # L'état est relu du disque à chaque relevé (Run) : il reste « sous l'objectif » dans la zone de marge.
    run(log_at(tmp_path / "a.json", 99.94), NOW + timedelta(hours=1))
    assert AlertState(run.state_path).slo_below(KEY) and len(run.sent) == 1
    found = crossings(log_at(tmp_path / "a.json", 99.96), config, AlertState(run.state_path), NOW, UTC)
    assert [(c.key, c.recovered, round(c.uptime, 2)) for c in found] == [(KEY, True, 99.96)]


def test_zero_margin_is_the_old_behaviour(tmp_path: Path):
    config = config_with(99.9)
    config.settings.availability_margin = 0.0
    run = Run(tmp_path, config, channel_setup(config))
    seen = []
    for hours, percent in enumerate((99.93, 99.89, 99.90, 99.89, 99.91)):
        run(log_at(tmp_path / "availability.json", percent), NOW + timedelta(hours=hours))
        seen.append(len(run.sent))
    # Alerte à 99,89, retour dès 99,90, nouvelle alerte à 99,89, nouveau retour à 99,91 : comme avant P40.
    assert seen == [0, 1, 2, 3, 4]
    assert titles(run) == [
        "CMA — objectif manqué",
        "CMA — objectif retrouvé",
        "CMA — objectif manqué",
        "CMA — objectif retrouvé",
    ]


def test_target_100_recovers_at_100_whatever_the_margin(tmp_path: Path):
    for margin in (0.0, 0.05, 1.0):
        config = config_with(100.0)
        config.settings.availability_margin = margin
        state = AlertState(tmp_path / f"state-{margin}.json")
        below = crossings(log_at(tmp_path / "a.json", 99.99), config, state, NOW, UTC)
        assert [(c.recovered, c.target) for c in below] == [(False, 100.0)], margin
        state.mark_slo(KEY, True, NOW)
        assert crossings(log_at(tmp_path / "a.json", 99.99), config, state, NOW, UTC) == [], margin
        back = crossings(log_at(tmp_path / "a.json", 100.0), config, state, NOW, UTC)
        assert [(c.recovered, c.uptime) for c in back] == [(True, 100.0)], margin


def test_large_margin_is_capped_below_100(tmp_path: Path):
    config = config_with(99.5)
    config.settings.availability_margin = 1.0  # 99,5 + 1 = 100,5 : plafonné à 100 %
    state = AlertState(tmp_path / "state.json")
    state.mark_slo(KEY, True, NOW)
    assert crossings(log_at(tmp_path / "a.json", 99.99), config, state, NOW, UTC) == []
    assert len(crossings(log_at(tmp_path / "a.json", 100.0), config, state, NOW, UTC)) == 1


def test_muted_object_gets_no_recovery(tmp_path: Path):
    config = config_with(99.9)
    state = AlertState(tmp_path / "state.json")
    state.mark_slo(KEY, True, NOW)
    log = log_at(tmp_path / "a.json", 99.99)  # retour dû, mais objet en sourdine
    assert crossings(log, config, state, NOW, UTC, muted=lambda _key: True) == []
    assert len(crossings(log, config, state, NOW, UTC, muted=lambda _key: False)) == 1
