"""Objectifs de disponibilité (P33) : bornes, franchissements annoncés une seule fois, sourdine, mois civil.

Aucun test ne dépend du fuseau du poste : fuseau UTC ou `Paris` (simulation de l'heure d'Europe centrale, y compris
le changement d'heure de fin octobre, de `test_availability_local_days`).
"""

from __future__ import annotations

import json
import math
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from cma import cli
from cma.core.alertlog import AlertLog
from cma.core.alerts import Alert, AlertError, secret_key
from cma.core.alertstate import STATE_FILE, AlertState
from cma.core.availability import AvailabilityLog
from cma.core.models import AlertChannel, Config, MaintenanceWindow
from cma.core.monitoring import deliver_follow_up, event_alert, event_nature, mute, prepare_follow_up
from cma.core.secrets import MemorySecretStore
from cma.core.slo import (
    crossings,
    has_targets,
    is_below,
    month_bounds,
    month_report,
    parse_month,
    percent_text,
    set_target,
    status,
    target_of,
    target_text,
)
from cma.core.slo_report import month_csv, month_html, month_json, report_lines
from cma.paths import AppPaths
from tests.unit.test_availability_local_days import Paris

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)  # jeudi
KEY = "service:wiki.exemple.fr"


def daily_log(
    path: Path, failures: int = 1, *, key: str = KEY, label: str = "wiki.exemple.fr"
) -> AvailabilityLog:
    """Un test par jour pendant les 30 jours qui précèdent NOW (le dernier à NOW), `failures` en échec."""
    log = AvailabilityLog(path)
    for offset in range(30):
        log.record_check(key, label, offset >= failures, 50.0, NOW - timedelta(days=offset), UTC)
    return log


def config_with(target: float | None = 99.0, *, key: str = KEY) -> Config:
    config = Config()
    if target is not None:
        set_target(config, key, target)
    return config


def channel_setup(config: Config, *, recoveries: bool = True) -> MemorySecretStore:
    secrets = MemorySecretStore()
    channel = AlertChannel(name="Équipe", kind="slack", recoveries=recoveries)
    secrets.set(secret_key(channel.id), "https://hooks.slack.com/services/x")
    config.settings.alert_channels.append(channel)
    return secrets


class Run:
    """Un relevé : prépare puis envoie le suivi, comme `Monitor` et la tâche planifiée."""

    def __init__(self, tmp_path: Path, config: Config, secrets: MemorySecretStore) -> None:
        self.config, self.secrets = config, secrets
        self.state_path = tmp_path / STATE_FILE
        self.journal = AlertLog(tmp_path / "alert_log.json")
        self.sent: list[Alert] = []

    def __call__(self, log: AvailabilityLog, now: datetime = NOW, *, fail: bool = False) -> list[str]:
        plan = prepare_follow_up(
            log, self.config, AlertState(self.state_path), check_digest=False, now=now, tz=UTC
        )

        def send(_kind: str, _url: str, alert: Alert) -> None:
            if fail:
                raise AlertError("injoignable")
            self.sent.append(alert)

        self.plan = plan
        return deliver_follow_up(plan, self.config, self.secrets, now, send, self.journal)


# --- Réglages -------------------------------------------------------------------------------------------------------


def test_targets_are_bounded_and_old_config_reads():
    old = Config.model_validate({"settings": {"alert_repeat_hours": 6}})  # une configuration d'avant P33
    assert old.settings.availability_targets == {} and old.settings.default_availability_target is None
    assert not has_targets(old)
    config = Config.model_validate(
        {
            "settings": {
                "availability_targets": {
                    "tunnel:a": 10,
                    "tunnel:b": 150,
                    "tunnel:c": 99.5,
                    "tunnel:d": math.nan,
                },
                "default_availability_target": 30,
            }
        }
    )
    assert config.settings.availability_targets == {"tunnel:a": 50.0, "tunnel:b": 100.0, "tunnel:c": 99.5}
    assert config.settings.default_availability_target == 50.0
    config.settings.default_availability_target = 120  # une affectation est bornée aussi
    assert config.settings.default_availability_target == 100.0
    config.settings.default_availability_target = math.nan
    assert config.settings.default_availability_target is None
    config.settings.default_availability_target = None
    assert has_targets(config)
    again = Config.model_validate_json(config.model_dump_json())
    assert again.settings.availability_targets == config.settings.availability_targets


def test_set_target_and_default():
    config = Config()
    set_target(config, KEY, 99.9)
    assert target_of(config, KEY) == 99.9 and target_of(config, "tunnel:x") is None
    config.settings.default_availability_target = 95
    assert target_of(config, "tunnel:x") == 95 and target_of(config, KEY) == 99.9  # le sien d'abord
    set_target(config, KEY, 5)
    assert target_of(config, KEY) == 50.0
    set_target(config, KEY, None)
    assert target_of(config, KEY) == 95
    set_target(config, "inconnu", None)  # retirer un objectif absent ne fait rien


def test_text_helpers():
    assert (
        percent_text(99.9) == "99.90 %" and percent_text(99.897) == "99.89 %"
    )  # jamais à la hauteur de l'objectif
    assert percent_text(100.0) == "100.00 %"
    assert target_text(None) == "—" and target_text(99.9) == "99.9 %" and target_text(99.0) == "99 %"
    assert (
        is_below(89.99, 90) and not is_below(90.0, 90) and not is_below(None, 90) and not is_below(50, None)
    )


def test_status_against_target(tmp_path: Path):
    log = daily_log(tmp_path / "a.json", failures=3)  # 27 sur 30 = 90 % pile
    config = config_with(90.0)
    current = status(log, config, KEY, NOW, UTC)
    assert current.uptime == pytest.approx(90.0) and current.checks == 30
    assert not current.below and current.gap == pytest.approx(0.0)  # l'objectif atteint n'est pas manqué
    config.settings.availability_targets[KEY] = 95.0
    current = status(log, config, KEY, NOW, UTC)
    assert current.below and current.gap == pytest.approx(-5.0)
    nothing = status(log, config_with(None), KEY, NOW, UTC)
    assert nothing.target is None and nothing.gap is None and not nothing.below
    empty = status(AvailabilityLog(tmp_path / "b.json"), config, KEY, NOW, UTC)
    assert empty.uptime is None and empty.gap is None and not empty.below


# --- Franchissements ------------------------------------------------------------------------------------------------


def test_one_alert_per_crossing_then_recovery(tmp_path: Path):
    config = config_with(99.0)
    secrets = channel_setup(config)
    run = Run(tmp_path, config, secrets)
    log = daily_log(tmp_path / "availability.json")  # 29 sur 30 = 96,67 % : sous 99 %
    assert run(log) == []
    assert len(run.sent) == 1
    alert = run.sent[0]
    assert alert.title == "CMA — objectif manqué : wiki.exemple.fr" and alert.level == "warning"
    assert "96.66 %" in alert.text and "(99 %)" in alert.text
    assert AlertState(run.state_path).slo_below(KEY)
    # Tant que l'objet reste dessous : rien de plus, relevé après relevé.
    for hours in (1, 2, 5):
        assert run(log, NOW + timedelta(hours=hours)) == [] and run.plan.empty
    assert len(run.sent) == 1
    # Il remonte : 200 tests réussis aujourd'hui → un seul message de retour.
    for _ in range(200):
        log.record_check(KEY, "wiki.exemple.fr", True, 50.0, NOW + timedelta(hours=6), UTC)
    run(log, NOW + timedelta(hours=7))
    assert [a.title for a in run.sent] == [
        "CMA — objectif manqué : wiki.exemple.fr",
        "CMA — objectif retrouvé : wiki.exemple.fr",
    ]
    assert run.sent[1].level == "success" and "au-dessus de l'objectif" in run.sent[1].text
    assert not AlertState(run.state_path).slo_below(KEY)
    run(log, NOW + timedelta(hours=8))
    assert len(run.sent) == 2  # pas de second retour
    # Un nouveau passage dessous est annoncé de nouveau.
    for _ in range(300):
        log.record_check(KEY, "wiki.exemple.fr", False, None, NOW + timedelta(hours=9), UTC)
    run(log, NOW + timedelta(hours=10))
    assert len(run.sent) == 3 and run.sent[2].title.startswith("CMA — objectif manqué")
    # Chaque envoi est noté au journal des envois avec la nature « slo », sans adresse.
    entries = AlertLog(tmp_path / "alert_log.json").entries()
    assert [e.nature for e in entries] == ["slo", "slo", "slo"] and all(e.ok for e in entries)
    assert "hooks.slack" not in json.dumps([e.subject for e in entries])


def test_event_title_and_nature(tmp_path: Path):
    config = config_with(99.0)
    plan = prepare_follow_up(
        daily_log(tmp_path / "a.json"),
        config,
        AlertState(tmp_path / STATE_FILE),
        check_digest=False,
        now=NOW,
        tz=UTC,
    )
    assert len(plan.slo) == 1 and not plan.empty
    event = plan.slo[0]
    assert (
        event_nature(event) == "slo" and event_alert(event).title == "CMA — objectif manqué : wiki.exemple.fr"
    )
    assert event.key == KEY and event.slo and not event.recovered and not event.muted


def test_failed_alert_is_retried_and_state_stays_empty(tmp_path: Path):
    config = config_with(99.0)
    run = Run(tmp_path, config, channel_setup(config))
    log = daily_log(tmp_path / "availability.json")
    assert run(log, fail=True) == ["Équipe : injoignable"]
    assert not AlertState(run.state_path).slo_below(KEY)  # rien d'annoncé : il repart au relevé suivant
    assert run(log, NOW + timedelta(minutes=5)) == []
    assert len(run.sent) == 1 and AlertState(run.state_path).slo_below(KEY)
    failed = AlertLog(tmp_path / "alert_log.json").entries()
    assert [e.ok for e in failed] == [False, True]  # du plus ancien au plus récent


def test_without_channel_nothing_is_marked(tmp_path: Path):
    config = config_with(99.0)
    run = Run(tmp_path, config, MemorySecretStore())
    log = daily_log(tmp_path / "availability.json")
    assert run(log) == [] and run.sent == []
    assert not AlertState(run.state_path).slo_below(KEY)  # le canal ajouté plus tard recevra l'alerte
    secrets = channel_setup(config)
    run.secrets = secrets
    run(log, NOW + timedelta(hours=1))
    assert len(run.sent) == 1


def test_recovery_clears_state_even_if_no_channel_wants_it(tmp_path: Path):
    config = config_with(99.0)
    run = Run(tmp_path, config, channel_setup(config, recoveries=False))
    log = daily_log(tmp_path / "availability.json")
    run(log)
    assert len(run.sent) == 1
    for _ in range(200):
        log.record_check(KEY, "wiki.exemple.fr", True, None, NOW + timedelta(hours=1), UTC)
    run(log, NOW + timedelta(hours=2))
    assert len(run.sent) == 1  # ce canal ne veut pas les retours…
    assert not AlertState(run.state_path).slo_below(
        KEY
    )  # … mais l'état est à jour : le prochain passage dessous part


def test_muted_object_and_maintenance_give_no_alert(tmp_path: Path):
    config = config_with(99.0)
    run = Run(tmp_path, config, channel_setup(config))
    log = daily_log(tmp_path / "availability.json")
    mute(config, KEY, timedelta(hours=3), NOW)
    run(log)
    assert run.sent == [] and not AlertState(run.state_path).slo_below(KEY)
    # La sourdine du tunnel couvre les noms d'hôte (correspondance mémorisée dans l'état).
    mute(config, KEY, None, NOW)
    mute(config, "tunnel:t1", timedelta(hours=3), NOW)
    state = AlertState(run.state_path)
    state.remember_tunnels({KEY: "t1"})
    state.save()
    run(log)
    assert run.sent == []
    # Maintenance hebdomadaire du compte entier : le jeudi 15/10/2026 de 11 h à 13 h (UTC).
    mute(config, "tunnel:t1", None, NOW)
    config.settings.maintenance_windows = [MaintenanceWindow(weekday=3, start="11:00", end="13:00")]
    run(log)
    assert run.sent == []
    # Hors du créneau et sans sourdine, l'alerte part : la situation dure.
    run(log, NOW + timedelta(hours=3))
    assert len(run.sent) == 1


def test_no_checks_in_period_means_no_event(tmp_path: Path):
    config = config_with(99.0)
    run = Run(tmp_path, config, channel_setup(config))
    log = AvailabilityLog(tmp_path / "availability.json")
    log.start(
        "service", KEY, "wiki.exemple.fr", "origin_down", NOW - timedelta(days=2)
    )  # un incident, aucun test
    log.record_check(KEY, "wiki.exemple.fr", False, None, NOW - timedelta(days=60), UTC)  # hors de la période
    assert run(log) == [] and run.sent == [] and run.plan.empty
    # Un objet annoncé dont le relevé s'interrompt garde son état : le trou n'est pas un retour.
    state = AlertState(run.state_path)
    state.mark_slo(KEY, True, NOW)
    state.save()
    run(log)
    assert run.sent == [] and AlertState(run.state_path).slo_below(KEY)


def test_state_forgets_objects_without_target_or_unwatched(tmp_path: Path):
    config = config_with(99.0)
    log = daily_log(tmp_path / "availability.json")
    state = AlertState(tmp_path / STATE_FILE)
    state.mark_slo(KEY, True, NOW)
    state.mark_slo("tunnel:disparu", True, NOW)
    state.save()
    # L'objet disparu du journal est oublié, l'autre garde son état (toujours sous l'objectif : rien à annoncer).
    loaded = AlertState(tmp_path / STATE_FILE)
    assert crossings(log, config, loaded, NOW, UTC) == [] and set(loaded.slo) == {KEY}
    loaded.save()
    assert set(AlertState(tmp_path / STATE_FILE).slo) == {KEY}
    # Plus d'objectif : tout est oublié, et rien n'est annoncé.
    config.settings.availability_targets = {}
    plan = prepare_follow_up(log, config, loaded, check_digest=False, now=NOW, tz=UTC)
    assert plan.slo == [] and loaded.slo == {}
    # Un type dont la surveillance est coupée n'est pas suivi.
    set_target(config, KEY, 99.0)
    config.settings.watch_services = False
    assert crossings(log, config, AlertState(tmp_path / "autre.json"), NOW, UTC) == []


def test_default_target_applies_to_objects_without_one(tmp_path: Path):
    config = Config()
    config.settings.default_availability_target = 99.0
    log = daily_log(tmp_path / "availability.json")
    state = AlertState(tmp_path / STATE_FILE)
    found = crossings(log, config, state, NOW, UTC)
    assert [(c.key, c.target, c.recovered) for c in found] == [(KEY, 99.0, False)]
    set_target(config, KEY, 90.0)  # l'objectif propre l'emporte : 96,67 % est au-dessus
    assert crossings(log, config, state, NOW, UTC) == []


def test_alert_state_reads_old_and_damaged_files(tmp_path: Path):
    path = tmp_path / STATE_FILE
    path.write_text(
        json.dumps({"reminders": {"a": "2026-10-15T08:00:00Z"}, "digest_week": "2026-W42"}), encoding="utf-8"
    )
    old = AlertState(path)  # fichier d'avant P33 : pas de clé « slo »
    assert old.slo == {} and old.digest_week == "2026-W42" and not old.slo_below(KEY)
    old.mark_slo(KEY, True, NOW)
    old.save()
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["slo"] == {KEY: "2026-10-15T12:00:00Z"} and saved["reminders"] == {
        "a": "2026-10-15T08:00:00Z"
    }
    path.write_text(json.dumps({"slo": ["pas", "un", "dict"]}), encoding="utf-8")
    assert AlertState(path).slo == {}
    path.write_text(json.dumps({"slo": {"a": "2026-10-15T12:00:00Z", "b": 3}}), encoding="utf-8")
    assert AlertState(path).slo == {"a": "2026-10-15T12:00:00Z"}
    again = AlertState(path)
    again.mark_slo("a", False, NOW)
    assert again.dirty and "a" not in again.slo
    again.mark_slo("a", False, NOW)  # déjà retiré : rien à écrire de plus
    again.keep_only_slo(())  # rien à oublier
    assert again.slo == {}
    again.save()  # sans objet annoncé, la clé n'est pas écrite : le fichier de qui n'a pas d'objectif ne change pas
    assert "slo" not in json.loads(path.read_text(encoding="utf-8"))


# --- Mois civil -----------------------------------------------------------------------------------------------------


def test_month_parsing_and_bounds():
    assert parse_month("2026-10") == (2026, 10)
    for bad in ("2026-13", "2026-00", "26-10", "2026/10", "2026-1", "octobre", "", "2026-10-01", "abcd-ef"):
        with pytest.raises(ValueError, match="AAAA-MM"):
            parse_month(bad)
    today = date(2026, 10, 15)
    assert month_bounds("2026-09", today) == (date(2026, 9, 1), date(2026, 9, 30))
    assert month_bounds("2026-10", today) == (
        date(2026, 10, 1),
        date(2026, 10, 15),
    )  # le mois en cours : jusqu'à aujourd'hui
    assert month_bounds("2025-12", today) == (date(2025, 12, 1), date(2025, 12, 31))
    assert month_bounds("2026-02", today) == (date(2026, 2, 1), date(2026, 2, 28))
    assert month_bounds("2024-02", today) == (date(2024, 2, 1), date(2024, 2, 29))
    assert month_bounds("2026-10", date(2026, 10, 1)) == (date(2026, 10, 1), date(2026, 10, 1))
    with pytest.raises(ValueError, match="pas commencé"):
        month_bounds("2026-11", today)


def hourly_log(path: Path) -> AvailabilityLog:
    """Un test par heure du 24/10 au 2/11/2026, heure de Paris (changement d'heure le dimanche 25/10), échec le
    25/10 de 3 h à 5 h locales : jour de 25 heures, 25 tests dont 2 en échec."""
    log = AvailabilityLog(path)
    paris = Paris()
    at = datetime(2026, 10, 24, 22, 0, tzinfo=UTC)  # 25/10 à 00:00 à Paris (heure d'été)
    while at < datetime(2026, 11, 2, 12, 0, tzinfo=UTC):
        local = at.astimezone(paris)
        failing = local.date() == date(2026, 10, 25) and local.hour in (3, 4)
        log.record_check(KEY, "wiki.exemple.fr", not failing, 40.0, at, paris)
        at += timedelta(hours=1)
    return log


def test_month_report_with_dst_change(tmp_path: Path):
    paris = Paris()
    log = hourly_log(tmp_path / "availability.json")
    config = config_with(99.0)
    now = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
    report = month_report(log, config, "2026-10", now, paris)
    assert (
        report.month == "2026-10" and report.first == date(2026, 10, 1) and report.last == date(2026, 10, 31)
    )
    (row,) = report.rows
    # Du 25/10 00:00 au 31/10 23:00 locaux, sans le 1er novembre : 25 + 6 × 24 = 169 heures, 2 en échec.
    assert row.stats.checks == 169
    assert row.uptime == pytest.approx(167 / 169 * 100)
    assert row.target == 99.0 and row.below and row.gap == pytest.approx(167 / 169 * 100 - 99.0)
    # Le jour de 25 heures reste un seul jour.
    assert sum(len(v) for v in log.days.values()) == 9  # 25/10 → 2/11
    assert log.days[KEY]["2026-10-25"][1] == 25
    november = month_report(log, config, "2026-11", now, paris)
    assert (
        november.rows[0].stats.checks == 37
    )  # du 1/11 à 00:00 locale (31/10 à 23:00 UTC) au 2/11 à 12:00 UTC
    assert november.first == date(2026, 11, 1) and november.last == date(2026, 11, 20)  # le mois en cours


def test_month_report_current_month_goes_up_to_today(tmp_path: Path):
    log = daily_log(tmp_path / "availability.json")  # un test par jour du 16/9 au 15/10
    config = config_with(99.9)
    report = month_report(log, config, "2026-10", NOW, UTC)
    assert report.last == date(2026, 10, 15)
    (row,) = report.rows
    assert row.stats.checks == 15  # du 1er au 15 octobre
    assert row.uptime == pytest.approx(14 / 15 * 100) and row.below  # l'échec du jour compte
    september = month_report(log, config, "2026-09", NOW, UTC)
    assert september.rows[0].stats.checks == 15 and september.last == date(2026, 9, 30)  # 16 → 30 septembre
    # Un mois en cours qui n'a que le jour même : le rapport va jusqu'à aujourd'hui, pas au-delà.
    first_day = month_report(log, config, "2026-10", datetime(2026, 10, 1, 12, 0, tzinfo=UTC), UTC)
    assert first_day.first == first_day.last == date(2026, 10, 1)


def test_month_report_empty_and_errors(tmp_path: Path):
    log = daily_log(tmp_path / "availability.json")
    empty = month_report(log, Config(), "2026-01", NOW, UTC)
    assert empty.rows == [] and empty.incidents == [] and empty.month == "2026-01"
    assert month_report(AvailabilityLog(tmp_path / "vide.json"), Config(), "2026-09", NOW, UTC).rows == []
    with pytest.raises(ValueError, match="pas commencé"):
        month_report(log, Config(), "2026-11", NOW, UTC)
    with pytest.raises(ValueError, match="AAAA-MM"):
        month_report(log, Config(), "2026-1", NOW, UTC)


def test_month_incidents_are_clipped_to_the_month(tmp_path: Path):
    paris = Paris()
    log = AvailabilityLog(tmp_path / "availability.json")
    log.record_check(KEY, "wiki.exemple.fr", True, None, datetime(2026, 10, 31, 10, 0, tzinfo=UTC), paris)
    log.record_check("tunnel:t1", "bureau", True, None, datetime(2026, 10, 12, 10, 0, tzinfo=UTC), paris)
    # Panne à cheval sur la fin d'octobre : minuit local du 1er novembre = 23:00 UTC (heure d'hiver).
    log.start("service", KEY, "wiki.exemple.fr", "origin_down", datetime(2026, 10, 31, 22, 30, tzinfo=UTC))
    log.end("service", KEY, datetime(2026, 11, 1, 2, 0, tzinfo=UTC))
    # Panne close avant le mois, et panne ouverte (en cours) : seule la seconde compte.
    log.start("tunnel", "tunnel:t1", "bureau", "down", datetime(2026, 9, 1, 0, 0, tzinfo=UTC))
    log.end("tunnel", "tunnel:t1", datetime(2026, 9, 2, 0, 0, tzinfo=UTC))
    now = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
    report = month_report(log, Config(), "2026-10", now, paris)
    by_key = {r.key: r for r in report.rows}
    assert by_key[KEY].incidents == 1 and by_key[KEY].downtime == timedelta(minutes=30)
    assert by_key["tunnel:t1"].incidents == 0 and by_key["tunnel:t1"].downtime == timedelta()
    assert [i.key for i in report.incidents] == [KEY]
    # Le même incident, en novembre : il y compte de minuit local (23:00 UTC) à sa fin, 3 h.
    november = month_report(log, Config(), "2026-11", now, paris)
    (row,) = november.rows
    assert row.incidents == 1 and row.downtime == timedelta(hours=3) and row.stats.uptime is None
    # Passage à l'heure d'été (29/03/2026) : une panne de 21 h à 3 h UTC est coupée à minuit local du 1er avril.
    log2 = AvailabilityLog(tmp_path / "mars.json")
    log2.record_check(KEY, "wiki.exemple.fr", True, None, datetime(2026, 3, 29, 12, 0, tzinfo=UTC), paris)
    log2.start("service", KEY, "wiki.exemple.fr", "origin_down", datetime(2026, 3, 31, 21, 0, tzinfo=UTC))
    log2.end("service", KEY, datetime(2026, 4, 1, 3, 0, tzinfo=UTC))
    march = month_report(log2, Config(), "2026-03", now, paris)
    assert march.rows[0].downtime == timedelta(hours=1)  # minuit local = 22:00 UTC (heure d'été)
    # Un incident ouvert est compté jusqu'à maintenant (mois en cours).
    log2.start("tunnel", "tunnel:t2", "poste", "down", datetime(2026, 11, 20, 10, 0, tzinfo=UTC))
    current = month_report(log2, Config(), "2026-11", now, paris)
    assert current.rows[0].downtime == timedelta(hours=2) and current.rows[0].stats.uptime is None


def test_month_rows_sorted_worst_first(tmp_path: Path):
    log = AvailabilityLog(tmp_path / "availability.json")
    for key, label, fails in (
        ("tunnel:a", "alpha", 0),
        ("tunnel:b", "bravo", 5),
        ("service:c", "charlie", 1),
    ):
        for hour in range(10):
            log.record_check(
                key, label, hour >= fails, 10.0 * (hour + 1), datetime(2026, 9, 10, hour, tzinfo=UTC), UTC
            )
    report = month_report(log, Config(), "2026-09", NOW, UTC)
    assert [r.label for r in report.rows] == ["bravo", "charlie", "alpha"]
    assert report.rows[0].kind == "tunnel" and report.rows[1].kind == "service"
    assert report.rows[0].gap is None and report.rows[0].target is None  # sans objectif : pas d'écart
    assert report.rows[0].stats.mean_ms == pytest.approx(55.0) and report.rows[0].stats.max_ms == 100.0


def test_month_formats(tmp_path: Path):
    log = daily_log(tmp_path / "availability.json", failures=0)
    log.start("service", KEY, "wiki.<exemple>.fr", "origin_down", NOW - timedelta(days=3))
    log.end("service", KEY, NOW - timedelta(days=3) + timedelta(hours=2))
    log.labels[KEY] = "wiki.<exemple>.fr"
    config = config_with(99.0)
    report = month_report(log, config, "2026-10", NOW, UTC)
    (line,) = report_lines(report)
    assert "wiki.<exemple>.fr" in line and "99 %" in line and line.count("%") == 2
    data = json.loads(month_json(report))
    assert data["month"] == "2026-10" and data["from"] == "2026-10-01" and data["to"] == "2026-10-15"
    obj = data["objects"][0]
    assert (
        obj["target"] == 99.0
        and obj["uptime"] == 1.0
        and obj["gap"] == pytest.approx(1.0)
        and not obj["below"]
    )
    assert (
        obj["incidents"] == 1 and obj["downtime_s"] == 7200 and data["incidents"][0]["state"] == "origin_down"
    )
    csv_text = month_csv(report)
    assert csv_text.splitlines()[0].startswith("Objet;Type;Disponibilité;Objectif;Écart (points)")
    assert "wiki.<exemple>.fr;Service;100.00 %;99 %;+1.00" in csv_text and "origin_down" in csv_text
    page = month_html(report, NOW)
    assert (
        "Disponibilité de 2026-10" in page and "wiki.&lt;exemple&gt;.fr" in page and "<exemple>" not in page
    )
    assert "http://" not in page and "https://" not in page
    # Sous l'objectif : écart négatif et teinte.
    set_target(config, KEY, 100.0)
    low = daily_log(tmp_path / "b.json", failures=2)
    report = month_report(low, config, "2026-10", NOW, UTC)
    assert report.rows[0].below and "bad" in month_html(report, NOW) and "-" in month_csv(report)
    # Rapport vide, et mois sans incident.
    empty = month_report(low, config, "2026-01", NOW, UTC)
    assert "Aucun relevé sur la période." in month_html(empty, NOW) and "Aucun incident" in month_html(
        empty, NOW
    )
    assert json.loads(month_json(empty))["objects"] == [] and report_lines(empty) == []
    still = AvailabilityLog(tmp_path / "c.json")
    still.record_check(KEY, "x", True, None, NOW, UTC)
    still.start("service", KEY, "x", "down", NOW - timedelta(hours=1))
    assert 'class="open">en cours' in month_html(month_report(still, Config(), "2026-10", NOW, UTC), NOW)


# --- Ligne de commande ----------------------------------------------------------------------------------------------


def make_paths(tmp_path: Path) -> AppPaths:
    paths = AppPaths(tmp_path / "data")
    paths.ensure()
    return paths


def test_cli_month_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    paths = make_paths(tmp_path)
    # Sans relevé : rapport vide, code 0.
    assert cli.show_availability(paths, month="2026-09", now=NOW, tz=UTC) == 0
    assert "Aucun relevé en 2026-09" in capsys.readouterr().out
    assert cli.show_availability(paths, month="2026-09", as_json=True, now=NOW, tz=UTC) == 0
    assert json.loads(capsys.readouterr().out)["objects"] == []
    daily_log(paths.data_dir / "availability.json").save(NOW, UTC)
    config = Config()
    set_target(config, KEY, 99.9)
    (paths.data_dir / "config.json").write_text(config.model_dump_json(), encoding="utf-8")
    assert cli.show_availability(paths, month="2026-09", now=NOW, tz=UTC) == 0
    out = capsys.readouterr().out
    assert "Disponibilité de 2026-09 (du 01/09/2026 au 30/09/2026)" in out
    assert "wiki.exemple.fr" in out and "99.9 %" in out and "+0.10" in out
    # Le mois en cours s'arrête à aujourd'hui.
    assert cli.show_availability(paths, month="2026-10", as_json=True, now=NOW, tz=UTC) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["to"] == "2026-10-15" and data["objects"][0]["checks"] == 15
    # Fichiers de rapport selon l'extension.
    for name in ("m.html", "m.csv", "m.json"):
        target = tmp_path / name
        assert cli.show_availability(paths, month="2026-09", output=str(target), now=NOW, tz=UTC) == 0
        assert target.exists() and "Rapport enregistré" in capsys.readouterr().out
    assert (tmp_path / "m.csv").read_bytes().startswith(b"\xef\xbb\xbf")
    assert json.loads((tmp_path / "m.json").read_text(encoding="utf-8"))["month"] == "2026-09"
    assert "<html" in (tmp_path / "m.html").read_text(encoding="utf-8")
    # Erreurs : code 1, message sur la sortie d'erreur.
    assert cli.show_availability(paths, month="2026-13", now=NOW, tz=UTC) == 1
    assert "AAAA-MM" in capsys.readouterr().err
    assert cli.show_availability(paths, month="2027-01", now=NOW, tz=UTC) == 1
    assert "pas commencé" in capsys.readouterr().err
    assert cli.show_availability(paths, month="2026-09", output=str(tmp_path / "m.txt"), now=NOW, tz=UTC) == 1
    assert "Extension inconnue" in capsys.readouterr().err
    blocker = tmp_path / "bloc"
    blocker.write_text("un fichier, pas un dossier", encoding="utf-8")
    assert cli.show_availability(paths, month="2026-09", output=str(blocker / "m.html"), now=NOW, tz=UTC) == 1
    assert "Erreur" in capsys.readouterr().err


def test_cli_parser_accepts_month():
    args = cli.build_parser().parse_args(["availability", "--month", "2026-10", "--json"])
    assert args.month == "2026-10" and args.json and args.days == 30
    assert cli.build_parser().parse_args(["availability"]).month is None
