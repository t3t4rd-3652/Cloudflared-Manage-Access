"""Disponibilité par jour local : fuseau explicite, ancien fichier, changements d'heure (P23).

Aucun test ne dépend du fuseau du poste ni du paquet `tzdata` : les fuseaux sont à décalage fixe, ou `Paris`
ci-dessous, une simulation de l'heure d'Europe centrale (UTC+1 l'hiver, UTC+2 l'été, règles européennes).
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta, timezone, tzinfo
from itertools import pairwise

from cma.core.availability import VERSION, AvailabilityLog, daily, local_date, report

PLUS_2 = timezone(timedelta(hours=2))
MINUS_5 = timezone(timedelta(hours=-5))


def _last_sunday(year: int, month: int) -> date:
    day = date(year, month, 31)  # mars et octobre ont 31 jours
    return day - timedelta(days=(day.weekday() + 1) % 7)


class Paris(tzinfo):
    """Heure d'Europe centrale : heure d'été du dernier dimanche de mars à celui d'octobre, à 01:00 UTC."""

    def _bounds(self, year: int) -> tuple[datetime, datetime]:
        start = datetime.combine(_last_sunday(year, 3), datetime.min.time()) + timedelta(hours=1)
        end = datetime.combine(_last_sunday(year, 10), datetime.min.time()) + timedelta(hours=1)
        return start, end  # en UTC naïf

    def utcoffset(self, dt: datetime | None) -> timedelta:
        assert dt is not None
        start, end = self._bounds(dt.year)
        naive = dt.replace(tzinfo=None)
        winter, summer = timedelta(hours=1), timedelta(hours=2)
        if naive < start + winter:  # avant 02:00 local le jour du passage à l'heure d'été
            return winter
        if naive < end + winter:  # jusqu'à 02:00 local, le jour du retour à l'heure d'hiver
            return summer
        if naive < end + summer:  # 02:00 à 03:00 : heure répétée, la seconde fois avec fold=1
            return winter if dt.fold else summer
        return winter

    def dst(self, dt: datetime | None) -> timedelta:
        assert dt is not None
        return self.utcoffset(dt) - timedelta(hours=1)

    def tzname(self, dt: datetime | None) -> str:
        return "CEST" if self.dst(dt) else "CET"

    def fromutc(self, dt: datetime) -> datetime:
        start, end = self._bounds(dt.year)
        naive = dt.replace(tzinfo=None)
        if start <= naive < end:
            return (naive + timedelta(hours=2)).replace(tzinfo=self)
        local = (naive + timedelta(hours=1)).replace(tzinfo=self)
        # La première heure suivant la fin de l'heure d'été est la seconde occurrence de l'heure locale.
        return local.replace(fold=1) if end <= naive < end + timedelta(hours=1) else local


PARIS = Paris()


def test_paris_simulation_matches_the_real_transitions():
    assert datetime(2026, 3, 28, 23, tzinfo=UTC).astimezone(PARIS).hour == 0  # minuit local, le 29
    assert datetime(2026, 3, 29, 22, tzinfo=UTC).astimezone(PARIS).day == 30  # 00:00 le 30 (UTC+2)
    assert datetime(2026, 10, 24, 22, tzinfo=UTC).astimezone(PARIS).day == 25
    assert (
        datetime(2026, 10, 25, 22, tzinfo=UTC).astimezone(PARIS).day == 25
    )  # 23:00 local (UTC+1) : encore le 25
    assert datetime(2026, 10, 25, 23, tzinfo=UTC).astimezone(PARIS).day == 26


def test_late_check_counts_for_its_local_day(tmp_path):
    log = AvailabilityLog(tmp_path / "a.json")
    # 23 h 30 à UTC+2 le 9 : 21 h 30 UTC, même jour. 00 h 30 à UTC+2 le 10 : 22 h 30 UTC le 9, mais jour local 10.
    log.record_check("tunnel:t1", "bureau", True, None, datetime(2026, 10, 9, 21, 30, tzinfo=UTC), PLUS_2)
    log.record_check("tunnel:t1", "bureau", False, None, datetime(2026, 10, 9, 22, 30, tzinfo=UTC), PLUS_2)
    assert sorted(log.days["tunnel:t1"]) == ["2026-10-09", "2026-10-10"]
    assert log.days["tunnel:t1"]["2026-10-10"][:2] == [0, 1]
    # À l'ouest de Greenwich, le jour local est en retard sur l'UTC : 21 h à UTC-5 le 9 est le 10 en UTC.
    log.record_check("tunnel:t2", "autre", True, None, datetime(2026, 10, 10, 2, tzinfo=UTC), MINUS_5)
    assert list(log.days["tunnel:t2"]) == ["2026-10-09"]


def test_default_zone_is_the_local_one(tmp_path):
    at = datetime(2026, 7, 1, 22, 30, tzinfo=UTC)
    assert local_date(at) == at.astimezone().date()
    assert local_date(at, None) == local_date(at, at.astimezone().tzinfo)
    log = AvailabilityLog(tmp_path / "a.json")
    log.record_check("service:x", "x", True, 10.0, at)
    assert list(log.days["service:x"]) == [at.astimezone().date().isoformat()]


def test_daily_and_stats_follow_the_local_day(tmp_path):
    log = AvailabilityLog(tmp_path / "a.json")
    # Un incident vers minuit à Paris (22 h 30 UTC le 8 = 00 h 30 le 9, UTC+2) : la barre est celle du 9.
    log.record_check("service:x", "x", False, None, datetime(2026, 10, 8, 22, 30, tzinfo=UTC), PARIS)
    log.record_check("service:x", "x", True, 80.0, datetime(2026, 10, 9, 10, tzinfo=UTC), PARIS)
    now = datetime(2026, 10, 9, 12, tzinfo=UTC)
    series = daily(log, "service:x", 3, now, PARIS)
    assert [d.day for d in series] == ["2026-10-07", "2026-10-08", "2026-10-09"]
    assert series[1].uptime is None and series[2].checks == 2 and series[2].uptime == 0.5
    # Le jour d'un relevé est celui du fuseau demandé : l'incident de 00 h 30 (Paris) est classé le 9, pas le 8.
    assert list(log.days["service:x"]) == ["2026-10-09"]
    assert [d.checks for d in series] == [0, 0, 2]
    # Les mêmes relevés classés en UTC tomberaient la veille : le 8 a un relevé, le 9 un seul.
    utc_log = AvailabilityLog(tmp_path / "utc.json")
    utc_log.record_check("service:x", "x", False, None, datetime(2026, 10, 8, 22, 30, tzinfo=UTC), UTC)
    utc_log.record_check("service:x", "x", True, 80.0, datetime(2026, 10, 9, 10, tzinfo=UTC), UTC)
    assert list(utc_log.days["service:x"]) == ["2026-10-08", "2026-10-09"]
    assert [d.checks for d in daily(utc_log, "service:x", 3, now, UTC)] == [0, 1, 1]
    assert log.stats("service:x", 1, now, PARIS).checks == 2
    # Le 9 à 23 h 30 UTC, il est déjà le 10 à Paris : « aujourd'hui » a changé, et le 9 reste le jour précédent.
    late = datetime(2026, 10, 9, 23, 30, tzinfo=UTC)
    assert daily(log, "service:x", 1, late, PARIS)[0].day == "2026-10-10"
    assert log.stats("service:x", 1, late, PARIS).checks == 0
    assert log.stats("service:x", 2, late, PARIS).checks == 2
    assert [r.stats.checks for r in report(log, 1, now, PARIS)] == [2]


def test_old_file_without_version_is_read_without_loss(tmp_path):
    path = tmp_path / "availability.json"
    old = {
        "incidents": [
            {
                "kind": "service",
                "key": "service:wiki",
                "label": "wiki",
                "state": "down",
                "started": "2026-10-08T21:50:00Z",
                "ended": "2026-10-08T22:10:00Z",
            }
        ],
        "days": {"service:wiki": {"2026-10-08": [9, 10, 1000.0, 300.0, 10]}},
        "labels": {"service:wiki": "wiki"},
    }
    path.write_text(json.dumps(old), encoding="utf-8")
    log = AvailabilityLog(path)
    assert log.version == 1
    assert log.days == old["days"] and len(log.incidents) == 1
    now = datetime(2026, 10, 9, 12, tzinfo=UTC)
    day = daily(log, "service:wiki", 2, now, PARIS)[0]
    assert (day.day, day.checks, day.uptime, day.mean_ms) == ("2026-10-08", 10, 0.9, 100.0)  # date gardée
    # Un relevé neuf s'ajoute au jour existant sans rien perdre, puis le fichier est réécrit en version 2.
    log.record_check("service:wiki", "wiki", True, 50.0, now, PARIS)
    log.save(now, PARIS)
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["version"] == VERSION == 2
    assert saved["days"]["service:wiki"]["2026-10-08"] == [9, 10, 1000.0, 300.0, 10]
    assert saved["days"]["service:wiki"]["2026-10-09"][:2] == [1, 1]
    again = AvailabilityLog(path)
    assert again.version == 2 and again.days == saved["days"] and again.incidents == log.incidents


def test_version_field_is_tolerant(tmp_path):
    path = tmp_path / "availability.json"
    for raw in ('"deux"', "true", "null", "[]"):
        path.write_text('{"version": ' + raw + ', "days": {}}', encoding="utf-8")
        assert AvailabilityLog(path).version == 1
    # Un fichier plus récent n'est jamais rétrogradé.
    path.write_text('{"version": 7, "days": {}}', encoding="utf-8")
    log = AvailabilityLog(path)
    log.save()
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 7
    # Fichier illisible : journal vide en version courante.
    path.write_text("{pas du json", encoding="utf-8")
    assert AvailabilityLog(path).days == {}


def test_prune_uses_local_days(tmp_path):
    log = AvailabilityLog(tmp_path / "a.json")
    log.days = {"service:x": {"2026-07-11": [1, 1, 0.0, 0.0, 0], "2026-07-12": [1, 1, 0.0, 0.0, 0]}}
    log.labels = {"service:x": "x"}
    now = datetime(2026, 10, 9, 23, 30, tzinfo=UTC)  # le 10 à UTC+2 : la limite est le 12 juillet
    log.prune(now, PLUS_2)
    assert list(log.days["service:x"]) == ["2026-07-12"]
    log.prune(now, UTC)  # le 9 en UTC : la limite est le 11 juillet, mais le 11 est déjà parti
    assert list(log.days["service:x"]) == ["2026-07-12"]
    log.days = {"service:x": {"2026-07-11": [1, 1, 0.0, 0.0, 0]}}
    log.prune(now, UTC)
    assert list(log.days["service:x"]) == ["2026-07-11"]
    log.prune(now + timedelta(days=1), PLUS_2)
    assert log.days == {} and log.labels == {}


def _hourly(log: AvailabilityLog, first: datetime, count: int, tz: tzinfo) -> None:
    for hour in range(count):
        log.record_check("tunnel:t1", "bureau", True, None, first + timedelta(hours=hour), tz)


def test_spring_forward_day_has_23_hours(tmp_path):
    """Le 29 mars 2026, Paris passe à l'heure d'été : un jour de 23 heures, ni perdu ni doublé."""
    log = AvailabilityLog(tmp_path / "a.json")
    _hourly(
        log, datetime(2026, 3, 27, 23, tzinfo=UTC), 24 * 4, PARIS
    )  # une heure par heure, du 28 au 31 mars
    rows = log.days["tunnel:t1"]
    assert {day: int(v[1]) for day, v in rows.items()} == {
        "2026-03-28": 24,
        "2026-03-29": 23,
        "2026-03-30": 24,
        "2026-03-31": 24,
        "2026-04-01": 1,  # la 96e heure est déjà le lendemain : 95 heures locales du 28 au 31
    }
    now = datetime(2026, 3, 31, 12, tzinfo=UTC)
    series = daily(log, "tunnel:t1", 5, now, PARIS)
    assert [d.day for d in series] == ["2026-03-27", "2026-03-28", "2026-03-29", "2026-03-30", "2026-03-31"]
    assert [d.checks for d in series] == [0, 24, 23, 24, 24]  # aucun jour doublé, aucun sauté


def test_spring_forward_exact_counts(tmp_path):
    log = AvailabilityLog(tmp_path / "a.json")
    # Du minuit local du 29 (23 h UTC le 28) au minuit local du 30 (22 h UTC le 29) : 23 heures.
    _hourly(log, datetime(2026, 3, 28, 23, tzinfo=UTC), 23, PARIS)
    assert {day: int(v[1]) for day, v in log.days["tunnel:t1"].items()} == {"2026-03-29": 23}
    log.record_check("tunnel:t1", "bureau", True, None, datetime(2026, 3, 29, 22, tzinfo=UTC), PARIS)
    assert int(log.days["tunnel:t1"]["2026-03-30"][1]) == 1
    # Quatre jours locaux autour du passage : quatre points consécutifs.
    now = datetime(2026, 3, 30, 12, tzinfo=UTC)
    assert [d.day for d in daily(log, "tunnel:t1", 4, now, PARIS)] == [
        "2026-03-27",
        "2026-03-28",
        "2026-03-29",
        "2026-03-30",
    ]
    assert log.stats("tunnel:t1", 2, now, PARIS).checks == 24


def test_fall_back_day_has_25_hours(tmp_path):
    """Le 25 octobre 2026, Paris revient à l'heure d'hiver : un jour de 25 heures, un seul point."""
    log = AvailabilityLog(tmp_path / "a.json")
    # Du minuit local du 25 (22 h UTC le 24, UTC+2) à celui du 26 (23 h UTC le 25, UTC+1) : 25 heures.
    _hourly(log, datetime(2026, 10, 24, 22, tzinfo=UTC), 25, PARIS)
    assert {day: int(v[1]) for day, v in log.days["tunnel:t1"].items()} == {"2026-10-25": 25}
    log.record_check("tunnel:t1", "bureau", False, None, datetime(2026, 10, 25, 23, tzinfo=UTC), PARIS)
    assert int(log.days["tunnel:t1"]["2026-10-26"][1]) == 1
    now = datetime(2026, 10, 26, 12, tzinfo=UTC)
    series = daily(log, "tunnel:t1", 4, now, PARIS)
    assert [d.day for d in series] == ["2026-10-23", "2026-10-24", "2026-10-25", "2026-10-26"]
    assert [d.checks for d in series] == [0, 0, 25, 1]
    assert log.stats("tunnel:t1", 2, now, PARIS).checks == 26


def test_each_hour_of_the_transition_days_maps_to_one_local_day():
    """Sur 72 heures autour de chaque passage, les jours locaux se suivent : un seul changement par minuit."""
    for start in (datetime(2026, 3, 28, 0, tzinfo=UTC), datetime(2026, 10, 24, 0, tzinfo=UTC)):
        days = [local_date(start + timedelta(hours=h), PARIS) for h in range(72)]
        assert days == sorted(days)
        assert len(set(days)) == 4  # trois jours de 24 h (ou 23, 25) à cheval sur quatre dates
        assert all((b - a).days in (0, 1) for a, b in pairwise(days))
