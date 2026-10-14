"""Séries par jour et rapport de disponibilité (CSV, HTML, JSON), commande `cma availability`."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from cma import cli
from cma.core.availability import AvailabilityLog, daily, report
from cma.core.availability_report import build, report_csv, report_html, report_json
from cma.paths import AppPaths

NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)


def sample_log(path) -> AvailabilityLog:
    log = AvailabilityLog(path)
    for hours in range(48):
        ok = hours not in (5, 6)
        log.record_check(
            "service:wiki", "wiki.<exemple>.fr", ok, 100.0 + hours, NOW - timedelta(hours=hours), UTC
        )
    log.record_check("tunnel:t1", "bureau", True, None, NOW, UTC)
    log.start("service", "service:wiki", "wiki.<exemple>.fr", "origin_down", NOW - timedelta(hours=6))
    log.end("service", "service:wiki", NOW - timedelta(hours=4, minutes=30))
    log.start("tunnel", "tunnel:t1", "bureau", "down", NOW - timedelta(minutes=20))
    # Un incident ancien, en partie hors de la période de 1 jour.
    log.start("service", "service:vieux", "vieux.fr", "no_connector", NOW - timedelta(days=2))
    log.end("service", "service:vieux", NOW - timedelta(hours=23))
    return log


def test_daily_series_keeps_empty_days(tmp_path):
    log = sample_log(tmp_path / "a.json")
    series = daily(log, "service:wiki", 4, NOW, UTC)
    assert [d.day for d in series] == ["2026-10-06", "2026-10-07", "2026-10-08", "2026-10-09"]
    assert series[0].uptime is None and series[0].checks == 0  # aucun relevé : pas une panne
    assert series[-1].checks == 13 and round(series[-1].uptime or 0, 3) == round(11 / 13, 3)


def test_report_rows_and_downtime(tmp_path):
    log = sample_log(tmp_path / "a.json")
    rows = {r.key: r for r in report(log, 1, NOW, UTC)}
    assert rows["service:wiki"].downtime == timedelta(hours=1, minutes=30)
    assert rows["tunnel:t1"].downtime == timedelta(minutes=20) and rows["tunnel:t1"].kind == "tunnel"
    assert rows["service:vieux"].downtime == timedelta(hours=1)  # bornée au début de la période
    ordered = [r.key for r in report(log, 1, NOW, UTC)]
    assert ordered[0] == "service:wiki"  # le moins disponible d'abord


def test_report_formats(tmp_path):
    log = sample_log(tmp_path / "a.json")
    rows, incidents = build(log, 30, NOW, UTC)
    text = report_csv(rows, incidents)
    assert text.splitlines()[0].startswith("Objet;Type;Disponibilité")
    assert "wiki.<exemple>.fr;Service;95.83 %" in text and "en cours" in text
    page = report_html(rows, incidents, 30, "Compte <test>", NOW)
    assert (
        page.startswith("<!doctype html>")
        and "<script" not in page
        and "http" not in page.split("</style>")[1]
    )
    assert "wiki.&lt;exemple&gt;.fr" in page and "Compte &lt;test&gt;" in page and "<exemple>" not in page
    data = json.loads(report_json(rows, incidents, 30))
    wiki = next(o for o in data["objects"] if o["key"] == "service:wiki")
    assert wiki["incidents"] == 1 and wiki["downtime_s"] == 5400 and data["days"] == 30
    assert any(i["ended"] is None for i in data["incidents"])
    empty = report_html([], [], 7, now=NOW)
    assert "Aucun incident sur la période." in empty


def test_report_html_language(tmp_path):
    from cma.i18n import get_language, set_language

    previous = get_language()
    set_language("de")
    try:
        page = report_html([], [], 7, now=NOW)
    finally:
        set_language(previous)
    assert '<html lang="de">' in page and "Verfügbarkeit der letzten 7 Tage" in page


def test_cli_availability(tmp_path, capsys):
    paths = AppPaths(tmp_path / "data")
    paths.ensure()
    assert cli.show_availability(paths) == 0
    assert "Aucun relevé" in capsys.readouterr().out
    log = sample_log(paths.data_dir / "availability.json")
    log.save(NOW)
    assert cli.show_availability(paths, days=90) == 2  # le tunnel est encore en panne
    out = capsys.readouterr().out
    assert "bureau" in out and "wiki.<exemple>.fr" in out
    assert cli.show_availability(paths, days=90, as_json=True) == 2
    assert json.loads(capsys.readouterr().out)["days"] == 90
