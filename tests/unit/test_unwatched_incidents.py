"""Un objet qui n'est plus relevé (tunnel inactif ou supprimé, service retiré) ne garde pas un incident ouvert : sinon
rappel toutes les N heures et « En cours » dans chaque résumé, sans fin (P28)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cma.core.alertstate import STATE_FILE, AlertState
from cma.core.availability import AvailabilityLog
from cma.core.cfapi import Tunnel
from cma.core.digest import build_digest
from cma.core.hostprobe import HostProbe
from cma.core.models import Config
from cma.core.monitoring import record_services, record_tunnels, reminder_events
from cma.core.servicewatch import ServiceTarget

T0 = datetime(2026, 10, 14, 6, 0, tzinfo=UTC)
WIKI = ServiceTarget("wiki.exemple.fr", "", "http://localhost:8080", "t1", "bureau")
BLOG = ServiceTarget("blog.exemple.fr", "", "http://localhost:8081", "t1", "bureau")


def config_with_reminders() -> Config:
    config = Config()
    config.settings.alert_repeat_hours = 4
    return config


def reminders(log: AvailabilityLog, config: Config, tmp_path: Path, at: datetime) -> list[str]:
    return [e.key for e in reminder_events(log, config, AlertState(tmp_path / STATE_FILE), at, UTC)]


def open_keys(log: AvailabilityLog) -> list[str]:
    return sorted(i.key for i in log.incidents if i.open)


def test_tunnel_going_inactive_closes_its_incident(tmp_path: Path):
    log = AvailabilityLog(tmp_path / "a.json")
    config = config_with_reminders()
    record_tunnels(log, config, [Tunnel("t1", "labo", "down"), Tunnel("t2", "bureau", "healthy")], T0)
    assert open_keys(log) == ["tunnel:t1"]
    late = T0 + timedelta(days=60)
    assert reminders(log, config, tmp_path, late) == ["tunnel:t1"]  # tant qu'il est en panne : rappelé
    # Le tunnel est arrêté pour de bon : « inactive ». Aucun événement (ni retour, ni panne), mais l'incident est clos.
    events = record_tunnels(
        log,
        config,
        [Tunnel("t1", "labo", "inactive"), Tunnel("t2", "bureau", "healthy")],
        T0 + timedelta(hours=1),
    )
    assert events == []
    assert open_keys(log) == []
    assert log.incidents[0].ended == "2026-10-14T07:00:00Z"
    assert reminders(log, config, tmp_path, late) == []
    assert "En cours" not in build_digest(log, config, late, UTC).text


def test_tunnel_missing_from_the_list_closes_its_incident(tmp_path: Path):
    log = AvailabilityLog(tmp_path / "a.json")
    config = config_with_reminders()
    record_tunnels(log, config, [Tunnel("t1", "labo", "down"), Tunnel("t2", "bureau", "degraded")], T0)
    assert open_keys(log) == ["tunnel:t1", "tunnel:t2"]
    # t1 est supprimé du compte ; t2, toujours là et dégradé, garde son incident.
    assert record_tunnels(log, config, [Tunnel("t2", "bureau", "degraded")], T0 + timedelta(hours=1)) == []
    assert open_keys(log) == ["tunnel:t2"]
    assert reminders(log, config, tmp_path, T0 + timedelta(days=60)) == ["tunnel:t2"]
    # Compte sans aucun tunnel : le relevé a réussi, tout est clos.
    record_tunnels(log, config, [], T0 + timedelta(hours=2))
    assert open_keys(log) == []


def test_failed_tunnel_survey_closes_nothing(tmp_path: Path):
    log = AvailabilityLog(tmp_path / "a.json")
    config = config_with_reminders()
    record_tunnels(log, config, [Tunnel("t1", "labo", "down")], T0)
    assert record_tunnels(log, config, [], T0 + timedelta(hours=1), complete=False) == []
    assert open_keys(log) == ["tunnel:t1"]


def test_service_missing_from_a_successful_survey_is_closed(tmp_path: Path):
    log = AvailabilityLog(tmp_path / "a.json")
    config = config_with_reminders()
    down = HostProbe("origin_down", 502, ms=12.0)
    record_services(log, config, [(WIKI, down), (BLOG, down)], T0)
    assert open_keys(log) == ["service:blog.exemple.fr", "service:wiki.exemple.fr"]
    late = T0 + timedelta(days=30)
    assert len(reminders(log, config, tmp_path, late)) == 2
    # Le nom d'hôte du blog n'est plus publié : relevé réussi sans lui. Pas d'événement de retour.
    events = record_services(log, config, [(WIKI, down)], T0 + timedelta(hours=1))
    assert events == []
    assert open_keys(log) == ["service:wiki.exemple.fr"]
    assert reminders(log, config, tmp_path, late) == ["service:wiki.exemple.fr"]
    assert "En cours : wiki.exemple.fr" in build_digest(log, config, late, UTC).text.splitlines()


def test_unreachable_service_keeps_its_incident(tmp_path: Path):
    log = AvailabilityLog(tmp_path / "a.json")
    config = config_with_reminders()
    record_services(
        log, config, [(WIKI, HostProbe("origin_down", 502, ms=12.0)), (BLOG, HostProbe("ok", 200))], T0
    )
    # Le poste n'a plus de réseau : « sans réponse » ne change pas l'état connu, le relevé reste réussi.
    events = record_services(
        log,
        config,
        [(WIKI, HostProbe("unreachable")), (BLOG, HostProbe("unreachable"))],
        T0 + timedelta(hours=1),
    )
    assert events == []
    assert open_keys(log) == ["service:wiki.exemple.fr"]


def test_empty_service_survey_closes_nothing(tmp_path: Path):
    # Relevé vide : échec de la tâche planifiée (`tested = []`) ou relevé non demandé, jamais de quoi tout fermer.
    log = AvailabilityLog(tmp_path / "a.json")
    config = config_with_reminders()
    record_services(log, config, [(WIKI, HostProbe("origin_down", 502, ms=12.0))], T0)
    assert record_services(log, config, [], T0 + timedelta(hours=1)) == []
    assert open_keys(log) == ["service:wiki.exemple.fr"]
    assert record_services(log, config, [], T0 + timedelta(hours=1), complete=False) == []
    assert open_keys(log) == ["service:wiki.exemple.fr"]
    # Un appelant qui sait que le relevé a réussi sans aucun service à tester peut le dire.
    record_services(log, config, [], T0 + timedelta(hours=2), complete=True)
    assert open_keys(log) == []


def test_closing_leaves_other_kinds_alone(tmp_path: Path):
    log = AvailabilityLog(tmp_path / "a.json")
    config = config_with_reminders()
    record_tunnels(log, config, [Tunnel("t1", "labo", "down")], T0)
    record_services(log, config, [(WIKI, HostProbe("origin_down", 502, ms=12.0))], T0)
    record_services(log, config, [(BLOG, HostProbe("ok", 200))], T0 + timedelta(hours=1))
    assert open_keys(log) == ["tunnel:t1"]  # le relevé des services ne touche pas aux tunnels
    record_tunnels(log, config, [Tunnel("t9", "autre", "healthy")], T0 + timedelta(hours=1))
    assert open_keys(log) == []


def test_service_recovery_is_still_announced(tmp_path: Path):
    log = AvailabilityLog(tmp_path / "a.json")
    config = config_with_reminders()
    record_services(log, config, [(WIKI, HostProbe("origin_down", 502, ms=12.0))], T0)
    events = record_services(log, config, [(WIKI, HostProbe("ok", 200, ms=9.0))], T0 + timedelta(hours=1))
    assert [(e.key, e.recovered) for e in events] == [("service:wiki.exemple.fr", True)]
    assert open_keys(log) == []


def test_unwatched_kind_is_neither_reminded_nor_announced(tmp_path: Path):
    """Surveillance des services (ou des tunnels) coupée : ses incidents ouverts ne sont plus rappelés ni annoncés
    « en cours » dans le résumé, puisque rien ne les clôt plus."""
    log = AvailabilityLog(tmp_path / "a.json")
    config = config_with_reminders()
    record_services(log, config, [(WIKI, HostProbe("origin_down", 502, ms=12.0))], T0)
    record_tunnels(log, config, [Tunnel("t2", "labo", "down")], T0)
    late = T0 + timedelta(days=30)
    assert sorted(reminders(log, config, tmp_path, late)) == ["service:wiki.exemple.fr", "tunnel:t2"]
    config.settings.watch_services = False
    assert reminders(log, config, tmp_path, late) == ["tunnel:t2"]
    assert not any(
        "wiki.exemple.fr" in line
        for line in build_digest(log, config, late, UTC).text.splitlines()
        if line.startswith("En cours")
    )
    config.settings.watch_tunnels = False
    assert reminders(log, config, tmp_path, late) == []


def test_tunnel_of_a_service_is_remembered_for_maintenance(tmp_path: Path):
    """La maintenance du tunnel couvre ses noms même quand le relevé des services n'a pas encore eu lieu : la
    correspondance nom d'hôte → tunnel est gardée dans `alert_state.json`."""
    from cma.core.models import MaintenanceWindow
    from cma.core.monitoring import prepare_follow_up

    log = AvailabilityLog(tmp_path / "a.json")
    config = config_with_reminders()
    record_services(log, config, [(WIKI, HostProbe("origin_down", 502, ms=12.0))], T0)
    late = T0 + timedelta(days=1)
    local = late.astimezone(UTC)
    config.settings.maintenance_windows = [
        MaintenanceWindow(weekday=local.weekday(), start="00:00", end="23:59", target="tunnel:t1")
    ]
    state_file = tmp_path / STATE_FILE
    # Premier passage avec un relevé des services : la correspondance est notée et le rappel est couvert.
    plan = prepare_follow_up(
        log,
        config,
        AlertState(state_file),
        check_digest=False,
        now=late,
        tz=UTC,
        tunnel_of={"service:wiki.exemple.fr": "t1"},
    )
    assert plan.reminders == []
    plan.state.save()
    # Plus tard, sans relevé des services (démarrage, tâche planifiée) : toujours couvert, d'après le fichier.
    plan = prepare_follow_up(log, config, AlertState(state_file), check_digest=False, now=late, tz=UTC)
    assert plan.reminders == []
    # Sans la maintenance, le rappel repart.
    config.settings.maintenance_windows = []
    plan = prepare_follow_up(log, config, AlertState(state_file), check_digest=False, now=late, tz=UTC)
    assert [e.key for e in plan.reminders] == ["service:wiki.exemple.fr"]


def test_switching_off_a_watch_closes_its_open_incidents_without_event(tmp_path: Path):
    """Surveillance coupée (P29) : les incidents ouverts de son type sont clos, ceux de l'autre type restent, et
    aucun événement n'est produit (rien à annoncer, rien à notifier)."""
    from cma.core.monitoring import close_unwatched_kinds

    log = AvailabilityLog(tmp_path / "a.json")
    config = config_with_reminders()
    record_tunnels(log, config, [Tunnel("t1", "labo", "down")], T0)
    record_services(log, config, [(WIKI, HostProbe("origin_down", 502, ms=12.0))], T0)
    assert open_keys(log) == ["service:wiki.exemple.fr", "tunnel:t1"]
    # Tout est surveillé : rien n'est clos.
    assert close_unwatched_kinds(log, config, T0 + timedelta(hours=1)) == 0
    assert open_keys(log) == ["service:wiki.exemple.fr", "tunnel:t1"]
    # Services coupés : seul l'incident du service est clos, à l'heure de la coupure.
    config.settings.watch_services = False
    assert close_unwatched_kinds(log, config, T0 + timedelta(hours=2)) == 1
    assert open_keys(log) == ["tunnel:t1"]
    wiki = next(i for i in log.incidents if i.key == "service:wiki.exemple.fr")
    assert wiki.ended == "2026-10-14T08:00:00Z"
    assert close_unwatched_kinds(log, config, T0 + timedelta(hours=3)) == 0  # déjà clos : rien de plus
    # Tunnels coupés à leur tour : le dernier incident ouvert est clos, l'ancien n'est pas retouché.
    config.settings.watch_tunnels = False
    assert close_unwatched_kinds(log, config, T0 + timedelta(hours=4)) == 1
    assert open_keys(log) == [] and wiki.ended == "2026-10-14T08:00:00Z"
    assert reminders(log, config, tmp_path, T0 + timedelta(days=30)) == []


def test_switching_off_only_the_tunnels_leaves_the_services(tmp_path: Path):
    from cma.core.monitoring import close_unwatched_kinds

    log = AvailabilityLog(tmp_path / "a.json")
    config = config_with_reminders()
    record_tunnels(log, config, [Tunnel("t1", "labo", "down")], T0)
    record_services(log, config, [(WIKI, HostProbe("origin_down", 502, ms=12.0))], T0)
    config.settings.watch_tunnels = False
    assert close_unwatched_kinds(log, config, T0 + timedelta(hours=1)) == 1
    assert open_keys(log) == ["service:wiki.exemple.fr"]
