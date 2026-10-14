"""Maintenance planifiée, rappel des pannes qui durent, état des envois (P24)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from cma.core.alerts import Alert, AlertError, secret_key
from cma.core.alertstate import STATE_FILE, AlertState, state_path
from cma.core.availability import AvailabilityLog
from cma.core.models import AlertChannel, Config, MaintenanceWindow
from cma.core.monitoring import (
    deliver_follow_up,
    is_muted,
    maintenance_window,
    mute,
    prepare_follow_up,
    reminder_events,
    send_reminders,
    window_active,
)
from cma.core.secrets import MemorySecretStore

PARIS = timezone(timedelta(hours=2))  # heure d'été : suffit pour des tests d'heure locale
T0 = datetime(2026, 10, 14, 6, 0, tzinfo=UTC)  # mercredi


def config_with(*windows: MaintenanceWindow, hours: int = 0) -> Config:
    config = Config()
    config.settings.maintenance_windows = list(windows)
    config.settings.alert_repeat_hours = hours
    return config


# --- Fenêtres de maintenance -------------------------------------------------------------------------------------


def test_window_inside_a_day():
    window = MaintenanceWindow(weekday=2, start="02:00", end="04:00")  # mercredi
    assert window_active(window, datetime(2026, 10, 14, 2, 0))
    assert window_active(window, datetime(2026, 10, 14, 3, 59))
    assert not window_active(window, datetime(2026, 10, 14, 4, 0))  # la fin est exclue
    assert not window_active(window, datetime(2026, 10, 14, 1, 59))
    assert not window_active(window, datetime(2026, 10, 15, 3, 0))  # un autre jour


def test_window_passing_midnight():
    window = MaintenanceWindow(weekday=5, start="23:00", end="02:00")  # samedi soir → dimanche matin
    assert window_active(window, datetime(2026, 10, 17, 23, 30))  # samedi
    assert window_active(window, datetime(2026, 10, 18, 1, 59))  # dimanche
    assert not window_active(window, datetime(2026, 10, 18, 2, 0))
    assert not window_active(window, datetime(2026, 10, 17, 22, 59))
    assert not window_active(window, datetime(2026, 10, 17, 1, 0))  # samedi matin : pas encore
    # Dimanche soir passe sur le lundi.
    sunday = MaintenanceWindow(weekday=6, start="22:00", end="01:00")
    assert window_active(sunday, datetime(2026, 10, 19, 0, 30))  # lundi
    assert window_active(sunday, datetime(2026, 10, 18, 23, 0))


def test_equal_start_and_end_covers_a_whole_day():
    window = MaintenanceWindow(weekday=2, start="00:00", end="00:00")
    assert window_active(window, datetime(2026, 10, 14, 0, 0))
    assert window_active(window, datetime(2026, 10, 14, 23, 59))
    assert window_active(window, datetime(2026, 10, 15, 0, 0) - timedelta(minutes=1))
    assert not window_active(window, datetime(2026, 10, 15, 0, 0))  # la fin est exclue : jeudi 0 h


def test_muted_during_a_window_uses_the_given_time_zone():
    config = config_with(MaintenanceWindow(weekday=5, start="23:00", end="02:00"))
    # 21 h 30 UTC = 23 h 30 à Paris (samedi) ; minuit trente à Paris = 22 h 30 UTC (dimanche local).
    assert is_muted(config, "tunnel:t1", now=datetime(2026, 10, 17, 21, 30, tzinfo=UTC), tz=PARIS)
    assert is_muted(config, "tunnel:t1", now=datetime(2026, 10, 17, 22, 30, tzinfo=UTC), tz=PARIS)
    assert not is_muted(config, "tunnel:t1", now=datetime(2026, 10, 17, 20, 0, tzinfo=UTC), tz=PARIS)
    assert not is_muted(config, "tunnel:t1", now=datetime(2026, 10, 18, 0, 0, tzinfo=UTC), tz=PARIS)
    # Le même instant en UTC n'est pas dans le créneau.
    assert not is_muted(config, "tunnel:t1", now=datetime(2026, 10, 17, 21, 30, tzinfo=UTC), tz=UTC)


def test_window_targets():
    now = datetime(2026, 10, 14, 3, 0, tzinfo=UTC)
    on_service = config_with(
        MaintenanceWindow(
            weekday=2, start="02:00", end="04:00", target="service:wiki.exemple.fr", label="Wiki"
        )
    )
    assert is_muted(on_service, "service:wiki.exemple.fr", now=now, tz=UTC)
    assert not is_muted(on_service, "service:autre.exemple.fr", now=now, tz=UTC)
    found = maintenance_window(on_service, "service:wiki.exemple.fr", now=now, tz=UTC)
    assert found is not None and found.label == "Wiki"
    assert maintenance_window(on_service, "tunnel:t1", now=now, tz=UTC) is None
    # Un tunnel visé couvre ses noms d'hôte, comme la sourdine d'un tunnel.
    on_tunnel = config_with(MaintenanceWindow(weekday=2, start="02:00", end="04:00", target="tunnel:t1"))
    assert is_muted(on_tunnel, "tunnel:t1", now=now, tz=UTC)
    assert is_muted(on_tunnel, "service:wiki.exemple.fr", "t1", now, UTC)
    assert not is_muted(on_tunnel, "service:wiki.exemple.fr", "t2", now, UTC)
    assert not is_muted(on_tunnel, "service:wiki.exemple.fr", None, now, UTC)
    # Tout le compte.
    everything = config_with(MaintenanceWindow(weekday=2, start="02:00", end="04:00"))
    assert is_muted(everything, "tunnel:t9", now=now, tz=UTC)
    assert is_muted(everything, "service:x", "t2", now, UTC)
    assert not is_muted(everything, "tunnel:t9", now=now + timedelta(hours=2), tz=UTC)


def test_default_time_zone_is_local():
    config = config_with(*[MaintenanceWindow(weekday=d, start="00:00", end="00:00") for d in range(7)])
    assert is_muted(config, "tunnel:t1")  # toute la semaine : vrai quel que soit le fuseau du poste


def test_old_and_invalid_configuration():
    old = Config.model_validate({"settings": {"theme": "dark", "muted": {}}})
    assert old.settings.maintenance_windows == []
    assert old.settings.alert_repeat_hours == 0
    again = Config.model_validate(json.loads(old.model_dump_json()))
    assert again == old
    with pytest.raises(ValidationError):
        MaintenanceWindow(weekday=7, start="02:00", end="04:00")
    with pytest.raises(ValidationError):
        MaintenanceWindow(weekday=1, start="25:00", end="04:00")
    with pytest.raises(ValidationError):
        MaintenanceWindow(weekday=1, start="2:00", end="04:00")
    with pytest.raises(ValidationError):
        Config.model_validate({"settings": {"alert_repeat_hours": 169}})
    kept = Config.model_validate(
        {"settings": {"maintenance_windows": [{"weekday": 1, "start": "01:00", "end": "02:30", "futur": 1}]}}
    )
    assert kept.settings.maintenance_windows[0].end == "02:30"  # champ inconnu ignoré


# --- État des envois ---------------------------------------------------------------------------------------------


def test_alert_state_is_tolerant(tmp_path: Path):
    path = state_path(tmp_path)
    assert path.name == STATE_FILE
    assert AlertState(path).reminders == {} and AlertState(path).digest_week == ""
    path.write_text("{ pas du json", encoding="utf-8")
    assert AlertState(path).reminders == {}
    path.write_text("[1, 2]", encoding="utf-8")
    assert AlertState(path).digest_week == ""
    path.write_text(
        json.dumps({"reminders": {"a": "2026-10-14T06:00:00Z", "b": 3, "c": "hier"}, "digest_week": 42}),
        encoding="utf-8",
    )
    state = AlertState(path)
    assert set(state.reminders) == {"a", "c"} and state.digest_week == ""
    assert state.last_reminder("a") == T0 and state.last_reminder("c") is None
    assert state.last_reminder("zzz") is None
    path.write_text(json.dumps({"reminders": "oups"}), encoding="utf-8")
    assert AlertState(path).reminders == {}
    path.write_bytes(b"\xff\xfe\x00")  # ni UTF-8 ni cp1252 propre : lu sans planter
    assert AlertState(path).reminders == {}


def test_alert_state_roundtrip_and_no_useless_write(tmp_path: Path):
    path = tmp_path / "sous" / STATE_FILE
    state = AlertState(path)
    state.save()
    assert not path.exists()  # rien à écrire
    state.mark_reminder("tunnel:t1", T0)
    state.mark_digest("2026-W42")
    state.save()
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "reminders": {"tunnel:t1": "2026-10-14T06:00:00Z"},
        "digest_week": "2026-W42",
    }
    assert not state.dirty
    again = AlertState(path)
    assert again.last_reminder("tunnel:t1") == T0 and again.digest_week == "2026-W42"
    again.keep_only(["tunnel:t1"])
    assert not again.dirty
    again.keep_only([])
    assert again.dirty and again.reminders == {}
    assert [p.name for p in path.parent.iterdir()] == [STATE_FILE]  # pas de fichier temporaire oublié


# --- Rappels -----------------------------------------------------------------------------------------------------


def channel_setup() -> tuple[MemorySecretStore, AlertChannel]:
    secrets = MemorySecretStore()
    channel = AlertChannel(name="Téléphone", kind="ntfy")
    secrets.set(secret_key(channel.id), "https://ntfy.sh/sujet-secret")
    return secrets, channel


def down_log(tmp_path: Path, started: datetime = T0) -> AvailabilityLog:
    log = AvailabilityLog(tmp_path / "availability.json")
    assert log.start("tunnel", "tunnel:t1", "bureau", "down", started)
    return log


def test_reminder_sent_once_per_period(tmp_path: Path):
    config = config_with(hours=4)
    log = down_log(tmp_path)
    state = AlertState(tmp_path / STATE_FILE)
    secrets, channel = channel_setup()
    config.settings.alert_channels.append(channel)
    sent: list[Alert] = []

    def sender(_kind: str, _url: str, alert: Alert) -> None:
        sent.append(alert)

    assert reminder_events(log, config, state, T0 + timedelta(hours=3, minutes=59), UTC) == []
    now = T0 + timedelta(hours=4)
    events = reminder_events(log, config, state, now, UTC)
    assert [(e.key, e.level, e.reminder, e.recovered, e.muted) for e in events] == [
        ("tunnel:t1", "error", True, False, False)
    ]
    assert events[0].text == "bureau est toujours en panne depuis 4 h 00."
    assert send_reminders(events, config, secrets, state, now, sender) == []
    assert [a.title for a in sent] == ["CMA — toujours en panne : bureau"]
    assert state.last_reminder("tunnel:t1") == now
    # Une seule fois par période : pas avant 4 h de plus, puis à nouveau.
    assert reminder_events(log, config, state, now + timedelta(hours=3, minutes=59), UTC) == []
    later = now + timedelta(hours=4)
    events = reminder_events(log, config, state, later, UTC)
    assert len(events) == 1 and events[0].text == "bureau est toujours en panne depuis 8 h 00."


def test_reminder_levels_for_degraded_and_services(tmp_path: Path):
    config = config_with(hours=1)
    log = AvailabilityLog(tmp_path / "a.json")
    log.start("tunnel", "tunnel:t2", "web", "degraded", T0)
    log.start("service", "service:wiki.exemple.fr", "wiki.exemple.fr", "origin_down", T0)
    log.start("service", "service:vieux.exemple.fr", "vieux.exemple.fr", "not_found", T0 - timedelta(days=3))
    events = reminder_events(log, config, AlertState(tmp_path / STATE_FILE), T0 + timedelta(hours=2), UTC)
    levels = {e.key: e.level for e in events}
    assert levels == {
        "tunnel:t2": "warning",
        "service:wiki.exemple.fr": "warning",
        "service:vieux.exemple.fr": "error",
    }
    old = next(e for e in events if e.key == "service:vieux.exemple.fr")
    assert "depuis 3 j 2 h" in old.text


def test_no_reminder_when_disabled_closed_or_muted(tmp_path: Path):
    log = down_log(tmp_path)
    state = AlertState(tmp_path / STATE_FILE)
    late = T0 + timedelta(hours=30)
    assert reminder_events(log, config_with(hours=0), state, late, UTC) == []  # 0 : jamais
    config = config_with(hours=4)
    assert len(reminder_events(log, config, state, late, UTC)) == 1
    mute(config, "tunnel:t1", timedelta(days=2), late)
    assert reminder_events(log, config, state, late, UTC) == []  # sourdine
    # Une sourdine posée sur le tunnel couvre le nom d'hôte via `tunnel_of`.
    log.start("service", "service:wiki.exemple.fr", "wiki.exemple.fr", "origin_down", T0)
    assert [e.key for e in reminder_events(log, config, state, late, UTC)] == ["service:wiki.exemple.fr"]
    assert reminder_events(log, config, state, late, UTC, tunnel_of={"service:wiki.exemple.fr": "t1"}) == []
    # Maintenance en cours (mercredi 14 octobre, 7 h 30 UTC) : pas de rappel, même passé l'heure.
    window = MaintenanceWindow(weekday=2, start="07:00", end="08:00")
    in_maintenance = config_with(window, hours=4)
    at = datetime(2026, 10, 14, 7, 30, tzinfo=UTC)
    log.start("tunnel", "tunnel:t3", "autre", "down", at - timedelta(hours=9))
    assert reminder_events(log, in_maintenance, state, at, UTC) == []
    after = reminder_events(log, in_maintenance, state, at + timedelta(hours=1), UTC)
    assert [e.key for e in after] == ["tunnel:t3"]  # la maintenance est finie ; les autres sont trop récents
    # Incident clos : plus de rappel, et l'état l'oublie.
    state.mark_reminder("tunnel:t1", T0)
    log.end("tunnel", "tunnel:t1", T0 + timedelta(hours=40))
    log.end("tunnel", "tunnel:t3", T0 + timedelta(hours=40))
    log.end("service", "service:wiki.exemple.fr", T0 + timedelta(hours=40))
    assert reminder_events(log, config_with(hours=4), state, T0 + timedelta(hours=50), UTC) == []
    assert state.reminders == {} and state.dirty


def test_failed_reminder_is_not_marked(tmp_path: Path):
    config = config_with(hours=1)
    log = down_log(tmp_path)
    state = AlertState(tmp_path / STATE_FILE)
    secrets, channel = channel_setup()
    config.settings.alert_channels.append(channel)
    now = T0 + timedelta(hours=2)
    events = reminder_events(log, config, state, now, UTC)

    def broken(_kind: str, _url: str, _alert: Alert) -> None:
        raise AlertError("refusé (403)")

    assert send_reminders(events, config, secrets, state, now, broken) == ["Téléphone : refusé (403)"]
    assert state.last_reminder("tunnel:t1") is None  # il repartira au prochain relevé
    # Sans canal actif : rien n'est envoyé, rien n'est noté.
    assert send_reminders(events, Config(), secrets, state, now, broken) == []
    assert state.last_reminder("tunnel:t1") is None


def test_follow_up_writes_the_state_file(tmp_path: Path):
    config = config_with(hours=2)
    log = down_log(tmp_path)
    secrets, channel = channel_setup()
    config.settings.alert_channels.append(channel)
    sent: list[str] = []
    now = T0 + timedelta(hours=3)
    path = state_path(tmp_path)

    plan = prepare_follow_up(log, config, AlertState(path), now=now, tz=UTC)
    assert not plan.empty
    assert deliver_follow_up(plan, config, secrets, now, lambda _k, _u, a: sent.append(a.title)) == []
    assert sent == ["CMA — toujours en panne : bureau"]
    assert json.loads(path.read_text(encoding="utf-8"))["reminders"] == {"tunnel:t1": "2026-10-14T09:00:00Z"}
    again = prepare_follow_up(log, config, AlertState(path), now=now, tz=UTC)
    assert again.empty


def test_follow_up_survives_an_unwritable_state(tmp_path: Path):
    config = config_with(hours=1)
    log = down_log(tmp_path)
    secrets, channel = channel_setup()
    config.settings.alert_channels.append(channel)
    blocker = tmp_path / "fichier"
    blocker.write_text("x", encoding="utf-8")  # un fichier là où il faudrait un dossier
    plan = prepare_follow_up(
        log,
        config,
        AlertState(blocker / STATE_FILE),
        now=T0 + timedelta(hours=2),
        tz=UTC,
    )
    assert deliver_follow_up(plan, config, secrets, T0 + timedelta(hours=2), lambda *_a: None) == []
