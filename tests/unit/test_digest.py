"""Résumé hebdomadaire (P25) : contenu, troncature, échéance, un seul envoi par semaine."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from cma.core.alerts import Alert, AlertError, secret_key
from cma.core.alertstate import STATE_FILE, AlertState
from cma.core.availability import AvailabilityLog
from cma.core.digest import LIMIT, build_digest, digest_due, truncate, week_id
from cma.core.models import AlertChannel, Config, ServiceToken
from cma.core.monitoring import deliver_follow_up, prepare_follow_up
from cma.core.secrets import MemorySecretStore

PARIS = timezone(timedelta(hours=2))
MONDAY = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)  # lundi, semaine ISO 42


def filled_log(tmp_path: Path, now: datetime = MONDAY) -> AvailabilityLog:
    log = AvailabilityLog(tmp_path / "availability.json")
    for day in range(1, 7):
        at = now - timedelta(days=day)
        log.record_check("tunnel:t1", "bureau", True, None, at)
        log.record_check("service:wiki.exemple.fr", "wiki.exemple.fr", day != 3, 50.0, at)
    log.start("service", "service:wiki.exemple.fr", "wiki.exemple.fr", "origin_down", now - timedelta(days=3))
    log.end("service", "service:wiki.exemple.fr", now - timedelta(days=3) + timedelta(hours=2, minutes=30))
    return log


def test_week_id_and_due_window():
    assert week_id(datetime(2026, 10, 12, 9, 0)) == "2026-W42"
    assert week_id(datetime(2026, 1, 1)) == "2026-W01"
    assert week_id(datetime(2027, 1, 3)) == "2026-W53"  # l'année ISO n'est pas l'année civile
    config = Config()
    state = AlertState(Path("inexistant") / STATE_FILE)
    assert not digest_due(config, state, MONDAY, UTC)  # réglage coupé
    config.settings.weekly_digest = True
    assert not digest_due(config, state, datetime(2026, 10, 12, 8, 59, tzinfo=UTC), UTC)
    assert digest_due(config, state, datetime(2026, 10, 12, 9, 0, tzinfo=UTC), UTC)
    assert not digest_due(config, state, datetime(2026, 10, 13, 12, 0, tzinfo=UTC), UTC)  # mardi
    # L'heure locale décide : 7 h UTC = 9 h à Paris.
    assert not digest_due(config, state, datetime(2026, 10, 12, 6, 59, tzinfo=UTC), PARIS)
    assert digest_due(config, state, datetime(2026, 10, 12, 7, 0, tzinfo=UTC), PARIS)
    # Dimanche 23 h UTC = lundi 1 h à Paris : trop tôt ; lundi 22 h UTC = mardi 0 h à Paris : fini.
    assert not digest_due(config, state, datetime(2026, 10, 11, 23, 0, tzinfo=UTC), PARIS)
    assert not digest_due(config, state, datetime(2026, 10, 12, 22, 0, tzinfo=UTC), PARIS)
    state.mark_digest("2026-W42")
    assert not digest_due(config, state, MONDAY, UTC)
    assert digest_due(config, state, MONDAY + timedelta(days=7), UTC)


def test_digest_content(tmp_path: Path):
    config = Config()
    config.tokens.append(ServiceToken(name="ci", client_id="x", expires_at=MONDAY + timedelta(days=12)))
    config.tokens.append(ServiceToken(name="vieux", client_id="y", expires_at=MONDAY - timedelta(days=3)))
    log = filled_log(tmp_path)
    log.start("tunnel", "tunnel:t1", "bureau", "down", MONDAY - timedelta(hours=1))
    alert = build_digest(log, config, MONDAY, UTC)
    assert alert.title == "CMA — semaine du 05/10/2026"
    assert alert.level == "warning"
    lines = alert.text.splitlines()
    assert lines[0] == "Disponibilité sur 7 jours."
    assert lines[1] == "Incidents : 2 · pannes cumulées : 3 h 30"
    assert "En cours : bureau" in lines
    assert "• ci : expire dans 12 j" in lines and "• vieux : expiré depuis 3 j" in lines
    # Les moins disponibles d'abord, avec leurs incidents.
    objects = [line for line in lines if line.startswith(("• wiki", "• bureau"))]
    assert objects[0].startswith("• wiki.exemple.fr : 83.33 %, 1 incident(s), pannes 2 h 30")
    assert objects[1] == "• bureau : 100 %, 1 incident(s), pannes 1 h 00"
    assert lines.index(objects[0]) > lines.index("• vieux : expiré depuis 3 j")


def test_calm_week_and_empty_log(tmp_path: Path):
    log = AvailabilityLog(tmp_path / "a.json")
    log.record_check("tunnel:t1", "bureau", True, None, MONDAY - timedelta(days=1))
    alert = build_digest(log, Config(), MONDAY, UTC)
    assert alert.level == "success"
    assert alert.text.splitlines()[1:] == ["Incidents : 0 · pannes cumulées : 0", "• bureau : 100 %"]
    empty = build_digest(AvailabilityLog(tmp_path / "vide.json"), Config(), MONDAY, UTC)
    assert "Aucun relevé sur la période" in empty.text and empty.level == "success"
    # Un objet sans aucun relevé dans la semaine (journal plus ancien) n'apparaît pas.
    old = AvailabilityLog(tmp_path / "old.json")
    old.record_check("tunnel:t9", "ancien", True, None, MONDAY - timedelta(days=30))
    assert "ancien" not in build_digest(old, Config(), MONDAY, UTC).text


def test_digest_is_truncated_cleanly(tmp_path: Path):
    log = AvailabilityLog(tmp_path / "a.json")
    for number in range(120):
        host = f"service-numero-{number:03d}.un-domaine-assez-long.exemple.fr"
        log.record_check(f"service:{host}", host, number % 2 == 0, 10.0, MONDAY - timedelta(days=1))
    config = Config()
    for number in range(12):
        config.tokens.append(
            ServiceToken(name=f"token-{number}", client_id="x", expires_at=MONDAY + timedelta(days=number))
        )
    alert = build_digest(log, config, MONDAY, UTC)
    assert len(alert.text) <= LIMIT
    lines = alert.text.splitlines()
    assert lines[-1].startswith("… et ") and lines[-1].endswith(" autres")
    shown = [line for line in lines if line.startswith("• service-numero")]
    assert str(120 - len(shown)) in lines[-1]
    assert all(line.endswith("%") for line in shown)  # lignes entières, jamais coupées au milieu
    assert "… et 4 autres" in lines  # 12 tokens, 8 listés
    # Le message complet reste sous les 2000 caractères de Discord.
    assert len(f"**{alert.title}**\n{alert.text}") < 2000


def test_truncate():
    assert truncate("court", 10) == "court"
    text = "ligne un\nligne deux\nligne trois"
    assert truncate(text, 22) == "ligne un\nligne deux…"
    assert truncate("x" * 50, 10) == "x" * 9 + "…"


def channel_setup(config: Config) -> MemorySecretStore:
    secrets = MemorySecretStore()
    channel = AlertChannel(name="Équipe", kind="slack")
    secrets.set(secret_key(channel.id), "https://hooks.slack.com/services/x")
    config.settings.alert_channels.append(channel)
    return secrets


def test_digest_sent_once_per_week(tmp_path: Path):
    config = Config()
    config.settings.weekly_digest = True
    secrets = channel_setup(config)
    log = filled_log(tmp_path)
    sent: list[Alert] = []
    path = tmp_path / STATE_FILE

    def run(now: datetime) -> list[str]:
        plan = prepare_follow_up(log, config, AlertState(path), check_digest=True, now=now, tz=UTC)
        return deliver_follow_up(plan, config, secrets, now, lambda _k, _u, a: sent.append(a))

    assert run(datetime(2026, 10, 12, 8, 0, tzinfo=UTC)) == [] and sent == []  # avant 9 h
    assert run(datetime(2026, 10, 12, 9, 0, tzinfo=UTC)) == []
    assert [a.title for a in sent] == ["CMA — semaine du 05/10/2026"]
    assert AlertState(path).digest_week == "2026-W42"
    run(datetime(2026, 10, 12, 9, 5, tzinfo=UTC))  # relevé suivant : déjà envoyé
    run(datetime(2026, 10, 12, 18, 0, tzinfo=UTC))
    assert len(sent) == 1
    run(datetime(2026, 10, 19, 9, 0, tzinfo=UTC))  # lundi suivant
    assert len(sent) == 2 and AlertState(path).digest_week == "2026-W43"
    # Sans demande de résumé (relevé des services), rien ne part.
    plan = prepare_follow_up(
        log,
        config,
        AlertState(path),
        check_digest=False,
        now=datetime(2026, 10, 26, 9, 0, tzinfo=UTC),
        tz=UTC,
    )
    assert plan.digest is None and plan.empty


def test_failed_digest_is_retried(tmp_path: Path):
    config = Config()
    config.settings.weekly_digest = True
    secrets = channel_setup(config)
    log = filled_log(tmp_path)
    path = tmp_path / STATE_FILE

    def broken(_kind: str, _url: str, _alert: Alert) -> None:
        raise AlertError("injoignable")

    plan = prepare_follow_up(log, config, AlertState(path), check_digest=True, now=MONDAY, tz=UTC)
    assert deliver_follow_up(plan, config, secrets, MONDAY, broken) == ["Équipe : injoignable"]
    assert AlertState(path).digest_week == ""
    again = prepare_follow_up(log, config, AlertState(path), check_digest=True, now=MONDAY, tz=UTC)
    assert again.digest is not None


def test_incident_without_any_check_has_no_percentage(tmp_path: Path):
    log = AvailabilityLog(tmp_path / "a.json")
    log.start("tunnel", "tunnel:t1", "bureau", "down", MONDAY - timedelta(hours=5))
    assert "• bureau : —, 1 incident(s), pannes 5 h 00" in build_digest(log, Config(), MONDAY, UTC).text
