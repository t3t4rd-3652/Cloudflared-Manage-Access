"""Historique des sessions : suivi des états, durée à l'écoute, incidents, résumé par profil, stockage."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta

from cma.core.events import SessionChanged
from cma.core.history import SessionHistory, SessionRecord
from cma.core.models import ServiceType
from cma.core.sessions import SessionInfo, SessionKind, SessionState

T0 = datetime(2026, 10, 7, 9, 0, 0)


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now

    def at(self, seconds: float) -> None:
        self.now = T0 + timedelta(seconds=seconds)


def info(
    state: SessionState, *, sid: str = "s1", profile: str = "p1", message: str = "", **extra
) -> SessionInfo:
    base = SessionInfo(
        id=sid,
        kind=SessionKind.CLOUDFLARE,
        profile_id=profile,
        forward_id=None,
        name=f"Profil {profile}",
        subtitle="",
        local_host="127.0.0.1",
        local_port=22022,
        state=state,
        message=message,
        started_at=T0,
        listening_since=None,
        service_type=ServiceType.SSH,
        scheme=None,
        service_user="",
        connections=0,
        bytes_up=0,
        bytes_down=0,
        reconnect_in=None,
        attempts=0,
    )
    return replace(base, **extra)


def test_a_session_is_followed_until_it_stops(tmp_path):
    clock = Clock()
    history = SessionHistory(tmp_path / "history.json", now=clock)
    history.handle(SessionChanged(info(SessionState.STARTING)))
    clock.at(10)
    history.track(info(SessionState.LISTENING, connections=2))
    clock.at(70)
    history.track(info(SessionState.RECONNECTING, message="Connexion perdue : délai dépassé"))
    clock.at(80)
    history.track(info(SessionState.LISTENING, connections=1, bytes_up=10, bytes_down=20))
    clock.at(100)
    history.track(info(SessionState.STOPPED, bytes_up=15, bytes_down=40))
    history.track(info(SessionState.STOPPED))  # répétée après la fin : ignorée

    [record] = history.records()
    assert (record.duration, record.listening_seconds, record.reconnects) == (100, 80, 1)
    assert record.incidents == ["Connexion perdue : délai dépassé"]
    assert (record.end_state, record.peak_connections) == ("stopped", 2)
    assert (record.bytes_up, record.bytes_down) == (15, 40)  # dernière information avant la fin

    # Relu depuis le fichier par une autre instance.
    again = SessionHistory(tmp_path / "history.json", now=clock)
    assert again.records() == [record]


def test_errors_incidents_and_summary(tmp_path):
    clock = Clock()
    history = SessionHistory(tmp_path / "history.json", now=clock)
    # p1 : 2 sessions sans incident, à l'écoute 90 % du temps.
    for start in (0, 1000):
        clock.at(start)
        history.track(info(SessionState.STARTING, sid=f"a{start}", started_at=clock.now))
        clock.at(start + 10)
        history.track(info(SessionState.LISTENING, sid=f"a{start}"))
        clock.at(start + 100)
        history.track(info(SessionState.STOPPED, sid=f"a{start}"))
    # p2 : une session qui finit en erreur après une reconnexion ; ses messages sont gardés (5 au plus).
    clock.at(2000)
    history.track(info(SessionState.STARTING, sid="b", profile="p2", started_at=clock.now))
    for n in range(6):
        history.track(info(SessionState.RECONNECTING, sid="b", profile="p2", message=f"échec {n}"))
        history.track(info(SessionState.STARTING, sid="b", profile="p2"))
    clock.at(2030)
    history.track(info(SessionState.ERROR, sid="b", profile="p2", message="abandon"))

    [unstable, stable] = history.summary()
    assert (unstable.key, unstable.errors, unstable.reconnects, unstable.availability) == (
        ("p2", None),
        1,
        6,
        0,
    )
    assert unstable.last_incident == "abandon"
    assert history.records("p2")[0].incidents == ["échec 2", "échec 3", "échec 4", "échec 5", "abandon"]
    assert (stable.sessions, stable.availability, stable.incidents) == (2, 0.9, 0)
    assert stable.last_started == T0 + timedelta(seconds=1000)
    clock.at(2030 + 3600)
    assert [s.key for s in history.summary(since=timedelta(minutes=61))] == [("p2", None)]


def test_close_all_unknown_sessions_and_pruning(tmp_path):
    clock = Clock()
    history = SessionHistory(tmp_path / "history.json", now=clock, keep=timedelta(days=1), max_records=2)
    history.track(info(SessionState.ERROR, sid="vieille"))  # déjà terminée à la découverte : rien
    assert history.records() == []

    history.track(info(SessionState.STARTING, sid="x"))
    history.track(info(SessionState.LISTENING, sid="x"))
    clock.at(50)
    history.close_all()  # fermeture de CMA
    [closed] = history.records()
    assert (closed.end_state, closed.listening_seconds) == ("stopped", 50)

    for n in range(3):
        clock.at(100 + n)
        history.track(info(SessionState.STARTING, sid=f"n{n}"))
        history.track(info(SessionState.STOPPED, sid=f"n{n}"))
    assert len(history.records()) == 2  # au plus `max_records`
    clock.now = T0 + timedelta(days=2)
    history.track(info(SessionState.STARTING, sid="récente"))
    history.track(info(SessionState.STOPPED, sid="récente"))
    assert [r.started_at for r in history.records()] == [T0]  # les sessions de plus d'un jour sont oubliées
    assert len(json.loads((tmp_path / "history.json").read_text(encoding="utf-8"))) == 1

    history.clear()
    assert history.records() == [] and not (tmp_path / "history.json").exists()


def test_unreadable_file_or_records_are_ignored(tmp_path):
    path = tmp_path / "history.json"
    good = SessionRecord("p1", None, "cloudflare", "A", T0, T0 + timedelta(seconds=5), "stopped").to_json()
    path.write_text(
        json.dumps([good, {"profile_id": "incomplet"}, {**good, "started_at": "hier"}]), encoding="utf-8"
    )
    assert len(SessionHistory(path).records()) == 1
    path.write_text("{ pas du json", encoding="utf-8")
    assert SessionHistory(path).records() == []
    unwritable = SessionHistory(tmp_path / "dossier" / "history.json")
    (tmp_path / "dossier").write_text("un fichier, pas un dossier", encoding="utf-8")
    unwritable.track(info(SessionState.STARTING))
    unwritable.track(info(SessionState.STOPPED))  # écriture impossible : journalisé, pas d'exception
    assert len(unwritable.records()) == 1
