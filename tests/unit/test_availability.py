"""Disponibilité, alertes et sourdine : journal, formats d'envoi, événements d'un relevé."""

from __future__ import annotations

import http.server
import json
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import ClassVar

import pytest

from cma.core.alerts import Alert, AlertError, build_request, kind_label, send_alert
from cma.core.availability import AvailabilityLog
from cma.core.cfapi import Tunnel
from cma.core.hostprobe import HostProbe
from cma.core.models import AlertChannel, Config
from cma.core.monitoring import (
    channels,
    is_muted,
    mute,
    muted_until,
    record_services,
    record_tunnels,
    send_events,
    service_key,
    tunnel_key,
)
from cma.core.secrets import MemorySecretStore
from cma.core.servicewatch import ServiceTarget

NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)
WIKI = ServiceTarget("wiki.exemple.fr", "", "http://localhost:8080", "t1", "bureau")


def test_log_counts_checks_and_incidents(tmp_path):
    path = tmp_path / "availability.json"
    log = AvailabilityLog(path)
    for hours, ok, ms in ((1, True, 100.0), (2, True, 300.0), (3, False, None), (24 * 10, True, 50.0)):
        log.record_check("service:wiki", "wiki.exemple.fr", ok, ms, NOW - timedelta(hours=hours))
    week = log.stats("service:wiki", 7, NOW)
    assert (week.checks, round(week.uptime or 0, 3), week.mean_ms, week.max_ms) == (3, 0.667, 200.0, 300.0)
    assert log.stats("service:wiki", 30, NOW).checks == 4
    assert log.stats("inconnu", 7, NOW).uptime is None
    # Un incident ouvert ne se rouvre pas ; la fin le ferme, une seconde fin ne fait rien.
    assert log.start("service", "service:wiki", "wiki.exemple.fr", "origin_down", NOW - timedelta(hours=2))
    assert not log.start("service", "service:wiki", "wiki.exemple.fr", "origin_down", NOW)
    ended = log.end("service", "service:wiki", NOW)
    assert ended is not None and ended.duration() == timedelta(hours=2)
    assert log.end("service", "service:wiki", NOW) is None
    log.start("tunnel", "tunnel:t1", "bureau", "down", NOW - timedelta(minutes=5))
    assert [i.key for i in log.history(now=NOW)] == ["tunnel:t1", "service:wiki"]
    assert log.history("tunnel:t1", now=NOW)[0].open
    log.save(NOW)
    again = AvailabilityLog(path)
    assert again.label("service:wiki") == "wiki.exemple.fr" and len(again.incidents) == 2
    assert again.keys() == ["tunnel:t1", "service:wiki"] or set(again.keys()) == {"tunnel:t1", "service:wiki"}
    # Au-delà de 90 jours : effacé (les incidents encore ouverts restent).
    again.prune(NOW + timedelta(days=95))
    assert [i.key for i in again.incidents] == ["tunnel:t1"] and again.days == {}


def test_alert_formats():
    alert = Alert("CMA — panne : wiki", "Service injoignable (502).", "error")
    ntfy = build_request("ntfy", "https://ntfy.sh/sujet", alert)
    assert ntfy.data == b"Service injoignable (502)."
    assert ntfy.get_header("Priority") == "high" and ntfy.get_header("Title").startswith("=?UTF-8?B?")
    slack = json.loads(build_request("slack", "https://hooks.slack.com/x", alert).data)  # type: ignore[arg-type]
    assert slack == {"text": "*CMA — panne : wiki*\nService injoignable (502)."}
    discord = json.loads(build_request("discord", "https://discord.com/x", alert).data)  # type: ignore[arg-type]
    assert discord["content"].startswith("**CMA — panne")
    teams = json.loads(build_request("teams", "https://x.logic.azure.com/x", alert).data)  # type: ignore[arg-type]
    assert teams["attachments"][0]["content"]["body"][1]["text"] == "Service injoignable (502)."
    generic = json.loads(build_request("webhook", "https://exemple.fr/a", alert, NOW).data)  # type: ignore[arg-type]
    assert generic["level"] == "error" and generic["at"] == "2026-10-09T12:00:00Z"
    assert kind_label("teams") == "Microsoft Teams"


class Receiver(http.server.BaseHTTPRequestHandler):
    received: ClassVar[list[tuple[str, bytes]]] = []
    status: ClassVar[int] = 200

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        Receiver.received.append((self.path, self.rfile.read(length)))
        self.send_response(Receiver.status)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture
def receiver() -> Iterator[str]:
    server = http.server.HTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_send_alert(receiver):
    Receiver.received.clear()
    Receiver.status = 200
    send_alert("webhook", receiver + "/alertes", Alert("t", "x", "info"))
    assert Receiver.received[0][0] == "/alertes"
    Receiver.status = 403
    with pytest.raises(AlertError, match="refusé l'alerte \\(403\\)"):
        send_alert("slack", receiver + "/x", Alert("t", "x", "info"))
    with pytest.raises(AlertError, match="https://"):
        send_alert("slack", "ftp://x", Alert("t", "x", "info"))
    with pytest.raises(AlertError, match="injoignable"):
        send_alert("ntfy", "http://127.0.0.1:1/x", Alert("t", "x", "info"), timeout=2)


def test_mute_and_events():
    config = Config()
    mute(config, tunnel_key("t1"), timedelta(hours=1), NOW)
    assert muted_until(config, tunnel_key("t1"), NOW) == NOW + timedelta(hours=1)
    assert is_muted(config, service_key(WIKI), "t1", NOW)  # le tunnel couvre ses noms
    assert not is_muted(config, service_key(WIKI), "t1", NOW + timedelta(hours=2))
    mute(config, tunnel_key("t1"), None, NOW)
    assert config.settings.muted == {}
    config.settings.muted["service:x"] = "illisible"
    assert muted_until(config, "service:x") is None

    log = AvailabilityLog.__new__(AvailabilityLog)
    log.incidents, log.days, log.labels = [], {}, {}
    tunnels = [Tunnel("t1", "bureau", "down"), Tunnel("t2", "labo", "inactive")]
    events = record_tunnels(log, config, tunnels, NOW)
    assert [(e.key, e.level, e.recovered) for e in events] == [("tunnel:t1", "error", False)]
    assert record_tunnels(log, config, tunnels, NOW) == []  # toujours en panne : rien de nouveau
    back = record_tunnels(log, config, [Tunnel("t1", "bureau", "healthy")], NOW)
    assert [(e.level, e.recovered) for e in back] == [("success", True)]
    assert "tunnel:t2" not in log.days  # inactif : pas suivi

    mute(config, service_key(WIKI), timedelta(hours=4), NOW)
    results = [(WIKI, HostProbe("origin_down", 502, ms=12.5)), (WIKI, HostProbe("unreachable"))]
    events = record_services(log, config, results, NOW)
    assert [(e.key, e.level, e.muted) for e in events] == [("service:wiki.exemple.fr", "warning", True)]
    assert log.days["service:wiki.exemple.fr"]["2026-10-09"] == [0, 1, 12.5, 12.5, 1]


def test_send_events_to_channels():
    config = Config()
    secrets = MemorySecretStore()
    phone = AlertChannel(name="Téléphone", kind="ntfy")
    team = AlertChannel(name="Équipe", kind="slack", recoveries=False)
    off = AlertChannel(name="Coupé", kind="discord", enabled=False)
    lost = AlertChannel(name="Sans adresse", kind="webhook")
    config.settings.alert_channels = [phone, team, off, lost]
    for channel in (phone, team, off):
        secrets.set(f"alert:{channel.id}", f"https://exemple.fr/{channel.kind}")
    assert [name for name, *_rest in channels(config, secrets)] == ["Téléphone", "Équipe"]

    from cma.core.monitoring import Event

    sent: list[tuple[str, str]] = []

    def sender(kind: str, url: str, alert: Alert) -> None:
        if kind == "slack":
            raise AlertError("refusé")
        sent.append((kind, alert.title))

    events = [
        Event("service:a", "a.exemple.fr", "error", "panne", False, False),
        Event("service:b", "b.exemple.fr", "success", "retour", False, True),
        Event("service:c", "c.exemple.fr", "error", "en sourdine", True, False),
    ]
    errors = send_events(events, config, secrets, sender)
    assert sent == [("ntfy", "CMA — panne : a.exemple.fr"), ("ntfy", "CMA — b.exemple.fr rétabli")]
    assert errors == ["Équipe : refusé"]  # le retour ne part pas vers « Équipe » (pannes seulement)
