"""Tâche planifiée (CMA fermé) : rappels des pannes qui durent (P24), écrits seulement quand CMA est fermé."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import cma.cli as cli_module
from cma.cli import build_parser, run
from cma.core.alerts import secret_key
from cma.core.alertstate import state_path
from cma.core.availability import AvailabilityLog
from cma.core.cfapi import Tunnel
from cma.core.models import AlertChannel
from cma.core.secrets import MemorySecretStore


def cli(paths, *args):
    return run(build_parser().parse_args(["--data-dir", str(paths.data_dir), *args]))


class Receiver:
    """Faux canal d'alerte local : lit le corps de la requête avant de répondre (sinon Windows coupe la connexion)."""

    def __init__(self, status: int = 200) -> None:
        self.bodies: list[dict[str, Any]] = []
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                receiver.bodies.append(json.loads(self.rfile.read(length) or b"{}"))
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args: object) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/alerte"

    def __enter__(self) -> Receiver:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


def add_channel(store, secrets: MemorySecretStore, url: str) -> AlertChannel:
    channel = AlertChannel(name="Équipe", kind="webhook")
    secrets.set(secret_key(channel.id), url)
    store.update(lambda c: c.settings.alert_channels.append(channel))
    return channel


def fill_log(paths) -> None:
    log = AvailabilityLog(paths.data_dir / "availability.json")
    now = datetime.now(UTC)
    for day in range(3):
        log.record_check(
            "service:wiki.exemple.fr", "wiki.exemple.fr", day != 1, 40.0, now - timedelta(days=day)
        )
    log.start(
        "service", "service:wiki.exemple.fr", "wiki.exemple.fr", "origin_down", now - timedelta(hours=2)
    )
    log.save()


# --- Tâche planifiée : rappels et résumé -------------------------------------------------------------------------


def scheduled_run(
    paths, monkeypatch, secrets: MemorySecretStore, tunnels: list[Tunnel], open_app: bool
) -> int:
    async def states(_self: object) -> list[Tunnel]:
        return tunnels

    monkeypatch.setattr("cma.core.cfadmin.CloudflareAdmin.tunnel_states", states)
    monkeypatch.setattr("cma.platform.notify.system_notification", lambda _t, _text: True)
    monkeypatch.setattr(cli_module, "send_command", lambda *_a, **_k: {"ok": True} if open_app else None)
    return cli_module.show_tunnels(paths, as_json=False, notify=True, secrets=secrets)


def test_scheduled_task_reminds_and_writes_only_when_cma_is_closed(paths, store, monkeypatch):
    secrets = MemorySecretStore()
    add_channel(store, secrets, "https://exemple.fr/alerte")
    store.update(lambda c: setattr(c.settings, "alert_repeat_hours", 4))
    sent: list[str] = []
    monkeypatch.setattr("cma.core.monitoring.send_alert", lambda _k, _u, alert: sent.append(alert.title))
    down = [Tunnel("t1", "labo", "down")]
    assert scheduled_run(paths, monkeypatch, secrets, down, open_app=False) == 2
    assert sent == ["CMA — panne : labo"]
    assert not state_path(paths.data_dir).exists()  # rien à rappeler encore

    def age_incident(hours: int) -> None:
        log = AvailabilityLog(paths.data_dir / "availability.json")
        log.incidents[0].started = (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        log.save()

    age_incident(5)
    # CMA ouvert : il surveille lui-même, la tâche n'écrit ni n'envoie rien.
    assert scheduled_run(paths, monkeypatch, secrets, down, open_app=True) == 2
    assert sent == ["CMA — panne : labo"] and not state_path(paths.data_dir).exists()
    # CMA fermé : le rappel part une fois, puis plus avant 4 heures de plus.
    assert scheduled_run(paths, monkeypatch, secrets, down, open_app=False) == 2
    assert sent[-1] == "CMA — toujours en panne : labo" and len(sent) == 2
    assert "tunnel:t1" in json.loads(state_path(paths.data_dir).read_text(encoding="utf-8"))["reminders"]
    assert scheduled_run(paths, monkeypatch, secrets, down, open_app=False) == 2
    assert len(sent) == 2
    # Rétabli : le retour part, et l'état oublie le rappel.
    assert scheduled_run(paths, monkeypatch, secrets, [Tunnel("t1", "labo", "healthy")], open_app=False) == 0
    assert sent[-1] == "CMA — labo rétabli"
    assert json.loads(state_path(paths.data_dir).read_text(encoding="utf-8"))["reminders"] == {}


def test_scheduled_task_without_reminder_setting_stays_silent(paths, store, monkeypatch):
    secrets = MemorySecretStore()
    add_channel(store, secrets, "https://exemple.fr/alerte")
    sent: list[str] = []
    monkeypatch.setattr("cma.core.monitoring.send_alert", lambda _k, _u, alert: sent.append(alert.title))
    down = [Tunnel("t1", "labo", "down")]
    scheduled_run(paths, monkeypatch, secrets, down, open_app=False)
    log = AvailabilityLog(paths.data_dir / "availability.json")
    log.incidents[0].started = "2026-01-01T00:00:00Z"
    log.save()
    scheduled_run(paths, monkeypatch, secrets, down, open_app=False)
    assert sent == ["CMA — panne : labo"]
