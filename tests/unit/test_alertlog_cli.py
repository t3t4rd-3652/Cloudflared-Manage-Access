"""`cma alerts test` et `cma alerts digest` notent leurs envois dans le journal (P31), avec un faux canal HTTP local."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import cma.cli as cli_module
from cma.core.alertlog import AlertLog, log_path
from cma.core.alerts import secret_key
from cma.core.models import AlertChannel
from cma.core.secrets import MemorySecretStore


class Channel:
    """Faux canal d'alerte local : lit le corps de la requête avant de répondre (sinon Windows coupe la connexion)."""

    def __init__(self, status: int = 200) -> None:
        self.hits = 0
        channel = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
                channel.hits += 1
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args: object) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def __enter__(self) -> Channel:
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


def add_channel(store, secrets: MemorySecretStore, name: str, url: str) -> None:
    channel = AlertChannel(name=name, kind="webhook")
    secrets.set(secret_key(channel.id), url)
    store.update(lambda c: c.settings.alert_channels.append(channel))


def test_alerts_test_notes_each_send(paths, store, capsys):
    secrets = MemorySecretStore()
    with Channel() as good, Channel(status=500) as bad:
        add_channel(store, secrets, "Bon", good.url("/jeton-ok-0123456789"))
        add_channel(store, secrets, "Mauvais", bad.url("/jeton-ko-9876543210"))
        assert cli_module.send_test_alerts(paths, secrets=secrets) == 1
    out = capsys.readouterr().out
    assert "✓ Bon" in out and "✗ Mauvais : Le canal a refusé l'alerte (500)." in out
    first, second = AlertLog(log_path(paths.data_dir)).entries()
    assert (first.channel, first.kind, first.nature, first.ok) == ("Bon", "webhook", "test", True)
    assert (second.channel, second.nature, second.ok) == ("Mauvais", "test", False)
    assert second.error == "Le canal a refusé l'alerte (500)."
    text = log_path(paths.data_dir).read_text(encoding="utf-8")
    assert "jeton-" not in text and "127.0.0.1" not in text  # ni adresse ni fragment


def test_alerts_digest_notes_each_send(paths, store, capsys):
    secrets = MemorySecretStore()
    with Channel() as good, Channel(status=503) as bad:
        add_channel(store, secrets, "Bon", good.url("/ok"))
        add_channel(store, secrets, "Mauvais", bad.url("/ko"))
        assert cli_module.send_digest(paths, secrets=secrets) == 1
    capsys.readouterr()
    first, second = AlertLog(log_path(paths.data_dir)).entries()
    assert (first.nature, first.subject, first.ok) == ("digest", "", True)
    assert (second.channel, second.nature, second.ok) == ("Mauvais", "digest", False)
    assert second.error == "Le canal a refusé l'alerte (503)."


def test_alerts_commands_without_channel_note_nothing(paths, store, capsys):
    assert cli_module.send_test_alerts(paths, secrets=MemorySecretStore()) == 1
    assert cli_module.send_digest(paths, secrets=MemorySecretStore()) == 1
    capsys.readouterr()
    assert not log_path(paths.data_dir).exists()
