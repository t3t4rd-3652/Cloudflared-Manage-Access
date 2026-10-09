"""Test d'un nom d'hôte depuis Internet : chaque réponse de Cloudflare reconnue (formes relevées sur un vrai compte)."""

from __future__ import annotations

import http.server
import threading
from collections.abc import Iterator
from typing import ClassVar

import pytest

from cma.core.hostprobe import HostProbe, classify, probe_hostname


def test_classify():
    assert classify(
        302, {"location": "https://equipe.cloudflareaccess.com/cdn-cgi/access/login"}, "", with_token=False
    ) == (HostProbe("access", 302))
    assert (
        classify(403, {"cf-mitigated": "challenge"}, "Just a moment...", with_token=False).state
        == "challenge"
    )
    assert classify(530, {}, "error code: 1033", with_token=False).state == "no_connector"
    assert classify(502, {}, "error code: 502", with_token=False) == HostProbe("origin_down", 502)
    assert classify(504, {}, "", with_token=False).state == "origin_down"
    assert classify(403, {}, "", with_token=True).state == "refused"
    assert classify(403, {}, "", with_token=False) == HostProbe("ok", 403)  # le service lui-même refuse
    assert classify(301, {"location": "https://ailleurs.fr"}, "", with_token=False) == HostProbe("ok", 301)


def test_summaries_and_tones():
    assert HostProbe("ok", 200).summary("app.fr") == "app.fr : le service répond (200)."
    assert "erreur 1033" in HostProbe("no_connector", 530).summary("app.fr")
    assert "vérification de navigateur" in HostProbe("challenge", 403).summary("app.fr")
    assert (
        HostProbe("unreachable", detail="timed out").summary("app.fr") == "app.fr : injoignable (timed out)."
    )
    assert [HostProbe(s).tone for s in ("ok", "access", "origin_down", "no_connector")] == [
        "success",
        "info",
        "warning",
        "error",
    ]


class Handler(http.server.BaseHTTPRequestHandler):
    seen: ClassVar[list[dict[str, str]]] = []

    def do_GET(self) -> None:
        Handler.seen.append({k.lower(): v for k, v in self.headers.items()})
        if self.path == "/access":
            self.send_response(302)
            self.send_header("Location", "https://x.cloudflareaccess.com/login")
        elif self.path == "/down":
            self.send_response(530)
        else:
            self.send_response(200)
        self.end_headers()
        if self.path == "/down":
            self.wfile.write(b"error code: 1033")

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture
def server() -> Iterator[int]:
    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1]
    httpd.shutdown()


def test_probe_against_a_local_server(server):
    def probe(path: str, **kwargs: object) -> HostProbe:
        return probe_hostname("app.exemple.fr", path=path, connect=("127.0.0.1", server), tls=False, **kwargs)  # type: ignore[arg-type]

    assert probe("/") == HostProbe("ok", 200)
    assert probe("/access").state == "access"
    assert probe("/down").state == "no_connector"
    # Le service token part en en-têtes, avec le bon Host.
    Handler.seen.clear()
    probe("/", token=("robot.access", "secret-de-test-assez-long"))
    sent = Handler.seen[-1]
    assert sent["host"] == "app.exemple.fr"
    assert (sent["cf-access-client-id"], sent["cf-access-client-secret"]) == (
        "robot.access",
        "secret-de-test-assez-long",
    )


def test_probe_failures(server):
    assert probe_hostname("*.exemple.fr") == HostProbe("wildcard")
    assert probe_hostname("nom-qui-n-existe-pas.invalid").state == "not_found"
    unreachable = probe_hostname("app.exemple.fr", connect=("127.0.0.1", 1), tls=False, timeout=2)
    assert unreachable.state == "unreachable" and unreachable.detail
