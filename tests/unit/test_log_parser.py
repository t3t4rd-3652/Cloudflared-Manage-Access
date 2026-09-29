"""Lignes réelles capturées avec cloudflared 2026.7.2 sous Windows (voir docs/ARCHITECTURE.md)."""

import pytest

from cma.core.cloudflared.log_parser import LogKind, parse_line

CASES = [
    (
        "2026-09-29T08:40:09Z INF Start Websocket listener host=127.0.0.1:38301",
        LogKind.LISTENER_STARTING,
        "INFO",
    ),
    (
        '2026-09-29T08:40:09Z ERR Error on Websocket listener error="failed to start forwarding server: listen tcp '
        "127.0.0.1:38301: bind: Une seule utilisation de chaque adresse de socket (protocole/adresse réseau/port) "
        'est habituellement autorisée."',
        LogKind.PORT_IN_USE,
        "ERROR",
    ),
    (
        "failed to start forwarding server: listen tcp 127.0.0.1:1: bind: address already in use",
        LogKind.PORT_IN_USE,
        "ERROR",
    ),
    (
        "failed to start forwarding server: listen tcp 127.0.0.1:59231: bind: An attempt was made to access a socket "
        "in a way forbidden by its access permissions.",
        LogKind.PORT_FORBIDDEN,
        "ERROR",
    ),
    (
        '2026-09-29T08:40:14Z ERR failed to connect to origin error="dial tcp: lookup cma-probe.invalid: no such host" '
        "originURL=https://cma-probe.invalid",
        LogKind.DNS_ERROR,
        "ERROR",
    ),
    (
        '2026-09-29T08:40:22Z ERR failed to connect to origin error="websocket: bad handshake" originURL=https://example.com',
        LogKind.AUTH_DENIED,
        "ERROR",
    ),
    ("Incorrect Usage: flag provided but not defined: -nope", LogKind.USAGE_ERROR, "ERROR"),
    ("2026-09-29T08:40:14Z DBG Websocket request: GET / HTTP/1.1", LogKind.OTHER, "DEBUG"),
    ("Host: cma-probe.invalid", LogKind.OTHER, "DEBUG"),
]


@pytest.mark.parametrize(("line", "kind", "level"), CASES)
def test_real_lines(line, kind, level):
    parsed = parse_line(line)
    assert parsed.kind == kind
    assert parsed.level == level


def test_proxy_error_is_recognized_with_the_profile_proxy():
    line = (
        '2026-09-29T08:40:17Z ERR failed to connect to origin error="dial tcp 127.0.0.1:9: connectex: '
        'Aucune connexion n’a pu être établie car l’ordinateur cible l’a expressément refusée." originURL=https://example.com'
    )
    assert parse_line(line, proxy_host_port="127.0.0.1:9").kind == LogKind.PROXY_ERROR
    assert parse_line(line).kind == LogKind.ORIGIN_UNREACHABLE


def test_fatal_and_connection_error_flags():
    assert parse_line("Incorrect Usage: x").fatal
    assert parse_line('ERR failed to connect to origin error="websocket: bad handshake"').connection_error
    assert not parse_line("2026-09-29T08:40:09Z INF Start Websocket listener host=x").fatal


def test_browser_login_url_is_extracted():
    parsed = parse_line(
        "2026-09-29T08:40:09Z INF A browser window should have opened at the following URL: "
        "https://app.exemple.fr/cdn-cgi/access/cli?token=abc"
    )
    assert parsed.kind == LogKind.AUTH_REQUIRED
    assert parsed.url == "https://app.exemple.fr/cdn-cgi/access/cli?token=abc"
