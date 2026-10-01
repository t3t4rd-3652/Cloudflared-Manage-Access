"""Test du service distant à travers le port local : réponse, silence ou fermeture."""

from __future__ import annotations

import asyncio

import pytest

from cma.core.models import ServiceType
from cma.core.probe import probe_kind, probe_service


async def serve(behaviour):
    async def handle(reader, writer):
        await behaviour(reader, writer)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def banner(_reader, writer):
    writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
    await writer.drain()
    await asyncio.sleep(0.5)
    writer.close()


async def http(reader, writer):
    await reader.read(1024)
    writer.write(b"HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n")
    await writer.drain()
    writer.close()


async def close_now(_reader, writer):
    writer.close()


async def silent(_reader, writer):
    await asyncio.sleep(2)
    writer.close()


@pytest.mark.parametrize(
    ("behaviour", "kind", "ok", "fragment"),
    [
        (banner, "ssh", True, "OpenSSH_9.6"),
        (http, "http", True, "302"),
        (close_now, "tcp", False, "fermée"),
        (close_now, "ssh", False, "injoignable"),
        (silent, "tcp", None, "attend"),
    ],
)
async def test_probe_interprets_the_answer(behaviour, kind, ok, fragment, monkeypatch):
    import cma.core.probe as probe_module

    monkeypatch.setattr(probe_module, "SILENT_WAIT", 0.5)
    server, port = await serve(behaviour)
    try:
        result = await probe_service("127.0.0.1", port, kind, timeout=1.5)
    finally:
        server.close()
    assert result.ok is ok and fragment in result.message


async def test_probe_refused_port():
    server, port = await serve(close_now)
    server.close()
    await server.wait_closed()
    result = await probe_service("127.0.0.1", port, "tcp", timeout=1)
    assert result.ok is False


def test_probe_kind():
    assert probe_kind(ServiceType.SSH, None) == "ssh"
    assert probe_kind(ServiceType.GENERIC, "https") == "https"
    assert probe_kind(ServiceType.HTTP, None) == "http"
    assert probe_kind(ServiceType.RDP, None) == "tcp"


async def test_probe_https_and_silent_web(monkeypatch):
    import cma.core.probe as probe_module

    monkeypatch.setattr(probe_module, "SILENT_WAIT", 0.3)
    server, port = await serve(close_now)
    try:
        refused_tls = await probe_service("127.0.0.1", port, "https", timeout=1)
    finally:
        server.close()
    assert refused_tls.ok is False

    server, port = await serve(silent)
    try:
        quiet_web = await probe_service("127.0.0.1", port, "http", timeout=0.5)
        quiet_ssh = await probe_service("127.0.0.1", port, "ssh", timeout=0.5)
    finally:
        server.close()
    assert quiet_web.ok is None and quiet_ssh.ok is None


async def test_probe_service_that_talks_first():
    async def greet(_reader, writer):
        writer.write(b"+OK serveur pret\r\n")
        await writer.drain()
        await asyncio.sleep(0.5)
        writer.close()

    server, port = await serve(greet)
    try:
        result = await probe_service("127.0.0.1", port, "tcp", timeout=1)
    finally:
        server.close()
    assert result.ok is True and "octets" in result.message
