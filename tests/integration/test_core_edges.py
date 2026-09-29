"""Cas limites du cœur : réseau, canal local, binaire absent, redirection sur port occupé, coffre de repli."""

import asyncio
import os
import socket
import sys
import time
from multiprocessing.connection import Client

import pytest

import cma.core.secrets as secrets_module
from cma.core import fsutil, netutil
from cma.core.cloudflared.command import CommandSpec
from cma.core.cloudflared.session import CloudflaredSession
from cma.core.instance import IpcServer, ipc_address, ipc_authkey
from cma.core.models import CloudflareProfile, SavedForward, SshProfile
from cma.core.netutil import PortStatus, check_local_port, find_free_port
from cma.core.sessions import Backoff, SessionState
from cma.core.ssh.connection import SshConnectionManager
from cma.core.ssh.forward import SshForwardSession
from tests.integration.test_ssh import ScriptedPrompter


def test_ipv6_and_unknown_addresses():
    if socket.has_ipv6:
        port = find_free_port("::1", port_range=(31000, 31999))
        assert port is not None
        assert check_local_port("::1", port).free
    assert check_local_port("localhost", 1).status in (
        PortStatus.FREE,
        PortStatus.IN_USE,
        PortStatus.RESERVED,
    )
    assert check_local_port("10.254.254.254", 31001).status == PortStatus.INVALID


def test_reserved_message_fallback(monkeypatch):
    netutil.excluded_port_ranges.cache_clear()
    monkeypatch.setattr(netutil.sys, "platform", "linux")
    try:
        assert "réservé ou interdit" in netutil.reserved_port_message(80)
        assert netutil.excluded_port_ranges() == ()
    finally:
        netutil.excluded_port_ranges.cache_clear()


def test_permission_error_is_reported_as_reserved(monkeypatch):
    class Refusing:
        def __init__(self, *a):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def bind(self, _address):
            raise PermissionError(13, "interdit")

    monkeypatch.setattr(netutil.socket, "socket", Refusing)
    assert check_local_port("127.0.0.1", 50001).status == PortStatus.RESERVED


def test_find_free_port_gives_up_when_everything_is_taken(monkeypatch):
    monkeypatch.setattr(netutil, "check_local_port", lambda *_a: netutil.PortCheck(PortStatus.IN_USE))
    assert find_free_port(port_range=(40000, 40005)) is None


def test_ipc_rejects_invalid_messages_and_reports_handler_errors(paths):
    def handler(message):
        raise ValueError("panne du gestionnaire")

    server = IpcServer(paths, handler)
    server.start()
    try:
        time.sleep(0.2)
        with Client(ipc_address(paths), authkey=ipc_authkey(paths)) as conn:
            conn.send(["pas", "un", "dict"])
            assert conn.recv() == {"ok": False, "error": "message invalide"}
        with Client(ipc_address(paths), authkey=ipc_authkey(paths)) as conn:
            conn.send({"cmd": "x"})
            assert conn.recv() == {"ok": False, "error": "panne du gestionnaire"}
        with pytest.raises(Exception):
            Client(ipc_address(paths), authkey=b"mauvaise-cle").send({"cmd": "x"})
    finally:
        server.stop()


def test_atomic_write_cleans_up_on_failure(tmp_path, monkeypatch):
    target = tmp_path / "fichier.json"
    fsutil.atomic_write_text(target, "v1", mode=0o600)
    monkeypatch.setattr(fsutil.os, "replace", lambda *_a: (_ for _ in ()).throw(OSError("disque plein")))
    with pytest.raises(OSError):
        fsutil.atomic_write_json(target, {"v": 2})
    assert target.read_text(encoding="utf-8") == "v1"
    assert list(tmp_path.iterdir()) == [target]


def test_memory_store_when_no_keyring(monkeypatch):
    monkeypatch.setattr(secrets_module, "system_keyring", lambda: None)
    store = secrets_module.open_secret_store()
    assert not store.persistent
    monkeypatch.setattr(secrets_module.sys, "platform", "linux")
    import keyring
    from keyring.backends import fail

    monkeypatch.setattr(keyring, "get_keyring", lambda: fail.Keyring())
    assert secrets_module.system_keyring() is None
    monkeypatch.setattr(keyring, "get_keyring", lambda: (_ for _ in ()).throw(RuntimeError("cassé")))
    assert secrets_module.system_keyring() is None


def test_backoff_gives_up():
    backoff = Backoff(delays=(1, 2), max_failures=3)
    assert [backoff.next_delay() for _ in range(3)] == [1, 2, 2]
    assert backoff.exhausted
    backoff.reset()
    assert not backoff.exhausted


async def test_missing_binary_is_a_fatal_error(bus):
    profile = CloudflareProfile(
        name="Absent", hostname="a.ex.fr", local_port=find_free_port(port_range=(32000, 32999))
    )
    session = CloudflaredSession(
        bus=bus,
        profile=profile,
        command=CommandSpec(("C:/nulle/part/cloudflared.exe", "access", "tcp"), dict(os.environ)),
    )
    session.start()
    for _ in range(100):
        if session.state == SessionState.ERROR:
            break
        await asyncio.sleep(0.05)
    assert "introuvable" in session.message
    await session.stop()
    assert session.state == SessionState.STOPPED


async def test_process_that_exits_without_listening(bus):
    profile = CloudflareProfile(
        name="Muet", hostname="a.ex.fr", local_port=find_free_port(port_range=(32000, 32999))
    )
    command = CommandSpec((sys.executable, "-c", "import sys; sys.exit(3)"), dict(os.environ))
    session = CloudflaredSession(bus=bus, profile=profile, command=command)
    session.start()
    for _ in range(100):
        if session.state == SessionState.ERROR:
            break
        await asyncio.sleep(0.05)
    assert "avant d'ouvrir le port (code 3)" in session.message


async def test_forward_on_a_busy_port_fails_cleanly(paths, secrets, bus):
    profile = SshProfile(name="P", host="127.0.0.1", port=1, user="u")
    connections = SshConnectionManager(
        paths=paths,
        settings=lambda: __import__("cma.core.models", fromlist=["Settings"]).Settings(),
        secrets=secrets,
        prompter=ScriptedPrompter(),
        bus=bus,
    )

    async def fake_get(_profile):
        class Conn:
            async def wait_closed(self):
                await asyncio.sleep(3600)

        return Conn()

    connections.get = fake_get  # type: ignore[method-assign]
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen()
        port = blocker.getsockname()[1]
        session = SshForwardSession(
            bus=bus,
            profile=profile,
            forward=SavedForward(remote_port=80, local_port=port),
            connections=connections,
        )
        session.start()
        for _ in range(100):
            if session.state == SessionState.ERROR:
                break
            await asyncio.sleep(0.05)
        assert "déjà utilisé" in session.message
        await session.stop()


async def test_forward_retries_then_gives_up_on_network_errors(paths, secrets, bus):
    profile = SshProfile(
        name="Injoignable", host="127.0.0.1", port=find_free_port(port_range=(33000, 33999)), user="u"
    )
    connections = SshConnectionManager(
        paths=paths,
        settings=lambda: __import__("cma.core.models", fromlist=["Settings"]).Settings(),
        secrets=secrets,
        prompter=ScriptedPrompter(passwords=["x"] * 5),
        bus=bus,
    )
    session = SshForwardSession(
        bus=bus,
        profile=profile,
        forward=SavedForward(remote_port=80, local_port=find_free_port(port_range=(34000, 34999))),
        connections=connections,
    )
    session.backoff = Backoff(delays=(0.05,), max_failures=2)
    session.start()
    for _ in range(200):
        if session.state == SessionState.ERROR:
            break
        await asyncio.sleep(0.05)
    assert "Abandon après 2 tentatives" in session.message
    await session.stop()
