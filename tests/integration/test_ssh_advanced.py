"""Redirections SOCKS (-D) et inverse (-R), rebond SSH (ProxyJump), contre le serveur asyncssh de test."""

from __future__ import annotations

import asyncio
import ipaddress

import pytest

from cma.core.models import SavedForward
from cma.core.netutil import find_free_port
from cma.core.sessions import SessionState
from cma.core.ssh.errors import SshError
from tests.integration.test_ssh import (  # noqa: F401 (fixtures)
    PASSWORD,
    ScriptedPrompter,
    _shutdown_managers,
    add_profile,
    make_manager,
    ssh_server,
)


async def echo_server():
    async def handle(reader, writer):
        while data := await reader.read(1024):
            writer.write(data)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def wait_listening(manager, info, timeout=10.0):
    for _ in range(int(timeout / 0.05)):
        session = manager.session(info.id)
        if session.state == SessionState.LISTENING:
            return session
        if session.state == SessionState.ERROR:
            raise AssertionError(session.message)
        await asyncio.sleep(0.05)
    raise AssertionError(manager.session(info.id).state)


def free_port():
    port = find_free_port(port_range=(31000, 31999))
    assert port is not None
    return port


async def test_socks_forward(paths, store, secrets, bus, ssh_server):  # noqa: F811
    echo, echo_port = await echo_server()
    local = free_port()
    forward = SavedForward(kind="socks", local_port=local, label="proxy")
    profile = add_profile(store, ssh_server["port"], saved_forwards=[forward])
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter(passwords=[PASSWORD]))
    info = await manager.start_forward(profile.id, forward)
    session = await wait_listening(manager, info)

    # SOCKS 5, adresse IPv4.
    reader, writer = await asyncio.open_connection("127.0.0.1", local)
    writer.write(b"\x05\x01\x00")
    assert await reader.readexactly(2) == b"\x05\x00"
    writer.write(
        b"\x05\x01\x00\x01" + ipaddress.IPv4Address("127.0.0.1").packed + echo_port.to_bytes(2, "big")
    )
    assert (await reader.readexactly(10))[1] == 0x00
    writer.write(b"bonjour")
    assert await reader.readexactly(7) == b"bonjour"
    writer.close()

    # SOCKS 4a, nom d'hôte.
    reader, writer = await asyncio.open_connection("127.0.0.1", local)
    writer.write(b"\x04\x01" + echo_port.to_bytes(2, "big") + b"\x00\x00\x00\x01cma\x00localhost\x00")
    assert (await reader.readexactly(8))[1] == 0x5A
    writer.write(b"salut")
    assert await reader.readexactly(5) == b"salut"
    writer.close()

    # Cible injoignable : refus SOCKS, la session reste à l'écoute.
    closed = free_port()
    reader, writer = await asyncio.open_connection("127.0.0.1", local)
    writer.write(b"\x05\x01\x00")
    await reader.readexactly(2)
    writer.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + closed.to_bytes(2, "big"))
    assert (await reader.readexactly(10))[1] != 0x00
    writer.close()
    assert session.state == SessionState.LISTENING
    echo.close()


async def test_remote_forward(paths, store, secrets, bus, ssh_server):  # noqa: F811
    echo, echo_port = await echo_server()
    remote = free_port()
    forward = SavedForward(kind="remote", remote_host="127.0.0.1", remote_port=remote, local_port=echo_port)
    profile = add_profile(store, ssh_server["port"], saved_forwards=[forward])
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter(passwords=[PASSWORD]))
    info = await manager.start_forward(profile.id, forward)
    session = await wait_listening(manager, info)
    assert "écoute sur 127.0.0.1:" in session.info().subtitle
    reader, writer = await asyncio.open_connection("127.0.0.1", remote)
    writer.write(b"inverse")
    assert await reader.readexactly(7) == b"inverse"
    writer.close()
    await asyncio.sleep(0.2)
    assert session.info().bytes_up >= 7
    echo.close()


async def test_jump_host_and_loop_detection(paths, store, secrets, bus, ssh_server):  # noqa: F811
    jump = add_profile(store, ssh_server["port"], name="Bastion")
    target = add_profile(store, ssh_server["port"], name="Interne", jump_profile=jump.id)
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter(passwords=[PASSWORD, PASSWORD]))
    await manager.ssh_connect(target.id)
    assert manager.ssh.is_connected(jump.id) and manager.ssh.is_connected(target.id)

    loop_a = add_profile(store, ssh_server["port"], name="A")
    loop_b = add_profile(store, ssh_server["port"], name="B", jump_profile=loop_a.id)
    store.update(lambda c: setattr(c.ssh_profile(loop_a.id), "jump_profile", loop_b.id))
    with pytest.raises(SshError, match="boucle"):
        await manager.ssh.get(store.snapshot().ssh_profile(loop_a.id))


def test_forward_model_rules():
    with pytest.raises(ValueError, match="port distant"):
        SavedForward(kind="local", local_port=1080)
    socks = SavedForward(kind="socks", local_port=1080)
    assert socks.short_label == "SOCKS" and socks.describe() == "SOCKS sur 127.0.0.1:1080"
    remote = SavedForward(kind="remote", remote_host="localhost", remote_port=8080, local_port=3000)
    assert remote.describe() == "serveur localhost:8080 → 127.0.0.1:3000 sur ce poste"


async def test_remote_forward_refused_by_the_server(paths, store, secrets, bus, ssh_server, monkeypatch):  # noqa: F811
    from tests.integration.test_ssh import FakeSshServer

    monkeypatch.setattr(FakeSshServer, "server_requested", lambda self, host, port: False)
    forward = SavedForward(kind="remote", remote_host="127.0.0.1", remote_port=free_port(), local_port=1)
    profile = add_profile(store, ssh_server["port"], saved_forwards=[forward])
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter(passwords=[PASSWORD]))
    info = await manager.start_forward(profile.id, forward)
    for _ in range(200):
        session = manager.session(info.id)
        if session.state == SessionState.ERROR:
            break
        await asyncio.sleep(0.05)
    assert session.state == SessionState.ERROR and "refuse d'écouter" in session.message


async def test_missing_jump_server(paths, store, secrets, bus, ssh_server):  # noqa: F811
    target = add_profile(store, ssh_server["port"], name="Orphelin", jump_profile="absent")
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter(passwords=[PASSWORD]))
    with pytest.raises(SshError, match="rebond n'existe plus"):
        await manager.ssh.get(target)
