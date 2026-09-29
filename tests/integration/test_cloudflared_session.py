"""Session cloudflared de bout en bout, avec un faux cloudflared (et le vrai si disponible)."""

import asyncio
import json
import os
import shutil
import sys

import pytest

from cma.core.cloudflared.command import CommandSpec, build_access_tcp
from cma.core.cloudflared.session import CloudflaredSession
from cma.core.events import Notification
from cma.core.models import AuthMode, CloudflareProfile
from cma.core.netutil import check_local_port, find_free_port
from cma.core.sessions import SessionState
from tests.conftest import fake_cloudflared_args


def make_session(bus, port, mode, *, tmp_path=None, auto_reconnect=True, extra_env=None):
    profile = CloudflareProfile(
        name="Test", hostname="app.exemple.fr", local_port=port, auto_reconnect=auto_reconnect
    )
    env = dict(os.environ)
    env["FAKE_CF_MODE"] = mode
    env.update(extra_env or {})
    args = (
        *fake_cloudflared_args(),
        "access",
        "tcp",
        "--hostname",
        profile.hostname,
        "--url",
        f"127.0.0.1:{port}",
    )
    return CloudflaredSession(bus=bus, profile=profile, command=CommandSpec(args, env))


async def wait_for(session, states, timeout=10.0):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if session.state in states:
            return session.state
        await asyncio.sleep(0.05)
    raise AssertionError(f"état {session.state} au lieu de {states} ; message : {session.message}")


@pytest.fixture
def port():
    value = find_free_port(port_range=(21000, 21999))
    assert value is not None
    return value


async def test_listening_then_stop_releases_the_port(bus, port):
    session = make_session(bus, port, "ok")
    session.start()
    await wait_for(session, {SessionState.LISTENING})
    assert session.pid is not None
    assert not check_local_port("127.0.0.1", port).free
    await session.stop()
    assert session.state == SessionState.STOPPED
    await asyncio.sleep(0.2)
    assert check_local_port("127.0.0.1", port).free


async def test_port_in_use_is_a_fatal_error(bus, port):
    session = make_session(bus, port, "port_in_use")
    session.start()
    await wait_for(session, {SessionState.ERROR})
    assert "déjà utilisé" in session.message
    await session.stop()


async def test_port_already_taken_before_start(bus, port):
    import socket

    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", port))
        blocker.listen()
        session = make_session(bus, port, "ok")
        session.start()
        await wait_for(session, {SessionState.ERROR})
        assert "déjà utilisé" in session.message
        await session.stop()


async def test_usage_error_with_exit_code_zero_is_an_error(bus, port):
    session = make_session(bus, port, "usage")
    session.start()
    await wait_for(session, {SessionState.ERROR})
    assert "refusé la commande" in session.message
    await session.stop()


async def test_crash_triggers_reconnection(bus, port):
    session = make_session(bus, port, "crash", extra_env={"FAKE_CF_CRASH_AFTER": "0.8"})
    session.start()
    await wait_for(session, {SessionState.LISTENING})
    await wait_for(session, {SessionState.RECONNECTING})
    assert session.info().reconnect_in is not None
    await wait_for(session, {SessionState.LISTENING}, timeout=8)
    assert session.backoff.failures >= 1
    await session.stop()


async def test_crash_without_auto_reconnect_is_an_error(bus, port):
    session = make_session(bus, port, "crash", auto_reconnect=False, extra_env={"FAKE_CF_CRASH_AFTER": "0.8"})
    session.start()
    await wait_for(session, {SessionState.ERROR}, timeout=8)
    await session.stop()


async def test_auth_error_degrades_the_session_and_notifies(bus, port):
    session = make_session(bus, port, "auth_error")
    session.start()
    await wait_for(session, {SessionState.LISTENING})
    _reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.close()
    await wait_for(session, {SessionState.DEGRADED})
    assert "Access a refusé" in session.message
    notifications = bus.of_type(Notification)
    assert notifications and notifications[-1].session_id == session.id
    await session.stop()


async def test_secret_reaches_the_process_by_environment(bus, port, tmp_path):
    dump = tmp_path / "env.json"
    profile = CloudflareProfile(
        name="T", hostname="app.exemple.fr", local_port=port, auth=AuthMode.SERVICE_TOKEN, token_id="t"
    )
    spec = build_access_tcp(
        sys.executable, profile, client_id="id.access", client_secret="le-secret", base_env=dict(os.environ)
    )
    args = (*fake_cloudflared_args(), *spec.args[1:])
    env = {**spec.env, "FAKE_CF_MODE": "ok", "FAKE_CF_ENV_DUMP": str(dump)}
    session = CloudflaredSession(bus=bus, profile=profile, command=CommandSpec(args, env))
    session.start()
    await wait_for(session, {SessionState.LISTENING})
    received = json.loads(dump.read_text(encoding="utf-8"))
    assert received["TUNNEL_SERVICE_TOKEN_SECRET"] == "le-secret"
    assert all("le-secret" not in line.message for line in session.logs)
    await session.stop()


@pytest.mark.real_cloudflared
async def test_real_cloudflared(bus, port):
    binary = shutil.which("cloudflared")
    if binary is None:
        pytest.skip("cloudflared absent")
    profile = CloudflareProfile(
        name="Réel", hostname="cma-test.invalid", local_port=port, auto_reconnect=False
    )
    session = CloudflaredSession(bus=bus, profile=profile, command=build_access_tcp(binary, profile))
    session.start()
    await wait_for(session, {SessionState.LISTENING}, timeout=15)
    second = CloudflaredSession(bus=bus, profile=profile, command=build_access_tcp(binary, profile))
    second.start()
    await wait_for(second, {SessionState.ERROR}, timeout=15)
    assert "déjà utilisé" in second.message
    await second.stop()
    await session.stop()
