"""SessionManager et commandes texte, avec un faux cloudflared (y compris le SSH chaîné à travers Cloudflare)."""

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

import cma.core.manager as manager_module
from cma.core.cloudflared.command import CommandSpec
from cma.core.commands import execute
from cma.core.events import Notification
from cma.core.manager import ManagerError, SessionManager
from cma.core.models import AuthMode, CloudflareProfile, ServiceToken, SshAuthMode, SshProfile
from cma.core.netutil import find_free_port
from cma.core.sessions import SessionState
from tests.conftest import FAKE_CLOUDFLARED
from tests.integration.test_ssh import PASSWORD, ScriptedPrompter, ssh_server  # noqa: F401 (fixture)

FAKE_ENV: dict[str, str] = {}


def _wrap(builder):
    def wrapped(*args, **kwargs):
        spec = builder(*args, **kwargs)
        return CommandSpec((sys.executable, str(FAKE_CLOUDFLARED), *spec.args[1:]), {**spec.env, **FAKE_ENV})

    return wrapped


@pytest.fixture
def manager(paths, store, secrets, bus, monkeypatch):
    FAKE_ENV.clear()
    FAKE_ENV["FAKE_CF_MODE"] = "ok"
    for name in ("build_access_tcp", "build_access_login", "build_access_token", "build_ssh_config"):
        monkeypatch.setattr(manager_module, name, _wrap(getattr(manager_module, name)))
    instance = SessionManager(
        paths=paths,
        store=store,
        secrets=secrets,
        bus=bus,
        prompter=ScriptedPrompter(passwords=[PASSWORD] * 5),
    )
    monkeypatch.setattr(instance, "cloudflared_path", lambda: Path(sys.executable))
    return instance


@pytest.fixture(autouse=True)
async def _shutdown(manager):
    yield
    await asyncio.wait_for(manager.shutdown(), 20)


def add(store, profile):
    store.update(
        lambda c: (c.ssh_profiles if isinstance(profile, SshProfile) else c.cloudflare_profiles).append(
            profile
        )
    )
    return profile


def free_port():
    port = find_free_port(port_range=(30000, 30999))
    assert port is not None
    return port


async def wait_state(manager, session_id, states, timeout=10.0):
    for _ in range(int(timeout / 0.05)):
        session = manager.session(session_id)
        if session is not None and session.state in states:
            return session
        await asyncio.sleep(0.05)
    session = manager.session(session_id)
    raise AssertionError(f"{session.state if session else None} : {session.message if session else ''}")


async def test_service_token_session(manager, store, secrets, tmp_path):
    token = ServiceToken(name="Prod", client_id="prod.access")
    store.update(lambda c: c.tokens.append(token))
    secrets.set(token.secret_key, "le-secret")
    profile = add(
        store,
        CloudflareProfile(
            name="P",
            hostname="app.ex.fr",
            local_port=free_port(),
            auth=AuthMode.SERVICE_TOKEN,
            token_id=token.id,
        ),
    )
    dump = tmp_path / "env.json"
    FAKE_ENV["FAKE_CF_ENV_DUMP"] = str(dump)
    info = await manager.start_cloudflare(profile.id)
    await wait_state(manager, info.id, {SessionState.LISTENING})
    assert json.loads(dump.read_text())["TUNNEL_SERVICE_TOKEN_SECRET"] == "le-secret"
    again = await manager.start_cloudflare(profile.id)
    assert again.id == info.id
    restarted = await manager.restart(info.id)
    assert restarted.id != info.id
    await wait_state(manager, restarted.id, {SessionState.LISTENING})
    await manager.stop_profile(profile.id)
    assert manager.list_sessions() == []


async def test_errors_are_reported_clearly(manager, store, monkeypatch):
    token = ServiceToken(name="Sans secret", client_id="x.access")
    store.update(lambda c: c.tokens.append(token))
    no_secret = add(
        store,
        CloudflareProfile(
            name="A",
            hostname="a.ex.fr",
            local_port=free_port(),
            auth=AuthMode.SERVICE_TOKEN,
            token_id=token.id,
        ),
    )
    with pytest.raises(ManagerError, match="absent du coffre"):
        await manager.start_cloudflare(no_secret.id)
    incomplete = add(store, CloudflareProfile(name="B"))
    with pytest.raises(ManagerError, match="incomplet"):
        await manager.start_cloudflare(incomplete.id)
    with pytest.raises(ManagerError, match="introuvable"):
        await manager.start_cloudflare("inexistant")
    ok = add(store, CloudflareProfile(name="C", hostname="c.ex.fr", local_port=free_port()))
    monkeypatch.setattr(manager, "cloudflared_path", lambda: None)
    with pytest.raises(ManagerError, match="cloudflared est introuvable"):
        await manager.start_cloudflare(ok.id)
    with pytest.raises(ManagerError):
        await manager.restart("inconnue")


async def test_port_conflict_between_profiles(manager, store):
    port = free_port()
    first = add(store, CloudflareProfile(name="Un", hostname="a.ex.fr", local_port=port))
    second = add(store, CloudflareProfile(name="Deux", hostname="b.ex.fr", local_port=port))
    await manager.start_cloudflare(first.id)
    with pytest.raises(ManagerError, match="déjà utilisé"):
        await manager.start_cloudflare(second.id)
    await manager.stop_all()


async def test_auto_start_profiles(manager, store, bus):
    good = add(
        store, CloudflareProfile(name="Auto", hostname="a.ex.fr", local_port=free_port(), auto_start=True)
    )
    add(store, CloudflareProfile(name="Auto incomplet", auto_start=True))
    await manager.start_auto_profiles()
    assert manager.active_session_for(good.id) is not None
    assert any("incomplet" in n.message for n in bus.of_type(Notification))


async def test_token_test_accepts_and_refuses(manager, store, secrets):
    token = ServiceToken(name="T", client_id="t.access")
    store.update(lambda c: c.tokens.append(token))
    secrets.set(token.secret_key, "s")
    profile = add(
        store,
        CloudflareProfile(
            name="Test",
            hostname="a.ex.fr",
            local_port=free_port(),
            auth=AuthMode.SERVICE_TOKEN,
            token_id=token.id,
        ),
    )
    ok, message = await manager.test_cloudflare_profile(profile.id)
    assert ok, message
    FAKE_ENV["FAKE_CF_MODE"] = "auth_error"
    ok, message = await manager.test_cloudflare_profile(profile.id)
    assert not ok
    assert "Access a refusé" in message
    browser = add(store, CloudflareProfile(name="Nav", hostname="b.ex.fr", local_port=free_port()))
    with pytest.raises(ManagerError):
        await manager.test_cloudflare_profile(browser.id)


async def test_access_login_and_ssh_config(manager, store):
    profile = add(store, CloudflareProfile(name="Login", hostname="app.exemple.fr", local_port=free_port()))
    assert "Successfully fetched" in await manager.access_login(profile.id)
    assert "Host app.exemple.fr" in await manager.ssh_config_snippet(profile.id)


async def test_access_token_status_never_exposes_the_token(manager, store, bus):
    profile = add(store, CloudflareProfile(name="Jeton", hostname="app.exemple.fr", local_port=free_port()))
    assert await manager.access_token_valid(profile.id) is False
    FAKE_ENV["FAKE_CF_ACCESS_TOKEN"] = "eyJ.jeton-secret.sig"
    assert await manager.access_token_valid(profile.id) is True
    assert "jeton-secret" not in repr(bus.events)
    incomplete = add(store, CloudflareProfile(name="Vide", hostname="", local_port=free_port()))
    with pytest.raises(ManagerError):
        await manager.access_token_valid(incomplete.id)


async def test_group_connect_and_disconnect(manager, store, bus):
    first = add(store, CloudflareProfile(name="A", group="Prod", hostname="a.ex.fr", local_port=free_port()))
    second = add(
        store, CloudflareProfile(name="B", group="prod ", hostname="b.ex.fr", local_port=free_port())
    )
    add(store, CloudflareProfile(name="C", group="Labo", hostname="c.ex.fr", local_port=free_port()))
    broken = add(store, CloudflareProfile(name="D", group="Prod", hostname="d.ex.fr", local_port=None))
    assert {p.id for p in manager.group_profiles("PROD")} == {first.id, second.id, broken.id}

    infos = await manager.start_group("Prod")
    assert {i.profile_id for i in infos} == {first.id, second.id}
    assert any(isinstance(e, Notification) and e.title == "D" for e in bus.events)
    for info in infos:
        await wait_state(manager, info.id, {SessionState.LISTENING})
    assert await manager.start_group("Prod") == []  # déjà connectés : rien de plus

    await manager.stop_group("prod")
    assert not [s for s in manager.sessions.values() if s.state.active]
    with pytest.raises(ManagerError):
        await manager.start_group("Inconnu")
    with pytest.raises(ManagerError):
        await manager.stop_group("Inconnu")


async def test_group_commands(manager, store):
    add(store, CloudflareProfile(name="A", group="Prod", hostname="a.ex.fr", local_port=free_port()))
    reply = await execute(manager, {"cmd": "connect", "group": "Prod"})
    assert reply["ok"] and len(reply["sessions"]) == 1
    assert (await execute(manager, {"cmd": "disconnect", "group": "Prod"}))["ok"]
    reply = await execute(manager, {"cmd": "connect", "group": "Absent"})
    assert not reply["ok"] and "Absent" in reply["error"]


async def test_ssh_through_cloudflare_tunnel(manager, store, ssh_server):  # noqa: F811
    FAKE_ENV["FAKE_CF_MODE"] = "proxy"
    FAKE_ENV["FAKE_CF_TARGET"] = f"127.0.0.1:{ssh_server['port']}"
    cf = add(store, CloudflareProfile(name="Bastion", hostname="ssh.exemple.fr", local_port=free_port()))
    ssh = add(
        store,
        SshProfile(name="Via CF", user="admin", auth=SshAuthMode.PASSWORD, via_cloudflare_profile=cf.id),
    )
    result = await manager.discover_ports(ssh.id)
    assert [p.port for p in result.ports] == [22]
    prompt = manager.ssh.prompter.host_key_prompts[0]
    assert prompt.host == "ssh.exemple.fr"
    assert prompt.port == 22
    assert prompt.via == "ssh.exemple.fr"
    assert manager.active_session_for(cf.id) is not None
    await manager.ssh_disconnect(ssh.id)
    assert not manager.ssh.is_connected(ssh.id)


async def test_text_commands(manager, store, ssh_server):  # noqa: F811
    cf = add(store, CloudflareProfile(name="Web", hostname="web.ex.fr", local_port=free_port()))
    ssh = add(store, SshProfile(name="Serveur", host="127.0.0.1", port=ssh_server["port"], user="admin"))
    listing = await execute(manager, {"cmd": "list"})
    assert {p["name"] for p in listing["profiles"]} == {"Web", "Serveur"}
    connected = await execute(manager, {"cmd": "connect", "profile": "web"})
    assert connected["ok"]
    assert connected["sessions"][0]["name"] == "Web"
    status = await execute(manager, {"cmd": "status"})
    assert len(status["sessions"]) == 1
    ssh_reply = await execute(manager, {"cmd": "connect", "profile": "Serveur"})
    assert ssh_reply["ok"]
    assert "aucune redirection" in ssh_reply["message"]
    assert (await execute(manager, {"cmd": "disconnect", "profile": ssh.id}))["ok"]
    assert (await execute(manager, {"cmd": "disconnect", "profile": cf.name}))["ok"]
    assert not (await execute(manager, {"cmd": "connect", "profile": "absent"}))["ok"]
    assert not (await execute(manager, {"cmd": "disconnect", "profile": "absent"}))["ok"]
    assert (await execute(manager, {"cmd": "disconnect", "all": True}))["ok"]
    assert not (await execute(manager, {"cmd": "bidule"}))["ok"]
    incomplete = add(store, CloudflareProfile(name="Vide"))
    assert "incomplet" in (await execute(manager, {"cmd": "connect", "profile": incomplete.name}))["error"]
    assert os.environ.get("FAKE_CF_MODE") is None


async def test_favorites_and_workspaces(manager, store):
    from cma.core.models import LaunchItem, SavedForward, Workspace

    fav = add(store, CloudflareProfile(name="Fav", favorite=True, hostname="f.ex.fr", local_port=free_port()))
    other = add(store, CloudflareProfile(name="Autre", hostname="o.ex.fr", local_port=free_port()))
    forward = SavedForward(remote_port=80, local_port=free_port(), label="web")
    server = add(store, SshProfile(name="Srv", host="127.0.0.1", user="u", saved_forwards=[forward]))
    items = store.snapshot().favorite_items()
    assert [(i.kind, i.profile_id) for i in items] == [("cloudflare", fav.id)]

    report = await manager.start_favorites()
    assert [i.profile_id for i in report.started] == [fav.id] and report.failed == []
    for info in report.started:
        await wait_state(manager, info.id, {SessionState.LISTENING})

    workspace = Workspace(
        name="Matin",
        items=[
            LaunchItem(kind="cloudflare", profile_id=other.id),
            LaunchItem(kind="ssh", profile_id=server.id, forward_id=forward.id),
            LaunchItem(kind="cloudflare", profile_id="supprimé"),
        ],
    )
    store.update(lambda c: c.workspaces.append(workspace))
    report = await manager.start_workspace("matin")
    assert {i.profile_id for i in report.started} == {other.id, server.id}
    assert report.failed == [("Élément supprimé", "Cet accès n'existe plus.")]
    with pytest.raises(ManagerError):
        await manager.start_workspace("Inconnu")
    store.update(lambda c: c.workspaces.append(Workspace(name="Vide")))
    with pytest.raises(ManagerError, match="vide"):
        await manager.start_workspace("Vide")


async def test_favorites_and_workspace_commands(manager, store):
    from cma.core.models import LaunchItem, Workspace

    fav = add(store, CloudflareProfile(name="Fav", favorite=True, hostname="f.ex.fr", local_port=free_port()))
    reply = await execute(manager, {"cmd": "connect", "favorites": True})
    assert reply["ok"] and len(reply["sessions"]) == 1
    store.update(
        lambda c: c.workspaces.append(
            Workspace(name="Soir", items=[LaunchItem(kind="cloudflare", profile_id="absent")])
        )
    )
    reply = await execute(manager, {"cmd": "connect", "workspace": "Soir"})
    assert reply["ok"] and reply["sessions"] == [] and "absent" not in reply["message"]
    assert "n'existe plus" in reply["message"]
    reply = await execute(manager, {"cmd": "connect", "workspace": "Inconnu"})
    assert not reply["ok"]
    assert fav


async def test_probe_session_reports_the_remote_answer(manager, store, monkeypatch):
    from cma.core.models import ServiceType

    async def handle(reader, writer):
        await reader.read(1024)
        writer.write(b"HTTP/1.1 200 OK\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    target = server.sockets[0].getsockname()[1]
    monkeypatch.setitem(FAKE_ENV, "FAKE_CF_MODE", "proxy")
    monkeypatch.setitem(FAKE_ENV, "FAKE_CF_TARGET", f"127.0.0.1:{target}")
    profile = add(
        store,
        CloudflareProfile(
            name="Web", hostname="w.ex.fr", local_port=free_port(), service_type=ServiceType.HTTP
        ),
    )
    info = await manager.start_cloudflare(profile.id)
    await wait_state(manager, info.id, {SessionState.LISTENING})
    result = await manager.probe_session(info.id)
    server.close()
    assert result.ok and "200" in result.message
    assert manager.session(info.id).info().probe_ok is True
    with pytest.raises(ManagerError):
        await manager.probe_session("absent")


async def test_guided_diagnosis(manager, store, secrets, monkeypatch):
    import cma.core.diagnose as diagnose

    token = ServiceToken(name="T", client_id="t.access")
    store.update(lambda c: c.tokens.append(token))
    secrets.set(token.secret_key, "secret")
    profile = add(
        store,
        CloudflareProfile(
            name="Diag",
            hostname="localhost",
            local_port=free_port(),
            auth=AuthMode.SERVICE_TOKEN,
            token_id=token.id,
        ),
    )
    monkeypatch.setattr(
        diagnose, "_https_head", lambda *_a: (302, "https://equipe.cloudflareaccess.com/cdn-cgi")
    )
    checks = await diagnose.diagnose_cloudflare_profile(manager, profile.id)
    by_name = {c.name: c for c in checks}
    assert by_name["Port local"].status == "ok"
    assert by_name["Résolution DNS"].status == "ok"
    assert by_name["Proxy"].status == "skipped"
    assert by_name["HTTPS et Cloudflare Access"].status == "ok"
    assert by_name["Authentification"].status in ("ok", "error")
    report = diagnose.format_report("Diag", checks)
    assert report.startswith("Diagnostic de « Diag »") and "secret" not in report

    monkeypatch.setattr(diagnose, "_https_head", lambda *_a: (200, ""))
    unprotected = await diagnose._access(profile)
    assert unprotected.status == "warning"
    proxied = profile.model_copy(update={"proxy": "127.0.0.1:1"})
    assert (await diagnose._proxy(proxied.proxy)).status == "error"
    assert (await diagnose.diagnose_cloudflare_profile(manager, "absent"))[0].status == "error"
