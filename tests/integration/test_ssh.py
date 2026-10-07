"""SSH de bout en bout contre un vrai serveur asyncssh lancé par le test (aucun serveur externe)."""

import asyncio
import contextlib

import asyncssh
import pytest

from cma.core.manager import ManagerError, SessionManager
from cma.core.models import SavedForward, SshAuthMode, SshProfile
from cma.core.netutil import find_free_port
from cma.core.prompts import PasswordAnswer
from cma.core.sessions import SessionState
from cma.core.ssh.errors import SshCancelled, SshError
from cma.core.ssh.hostkeys import KnownHostsFile
from cma.core.ssh.keys import DeployResult, generate_key

PASSWORD = "motdepasse-test"
NDJSON = (
    '{"v":2,"meta":{"version":"2.0.0","docker":"none","web_probe":true}}\n'
    '{"v":2,"proto":"tcp","port":22,"bind":["0.0.0.0"],"service":"ssh","container":null,"scheme":null,"http_code":null,"final_url":null}\n'
)


class ScriptedPrompter:
    def __init__(self, passwords=(), passphrases=(), trust=True):
        self.passwords = list(passwords)
        self.passphrases = list(passphrases)
        self.trust = trust
        self.host_key_prompts = []
        self.password_requests = []

    async def confirm_host_key(self, prompt):
        self.host_key_prompts.append(prompt)
        return self.trust

    async def ask_password(self, request):
        self.password_requests.append(request)
        if not self.passwords:
            return None
        return PasswordAnswer(self.passwords.pop(0))

    async def ask_passphrase(self, request):
        return self.passphrases.pop(0) if self.passphrases else None


class FakeSshServer(asyncssh.SSHServer):
    def __init__(self, home):
        self.home = home

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == "admin" and password == PASSWORD

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        authorized = self.home / ".ssh" / "authorized_keys"
        if not authorized.is_file():
            return False
        wanted = key.export_public_key("openssh").decode().split()[1]
        return any(wanted in line for line in authorized.read_text().splitlines())

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        return True

    def server_requested(self, listen_host, listen_port):
        return True  # redirection inverse (-R) acceptée


WINDOWS_NDJSON = (
    '{"v":2,"meta":{"version":"2.1.0","os":"windows","source":"Get-NetTCPConnection","docker":"absent","web_probe":true}}\n'
    '{"v":2,"proto":"tcp","port":3389,"bind":["0.0.0.0"],"service":"TermService","container":null,'
    '"scheme":null,"http_code":null,"final_url":null}\n'
)


class ServerState:
    bash_available = True
    windows = False
    received_scripts: list[str]

    def __init__(self):
        self.received_scripts = []


async def create_test_server(tmp_path):
    """Serveur SSH de test (mot de passe, clés, SFTP chrooté, direct-tcpip, bash -s simulé)."""
    home = tmp_path / "home"
    home.mkdir()
    state = ServerState()
    host_key = asyncssh.generate_private_key("ssh-ed25519")

    async def handle(process: asyncssh.SSHServerProcess):
        command = process.command or ""
        if command == "echo %OS% $env:OS":
            process.stdout.write("Windows_NT $env:OS\r\n" if state.windows else "%OS% :OS\n")
            process.exit(0)
        elif command.startswith("powershell ") and state.windows:
            state.received_scripts.append(await process.stdin.read())
            process.stdout.write(WINDOWS_NDJSON)
            process.exit(0)
        elif command.startswith("bash -s") and state.bash_available:
            state.received_scripts.append(await process.stdin.read())
            process.stdout.write(NDJSON)
            process.exit(0)
        elif command.startswith("bash -s"):
            process.stderr.write("bash: not found\n")
            process.exit(127)
        elif command.startswith("ss "):
            process.stdout.write("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n")
            process.exit(0)
        else:
            process.exit(127)

    class ChrootSftp(asyncssh.SFTPServer):
        def __init__(self, chan):
            super().__init__(chan, chroot=str(home))

    server = await asyncssh.create_server(
        lambda: FakeSshServer(home),
        "127.0.0.1",
        0,
        server_host_keys=[host_key],
        process_factory=handle,
        sftp_factory=ChrootSftp,
    )
    port = server.sockets[0].getsockname()[1]
    return {"port": port, "home": home, "state": state, "host_key": host_key, "server": server}


@pytest.fixture
async def ssh_server(tmp_path):
    info = await create_test_server(tmp_path)
    yield info
    server = info["server"]
    server.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(server.wait_closed(), 5)


_MANAGERS: list[SessionManager] = []


def make_manager(paths, store, secrets, bus, prompter):
    manager = SessionManager(paths=paths, store=store, secrets=secrets, bus=bus, prompter=prompter)
    _MANAGERS.append(manager)
    return manager


@pytest.fixture(autouse=True)
async def _shutdown_managers():
    yield
    while _MANAGERS:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(_MANAGERS.pop().shutdown(), 10)


def add_profile(store, port, **overrides):
    values = {
        "name": "Serveur test",
        "host": "127.0.0.1",
        "port": port,
        "user": "admin",
        "auth": SshAuthMode.PASSWORD,
    }
    values.update(overrides)
    profile = SshProfile(**values)
    store.update(lambda config: config.ssh_profiles.append(profile))
    return profile


async def test_password_auth_and_trust_on_first_use(paths, store, secrets, bus, ssh_server):
    profile = add_profile(store, ssh_server["port"])
    prompter = ScriptedPrompter(passwords=[PASSWORD])
    manager = make_manager(paths, store, secrets, bus, prompter)
    await manager.ssh_connect(profile.id)
    assert manager.ssh.is_connected(profile.id)
    assert len(prompter.host_key_prompts) == 1
    prompt = prompter.host_key_prompts[0]
    assert not prompt.changed
    assert prompt.fingerprint == ssh_server["host_key"].get_fingerprint("sha256")
    assert f"[127.0.0.1]:{ssh_server['port']}" in paths.known_hosts.read_text()
    await manager.shutdown()

    # Deuxième connexion : clé connue, aucune question sur la clé d'hôte.
    second = ScriptedPrompter(passwords=[PASSWORD])
    manager = make_manager(paths, store, secrets, bus, second)
    await manager.ssh_connect(profile.id)
    assert second.host_key_prompts == []
    await manager.shutdown()


async def test_refused_host_key_cancels_and_writes_nothing(paths, store, secrets, bus, ssh_server):
    profile = add_profile(store, ssh_server["port"])
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter(passwords=[PASSWORD], trust=False))
    with pytest.raises(ManagerError):
        await manager.ssh_connect(profile.id)
    assert not paths.known_hosts.exists()
    await manager.shutdown()


async def test_changed_host_key_is_flagged(paths, store, secrets, bus, ssh_server):
    profile = add_profile(store, ssh_server["port"])
    other_key = asyncssh.generate_private_key("ssh-ed25519")
    KnownHostsFile(paths.known_hosts).add("127.0.0.1", ssh_server["port"], other_key, replace=True)
    prompter = ScriptedPrompter(passwords=[PASSWORD])
    manager = make_manager(paths, store, secrets, bus, prompter)
    await manager.ssh_connect(profile.id)
    prompt = prompter.host_key_prompts[0]
    assert prompt.changed
    assert prompt.previous_fingerprints == (other_key.get_fingerprint("sha256"),)
    assert other_key.get_fingerprint("sha256") not in KnownHostsFile(paths.known_hosts).fingerprints_for(
        "127.0.0.1", ssh_server["port"]
    )
    await manager.shutdown()


async def test_wrong_password_three_times_then_fatal(paths, store, secrets, bus, ssh_server):
    profile = add_profile(store, ssh_server["port"])
    prompter = ScriptedPrompter(passwords=["faux1", "faux2", "faux3"])
    manager = make_manager(paths, store, secrets, bus, prompter)
    with pytest.raises(ManagerError, match="refusée"):
        await manager.ssh_connect(profile.id)
    assert len(prompter.password_requests) == 3
    assert prompter.password_requests[1].error
    await manager.shutdown()


async def test_cancelled_password(paths, store, secrets, bus, ssh_server):
    profile = add_profile(store, ssh_server["port"])
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter(passwords=[]))
    with pytest.raises(SshCancelled):
        await manager.ssh.get(store.snapshot().ssh_profile(profile.id))
    await manager.shutdown()


async def test_remembered_password_goes_to_the_vault(paths, store, secrets, bus, ssh_server):
    profile = add_profile(store, ssh_server["port"])

    class RememberingPrompter(ScriptedPrompter):
        async def ask_password(self, request):
            self.password_requests.append(request)
            return PasswordAnswer(PASSWORD, remember=True)

    manager = make_manager(paths, store, secrets, bus, RememberingPrompter())
    await manager.ssh_connect(profile.id)
    assert secrets.get(profile.password_key) == PASSWORD
    assert store.snapshot().ssh_profile(profile.id).remember_password
    await manager.shutdown()

    silent = ScriptedPrompter(passwords=[])
    manager = make_manager(paths, store, secrets, bus, silent)
    await manager.ssh_connect(profile.id)
    assert silent.password_requests == []
    await manager.shutdown()


async def test_key_generation_deploy_and_key_auth(paths, store, secrets, bus, ssh_server):
    key = generate_key(paths.keys_dir, "test", passphrase="phrase-cle")
    profile = add_profile(store, ssh_server["port"], auth=SshAuthMode.KEY, key_path=key.path.name)
    prompter = ScriptedPrompter(passwords=[PASSWORD], passphrases=["mauvaise", "phrase-cle"])
    manager = make_manager(paths, store, secrets, bus, prompter)

    with pytest.raises(ManagerError, match="clé non autorisée"):
        await manager.ssh_connect(profile.id)
    assert await manager.deploy_key(profile.id, key.path.name) == DeployResult.ADDED
    authorized = ssh_server["home"] / ".ssh" / "authorized_keys"
    assert key.fingerprint and authorized.read_text().count("ssh-ed25519") == 1
    prompter.passwords.append(PASSWORD)
    assert await manager.deploy_key(profile.id, key.path.name) == DeployResult.ALREADY_PRESENT
    assert authorized.read_text().count("ssh-ed25519") == 1

    await manager.ssh_connect(profile.id)
    assert manager.ssh.is_connected(profile.id)
    await manager.shutdown()


async def test_discovery_sends_the_script_by_stdin(paths, store, secrets, bus, ssh_server):
    profile = add_profile(store, ssh_server["port"])
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter(passwords=[PASSWORD]))
    result = await manager.discover_ports(profile.id)
    assert [p.port for p in result.ports] == [22]
    assert result.script_version == "2.0.0"
    assert ssh_server["state"].received_scripts[0].startswith("#!/usr/bin/env bash")
    await manager.shutdown()


async def test_discovery_on_a_windows_server(paths, store, secrets, bus, ssh_server):
    ssh_server["state"].windows = True
    profile = add_profile(store, ssh_server["port"])
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter(passwords=[PASSWORD]))
    result = await manager.discover_ports(profile.id, probe_web=False)
    assert result.os == "windows"
    assert [(p.port, p.service) for p in result.ports] == [(3389, "TermService")]
    script = ssh_server["state"].received_scripts[0]
    assert script.startswith("$CmaNoWeb = $true\n")
    assert script.isascii() and "Get-NetTCPConnection" in script
    await manager.shutdown()


async def test_discovery_falls_back_to_ss_without_bash(paths, store, secrets, bus, ssh_server):
    ssh_server["state"].bash_available = False
    profile = add_profile(store, ssh_server["port"])
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter(passwords=[PASSWORD]))
    result = await manager.discover_ports(profile.id)
    assert result.mode == "ss"
    assert [(p.port, p.bind) for p in result.ports] == [(22, ("0.0.0.0",)), (5432, ("127.0.0.1",))]
    await manager.shutdown()


async def wait_state(session, states, timeout=10.0):
    for _ in range(int(timeout / 0.05)):
        if session.state in states:
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"{session.state} : {session.message}")


@pytest.fixture
async def echo_server():
    async def echo(reader, writer):
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    yield server.sockets[0].getsockname()[1]
    server.close()


async def test_forward_relays_data_and_counts_bytes(paths, store, secrets, bus, ssh_server, echo_server):
    profile = add_profile(store, ssh_server["port"])
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter(passwords=[PASSWORD]))
    local_port = find_free_port(port_range=(22000, 22999))
    forward = SavedForward(
        remote_host="127.0.0.1", remote_port=echo_server, local_port=local_port, label="echo"
    )
    info = await manager.start_forward(profile.id, forward, save=True)
    session = manager.session(info.id)
    await wait_state(session, {SessionState.LISTENING})
    assert store.snapshot().ssh_profile(profile.id).saved_forwards[0].id == forward.id

    payload = bytes(range(256)) * 2048
    reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
    writer.write(payload)
    await writer.drain()
    received = await reader.readexactly(len(payload))
    writer.close()
    assert received == payload
    await asyncio.sleep(0.2)
    assert session.bytes_up == len(payload)
    assert session.bytes_down == len(payload)

    await manager.stop(info.id)
    assert manager.session(info.id) is None
    # L'historique a suivi la redirection jusqu'à son arrêt, octets compris.
    [record] = manager.history.records(profile.id)
    assert (record.kind, record.forward_id, record.end_state) == ("ssh_forward", forward.id, "stopped")
    assert record.bytes_up == len(payload) and record.listening_seconds > 0
    assert paths.history_file.exists()
    await manager.shutdown()


async def test_forward_to_closed_port_degrades(paths, store, secrets, bus, ssh_server):
    profile = add_profile(store, ssh_server["port"])
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter(passwords=[PASSWORD]))
    closed = find_free_port(port_range=(23000, 23999))
    local_port = find_free_port(port_range=(24000, 24999))
    info = await manager.start_forward(profile.id, SavedForward(remote_port=closed, local_port=local_port))
    session = manager.session(info.id)
    await wait_state(session, {SessionState.LISTENING})
    reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
    await reader.read()
    writer.close()
    await wait_state(session, {SessionState.DEGRADED})
    assert "n'a pas pu joindre" in session.message
    await manager.shutdown()


async def test_forward_reconnects_after_connection_loss(paths, store, secrets, bus, ssh_server, echo_server):
    profile = add_profile(store, ssh_server["port"])
    prompter = ScriptedPrompter(passwords=[PASSWORD])
    manager = make_manager(paths, store, secrets, bus, prompter)
    local_port = find_free_port(port_range=(25000, 25999))
    info = await manager.start_forward(
        profile.id, SavedForward(remote_port=echo_server, local_port=local_port)
    )
    session = manager.session(info.id)
    await wait_state(session, {SessionState.LISTENING})
    manager.ssh._connections[profile.id].abort()
    await wait_state(session, {SessionState.RECONNECTING})
    await wait_state(session, {SessionState.LISTENING}, timeout=10)
    # Le mot de passe est resté en mémoire pour la session : aucune nouvelle question.
    assert len(prompter.password_requests) == 1
    reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
    writer.write(b"ping")
    assert await reader.readexactly(4) == b"ping"
    writer.close()
    await manager.shutdown()


async def test_local_port_conflict_between_sessions(paths, store, secrets, bus, ssh_server, echo_server):
    profile = add_profile(store, ssh_server["port"])
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter(passwords=[PASSWORD]))
    local_port = find_free_port(port_range=(26000, 26999))
    await manager.start_forward(profile.id, SavedForward(remote_port=echo_server, local_port=local_port))
    with pytest.raises(ManagerError, match="déjà utilisé"):
        await manager.start_forward(profile.id, SavedForward(remote_port=echo_server, local_port=local_port))
    await manager.shutdown()


async def test_missing_user_is_reported(paths, store, secrets, bus):
    profile = SshProfile(name="Incomplet", host="h")
    store.update(lambda config: config.ssh_profiles.append(profile))
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter())
    with pytest.raises(ManagerError, match="incomplet"):
        await manager.ssh_connect(profile.id)
    with pytest.raises(SshError):
        await manager.ssh.open(profile)


async def test_sftp_browse_transfer_and_tidy(paths, store, secrets, bus, ssh_server, tmp_path):
    home = ssh_server["home"]
    (home / "docs" / "sous").mkdir(parents=True)
    (home / "docs" / "a.txt").write_text("alpha", encoding="utf-8")
    (home / "docs" / "sous" / "b.txt").write_text("bravo", encoding="utf-8")
    (home / "z.log").write_text("x" * 1000, encoding="utf-8")
    profile = add_profile(store, ssh_server["port"])
    manager = make_manager(paths, store, secrets, bus, ScriptedPrompter(passwords=[PASSWORD]))

    root, entries = await manager.sftp_list(profile.id)
    assert [(e.name, e.is_dir) for e in entries] == [("docs", True), ("z.log", False)]
    log_entry = entries[1]
    assert log_entry.size == 1000 and log_entry.permissions.startswith("-") and log_entry.modified is not None
    docs, inside = await manager.sftp_list(profile.id, entries[0].path)
    assert docs.endswith("docs") and [e.name for e in inside] == ["sous", "a.txt"]

    # Téléchargement récursif, avec la progression.
    seen: list[tuple[str, int, int]] = []
    local = tmp_path / "local"
    created = await manager.sftp_download(profile.id, [entries[0].path], local, lambda *p: seen.append(p))
    assert created == [local / "docs"]
    assert (local / "docs" / "sous" / "b.txt").read_text(encoding="utf-8") == "bravo"
    assert any(name == "a.txt" and copied == total == 5 for name, copied, total in seen)

    # Envoi d'un fichier et d'un dossier ; ce qui existe déjà est signalé avant.
    outgoing = tmp_path / "envoi"
    (outgoing / "lot").mkdir(parents=True)
    (outgoing / "lot" / "c.txt").write_text("charlie", encoding="utf-8")
    (outgoing / "a.txt").write_text("nouveau", encoding="utf-8")
    assert await manager.sftp_existing(profile.id, docs, ["a.txt", "lot"]) == ["a.txt"]
    await manager.sftp_upload(profile.id, [outgoing / "a.txt", outgoing / "lot"], docs)
    assert (home / "docs" / "a.txt").read_text(encoding="utf-8") == "nouveau"
    assert (home / "docs" / "lot" / "c.txt").read_text(encoding="utf-8") == "charlie"

    # Ranger : dossier, renommage, suppressions ; les noms invalides sont refusés.
    made = await manager.sftp_mkdir(profile.id, docs, "  archives ")
    assert made.endswith("docs/archives") and (home / "docs" / "archives").is_dir()
    for bad in ("", "..", "a/b"):
        with pytest.raises(ManagerError, match="Nom invalide"):
            await manager.sftp_mkdir(profile.id, docs, bad)
    renamed = await manager.sftp_rename(profile.id, f"{docs}/a.txt", "alpha.txt")
    assert renamed.endswith("docs/alpha.txt") and (home / "docs" / "alpha.txt").exists()
    with pytest.raises(ManagerError, match="existe déjà"):
        await manager.sftp_rename(profile.id, renamed, "lot")
    _, inside = await manager.sftp_list(profile.id, docs)
    by_name = {e.name: e for e in inside}
    await manager.sftp_remove(profile.id, by_name["alpha.txt"])
    await manager.sftp_remove(profile.id, by_name["sous"])  # dossier avec son contenu
    assert sorted(p.name for p in (home / "docs").iterdir()) == ["archives", "lot"]

    with pytest.raises(ManagerError, match="impossible"):
        await manager.sftp_list(profile.id, "/inexistant")
    with pytest.raises(ManagerError, match="introuvable"):
        await manager.sftp_list("inconnu")
