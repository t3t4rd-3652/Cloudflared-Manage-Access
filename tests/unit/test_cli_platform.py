"""Ligne de commande (avec et sans instance), lanceurs externes, démarrage automatique."""

import json
import sys
import time
import types

import pytest

import cma.platform.autostart as autostart
import cma.platform.launchers as launchers
from cma.__main__ import main
from cma.cli import CliPrompter, build_parser, run
from cma.core.instance import IpcServer
from cma.core.models import CloudflareProfile, SshProfile
from cma.core.prompts import PassphraseRequest, PasswordRequest
from cma.core.ssh.hostkeys import HostKeyPrompt


def cli(paths, *args):
    return run(build_parser().parse_args(["--data-dir", str(paths.data_dir), *args]))


def test_list_and_doctor(paths, store, capsys):
    store.update(
        lambda c: c.cloudflare_profiles.append(
            CloudflareProfile(name="Web", hostname="w.ex.fr", local_port=8080)
        )
    )
    store.update(lambda c: c.ssh_profiles.append(SshProfile(name="NAS", host="nas", user="u")))
    assert cli(paths, "list") == 0
    out = capsys.readouterr().out
    assert "Web" in out and "NAS" in out
    assert cli(paths, "list", "--json") == 0
    assert {p["name"] for p in json.loads(capsys.readouterr().out)} == {"Web", "NAS"}
    assert cli(paths, "doctor") == 0
    assert capsys.readouterr().out.strip().endswith(".zip")


def test_commands_without_instance(paths, capsys):
    assert cli(paths, "status") == 1
    assert cli(paths, "disconnect", "--all") == 1
    assert cli(paths, "quit") == 1
    assert cli(paths, "disconnect") == 2
    assert cli(paths, "connect") == 2
    assert "Aucune instance" in capsys.readouterr().out


def test_commands_through_a_running_instance(paths, capsys):
    replies = {
        "status": {
            "ok": True,
            "sessions": [
                {
                    "name": "Web",
                    "state_label": "À l'écoute",
                    "local": "127.0.0.1:1",
                    "target": "w",
                    "message": "",
                }
            ],
        },
        "connect": {"ok": True, "sessions": [], "message": "connecté"},
        "disconnect": {"ok": False, "error": "refus"},
        "quit": {"ok": True},
    }
    received: list[dict] = []

    def handler(message):
        received.append(message)
        return replies[message["cmd"]]

    server = IpcServer(paths, handler)
    server.start()
    try:
        time.sleep(0.2)
        assert cli(paths, "status") == 0
        assert "À l'écoute" in capsys.readouterr().out
        assert cli(paths, "status", "--json") == 0
        assert json.loads(capsys.readouterr().out)[0]["name"] == "Web"
        assert cli(paths, "connect", "Web") == 0
        assert "connecté" in capsys.readouterr().out
        assert cli(paths, "disconnect", "Web") == 1
        assert cli(paths, "connect", "--group", "Prod") == 0
        assert cli(paths, "disconnect", "--group", "Prod") == 1
        assert [m.get("group") for m in received[-2:]] == ["Prod", "Prod"]
        assert cli(paths, "quit") == 0
    finally:
        server.stop()


def test_foreground_connect_reports_errors(paths, store, capsys, monkeypatch):
    import cma.context
    from tests.conftest import PersistentMemoryStore

    monkeypatch.setattr(cma.context, "open_secret_store", PersistentMemoryStore)
    store.update(lambda c: c.cloudflare_profiles.append(CloudflareProfile(name="Vide")))
    assert cli(paths, "connect", "Vide", "--foreground") == 1
    assert "incomplet" in capsys.readouterr().err


def test_main_dispatches_to_cli(paths):
    assert main(["--data-dir", str(paths.data_dir), "list"]) == 0


def test_help_without_command(paths, capsys):
    args = build_parser().parse_args(["--data-dir", str(paths.data_dir)])
    args.command = "inconnue"
    assert run(args) == 2


async def test_cli_prompter(monkeypatch, capsys):
    prompter = CliPrompter()
    monkeypatch.setattr("builtins.input", lambda _p: "o")
    prompt = HostKeyPrompt(
        "h", 22, "ssh-ed25519", "SHA256:x", changed=True, previous_fingerprints=("SHA256:old",)
    )
    assert await prompter.confirm_host_key(prompt)
    monkeypatch.setattr("cma.cli.getpass.getpass", lambda _p: "mdp")
    answer = await prompter.ask_password(PasswordRequest("p", "u@h:22", error="refusé"))
    assert answer is not None and answer.password == "mdp"
    assert await prompter.ask_passphrase(PassphraseRequest("k", error="faux")) == "mdp"
    monkeypatch.setattr("cma.cli.getpass.getpass", lambda _p: "")
    assert await prompter.ask_password(PasswordRequest("p", "t")) is None
    assert "CHANGÉ" in capsys.readouterr().out


# --- Lanceurs ----------------------------------------------------------------------------------


@pytest.fixture
def spawned(monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(launchers, "_spawn", lambda args, new_console=False: calls.append(args))
    return calls


def test_ssh_terminal_and_rdp(spawned, monkeypatch):
    assert launchers.ssh_command("127.0.0.1", 2222, "admin") == ["ssh", "-p", "2222", "admin@127.0.0.1"]
    monkeypatch.setattr(launchers.shutil, "which", lambda name: "wt.exe" if name == "wt.exe" else None)
    monkeypatch.setattr(launchers.sys, "platform", "win32")
    launchers.open_ssh_terminal("127.0.0.1", 2222, "admin", "Bastion")
    assert spawned[-1][:4] == ["wt.exe", "new-tab", "--title", "Bastion"]
    monkeypatch.setattr(launchers.shutil, "which", lambda _n: None)
    launchers.open_ssh_terminal("127.0.0.1", 22)
    assert spawned[-1][:2] == ["cmd.exe", "/k"]
    launchers.open_rdp("127.0.0.1", 3390)
    assert spawned[-1] == ["mstsc.exe", "/v:127.0.0.1:3390"]
    monkeypatch.setattr(launchers.sys, "platform", "linux")
    with pytest.raises(launchers.LaunchError):
        launchers.open_ssh_terminal("h", 22)
    with pytest.raises(launchers.LaunchError):
        launchers.open_rdp("h", 1)
    monkeypatch.setattr(launchers.shutil, "which", lambda name: "/usr/bin/xterm" if name == "xterm" else None)
    launchers.open_ssh_terminal("h", 22)
    assert spawned[-1][:2] == ["xterm", "-e"]


def test_mongodb_compass(spawned, tmp_path, monkeypatch):
    monkeypatch.setattr(launchers, "find_mongodb_compass", lambda: None)
    with pytest.raises(launchers.LaunchError):
        launchers.open_mongodb_compass("mongodb://x")
    compass = tmp_path / "MongoDBCompass.exe"
    compass.write_bytes(b"")
    monkeypatch.setattr(launchers, "find_mongodb_compass", lambda: compass)
    launchers.open_mongodb_compass("mongodb://127.0.0.1:27017")
    assert spawned[-1] == [str(compass), "mongodb://127.0.0.1:27017"]


def test_spawn_failure_is_a_launch_error():
    with pytest.raises(launchers.LaunchError):
        launchers._spawn(["programme-qui-n-existe-pas-cma"])


# --- Démarrage automatique ---------------------------------------------------------------------


def test_autostart_windows_registry(monkeypatch):
    values: dict[str, str] = {}

    class Key:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    fake = types.SimpleNamespace(
        HKEY_CURRENT_USER=1,
        KEY_SET_VALUE=2,
        REG_SZ=1,
        OpenKey=lambda *a: Key(),
        SetValueEx=lambda _k, name, _r, _t, value: values.__setitem__(name, value),
        DeleteValue=lambda _k, name: (
            values.pop(name) if name in values else (_ for _ in ()).throw(FileNotFoundError())
        ),
        QueryValueEx=lambda _k, name: (
            (values[name], 1) if name in values else (_ for _ in ()).throw(OSError())
        ),
    )
    monkeypatch.setitem(sys.modules, "winreg", fake)
    monkeypatch.setattr(autostart.sys, "platform", "win32")
    autostart.set_enabled(True)
    assert autostart.is_enabled()
    assert "--minimized" in values["CloudflaredManageAccess"]
    autostart.set_enabled(False)
    autostart.set_enabled(False)
    assert not autostart.is_enabled()


def test_autostart_linux_desktop_file(monkeypatch, tmp_path):
    desktop = tmp_path / "autostart" / "cma.desktop"
    monkeypatch.setattr(autostart, "_DESKTOP_FILE", desktop)
    monkeypatch.setattr(autostart.sys, "platform", "linux")
    assert autostart.supported()
    autostart.set_enabled(True)
    assert "--minimized" in desktop.read_text(encoding="utf-8")
    assert autostart.is_enabled()
    autostart.set_enabled(False)
    assert not desktop.exists()
    monkeypatch.setattr(autostart.sys, "platform", "darwin")
    with pytest.raises(NotImplementedError):
        autostart.set_enabled(True)


def test_launch_command_frozen(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert autostart.launch_command() == [sys.executable, "--minimized"]
