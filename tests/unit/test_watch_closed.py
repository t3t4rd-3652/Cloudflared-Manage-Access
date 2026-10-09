"""Surveillance quand CMA est fermé : tâche planifiée, notification du système, `cma tunnels --notify`.

Aucun appel réel : schtasks, PowerShell et notify-send sont remplacés ; rien n'est créé sur le poste.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import cma.cli as cli
from cma.core.secrets import EncryptedFileSecretStore, MemorySecretStore
from cma.paths import AppPaths
from cma.platform import notify, schedule


def completed(code: int = 0, out: str = "", err: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], code, out, err)


def test_scheduled_task(monkeypatch):
    calls: list[tuple[str, ...]] = []
    existing = {"value": False}

    def fake(*args: str) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[0] == "/Query":
            return completed(0 if existing["value"] else 1)
        return completed()

    monkeypatch.setattr(schedule, "_schtasks", fake)
    monkeypatch.setattr(schedule.sys, "platform", "win32")
    assert schedule.supported() and not schedule.is_enabled()
    schedule.set_enabled(True)
    create = calls[-1]
    assert create[:3] == ("/Create", "/TN", schedule.TASK_NAME)
    assert "tunnels --notify" in create[4] and create[5:9] == ("/SC", "MINUTE", "/MO", "15")
    # Retirer une tâche absente ne fait rien ; présente, elle est supprimée.
    calls.clear()
    schedule.set_enabled(False)
    assert [c[0] for c in calls] == ["/Query"]
    existing["value"] = True
    schedule.set_enabled(False)
    assert calls[-1][:3] == ("/Delete", "/TN", schedule.TASK_NAME)
    # Un refus de schtasks remonte avec son message.
    monkeypatch.setattr(schedule, "_schtasks", lambda *_a: completed(1, err="Accès refusé."))
    with pytest.raises(OSError, match="Accès refusé"):
        schedule.set_enabled(True)
    monkeypatch.setattr(schedule.sys, "platform", "linux")
    assert not schedule.supported() and not schedule.is_enabled()
    with pytest.raises(OSError):
        schedule.set_enabled(True)


def test_monitor_command(monkeypatch, tmp_path):
    monkeypatch.setattr(schedule.sys, "frozen", True, raising=False)
    monkeypatch.setattr(schedule.sys, "executable", str(tmp_path / "CloudflaredManageAccess.exe"))
    assert schedule.monitor_command()[1:] == ["tunnels", "--notify"]
    monkeypatch.setattr(schedule.sys, "frozen", False, raising=False)
    assert schedule.monitor_command()[1:] == ["-m", "cma", "tunnels", "--notify"]


@pytest.mark.parametrize("platform", ["win32", "darwin", "linux"])
def test_system_notification(monkeypatch, platform):
    seen: list[SimpleNamespace] = []

    def run(args, **kwargs):
        seen.append(SimpleNamespace(args=args, env=kwargs.get("env")))
        return completed()

    monkeypatch.setattr(notify.sys, "platform", platform)
    monkeypatch.setattr(notify.subprocess, "run", run)
    monkeypatch.setattr(notify.shutil, "which", lambda _name: "/usr/bin/notify-send")
    assert notify.system_notification("CMA", "Tunnel « labo » hors ligne") is True
    call = seen[0]
    if platform == "win32":
        # Le texte passe par l'environnement, jamais dans le script.
        assert call.env["CMA_TOAST_TEXT"] == "Tunnel « labo » hors ligne"
        assert "labo" not in " ".join(call.args)
    else:
        assert call.args[-2:] == ["CMA", "Tunnel « labo » hors ligne"]


def test_system_notification_failures(monkeypatch):
    monkeypatch.setattr(notify.sys, "platform", "linux")
    monkeypatch.setattr(notify.shutil, "which", lambda _name: None)
    assert notify.system_notification("CMA", "x") is False

    def broken(*_a, **_k):
        raise OSError("absent")

    monkeypatch.setattr(notify.sys, "platform", "win32")
    monkeypatch.setattr(notify.subprocess, "run", broken)
    assert notify.system_notification("CMA", "x") is False


def test_tunnels_notify_only_when_cma_is_closed(monkeypatch, tmp_path):
    from cma.core.cfapi import Tunnel

    paths = AppPaths(tmp_path / "data")
    paths.ensure()
    shown: list[str] = []
    monkeypatch.setattr(
        "cma.platform.notify.system_notification", lambda _t, text: shown.append(text) or True
    )
    readings = {"value": [Tunnel("t1", "labo", "down")]}

    async def states(_self) -> list[Tunnel]:
        return readings["value"]

    monkeypatch.setattr("cma.core.cfadmin.CloudflareAdmin.tunnel_states", states)
    running = {"value": None}
    monkeypatch.setattr(cli, "send_command", lambda *_a, **_k: running["value"])
    assert cli.show_tunnels(paths, as_json=False, notify=True, secrets=MemorySecretStore()) == 2
    assert shown == ["Tunnel « labo » hors ligne — ouvrez CMA pour le diagnostic."]
    # CMA ouvert : il surveille déjà, pas de seconde notification.
    running["value"] = {"ok": True}
    assert (
        cli.show_tunnels(paths, as_json=False, notify=True, secrets=MemorySecretStore()) == 2
        and len(shown) == 1
    )
    # Tout va bien : rien.
    running["value"] = None
    readings["value"] = [Tunnel("t1", "labo", "healthy")]
    assert (
        cli.show_tunnels(paths, as_json=False, notify=True, secrets=MemorySecretStore()) == 0
        and len(shown) == 1
    )


def test_windowed_entry_runs_the_silent_check(monkeypatch):
    import cma.__main__ as entry

    ran: list[str] = []
    monkeypatch.setattr(sys, "argv", ["CloudflaredManageAccess.exe", "tunnels", "--notify"])
    monkeypatch.setattr(cli, "run", lambda args: ran.append(args.command) or 0)
    assert entry.gui_main() == 0 and ran == ["tunnels"]


def test_portable_vault_uses_the_remembered_passphrase(monkeypatch, tmp_path):
    from cma.core import dpapi

    paths = AppPaths(tmp_path / "data", portable=True)
    paths.ensure()
    EncryptedFileSecretStore(paths.encrypted_secrets_file, "phrase-longue").set("k", "v")
    monkeypatch.setattr(dpapi, "remembered_passphrase", lambda _d: "phrase-longue")
    monkeypatch.setattr(cli.getpass, "getpass", lambda _p: pytest.fail("aucune question attendue"))
    store = cli.portable_secret_store(paths)
    assert isinstance(store, EncryptedFileSecretStore) and store.get("k") == "v"
    # Phrase mémorisée périmée : on retombe sur la question.
    monkeypatch.setattr(dpapi, "remembered_passphrase", lambda _d: "ancienne")
    monkeypatch.setattr(cli.getpass, "getpass", lambda _p: "phrase-longue")
    assert isinstance(cli.portable_secret_store(paths), EncryptedFileSecretStore)
    assert Path(paths.encrypted_secrets_file).exists()


def test_scheduled_check_also_reports_services(monkeypatch, tmp_path):
    """Tâche planifiée : un service en panne derrière un tunnel en ligne est signalé si le réglage le demande, et un
    test des services impossible ne fait pas échouer le relevé des tunnels."""
    from cma.core.cfapi import CloudflareApiError, Tunnel
    from cma.core.hostprobe import HostProbe
    from cma.core.servicewatch import ServiceTarget

    paths = AppPaths(tmp_path / "data")
    paths.ensure()
    shown: list[str] = []
    monkeypatch.setattr(
        "cma.platform.notify.system_notification", lambda _t, text: shown.append(text) or True
    )

    async def states(_self) -> list[Tunnel]:
        return [Tunnel("t1", "bureau", "healthy")]

    target = ServiceTarget("app.exemple.fr", "", "http://localhost:3000", "t1", "bureau")
    outcome: dict[str, object] = {"value": [(target, HostProbe("origin_down", 502))]}

    async def services(_self) -> list[tuple[ServiceTarget, HostProbe]]:
        if isinstance(outcome["value"], Exception):
            raise outcome["value"]
        return outcome["value"]  # type: ignore[return-value]

    monkeypatch.setattr("cma.core.cfadmin.CloudflareAdmin.tunnel_states", states)
    monkeypatch.setattr("cma.core.cfadmin.CloudflareAdmin.check_services", services)
    monkeypatch.setattr(cli, "send_command", lambda *_a, **_k: None)
    assert cli.show_tunnels(paths, as_json=False, notify=True, secrets=MemorySecretStore()) == 2
    assert shown == ["app.exemple.fr ne répond plus — ouvrez CMA pour le diagnostic."]
    outcome["value"] = CloudflareApiError("zone illisible")
    assert cli.show_tunnels(paths, as_json=False, notify=True, secrets=MemorySecretStore()) == 0
    assert len(shown) == 1
