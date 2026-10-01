"""Mise à jour de la version portable : mode détecté, archive vérifiée, remplacement lancé après fermeture."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

import pytest

import cma.core.updates as updates
from cma.core.cloudflared.binary import DownloadError, ReleaseAsset
from cma.core.updates import UpdateInfo
from tests.unit.test_updates import served  # noqa: F401 (fixture)

PORTABLE = "CloudflaredManageAccess-9.9.9-portable.zip"


def make_zip(path: Path, *, complete: bool = True, evil: bool = False) -> bytes:
    with zipfile.ZipFile(path, "w") as bundle:
        bundle.writestr("CloudflaredManageAccess/CloudflaredManageAccess.exe", b"MZ")
        if complete:
            bundle.writestr("CloudflaredManageAccess/_internal/base_library.zip", b"PK")
        bundle.writestr("CloudflaredManageAccess/data/LISEZMOI.txt", "données")
        if evil:
            bundle.writestr("../../evade.txt", "x")
    return path.read_bytes()


def test_update_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(updates, "can_self_update", lambda: True)
    assert updates.update_mode() == "installer"
    monkeypatch.setattr(updates, "can_self_update", lambda: False)
    monkeypatch.setattr(updates, "is_frozen", lambda: True)
    monkeypatch.setattr(updates, "portable_data_dir", lambda: tmp_path / "data")
    monkeypatch.setattr(updates.sys, "platform", "win32")
    monkeypatch.setattr(updates.sys, "executable", str(tmp_path / "CloudflaredManageAccess.exe"))
    assert updates.update_mode() == "portable"
    scoop = (
        tmp_path / "scoop" / "apps" / "cloudflared-manage-access" / "current" / "CloudflaredManageAccess.exe"
    )
    monkeypatch.setattr(updates.sys, "executable", str(scoop))
    assert updates.update_mode() == "scoop"
    monkeypatch.setattr(updates, "portable_data_dir", lambda: None)
    assert updates.update_mode() is None


def test_download_and_prepare_portable(served, tmp_path):  # noqa: F811
    root, base = served
    payload = make_zip(root / PORTABLE)
    asset = ReleaseAsset(PORTABLE, f"{base}/{PORTABLE}", len(payload), hashlib.sha256(payload).hexdigest())
    info = UpdateInfo("2.0.0", "9.9.9", "https://github.com/x", (asset,))
    assert info.portable_zip == asset
    archive = updates.download_portable(info, tmp_path / "dl")
    app = updates.prepare_portable(archive, tmp_path / "staging")
    assert (app / "CloudflaredManageAccess.exe").read_bytes() == b"MZ"

    with pytest.raises(DownloadError, match="portable"):
        updates.download_portable(UpdateInfo("2.0.0", "9.9.9", None, ()), tmp_path / "dl")


def test_prepare_refuses_bad_archives(tmp_path):
    incomplete = tmp_path / "incomplet.zip"
    make_zip(incomplete, complete=False)
    with pytest.raises(DownloadError, match="incomplète"):
        updates.prepare_portable(incomplete, tmp_path / "a")
    evil = tmp_path / "evade.zip"
    make_zip(evil, evil=True)
    with pytest.raises(DownloadError, match="chemin"):
        updates.prepare_portable(evil, tmp_path / "b")


def test_launch_portable_update_waits_then_copies(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(updates.subprocess, "Popen", lambda args, **kw: calls.append((args, kw)))
    updates.launch_portable_update(tmp_path / "new", tmp_path / "app", tmp_path / "staging", wait_pid=42)
    args, kwargs = calls[0]
    assert args[0] == "powershell.exe" and "robocopy" in args[-1] and "'data'" in args[-1]
    env = kwargs["env"]
    assert (
        env["CMA_WAIT_PID"] == "42" and env["CMA_APP"] == str(tmp_path / "app") and env["CMA_RELAUNCH"] == "1"
    )
