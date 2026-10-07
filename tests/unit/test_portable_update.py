"""Mise à jour de la version portable : mode détecté, archive vérifiée, remplacement lancé après fermeture."""

from __future__ import annotations

import hashlib
import os
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


# --- AppImage (Linux) -------------------------------------------------------------------------------------


def test_appimage_mode_and_asset(monkeypatch, tmp_path):
    image = tmp_path / "CloudflaredManageAccess-2.2.0-x86_64.AppImage"
    image.write_bytes(b"ancienne")
    monkeypatch.setattr(updates.sys, "platform", "linux")
    monkeypatch.setattr(updates, "is_frozen", lambda: True)
    monkeypatch.setenv("APPIMAGE", str(image))
    assert updates.appimage_path() == image and updates.update_mode() == "appimage"
    monkeypatch.setenv("APPIMAGE", str(tmp_path / "absente.AppImage"))
    assert updates.appimage_path() is None
    monkeypatch.delenv("APPIMAGE")
    assert updates.appimage_path() is None
    monkeypatch.setattr(updates.sys, "platform", "win32")
    monkeypatch.setenv("APPIMAGE", str(image))
    assert updates.appimage_path() is None

    assets = tuple(
        ReleaseAsset(name, f"https://exemple/{name}", 1, "")
        for name in (
            "CloudflaredManageAccess-9.9.9-x86_64.AppImage",
            "CloudflaredManageAccess-9.9.9-portable.zip",
        )
    )
    info = UpdateInfo("2.2.0", "9.9.9", "https://exemple", assets)
    assert info.asset_for("appimage") == assets[0] and info.asset_for("portable") == assets[1]
    assert info.asset_for("installer") is None and info.asset_for(None) is None  # pas d'installeur ici
    assert UpdateInfo("2.2.0", None, None).appimage is None


def test_install_appimage_replaces_the_file_at_once(tmp_path):
    target = tmp_path / "CloudflaredManageAccess.AppImage"
    target.write_bytes(b"ancienne")
    downloaded = tmp_path / "telechargement.AppImage"
    downloaded.write_bytes(b"nouvelle version")
    assert updates.install_appimage(downloaded, target) == target
    assert target.read_bytes() == b"nouvelle version"
    assert not (tmp_path / ".CloudflaredManageAccess.AppImage.new").exists()
    if os.name == "posix":
        assert os.access(target, os.X_OK)
    with pytest.raises(DownloadError, match="Impossible de remplacer"):
        updates.install_appimage(downloaded, tmp_path / "absent" / "CMA.AppImage")


def test_appimage_relaunch_uses_a_clean_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_MEIxxxx")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/usr/local/lib")
    monkeypatch.setenv("APPIMAGE", "/home/moi/CMA.AppImage")
    monkeypatch.setenv("APPDIR", "/tmp/.mount_CMA")
    env = updates.clean_environment()
    assert env["LD_LIBRARY_PATH"] == "/usr/local/lib" and "LD_LIBRARY_PATH_ORIG" not in env
    assert "APPIMAGE" not in env and "APPDIR" not in env
    monkeypatch.delenv("LD_LIBRARY_PATH_ORIG")
    assert "LD_LIBRARY_PATH" not in updates.clean_environment()

    calls: list[tuple[list[str], dict]] = []
    monkeypatch.setattr(updates.subprocess, "Popen", lambda args, **kw: calls.append((args, kw)))
    updates.relaunch_after_exit(tmp_path / "CMA.AppImage", wait_pid=4242)
    [(args, kw)] = calls
    assert args[:2] == ["/bin/sh", "-c"] and "kill -0" in args[2]
    assert kw["env"]["CMA_WAIT_PID"] == "4242" and kw["env"]["CMA_APP"].endswith("CMA.AppImage")
    assert kw["start_new_session"] is True and "APPIMAGE" not in kw["env"]
