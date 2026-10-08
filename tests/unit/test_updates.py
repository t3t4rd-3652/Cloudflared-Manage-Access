"""Mise à jour de CMA : empreintes, signature, commande d'installation. Serveur HTTP local, sans Internet."""

from __future__ import annotations

import hashlib
import http.server
import threading
from functools import partial
from pathlib import Path

import pytest

import cma.core.updates as updates
from cma.core.cloudflared.binary import DownloadError, ReleaseAsset
from cma.core.updates import UpdateInfo

INSTALLER = "CloudflaredManageAccess-9.9.9-setup.exe"
PAYLOAD = b"MZ faux installeur " * 5000


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


@pytest.fixture
def served(tmp_path):
    root = tmp_path / "srv"
    root.mkdir()
    (root / INSTALLER).write_bytes(PAYLOAD)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(root)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield root, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def info_with(base: str, *, sha: str | None, sums: bool = False) -> UpdateInfo:
    assets = [ReleaseAsset(INSTALLER, f"{base}/{INSTALLER}", len(PAYLOAD), sha)]
    if sums:
        assets.append(ReleaseAsset("SHA256SUMS.txt", f"{base}/SHA256SUMS.txt", 0, None))
    return UpdateInfo("2.0.0", "9.9.9", "https://github.com/x", tuple(assets))


def accept(_path: Path) -> tuple[bool, str]:
    return True, "NotSigned"


def test_download_checks_the_github_digest(served, tmp_path):
    _root, base = served
    good = hashlib.sha256(PAYLOAD).hexdigest()
    seen: list[int] = []
    path = updates.download_installer(
        info_with(base, sha=good),
        tmp_path / "dl",
        progress=lambda r, _t: seen.append(r),
        verify_signature=accept,
    )
    assert path.read_bytes() == PAYLOAD
    assert seen[-1] == len(PAYLOAD)

    with pytest.raises(DownloadError, match="SHA-256"):
        updates.download_installer(info_with(base, sha="0" * 64), tmp_path / "bad", verify_signature=accept)
    assert not list((tmp_path / "bad").iterdir())


def test_download_falls_back_to_sha256sums(served, tmp_path):
    root, base = served
    (root / "SHA256SUMS.txt").write_text(f"{hashlib.sha256(PAYLOAD).hexdigest()}  {INSTALLER}\n")
    path = updates.download_installer(info_with(base, sha=None, sums=True), tmp_path, verify_signature=accept)
    assert path.name == INSTALLER
    with pytest.raises(DownloadError, match="empreinte"):
        updates.download_installer(info_with(base, sha=None), tmp_path / "x", verify_signature=accept)


def test_bad_signature_or_missing_installer_is_refused(served, tmp_path):
    _root, base = served
    good = hashlib.sha256(PAYLOAD).hexdigest()
    with pytest.raises(DownloadError, match="Signature"):
        updates.download_installer(
            info_with(base, sha=good), tmp_path, verify_signature=lambda _p: (False, "HashMismatch")
        )
    assert not (tmp_path / INSTALLER).exists()
    with pytest.raises(DownloadError, match="installeur"):
        updates.download_installer(UpdateInfo("2.0.0", "9.9.9", None), tmp_path)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(DownloadError, match="annulé"):
        updates.download_installer(
            info_with(base, sha=good), tmp_path / "c", cancel=cancel, verify_signature=accept
        )


def test_installer_command_and_launch(monkeypatch, tmp_path):
    installer = tmp_path / INSTALLER
    command = updates.installer_command(installer)
    assert command[0] == str(installer)
    assert {"/SILENT", "/SUPPRESSMSGBOXES", "/RELAUNCH=1"} <= set(command)
    assert "/RELAUNCH=1" not in updates.installer_command(installer, relaunch=False)

    calls: list[tuple[list[str], dict[str, str]]] = []
    monkeypatch.setattr(updates.subprocess, "Popen", lambda args, **kw: calls.append((args, kw["env"])))
    updates.launch_installer(installer, wait_pid=4242)
    args, env = calls[0]
    assert args[0] == "powershell.exe"
    assert str(installer) not in " ".join(args)  # le chemin passe par l'environnement, jamais dans le script
    assert env["CMA_INSTALLER"] == str(installer)
    assert env["CMA_WAIT_PID"] == "4242"
    assert "/SILENT" in env["CMA_INSTALLER_ARGS"]


def test_self_update_only_for_the_installed_copy(monkeypatch, tmp_path):
    assert updates.can_self_update() is False  # depuis les sources
    monkeypatch.setattr(updates, "is_frozen", lambda: True)
    monkeypatch.setattr(updates, "portable_data_dir", lambda: None)
    monkeypatch.setattr(updates, "installed_location", lambda: tmp_path)
    monkeypatch.setattr(updates.sys, "executable", str(tmp_path / "CloudflaredManageAccess.exe"))
    assert updates.can_self_update() is (updates.sys.platform == "win32")
    monkeypatch.setattr(updates, "installed_location", lambda: tmp_path / "ailleurs")
    assert updates.can_self_update() is False
    monkeypatch.setattr(updates, "portable_data_dir", lambda: tmp_path / "data")
    assert updates.can_self_update() is False


def test_installed_location_reads_the_registry():
    location = updates.installed_location()
    assert location is None or isinstance(location, Path)


def test_signature_check_accepts_unsigned_files(tmp_path):
    sample = tmp_path / "x.exe"
    sample.write_bytes(b"MZ")
    ok, status = updates.signature_is_acceptable(sample)
    if updates.sys.platform == "win32":
        assert status in ("NotSigned", "UnknownError", "HashMismatch", "NotSupportedFileFormat")
        assert ok is (status == "NotSigned")
    else:
        assert ok


def test_signature_policy():
    from cma.core.updates import UNSIGNED, Signature, signature_policy

    ours = Signature("Valid", "CN=Cloudflared Manage Access, O=SignPath Foundation")
    other = Signature("Valid", "CN=Quelqu'un d'autre")
    # Copie non signée (aujourd'hui) : non signé ou validement signé, rien d'autre.
    assert signature_policy(UNSIGNED, UNSIGNED) == (True, "NotSigned")
    assert signature_policy(UNSIGNED, ours)[0] is True
    assert signature_policy(UNSIGNED, Signature("HashMismatch", ours.subject)) == (False, "HashMismatch")
    # Copie signée : seulement le même éditeur, validement.
    assert signature_policy(ours, ours) == (True, ours.subject)
    ok, detail = signature_policy(ours, UNSIGNED)
    assert not ok and "la mise à jour ne l'est pas (NotSigned)" in detail
    ok, detail = signature_policy(ours, other)
    assert not ok and "autre éditeur" in detail and "Quelqu'un" in detail
    assert signature_policy(ours, Signature("HashMismatch", ours.subject))[0] is False


def test_signature_is_acceptable_compares_with_the_running_copy(monkeypatch, tmp_path):
    from cma.core.updates import Signature

    monkeypatch.setattr(updates.sys, "platform", "win32")
    signed = Signature("Valid", "CN=CMA")
    files = {"app.exe": signed, "update.exe": Signature("NotSigned")}

    def reader(path: Path) -> Signature:
        return files[path.name]

    monkeypatch.setattr(updates.sys, "executable", str(tmp_path / "app.exe"))
    monkeypatch.setattr(updates, "is_frozen", lambda: True)
    ok, _detail = updates.signature_is_acceptable(tmp_path / "update.exe", reader=reader)
    assert ok is False
    files["update.exe"] = signed
    assert updates.signature_is_acceptable(tmp_path / "update.exe", reader=reader) == (True, "CN=CMA")
    # Depuis les sources (non figé), la copie en service compte comme non signée.
    monkeypatch.setattr(updates, "is_frozen", lambda: False)
    files["update.exe"] = Signature("NotSigned")
    assert updates.signature_is_acceptable(tmp_path / "update.exe", reader=reader) == (True, "NotSigned")
