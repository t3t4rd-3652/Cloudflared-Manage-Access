"""Modules annexes du cœur : erreurs SSH, diagnostic, mises à jour, binaire, coffre, clés, chemins, journaux."""

import hashlib
import http.server
import io
import json
import logging
import socket
import sys
import tarfile
import threading
import urllib.error
import zipfile
from pathlib import Path

import asyncssh
import pytest

import cma.core.cloudflared.binary as binary
import cma.core.updates as updates
from cma import __version__
from cma.core.config_store import ConfigStore
from cma.core.diagnostics import build_report
from cma.core.events import EventBus, LogLine
from cma.core.redact import redact
from cma.core.secrets import KeyringSecretStore, SecretStoreError, open_secret_store
from cma.core.ssh import keys
from cma.core.ssh.errors import SshCancelled, SshError, describe_error
from cma.logging_setup import attach_bus, install_excepthooks, setup_logging
from cma.paths import AppPaths, ports_report_script, resolve_paths

# --- Erreurs SSH ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exc", "fragment", "fatal"),
    [
        (asyncssh.PermissionDenied("x"), "Authentification refusée", True),
        (asyncssh.HostKeyNotVerifiable("x"), "non vérifiée", True),
        (socket.gaierror("x"), "introuvable", True),
        (ConnectionRefusedError(), "refusée par", False),
        (TimeoutError(), "Délai dépassé", False),
        (asyncssh.ConnectionLost("coupé"), "fermée par", False),
        (OSError(1, "réseau"), "Impossible de joindre", False),
        (ValueError("bizarre"), "Erreur SSH", False),
    ],
)
def test_describe_error(exc, fragment, fatal):
    error = describe_error(exc, "h", 22)
    assert fragment in str(error)
    assert error.fatal is fatal


def test_describe_error_keeps_ssh_errors():
    original = SshError("déjà traduit")
    assert describe_error(original, "h", 1) is original
    assert SshCancelled().fatal


# --- Diagnostic et mises à jour ---------------------------------------------------------------


def test_diagnostic_report_has_no_secret(paths, store):
    store.update(lambda c: setattr(c.settings, "window_geometry", "AAAA"))
    (paths.logs_dir / "cma.log").write_text("TUNNEL_SERVICE_TOKEN_SECRET=fuite\n", encoding="utf-8")
    report = build_report(
        paths,
        store,
        sessions=[],
        cloudflared_path="C:/cf.exe",
        cloudflared_version="2026.9.3",
        extra={"Qt": "6"},
    )
    with zipfile.ZipFile(report) as archive:
        names = archive.namelist()
        content = "".join(archive.read(n).decode("utf-8") for n in names)
    assert {
        "informations.txt",
        "configuration-sans-secrets.json",
        "sessions.json",
        "journaux/cma.log",
    } <= set(names)
    assert "fuite" not in content
    assert "AAAA" not in content


class FakeResponse(io.BytesIO):
    def __init__(self, data: bytes, headers: dict[str, str] | None = None) -> None:
        super().__init__(data)
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def test_update_check(monkeypatch):
    monkeypatch.setattr(
        updates.urllib.request,
        "urlopen",
        lambda *a, **k: FakeResponse(json.dumps({"tag_name": "v99.0.0", "html_url": "u"}).encode()),
    )
    info = updates.check_for_update()
    assert info.available
    assert info.latest == "99.0.0"
    assert info.current == __version__

    def not_found(*_a, **_k):
        raise urllib.error.HTTPError("u", 404, "absent", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(updates.urllib.request, "urlopen", not_found)
    assert updates.check_for_update().latest is None


# --- Binaire cloudflared : détection, release, téléchargement vérifié --------------------------------


def test_detection_prefers_configured_path(paths, tmp_path, monkeypatch):
    fake = tmp_path / "cloudflared.exe"
    fake.write_bytes(b"x")
    assert binary.detect(paths, str(fake)) == fake
    monkeypatch.setattr(binary.shutil, "which", lambda _n: None)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "vide"))
    downloaded = paths.bin_dir / f"cloudflared-2026.9.3{binary._EXE}"
    downloaded.write_bytes(b"x")
    assert downloaded in binary.candidate_paths(paths)
    assert binary.detect(paths, str(tmp_path / "absent")) is not None


def test_release_cache(tmp_path, monkeypatch):
    cache = tmp_path / "release.json"
    cache.write_text(json.dumps({"tag_name": "2026.1.1", "assets": []}), encoding="utf-8")
    monkeypatch.setattr(binary, "_http_get", lambda *a, **k: pytest.fail("pas de réseau attendu"))
    assert binary.fetch_latest_release(cache).version == "2026.1.1"
    monkeypatch.setattr(
        binary,
        "_http_get",
        lambda *a, **k: FakeResponse(json.dumps({"tag_name": "2026.2.2", "assets": []}).encode()),
    )
    assert binary.fetch_latest_release(cache, max_age=0).version == "2026.2.2"


@pytest.fixture
def http_files(tmp_path):
    root = tmp_path / "www"
    root.mkdir()

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(root), **kwargs)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield root, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def release_for(url: str, name: str, data: bytes, *, good: bool = True) -> binary.ReleaseInfo:
    digest = hashlib.sha256(data if good else b"autre").hexdigest()
    return binary.ReleaseInfo(
        "2026.9.3", "", (binary.ReleaseAsset(name, f"{url}/{name}", len(data), digest),)
    )


def test_verified_download(tmp_path, http_files, monkeypatch):
    root, url = http_files
    data = b"MZ faux binaire" * 1000
    name = "cloudflared-windows-amd64.exe"
    (root / name).write_bytes(data)
    monkeypatch.setattr(binary, "verify_authenticode", lambda _p: (True, ""))
    seen: list[int] = []
    path = binary.download_release_binary(
        release_for(url, name, data), tmp_path / "bin", name=name, progress=lambda r, _t: seen.append(r)
    )
    assert path.read_bytes() == data
    assert seen[-1] == len(data)
    assert not list((tmp_path / "bin").glob("*.part"))


def test_download_refuses_bad_digest_and_bad_signature(tmp_path, http_files, monkeypatch):
    root, url = http_files
    data = b"contenu"
    name = "cloudflared-linux-amd64"
    (root / name).write_bytes(data)
    with pytest.raises(binary.DownloadError, match="SHA-256"):
        binary.download_release_binary(release_for(url, name, data, good=False), tmp_path / "bin", name=name)
    with pytest.raises(binary.DownloadError, match="Aucun fichier"):
        binary.download_release_binary(release_for(url, name, data), tmp_path / "bin", name="absent")
    no_digest = binary.ReleaseInfo("1", "", (binary.ReleaseAsset(name, f"{url}/{name}", 1, None),))
    with pytest.raises(binary.DownloadError, match="SHA-256"):
        binary.download_release_binary(no_digest, tmp_path / "bin", name=name)
    if sys.platform == "win32":
        monkeypatch.setattr(binary, "verify_authenticode", lambda _p: (False, "NotSigned"))
        with pytest.raises(binary.DownloadError, match="Authenticode"):
            binary.download_release_binary(release_for(url, name, data), tmp_path / "bin", name=name)
        assert not list((tmp_path / "bin").glob("cloudflared-*"))


def test_download_extracts_macos_archive(tmp_path, http_files, monkeypatch):
    root, url = http_files
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        content = b"binaire macos"
        info = tarfile.TarInfo("cloudflared")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    name = "cloudflared-darwin-arm64.tgz"
    (root / name).write_bytes(buffer.getvalue())
    monkeypatch.setattr(binary, "verify_authenticode", lambda _p: (True, ""))
    path = binary.download_release_binary(
        release_for(url, name, buffer.getvalue()), tmp_path / "bin", name=name
    )
    assert path.read_bytes() == b"binaire macos"


def test_download_can_be_cancelled(tmp_path, http_files):
    root, url = http_files
    name = "gros"
    (root / name).write_bytes(b"x" * 2_000_000)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(binary.DownloadError, match="annulé"):
        binary.download_release_binary(
            release_for(url, name, b"x" * 2_000_000), tmp_path / "bin", name=name, cancel=cancel
        )


@pytest.mark.skipif(sys.platform != "win32", reason="Authenticode : Windows uniquement")
def test_authenticode_rejects_unsigned_file(tmp_path):
    fake = tmp_path / "faux.exe"
    fake.write_bytes(b"MZ")
    ok, _detail = binary.verify_authenticode(fake)
    assert not ok


@pytest.mark.real_cloudflared
async def test_read_version_of_real_binary(paths):
    found = binary.detect(paths, None)
    if found is None:
        pytest.skip("cloudflared absent")
    assert binary.parse_version(f"version {await binary.read_version(found)}")


async def test_read_version_of_missing_binary(tmp_path):
    assert await binary.read_version(tmp_path / "absent.exe") is None


# --- Coffre ------------------------------------------------------------------------------------------


class FakeBackend:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service, key):
        return self.values.get((service, key))

    def set_password(self, service, key, value):
        if value == "refus":
            raise RuntimeError("refusé par le trousseau")
        self.values[(service, key)] = value

    def delete_password(self, service, key):
        if (service, key) not in self.values:
            raise RuntimeError("Password not found")
        del self.values[(service, key)]


def test_keyring_store_with_fake_backend():
    store = KeyringSecretStore(FakeBackend())
    store.set("token:1", "valeur-keyring")
    assert store.get("token:1") == "valeur-keyring"
    assert "valeur-keyring" not in redact("valeur-keyring")
    store.delete("token:1")
    store.delete("token:1")
    assert store.get("token:1") is None
    with pytest.raises(SecretStoreError):
        store.set("token:2", "refus")


def test_default_store_is_persistent_on_windows():
    store = open_secret_store()
    if sys.platform == "win32":
        assert store.persistent
        assert store.description == "WinVaultKeyring"


# --- Clés ------------------------------------------------------------------------------------------


def test_keys_listing_and_deletion(paths, tmp_path, monkeypatch):
    user_dir = tmp_path / "home_ssh"
    user_dir.mkdir()
    monkeypatch.setattr(keys, "user_ssh_dir", lambda: user_dir)
    app_key = keys.generate_key(paths.keys_dir, "appli")
    encrypted = keys.generate_key(paths.keys_dir, "id_chiffree", passphrase="phrase-cle")
    user_key = keys.generate_key(user_dir, "perso")
    (user_dir / "known_hosts").write_text("x", encoding="utf-8")
    (user_dir / "config").write_text("Host x", encoding="utf-8")
    listed = {k.name: k for k in keys.list_keys(paths.keys_dir)}
    assert {app_key.name, encrypted.name, user_key.name} <= set(listed)
    assert listed[encrypted.name].encrypted
    assert listed[user_key.name].source == keys.KeySource.USER
    with pytest.raises(FileExistsError):
        keys.generate_key(paths.keys_dir, "appli")
    with pytest.raises(ValueError):
        keys.generate_key(paths.keys_dir, "nom invalide")
    with pytest.raises(PermissionError):
        keys.delete_key(user_key.path, paths.keys_dir)
    app_key.public_path.unlink()
    assert keys.public_key_line(app_key.path).startswith("ssh-ed25519 ")
    keys.delete_key(app_key.path, paths.keys_dir)
    assert not app_key.path.exists()
    assert keys.resolve_key_path("id_x", paths.keys_dir) == paths.keys_dir / "id_x"
    assert keys.resolve_key_path(str(user_key.path), paths.keys_dir) == user_key.path


# --- Chemins et journaux ---------------------------------------------------------------------------


def test_resolve_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("CMA_DATA_DIR", str(tmp_path / "env"))
    assert resolve_paths().data_dir == (tmp_path / "env").resolve()
    assert resolve_paths(tmp_path / "arg").data_dir == (tmp_path / "arg").resolve()
    monkeypatch.delenv("CMA_DATA_DIR")
    exe_dir = tmp_path / "portable"
    (exe_dir / "data").mkdir(parents=True)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(exe_dir / "CloudflaredManageAccess.exe"))
    portable = resolve_paths()
    assert portable.portable
    assert portable.data_dir == exe_dir / "data"


def test_ports_report_script_is_available():
    script = ports_report_script()
    assert script.startswith("#!/usr/bin/env bash")
    assert "\r" not in script


def test_logging_redacts_and_reaches_the_bus(paths):
    bus = EventBus()
    lines: list[LogLine] = []
    bus.subscribe(lambda e: lines.append(e) if isinstance(e, LogLine) else None)
    setup_logging(paths, "INFO", console=True)
    attach_bus(bus)
    errors: list[str] = []
    install_excepthooks(errors.append)
    try:
        logging.getLogger("cma.test").warning("password=trop-visible")
        sys.excepthook(ValueError, ValueError("boum"), None)
        hook_args = threading.ExceptHookArgs((RuntimeError, RuntimeError("fil"), None, None))
        threading.excepthook(hook_args)
    finally:
        sys.excepthook = sys.__excepthook__
        threading.excepthook = threading.__excepthook__
        root = logging.getLogger()
        for handler in list(root.handlers):
            handler.close()
            root.removeHandler(handler)
    content = (paths.logs_dir / "cma.log").read_text(encoding="utf-8")
    assert "trop-visible" not in content
    assert "boum" in content
    assert any("password" in line.message for line in lines)
    assert errors == ["ValueError : boum", "RuntimeError : fil"]


def test_config_store_path_helpers(paths):
    store = ConfigStore(paths)
    assert store.path == paths.config_file
    assert store.backup() is None
    assert isinstance(AppPaths(Path(".")).encrypted_secrets_file, Path)
