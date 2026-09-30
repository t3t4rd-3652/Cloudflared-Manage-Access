"""Version portable : les secrets suivent le dossier data/ (coffre chiffré), jamais le trousseau du poste."""

from __future__ import annotations

import pytest

import cma.cli as cli
from cma.core.secrets import EncryptedFileSecretStore, MemorySecretStore
from cma.paths import AppPaths


@pytest.fixture
def portable(tmp_path) -> AppPaths:
    paths = AppPaths(tmp_path / "data", portable=True)
    paths.ensure()
    return paths


def test_cli_keeps_the_system_keyring_outside_portable_mode(tmp_path):
    assert cli.portable_secret_store(AppPaths(tmp_path, portable=False)) is None


def test_cli_without_portable_vault_uses_memory(portable):
    store = cli.portable_secret_store(portable)
    assert isinstance(store, MemorySecretStore)


def test_cli_unlocks_the_portable_vault(portable, monkeypatch, capsys):
    EncryptedFileSecretStore(portable.encrypted_secrets_file, "phrase-longue").set("k", "v")
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "phrase-longue")
    store = cli.portable_secret_store(portable)
    assert isinstance(store, EncryptedFileSecretStore) and store.get("k") == "v"
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: "fausse")
    assert isinstance(cli.portable_secret_store(portable), MemorySecretStore)
    assert capsys.readouterr().err
