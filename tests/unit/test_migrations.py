"""Migration v1 → v2 sur un jeu qui reproduit la structure réelle constatée :
7 profils dont 5 avec un secret recopié, 3 tokens, 2 profils SSH, accents, fichier en cp1252."""

import json

import pytest

from cma.core.migrations import (
    MigrationError,
    delete_v1_files,
    find_v1_files,
    migrate_v1,
    needs_migration,
)
from cma.core.models import AuthMode, ServiceType, SshAuthMode
from cma.core.secrets import MemorySecretStore

TOKENS = {
    "Prod": {"token_id": "prod.access", "token_secret": "secret-prod"},
    "Recette": {"token_id": "rec.access", "token_secret": "secret-rec"},
    "Équipe": {"token_id": "eq.access", "token_secret": "secret-eq"},
}
PROFILES = {
    "MongoDB prod": {
        "hostname": "mongodb.exemple.fr",
        "host": "127.0.0.1",
        "port": "27017",
        "token_id": "prod.access",
        "token_secret": "secret-prod",
        "proxy": "",
    },
    "SSH prod": {
        "hostname": "ssh.exemple.fr",
        "host": "127.0.0.1",
        "port": "2222",
        "token_id": "prod.access",
        "token_secret": "secret-prod",
        "proxy": "",
    },
    "RDP recette": {
        "hostname": "rdp.exemple.fr",
        "host": "127.0.0.1",
        "port": "3389",
        "token_id": "rec.access",
        "token_secret": "secret-rec",
        "proxy": "",
    },
    "Appli équipe": {
        "hostname": "https://appli.exemple.fr/",
        "host": "127.0.0.1",
        "port": "8080",
        "token_id": "eq.access",
        "token_secret": "secret-eq",
        "proxy": "",
    },
    "Ancien secret": {
        "hostname": "vieux.exemple.fr",
        "host": "127.0.0.1",
        "port": "9000",
        "token_id": "prod.access",
        "token_secret": "secret-perime",
        "proxy": "proxy.corp:3128",
    },
    "Navigateur": {
        "hostname": "web.exemple.fr",
        "host": "127.0.0.1",
        "port": "8443",
        "token_id": "",
        "token_secret": "",
    },
    "Brouillon": {"hostname": "", "host": "", "port": ""},
}
SSH = {
    "Default": {"host": "localhost", "port": "22", "user": ""},
    "NAS": {"host": "nas.exemple.lan", "port": "2222", "user": "admin"},
}


@pytest.fixture
def v1_dir(paths):
    data = paths.data_dir
    (data / "cloudflared_tokens.json").write_text(json.dumps(TOKENS), encoding="utf-8")
    # La v1 lisait et écrivait en cp1252 sous Windows : le fichier de profils l'est ici.
    (data / "cloudflared_configs.json").write_bytes(json.dumps(PROFILES, ensure_ascii=False).encode("cp1252"))
    (data / "cloudflared_ssh_redir.json").write_text(json.dumps(SSH), encoding="utf-8")
    (data / "cloudflared_path.json").write_text(
        json.dumps({"path": "C:/outils/cloudflared.exe"}), encoding="utf-8"
    )
    (data / "config.yml").write_text("{}\n", encoding="utf-8")
    return data


def test_detection(v1_dir):
    assert needs_migration(v1_dir)
    assert len(find_v1_files(v1_dir)) == 4


def test_full_migration(v1_dir, secrets):
    config, report = migrate_v1(v1_dir, secrets)

    assert report.profiles == 7
    assert report.ssh_profiles == 2
    # 3 tokens d'origine + 1 créé pour le profil dont le secret ne correspond à aucun token.
    assert report.tokens == 4
    assert report.created_tokens == ["Ancien secret (migré)"]

    tokens = {t.name: t for t in config.tokens}
    profiles = {p.name: p for p in config.cloudflare_profiles}
    assert profiles["MongoDB prod"].token_id == tokens["Prod"].id
    assert profiles["SSH prod"].token_id == tokens["Prod"].id
    assert profiles["Ancien secret"].token_id == tokens["Ancien secret (migré)"].id
    assert profiles["Navigateur"].auth == AuthMode.BROWSER
    assert profiles["Appli équipe"].hostname == "appli.exemple.fr"
    assert profiles["Ancien secret"].proxy == "proxy.corp:3128"
    assert profiles["MongoDB prod"].service_type == ServiceType.MONGODB
    assert profiles["Brouillon"].local_port is None
    assert profiles["Brouillon"].hostname == ""

    # Les secrets sont dans le coffre, et nulle part dans la configuration.
    assert secrets.get(tokens["Prod"].secret_key) == "secret-prod"
    assert secrets.get(tokens["Ancien secret (migré)"].secret_key) == "secret-perime"
    dumped = config.model_dump_json()
    for value in ("secret-prod", "secret-rec", "secret-eq", "secret-perime"):
        assert value not in dumped

    ssh = {p.name: p for p in config.ssh_profiles}
    assert ssh["NAS"].port == 2222
    assert ssh["NAS"].auth == SshAuthMode.PASSWORD
    assert config.settings.cloudflared_path == "C:/outils/cloudflared.exe"

    assert report.backup_dir is not None
    assert {p.name for p in report.backup_dir.iterdir()} == {
        "cloudflared_configs.json",
        "cloudflared_tokens.json",
        "cloudflared_ssh_redir.json",
        "cloudflared_path.json",
    }
    assert any("config.yml" in w for w in report.warnings)
    assert any("Brouillon" in w for w in report.warnings)
    # Les fichiers v1 sont laissés en place.
    assert (v1_dir / "cloudflared_tokens.json").exists()


def test_invalid_fields_are_cleared_not_fatal(paths, secrets):
    bad = {"Bizarre": {"hostname": "avec espace", "host": "pas une ip", "port": "99999", "proxy": "nimporte"}}
    (paths.data_dir / "cloudflared_configs.json").write_text(json.dumps(bad), encoding="utf-8")
    config, report = migrate_v1(paths.data_dir, secrets)
    profile = config.cloudflare_profiles[0]
    assert profile.name == "Bizarre"
    assert profile.hostname == ""
    assert profile.local_host == "127.0.0.1"
    assert profile.local_port is None
    assert profile.proxy is None
    assert len(report.warnings) >= 3


def test_refuses_non_persistent_secret_store(v1_dir):
    with pytest.raises(MigrationError):
        migrate_v1(v1_dir, MemorySecretStore())


def test_delete_v1_files(v1_dir, secrets):
    migrate_v1(v1_dir, secrets)
    removed = delete_v1_files(v1_dir)
    assert not find_v1_files(v1_dir)
    assert not list(v1_dir.glob("backup-v1-*"))
    assert len(removed) == 6
