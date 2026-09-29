import json

import pytest

from cma.core.crypto import WrongPassphraseError
from cma.core.models import AuthMode, CloudflareProfile, ServiceToken, SshProfile
from cma.core.transfer import Action, ImportError_, apply_import, build_export, plan_import


@pytest.fixture
def filled(store, secrets):
    token = ServiceToken(name="Prod", client_id="prod.access")
    profile = CloudflareProfile(
        name="Mongo", hostname="m.ex.fr", local_port=27017, auth=AuthMode.SERVICE_TOKEN, token_id=token.id
    )
    ssh = SshProfile(
        name="NAS", host="nas", user="admin", via_cloudflare_profile=profile.id, remember_password=True
    )

    def fill(config):
        config.tokens.append(token)
        config.cloudflare_profiles.append(profile)
        config.ssh_profiles.append(ssh)

    store.update(fill)
    secrets.set(token.secret_key, "secret-prod")
    secrets.set(ssh.password_key, "mdp-nas")
    return token, profile, ssh


def test_export_without_passphrase_has_no_secret(store, secrets, filled):
    data = build_export(store.snapshot(), secrets)
    text = json.dumps(data)
    assert "secret-prod" not in text
    assert "mdp-nas" not in text
    assert "secrets" not in data
    assert data["format"] == "cma-export"


def test_export_of_one_profile_includes_its_token(store, secrets, filled):
    token, profile, _ = filled
    data = build_export(
        store.snapshot(), secrets, cloudflare_ids={profile.id}, ssh_ids=set(), token_ids=set()
    )
    assert [t["id"] for t in data["tokens"]] == [token.id]


def test_roundtrip_into_another_installation(tmp_path, store, secrets, filled):
    from cma.core.config_store import ConfigStore
    from cma.paths import AppPaths
    from tests.conftest import PersistentMemoryStore

    data = build_export(store.snapshot(), secrets, passphrase="phrase")
    assert "secret-prod" not in json.dumps(data)

    other_paths = AppPaths(tmp_path / "autre")
    other_paths.ensure()
    other_store = ConfigStore(other_paths)
    other_store.load()
    other_secrets = PersistentMemoryStore()

    plan = plan_import(data, other_store.snapshot())
    assert plan.needs_passphrase
    with pytest.raises(WrongPassphraseError):
        plan.unlock("mauvaise")
    plan.unlock("phrase")
    assert all(item.action == Action.ADD for item in plan.items)
    summary = apply_import(plan, other_store, other_secrets)
    assert summary.added == 3
    assert summary.secrets == 2

    config = other_store.snapshot()
    token = config.tokens[0]
    ssh = config.ssh_profiles[0]
    assert other_secrets.get(token.secret_key) == "secret-prod"
    assert other_secrets.get(ssh.password_key) == "mdp-nas"
    assert ssh.remember_password
    assert config.cloudflare_profiles[0].token_id == token.id
    assert ssh.via_cloudflare_profile == config.cloudflare_profiles[0].id


def test_conflicts_replace_rename_and_skip(store, secrets, filled):
    token, profile, ssh = filled
    data = build_export(store.snapshot(), secrets)
    data["cloudflare_profiles"][0]["hostname"] = "nouveau.ex.fr"
    plan = plan_import(data, store.snapshot())
    actions = {item.name: item.action for item in plan.items}
    assert actions == {"Prod": Action.REPLACE, "Mongo": Action.REPLACE, "NAS": Action.REPLACE}

    for item in plan.items:
        if item.name == "Prod":
            item.action = Action.SKIP
        if item.name == "NAS":
            item.action = Action.RENAME
    summary = apply_import(plan, store, secrets)
    config = store.snapshot()
    assert summary.replaced == 1
    assert summary.skipped == 1
    assert summary.added == 1
    assert config.cloudflare_profile(profile.id).hostname == "nouveau.ex.fr"
    assert config.cloudflare_profile(profile.id).token_id == token.id
    assert sorted(p.name for p in config.ssh_profiles) == ["NAS", "NAS (2)"]
    renamed = next(p for p in config.ssh_profiles if p.name == "NAS (2)")
    assert renamed.id != ssh.id
    assert renamed.via_cloudflare_profile == profile.id


def test_same_name_different_id_is_renamed_by_default(store, secrets, filled):
    data = {
        "format": "cma-export",
        "version": 2,
        "tokens": [],
        "cloudflare_profiles": [{"id": "autre", "name": "mongo", "hostname": "x.ex.fr"}],
        "ssh_profiles": [],
    }
    plan = plan_import(data, store.snapshot())
    assert plan.items[0].action == Action.RENAME


def test_missing_token_falls_back_to_browser(store, secrets):
    data = {
        "format": "cma-export",
        "version": 2,
        "tokens": [],
        "cloudflare_profiles": [
            {
                "id": "p1",
                "name": "Orphelin",
                "hostname": "x.ex.fr",
                "auth": "service_token",
                "token_id": "absent",
            }
        ],
        "ssh_profiles": [],
    }
    summary = apply_import(plan_import(data, store.snapshot()), store, secrets)
    profile = store.snapshot().cloudflare_profiles[0]
    assert profile.auth == AuthMode.BROWSER
    assert summary.warnings


def test_v1_files_can_be_imported(store, secrets):
    v1_tokens = {"Prod": {"token_id": "prod.access", "token_secret": "s1"}}
    plan = plan_import(v1_tokens, store.snapshot())
    assert plan.source == "v1-tokens"
    apply_import(plan, store, secrets)
    token = store.snapshot().tokens[0]
    assert secrets.get(token.secret_key) == "s1"

    v1_ssh = {"NAS": {"host": "nas", "port": "22", "user": "admin"}}
    assert plan_import(v1_ssh, store.snapshot()).source == "v1-ssh"


@pytest.mark.parametrize("raw", [[], {"a": 1}, {"format": "cma-export", "version": 2}, "texte"])
def test_unknown_formats_are_refused(raw, store):
    with pytest.raises(ImportError_):
        plan_import(raw, store.snapshot())
