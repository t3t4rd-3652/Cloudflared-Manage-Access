import json

import pytest

from cma.core.config_store import ConfigReadOnlyError, ConfigStore
from cma.core.models import CloudflareProfile, Config


def add_profile(name):
    def mutate(config: Config) -> None:
        config.cloudflare_profiles.append(CloudflareProfile(name=name, hostname="a.ex.fr", local_port=2222))

    return mutate


def test_missing_file_gives_empty_config(store):
    assert store.snapshot().cloudflare_profiles == []
    assert not store.exists()


def test_update_writes_and_reloads(paths, store):
    store.update(add_profile("Accentué é"))
    raw = paths.config_file.read_text(encoding="utf-8")
    assert "Accentué é" in raw
    reloaded = ConfigStore(paths)
    assert reloaded.load() == []
    assert reloaded.snapshot().cloudflare_profiles[0].name == "Accentué é"


def test_snapshot_is_independent(store):
    store.update(add_profile("A"))
    snap = store.snapshot()
    snap.cloudflare_profiles.clear()
    assert len(store.snapshot().cloudflare_profiles) == 1


def test_invalid_mutation_is_rejected_and_nothing_is_written(paths, store):
    store.update(add_profile("A"))
    before = paths.config_file.read_text(encoding="utf-8")

    def bad(config: Config) -> None:
        config.settings.auto_port_min = 60000  # plage inversée : validation du modèle complet

    with pytest.raises(ValueError):
        store.update(bad)
    assert paths.config_file.read_text(encoding="utf-8") == before


def test_first_write_of_session_is_backed_up(paths, store):
    store.update(add_profile("A"))
    second = ConfigStore(paths)
    second.load()
    second.update(add_profile("B"))
    second.update(add_profile("C"))
    backups = second.list_backups()
    assert len(backups) == 1
    assert "A" in backups[0].read_text(encoding="utf-8")


def test_corrupted_file_is_set_aside_and_backup_restored(paths, store):
    store.update(add_profile("A"))
    other = ConfigStore(paths)
    other.load()
    other.update(add_profile("B"))  # sauvegarde de l'état « A »
    paths.config_file.write_text("{cassé", encoding="utf-8")
    recovered = ConfigStore(paths)
    warnings = recovered.load()
    assert any("illisible" in w for w in warnings)
    assert any("restaurée" in w for w in warnings)
    assert [p.name for p in recovered.snapshot().cloudflare_profiles] == ["A"]
    assert list(paths.data_dir.glob("config.json.corrupt-*"))


def test_newer_schema_is_read_only(paths):
    data = Config().model_dump(mode="json")
    data["schema_version"] = 99
    paths.config_file.write_text(json.dumps(data), encoding="utf-8")
    store = ConfigStore(paths)
    assert store.load()
    assert store.read_only
    with pytest.raises(ConfigReadOnlyError):
        store.update(add_profile("X"))


def test_backup_rotation(paths, store):
    store.update(add_profile("A"))
    for _ in range(15):
        store.backup("test")
    assert len(store.list_backups()) == 10


def test_listeners_are_notified(store):
    calls = []
    store.add_listener(lambda: calls.append(1))
    store.update(add_profile("A"))
    assert calls == [1]
