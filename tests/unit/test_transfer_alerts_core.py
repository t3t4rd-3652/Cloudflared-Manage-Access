"""P30 : canaux d'alerte, maintenances et réglages des rappels dans l'export de configuration."""

import json

import pytest

from cma.core.alerts import secret_key as alert_secret_key
from cma.core.config_store import ConfigStore
from cma.core.models import AlertChannel, MaintenanceWindow, ServiceToken
from cma.core.transfer import ImportError_, apply_import, build_export, plan_import, write_export
from cma.paths import AppPaths
from tests.conftest import PersistentMemoryStore

# Adresses d'exemple longues : une adresse courte serait masquée par le module de rédaction.
NTFY_ADDRESS = "https://ntfy.exemple.test/astreinte-topic-9f3a7c21d4"
SLACK_ADDRESS = "https://hooks.slack.com/services/T0ABCDEF/B0GHIJKL/Zq8RsTuVwXyz1234"
ADDRESS_FRAGMENTS = (
    NTFY_ADDRESS,
    SLACK_ADDRESS,
    "astreinte-topic-9f3a7c21d4",
    "ntfy.exemple.test",
    "hooks.slack.com",
    "T0ABCDEF",
    "B0GHIJKL",
    "Zq8RsTuVwXyz1234",
)
PHRASE = "phrase-longue-1"


@pytest.fixture
def alerting(store, secrets):
    """Une installation avec deux canaux (adresses dans le coffre), deux maintenances et des rappels."""
    ntfy = AlertChannel(name="Astreinte", kind="ntfy")
    slack = AlertChannel(name="Équipe", kind="slack", recoveries=False)
    night = MaintenanceWindow(weekday=1, start="02:00", end="04:00", label="Sauvegardes")
    sunday = MaintenanceWindow(weekday=6, start="23:00", end="01:00", target="tunnel:t-1")

    def fill(config):
        config.settings.alert_channels.extend([ntfy, slack])
        config.settings.maintenance_windows.extend([night, sunday])
        config.settings.alert_repeat_hours = 6
        config.settings.weekly_digest = True

    store.update(fill)
    secrets.set(alert_secret_key(ntfy.id), NTFY_ADDRESS)
    secrets.set(alert_secret_key(slack.id), SLACK_ADDRESS)
    return ntfy, slack


@pytest.fixture
def other(tmp_path):
    """Une autre installation, vide, avec son propre coffre."""
    paths = AppPaths(tmp_path / "autre")
    paths.ensure()
    config_store = ConfigStore(paths)
    config_store.load()
    return config_store, PersistentMemoryStore()


def test_clear_export_never_contains_a_channel_address(tmp_path, store, secrets, alerting):
    data = build_export(store.snapshot(), secrets)
    target = tmp_path / "export.json"
    write_export(target, data)
    for text in (json.dumps(data, ensure_ascii=False), target.read_text(encoding="utf-8")):
        for fragment in ADDRESS_FRAGMENTS:
            assert fragment not in text
        assert "alert:" not in text
    assert "secrets" not in data
    assert [c["name"] for c in data["alert_channels"]] == ["Astreinte", "Équipe"]
    assert len(data["maintenance_windows"]) == 2
    assert data["alert_settings"] == {"alert_repeat_hours": 6, "weekly_digest": True}


def test_encrypted_export_hides_the_address_in_the_file(store, secrets, alerting):
    data = build_export(store.snapshot(), secrets, passphrase=PHRASE)
    text = json.dumps(data, ensure_ascii=False)
    for fragment in ADDRESS_FRAGMENTS:
        assert fragment not in text
    assert "secrets" in data


def test_clear_roundtrip_creates_channels_disabled_without_duplicates(store, secrets, alerting, other):
    other_store, other_secrets = other
    data = build_export(store.snapshot(), secrets)
    plan = plan_import(data, other_store.snapshot())
    assert plan.items == []
    assert [c.name for c in plan.channels] == ["Astreinte", "Équipe"]
    assert [c.name for c in plan.channels_waiting] == ["Astreinte", "Équipe"]
    assert (
        plan.alert_count == 4
    )  # les réglages des rappels ne sont pas comptés tant qu'ils ne sont pas demandés

    summary = apply_import(plan, other_store, other_secrets)
    assert (summary.channels, summary.windows, summary.secrets) == (2, 2, 0)
    assert summary.waiting == ("Astreinte", "Équipe")
    assert not summary.alert_settings
    config = other_store.snapshot()
    assert [(c.name, c.kind, c.enabled, c.recoveries) for c in config.settings.alert_channels] == [
        ("Astreinte", "ntfy", False, True),
        ("Équipe", "slack", False, False),
    ]
    assert config.settings.maintenance_windows == store.snapshot().settings.maintenance_windows
    assert config.settings.alert_repeat_hours == 0
    assert config.settings.weekly_digest is False
    for channel in config.settings.alert_channels:
        assert other_secrets.get(alert_secret_key(channel.id)) is None

    again = plan_import(data, other_store.snapshot())
    assert again.channels == [] and again.windows == []
    assert (again.skipped_channels, again.skipped_windows) == (2, 2)
    summary = apply_import(again, other_store, other_secrets)
    assert (summary.channels, summary.windows) == (0, 0)
    config = other_store.snapshot()
    assert len(config.settings.alert_channels) == 2
    assert len(config.settings.maintenance_windows) == 2


def test_encrypted_roundtrip_restores_the_address_and_enables_the_channel(store, secrets, alerting, other):
    other_store, other_secrets = other
    data = build_export(store.snapshot(), secrets, passphrase=PHRASE)
    plan = plan_import(data, other_store.snapshot())
    assert plan.needs_passphrase
    assert plan.channels_waiting == []  # inconnu tant que le fichier n'est pas déchiffré
    plan.unlock(PHRASE)
    assert plan.channels_waiting == []

    summary = apply_import(plan, other_store, other_secrets)
    assert summary.waiting == ()
    assert summary.secrets == 2  # les deux adresses
    by_name = {c.name: c for c in other_store.snapshot().settings.alert_channels}
    assert all(c.enabled for c in by_name.values())
    assert other_secrets.get(alert_secret_key(by_name["Astreinte"].id)) == NTFY_ADDRESS
    assert other_secrets.get(alert_secret_key(by_name["Équipe"].id)) == SLACK_ADDRESS


def test_encrypted_import_without_passphrase_leaves_channels_disabled(store, secrets, alerting, other):
    other_store, other_secrets = other
    data = build_export(store.snapshot(), secrets, passphrase=PHRASE)
    summary = apply_import(plan_import(data, other_store.snapshot()), other_store, other_secrets)
    assert summary.waiting == ("Astreinte", "Équipe")
    assert not any(c.enabled for c in other_store.snapshot().settings.alert_channels)


def test_reminder_settings_are_imported_only_on_request(store, secrets, alerting, other):
    other_store, other_secrets = other
    data = build_export(store.snapshot(), secrets)
    plan = plan_import(data, other_store.snapshot())
    assert plan.alert_settings == {"alert_repeat_hours": 6, "weekly_digest": True}
    assert plan.apply_alert_settings is False
    plan.apply_alert_settings = True
    assert plan.alert_count == 5
    summary = apply_import(plan, other_store, other_secrets)
    assert summary.alert_settings
    settings = other_store.snapshot().settings
    assert (settings.alert_repeat_hours, settings.weekly_digest) == (6, True)


def test_alerts_can_be_left_out_of_an_export(store, secrets, alerting):
    data = build_export(store.snapshot(), secrets, alerts=False)
    assert not {"alert_channels", "maintenance_windows", "alert_settings"} & set(data)


def test_same_name_and_kind_is_not_duplicated(store, secrets, alerting):
    data = build_export(store.snapshot(), secrets)
    data["alert_channels"][0]["id"] = "autre-id"  # même nom et même type, autre identifiant
    data["alert_channels"].append({"id": "x", "name": "Astreinte", "kind": "slack"})  # autre type : nouveau
    plan = plan_import(data, store.snapshot())
    assert [(c.name, c.kind) for c in plan.channels] == [("Astreinte", "slack")]
    assert plan.skipped_channels == 2
    assert apply_import(plan, store, secrets).channels == 1
    assert len(store.snapshot().settings.alert_channels) == 3


def test_a_channel_id_already_taken_gets_a_new_one(store, secrets, alerting):
    ntfy, _ = alerting
    data = build_export(store.snapshot(), secrets, passphrase=PHRASE)
    data["alert_channels"][0]["name"] = "Renommé"  # même identifiant, autre nom
    plan = plan_import(data, store.snapshot())
    plan.unlock(PHRASE)
    apply_import(plan, store, secrets)
    imported = next(c for c in store.snapshot().settings.alert_channels if c.name == "Renommé")
    assert imported.id != ntfy.id
    assert secrets.get(alert_secret_key(imported.id)) == NTFY_ADDRESS
    assert secrets.get(alert_secret_key(ntfy.id)) == NTFY_ADDRESS


def test_unreadable_alert_entries_are_reported_not_fatal(store, secrets):
    data = {
        "format": "cma-export",
        "version": 2,
        "tokens": [],
        "cloudflare_profiles": [],
        "ssh_profiles": [],
        "alert_channels": [{"name": "Bon", "kind": "ntfy"}, {"name": "Mauvais", "kind": "sms"}, "texte"],
        "maintenance_windows": [{"weekday": 9, "start": "02:00", "end": "03:00"}],
        "alert_settings": {"alert_repeat_hours": 9999, "weekly_digest": "oui"},
    }
    plan = plan_import(data, store.snapshot())
    assert [c.name for c in plan.channels] == ["Bon"]
    assert plan.windows == [] and plan.alert_settings is None
    assert len(plan.warnings) == 4
    apply_import(plan, store, secrets)
    assert [c.name for c in store.snapshot().settings.alert_channels] == ["Bon"]


def test_old_export_without_alert_keys_is_read_as_before(store, secrets, alerting):
    store.update(lambda c: c.tokens.append(ServiceToken(name="Prod", client_id="prod.access")))
    data = build_export(store.snapshot(), secrets)
    for key in ("alert_channels", "maintenance_windows", "alert_settings"):
        data.pop(key)
    plan = plan_import(data, store.snapshot())
    assert [item.name for item in plan.items] == ["Prod"]
    assert not plan.has_alert_data
    assert plan.channels == [] and plan.windows == [] and plan.alert_settings is None
    assert plan.alert_count == 0
    summary = apply_import(plan, store, secrets)
    assert (summary.channels, summary.windows, summary.alert_settings, summary.waiting) == (0, 0, False, ())


def test_alert_only_export_is_accepted_but_an_empty_one_is_not(store, secrets, alerting, other):
    data = build_export(store.snapshot(), secrets, cloudflare_ids=set(), ssh_ids=set(), token_ids=set())
    assert plan_import(data, other[0].snapshot()).items == []
    for key in ("alert_channels", "maintenance_windows", "alert_settings"):
        data.pop(key)
    with pytest.raises(ImportError_):
        plan_import(data, store.snapshot())
