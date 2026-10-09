"""Instantanés : plages CIDR, comparaison, fichiers gardés par compte."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from cma.core.privnet import is_private, normalize_network
from cma.core.snapshot import (
    counts,
    diff_snapshots,
    list_snapshots,
    load_snapshot,
    save_snapshot,
    section_label,
)


def test_normalize_network():
    assert normalize_network(" 10.0.0.5 ") == "10.0.0.5/32"
    assert normalize_network("192.168.1.7/24") == "192.168.1.0/24"
    assert normalize_network("fd00::1/64") == "fd00::/64"
    with pytest.raises(ValueError, match=r"10.0.0.0/24"):
        normalize_network("10.0.0.300")
    assert is_private("10.0.0.0/8") and not is_private("8.8.8.0/24")


def snap(when: datetime, **sections: object) -> dict[str, object]:
    return {
        "version": 1,
        "taken_at": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "account": {"id": "acc1", "name": "Compte"},
        **sections,
    }


def test_diff_lists_added_removed_and_changed_fields():
    now = datetime(2026, 10, 9, 8, tzinfo=UTC)
    old = snap(
        now,
        policies={
            "p1": {"name": "Admins", "include": [{"email": {"email": "a@x.fr"}}]},
            "p2": {"name": "Ancienne"},
        },
        dns={"app.x.fr CNAME": {"content": "t1.cfargotunnel.com", "proxied": True}},
    )
    new = snap(
        now,
        policies={"p1": {"name": "Admins", "include": [{"email": {"email": "b@x.fr"}}, {"everyone": {}}]}},
        dns={"app.x.fr CNAME": {"content": "t1.cfargotunnel.com", "proxied": False}},
        service_tokens={"s1": {"name": "Robot", "client_id": "robot.access"}},
    )
    changes = diff_snapshots(old, new)
    assert [(c.section, c.name, c.kind) for c in changes] == [
        ("policies", "Admins", "changed"),
        ("policies", "Ancienne", "removed"),
        ("service_tokens", "Robot", "added"),
        ("dns", "app.x.fr CNAME", "changed"),
    ]
    assert changes[0].details == (
        "include[0].email.email : a@x.fr → b@x.fr",
        "include[1].everyone : — → {}",
    )
    assert changes[3].details == ("proxied : true → false",)
    assert counts(new)["policies"] == 1 and section_label("routes") == "Réseaux privés"


def test_files_are_kept_per_account_newest_first(tmp_path):
    start = datetime(2026, 10, 1, tzinfo=UTC)
    for day in range(5):
        save_snapshot(tmp_path, snap(start + timedelta(days=day)), keep=3)
    other = snap(start)
    other["account"] = {"id": "acc2", "name": "Autre"}
    save_snapshot(tmp_path, other)
    files = list_snapshots(tmp_path, "acc1")
    assert [f.taken_at.day for f in files] == [5, 4, 3]  # les deux plus anciens sont retirés
    assert len(list_snapshots(tmp_path, "acc2")) == 1 and list_snapshots(tmp_path / "absent", "acc1") == []
    assert load_snapshot(files[0].path)["taken_at"] == "2026-10-05T00:00:00Z"
    (tmp_path / "acc1-20260101T000000Z.json").write_text(json.dumps({"version": 99}), encoding="utf-8")
    with pytest.raises(ValueError, match="n'est pas un instantané"):
        load_snapshot(tmp_path / "acc1-20260101T000000Z.json")
