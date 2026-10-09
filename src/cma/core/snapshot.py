"""Instantanés de la configuration Cloudflare : ce qu'était le compte à un moment donné, et ce qui a changé depuis.

Un instantané est un JSON lisible (aucun secret : ni jeton, ni secret de service token, seulement les Client ID) :
tunnels et leur configuration (règles d'ingress, routage WARP), applications Access, politiques réutilisables,
service tokens, DNS des noms publiés, routes et réseaux virtuels. Les champs qui bougent sans que personne n'ait rien
changé (dates de mise à jour, état des tunnels, nombre d'applications d'une politique…) sont retirés : deux
instantanés d'un compte inchangé sont identiques. Une section illisible (permission manquante) est notée à part et
n'est pas comparée. Pas de restauration : comparer suffit à repérer une modification faite ailleurs.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from cma.core.cfapi import Account, CloudflareApi, CloudflareApiError, Zone
from cma.core.fsutil import atomic_write_json
from cma.i18n import tr

SNAPSHOT_VERSION = 1
KEEP = 30  # instantanés gardés par compte
WORKERS = 8
# Champs qui changent sans modification de la configuration.
VOLATILE = {
    "created_at",
    "updated_at",
    "created_on",
    "modified_on",
    "deleted_at",
    "last_seen_at",
    "app_count",
    "status",
    "conns",
    "connections",
    "conns_active_at",
    "conns_inactive_at",
    "meta",
    "comment_modified_on",
    "tags_modified_on",
}
SECTIONS = ("tunnels", "apps", "policies", "service_tokens", "dns", "routes", "virtual_networks")


def section_label(section: str) -> str:
    return {
        "tunnels": tr("Tunnels"),
        "apps": tr("Applications Access"),
        "policies": tr("Politiques Access"),
        "service_tokens": tr("Service tokens"),
        "dns": tr("DNS"),
        "routes": tr("Réseaux privés"),
        "virtual_networks": tr("Réseaux virtuels"),
    }.get(section, section)


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        items = cast(dict[str, Any], value).items()
        return {k: _clean(v) for k, v in sorted(items) if k not in VOLATILE}
    if isinstance(value, list):
        return [_clean(v) for v in cast(list[Any], value)]
    return value


def _by_id(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {str(item.get("id", "")): _clean(item) for item in items if item.get("id")}


def take_snapshot(api: CloudflareApi, account: Account, now: datetime | None = None) -> dict[str, Any]:
    """Lit tout le compte (appels en parallèle) et renvoie l'instantané."""
    base = f"/accounts/{account.id}"
    unreadable: set[str] = set()
    sources: dict[str, tuple[str, dict[str, Any] | None]] = {
        "tunnels": (f"{base}/cfd_tunnel", {"is_deleted": "false"}),
        "apps": (f"{base}/access/apps", None),
        "policies": (f"{base}/access/policies", None),
        "service_tokens": (f"{base}/access/service_tokens", None),
        "routes": (f"{base}/teamnet/routes", {"is_deleted": "false"}),
        "virtual_networks": (f"{base}/teamnet/virtual_networks", {"is_deleted": "false"}),
    }

    def read_list(section: str) -> list[dict[str, Any]]:
        path, params = sources[section]
        try:
            return api.get_list(path, params)
        except CloudflareApiError:
            unreadable.add(section)
            return []

    def read_config(tunnel_id: str) -> dict[str, Any]:
        try:
            return api.tunnel_config(account.id, tunnel_id)
        except CloudflareApiError:
            unreadable.add("tunnels")
            return {}

    def read_zones() -> list[Zone]:
        try:
            return api.list_zones(account.id)
        except CloudflareApiError:
            unreadable.add("dns")
            return []

    def read_records(zone_id: str) -> list[dict[str, Any]]:
        try:
            return api.zone_records(zone_id)
        except CloudflareApiError:
            unreadable.add("dns")
            return []

    with ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="cma-snap") as pool:
        lists = {section: pool.submit(read_list, section) for section in sources}
        zones_call = pool.submit(read_zones)
        tunnels = lists["tunnels"].result()
        configs = {str(t["id"]): pool.submit(read_config, str(t["id"])) for t in tunnels if t.get("id")}
        records = [pool.submit(read_records, zone.id) for zone in zones_call.result()]
        snapshot_tunnels: dict[str, Any] = {
            str(t["id"]): {"name": str(t.get("name", "")), "config": _clean(configs[str(t["id"])].result())}
            for t in tunnels
            if t.get("id")
        }
        published: set[str] = set()
        for tunnel in snapshot_tunnels.values():
            config = cast(dict[str, Any], tunnel["config"])
            for rule in cast(list[dict[str, Any]], config.get("ingress") or []):
                if rule.get("hostname"):
                    published.add(str(rule["hostname"]).lower())
        dns: dict[str, Any] = {}
        for call in records:
            for record in call.result():
                name = str(record.get("name", "")).lower()
                if name in published or str(record.get("content", "")).endswith(".cfargotunnel.com"):
                    dns[f"{name} {record.get('type', '')}"] = {
                        k: record.get(k) for k in ("name", "type", "content", "proxied", "ttl")
                    }
        result: dict[str, Any] = {
            "version": SNAPSHOT_VERSION,
            "taken_at": (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "account": {"id": account.id, "name": account.name},
            "tunnels": snapshot_tunnels,
            "dns": dns,
        }
        for section in ("apps", "policies", "service_tokens", "routes", "virtual_networks"):
            result[section] = _by_id(lists[section].result())
    result["unreadable"] = sorted(unreadable)
    return result


@dataclass(frozen=True)
class SnapshotChange:
    section: str
    key: str
    name: str
    kind: str  # added, removed, changed
    details: tuple[str, ...] = ()


def item_name(section: str, key: str, item: dict[str, Any]) -> str:
    if section == "routes":
        return str(item.get("network") or key)
    if section == "dns":
        return key
    return str(item.get("name") or item.get("domain") or key)


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        flat: dict[str, Any] = {}
        for k, v in cast(dict[str, Any], value).items():
            flat.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
        return flat or {prefix: {}}
    if isinstance(value, list):
        flat = {}
        for index, v in enumerate(cast(list[Any], value)):
            flat.update(_flatten(v, f"{prefix}[{index}]"))
        return flat or {prefix: []}
    return {prefix: value}


def _show(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return text if len(text) <= 80 else text[:77] + "…"


def diff_snapshots(old: dict[str, Any], new: dict[str, Any]) -> list[SnapshotChange]:
    """Ce qui a changé de `old` à `new`, section par section. Une section illisible dans l'un des deux est sautée."""
    skipped = set(cast(list[str], old.get("unreadable") or [])) | set(
        cast(list[str], new.get("unreadable") or [])
    )
    changes: list[SnapshotChange] = []
    for section in SECTIONS:
        if section in skipped:
            continue
        before = cast(dict[str, Any], old.get(section) or {})
        after = cast(dict[str, Any], new.get(section) or {})
        for key in sorted(
            set(before) | set(after),
            key=lambda k: item_name(section, k, after.get(k) or before.get(k) or {}).lower(),
        ):
            if key not in before:
                changes.append(SnapshotChange(section, key, item_name(section, key, after[key]), "added"))
            elif key not in after:
                changes.append(SnapshotChange(section, key, item_name(section, key, before[key]), "removed"))
            elif before[key] != after[key]:
                was, now = _flatten(before[key]), _flatten(after[key])
                details = tuple(
                    f"{path} : {_show(was[path]) if path in was else '—'} → {_show(now[path]) if path in now else '—'}"
                    for path in sorted(set(was) | set(now))
                    if was.get(path, ...) != now.get(path, ...)
                )
                changes.append(
                    SnapshotChange(section, key, item_name(section, key, after[key]), "changed", details)
                )
    return changes


def counts(snapshot: dict[str, Any]) -> dict[str, int]:
    return {section: len(cast(dict[str, Any], snapshot.get(section) or {})) for section in SECTIONS}


# --- Fichiers -------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SnapshotFile:
    path: Path
    taken_at: datetime
    account_id: str


_NAME = re.compile(r"^(?P<account>[\w-]+)-(?P<stamp>\d{8}T\d{6}Z)\.json$")


def save_snapshot(directory: Path, snapshot: dict[str, Any], keep: int = KEEP) -> Path:
    """Enregistre l'instantané (écriture atomique) et ne garde que les `keep` plus récents de ce compte."""
    account = str(cast(dict[str, Any], snapshot["account"])["id"])
    taken = datetime.strptime(str(snapshot["taken_at"]), "%Y-%m-%dT%H:%M:%SZ")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{account}-{taken.strftime('%Y%m%dT%H%M%SZ')}.json"
    atomic_write_json(path, snapshot)
    for old in list_snapshots(directory, account)[keep:]:
        old.path.unlink(missing_ok=True)
    return path


def list_snapshots(directory: Path, account_id: str) -> list[SnapshotFile]:
    """Instantanés enregistrés pour ce compte, du plus récent au plus ancien."""
    found: list[SnapshotFile] = []
    if not directory.is_dir():
        return found
    for path in directory.glob("*.json"):
        match = _NAME.match(path.name)
        if match and match.group("account") == account_id:
            taken = datetime.strptime(match.group("stamp"), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
            found.append(SnapshotFile(path, taken, account_id))
    return sorted(found, key=lambda f: f.taken_at, reverse=True)


def load_snapshot(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or cast(dict[str, Any], data).get("version") != SNAPSHOT_VERSION:
        raise ValueError(tr("{file} n'est pas un instantané de CMA.").format(file=path.name))
    return cast(dict[str, Any], data)
