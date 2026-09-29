"""Import et export des profils, avec aperçu des conflits.

Format d'export v2 : {"format": "cma-export", "version": 2, ...}. Les secrets ne sont exportés
que sur demande, chiffrés par phrase de passe. L'import accepte aussi les fichiers de la v1
(profils, tokens, profils SSH), convertis par la même logique que la migration.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import ValidationError

from cma import __version__
from cma.core.config_store import ConfigStore
from cma.core.crypto import decrypt_json, encrypt_json
from cma.core.fsutil import atomic_write_json, read_json_lenient
from cma.core.migrations import MigrationReport, convert_v1
from cma.core.models import AuthMode, CloudflareProfile, Config, ServiceToken, SshProfile, new_id, unique_name
from cma.core.secrets import SecretStore
from cma.i18n import tr

EXPORT_FORMAT = "cma-export"
EXPORT_VERSION = 2

Kind = Literal["token", "cloudflare", "ssh"]


class ImportError_(ValueError):
    """Fichier d'import illisible ou d'un format inconnu."""


class Action(StrEnum):
    ADD = "add"
    REPLACE = "replace"
    RENAME = "rename"
    SKIP = "skip"

    @property
    def label(self) -> str:
        return {
            Action.ADD: tr("Ajouter"),
            Action.REPLACE: tr("Remplacer"),
            Action.RENAME: tr("Ajouter sous un autre nom"),
            Action.SKIP: tr("Ignorer"),
        }[self]


@dataclass
class ImportItem:
    kind: Kind
    incoming: ServiceToken | CloudflareProfile | SshProfile
    existing: ServiceToken | CloudflareProfile | SshProfile | None
    action: Action

    @property
    def name(self) -> str:
        return self.incoming.name

    @property
    def conflict(self) -> bool:
        return self.existing is not None


@dataclass
class ImportPlan:
    source: str
    items: list[ImportItem] = field(default_factory=list[ImportItem])
    secrets: dict[str, str] | None = None
    encrypted_secrets: dict[str, Any] | None = None
    warnings: list[str] = field(default_factory=list[str])

    @property
    def needs_passphrase(self) -> bool:
        return self.encrypted_secrets is not None and self.secrets is None

    def unlock(self, passphrase: str) -> None:
        """Déchiffre les secrets de l'export. Lève WrongPassphraseError si la phrase est fausse."""
        if self.encrypted_secrets is not None:
            self.secrets = dict(decrypt_json(self.encrypted_secrets, passphrase))


@dataclass(frozen=True)
class ImportSummary:
    added: int
    replaced: int
    skipped: int
    secrets: int
    warnings: list[str]


# --- Export ---------------------------------------------------------------------------------


def build_export(
    config: Config,
    secrets: SecretStore,
    *,
    cloudflare_ids: set[str] | None = None,
    ssh_ids: set[str] | None = None,
    token_ids: set[str] | None = None,
    passphrase: str | None = None,
) -> dict[str, Any]:
    """Export JSON. `None` = tout exporter. Les tokens utilisés par les profils exportés sont toujours inclus."""
    cloudflare = [p for p in config.cloudflare_profiles if cloudflare_ids is None or p.id in cloudflare_ids]
    ssh = [p for p in config.ssh_profiles if ssh_ids is None or p.id in ssh_ids]
    wanted_tokens = set(token_ids) if token_ids is not None else {t.id for t in config.tokens}
    wanted_tokens |= {p.token_id for p in cloudflare if p.token_id}
    tokens = [t for t in config.tokens if t.id in wanted_tokens]
    data: dict[str, Any] = {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "app_version": __version__,
        "exported_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "tokens": [t.model_dump(mode="json") for t in tokens],
        "cloudflare_profiles": [p.model_dump(mode="json") for p in cloudflare],
        "ssh_profiles": [p.model_dump(mode="json") for p in ssh],
    }
    if passphrase:
        payload: dict[str, str] = {}
        for token in tokens:
            value = secrets.get(token.secret_key)
            if value:
                payload[token.secret_key] = value
        for profile in ssh:
            if profile.remember_password:
                value = secrets.get(profile.password_key)
                if value:
                    payload[profile.password_key] = value
        data["secrets"] = encrypt_json(payload, passphrase)
    return data


def write_export(path: Path, data: dict[str, Any]) -> None:
    atomic_write_json(path, data)


# --- Import ---------------------------------------------------------------------------------


def _is_mapping_of_dicts(raw: Any) -> bool:
    if not isinstance(raw, dict) or not raw:
        return False
    return all(isinstance(v, dict) for v in cast(dict[Any, Any], raw).values())


def read_import_file(path: Path) -> Any:
    try:
        return read_json_lenient(path)
    except Exception as exc:
        raise ImportError_(tr("Fichier illisible : {error}").format(error=exc)) from exc


def _find_conflict(kind: Kind, item: Any, config: Config) -> Any:
    pool: list[Any] = {
        "token": config.tokens,
        "cloudflare": config.cloudflare_profiles,
        "ssh": config.ssh_profiles,
    }[kind]
    same_id = next((x for x in pool if x.id == item.id), None)
    if same_id is not None:
        return same_id
    return next((x for x in pool if x.name.lower() == item.name.lower()), None)


def plan_import(raw: Any, config: Config) -> ImportPlan:
    """Analyse un fichier d'import et propose une action par élément."""
    data: dict[str, Any] = cast(dict[str, Any], raw) if isinstance(raw, dict) else {}
    if data.get("format") == EXPORT_FORMAT:
        plan = ImportPlan(source="v2")
        incoming = _parse_v2(data, plan)
        if isinstance(data.get("secrets"), dict):
            plan.encrypted_secrets = data["secrets"]
    elif _is_mapping_of_dicts(raw):
        mapping = cast(dict[str, dict[str, Any]], raw)
        values = list(mapping.values())
        report = MigrationReport()
        collected: dict[str, str] = {}
        if any("hostname" in v for v in values):
            plan = ImportPlan(source="v1-profiles")
            converted = convert_v1(
                profiles=mapping, tokens={}, ssh={}, secret_sink=collected.__setitem__, report=report
            )
        elif any("token_secret" in v or "token_id" in v for v in values):
            plan = ImportPlan(source="v1-tokens")
            converted = convert_v1(
                profiles={}, tokens=mapping, ssh={}, secret_sink=collected.__setitem__, report=report
            )
        elif any("user" in v or "host" in v for v in values):
            plan = ImportPlan(source="v1-ssh")
            converted = convert_v1(
                profiles={}, tokens={}, ssh=mapping, secret_sink=collected.__setitem__, report=report
            )
        else:
            raise ImportError_(tr("Format de fichier inconnu."))
        plan.secrets = collected
        plan.warnings.extend(report.warnings)
        incoming = (converted.tokens, converted.cloudflare_profiles, converted.ssh_profiles)
    else:
        raise ImportError_(tr("Format de fichier inconnu."))

    tokens, cloudflare, ssh = incoming
    for kind, items in (("token", tokens), ("cloudflare", cloudflare), ("ssh", ssh)):
        for item in items:
            existing = _find_conflict(kind, item, config)  # type: ignore[arg-type]
            if existing is None:
                action = Action.ADD
            elif existing.id == item.id:
                action = Action.REPLACE
            else:
                action = Action.RENAME
            plan.items.append(ImportItem(kind=kind, incoming=item, existing=existing, action=action))  # type: ignore[arg-type]
    if not plan.items:
        raise ImportError_(tr("Le fichier ne contient aucun profil ni token."))
    return plan


def _parse_v2(
    raw: dict[str, Any], plan: ImportPlan
) -> tuple[list[ServiceToken], list[CloudflareProfile], list[SshProfile]]:
    def load(model: Any, key: str) -> list[Any]:
        result: list[Any] = []
        entries: list[Any] = list(raw.get(key) or [])
        for entry in entries:
            try:
                result.append(model.model_validate(entry))
            except ValidationError as exc:
                name = str(cast(dict[str, Any], entry).get("name", "?")) if isinstance(entry, dict) else "?"
                plan.warnings.append(
                    tr("« {name} » ignoré : {error}").format(name=name, error=exc.errors()[0].get("msg", exc))
                )
        return result

    return (
        load(ServiceToken, "tokens"),
        load(CloudflareProfile, "cloudflare_profiles"),
        load(SshProfile, "ssh_profiles"),
    )


def apply_import(plan: ImportPlan, store: ConfigStore, secrets: SecretStore) -> ImportSummary:
    """Applique le plan (sauvegarde préalable de la configuration), secrets compris s'ils sont disponibles."""
    store.backup("avant-import")
    counters = {"added": 0, "replaced": 0, "skipped": 0, "secrets": 0}
    warnings: list[str] = list(plan.warnings)
    pending_secrets: list[tuple[str, str]] = []

    def mutate(config: Config) -> None:
        id_map: dict[str, dict[str, str | None]] = {"token": {}, "cloudflare": {}, "ssh": {}}
        pools: dict[Kind, list[Any]] = {
            "token": config.tokens,
            "cloudflare": config.cloudflare_profiles,
            "ssh": config.ssh_profiles,
        }

        for kind in ("token", "cloudflare", "ssh"):
            for item in [i for i in plan.items if i.kind == kind]:
                pool = pools[kind]
                incoming = copy.deepcopy(item.incoming)
                original_id = incoming.id
                if kind == "cloudflare":
                    assert isinstance(incoming, CloudflareProfile)
                    if incoming.token_id:
                        mapped = id_map["token"].get(incoming.token_id, incoming.token_id)
                        if mapped is None or not any(t.id == mapped for t in config.tokens):
                            warnings.append(
                                tr(
                                    "« {name} » : son token n'a pas été importé, authentification navigateur."
                                ).format(name=incoming.name)
                            )
                            incoming.auth = AuthMode.BROWSER
                            incoming.token_id = None
                        else:
                            incoming.token_id = mapped
                if kind == "ssh":
                    assert isinstance(incoming, SshProfile)
                    if incoming.via_cloudflare_profile:
                        mapped = id_map["cloudflare"].get(
                            incoming.via_cloudflare_profile, incoming.via_cloudflare_profile
                        )
                        if mapped is None or not any(p.id == mapped for p in config.cloudflare_profiles):
                            warnings.append(
                                tr(
                                    "« {name} » : son profil Cloudflare de passage n'a pas été importé."
                                ).format(name=incoming.name)
                            )
                            incoming.via_cloudflare_profile = None
                        else:
                            incoming.via_cloudflare_profile = mapped
                    incoming.remember_password = bool(
                        plan.secrets and plan.secrets.get(f"ssh-password:{original_id}")
                    )

                if item.action == Action.SKIP:
                    id_map[kind][original_id] = item.existing.id if item.existing is not None else None
                    counters["skipped"] += 1
                    continue
                if item.action == Action.REPLACE and item.existing is not None:
                    index = next(i for i, x in enumerate(pool) if x.id == item.existing.id)
                    incoming.id = item.existing.id
                    pool[index] = incoming
                    counters["replaced"] += 1
                else:
                    if item.action == Action.RENAME or any(
                        x.name.lower() == incoming.name.lower() for x in pool
                    ):
                        incoming.name = unique_name(incoming.name, [x.name for x in pool])
                    if any(x.id == incoming.id for x in pool):
                        incoming.id = new_id()
                    pool.append(incoming)
                    counters["added"] += 1
                id_map[kind][original_id] = incoming.id

                if plan.secrets:
                    prefix = {"token": "token", "ssh": "ssh-password"}.get(kind)
                    value = plan.secrets.get(f"{prefix}:{original_id}") if prefix else None
                    if value:
                        pending_secrets.append((f"{prefix}:{incoming.id}", value))

    store.update(mutate)
    for key, value in pending_secrets:
        secrets.set(key, value)
        counters["secrets"] += 1
    return ImportSummary(
        added=counters["added"],
        replaced=counters["replaced"],
        skipped=counters["skipped"],
        secrets=counters["secrets"],
        warnings=warnings,
    )
