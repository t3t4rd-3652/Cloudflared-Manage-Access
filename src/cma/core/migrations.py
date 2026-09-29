"""Migration des données de la v1 (quatre fichiers JSON) vers la configuration v2.

Étapes : sauvegarde des fichiers v1, lecture tolérante (UTF-8 puis cp1252), secrets vers le coffre,
dédoublonnage des secrets recopiés dans les profils, puis rapport. Les fichiers v1 restent en place :
leur suppression est proposée à l'utilisateur, jamais faite d'office.
"""

from __future__ import annotations

import logging
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from cma.core.fsutil import read_json_lenient
from cma.core.models import (
    AuthMode,
    CloudflareProfile,
    Config,
    ServiceToken,
    SshAuthMode,
    SshProfile,
    guess_service_type,
    is_valid_host,
    normalize_hostname,
    unique_name,
)
from cma.core.secrets import SecretStore
from cma.i18n import tr

log = logging.getLogger(__name__)

V1_PROFILES = "cloudflared_configs.json"
V1_TOKENS = "cloudflared_tokens.json"
V1_SSH = "cloudflared_ssh_redir.json"
V1_PATH = "cloudflared_path.json"
V1_FILES = (V1_PROFILES, V1_TOKENS, V1_SSH, V1_PATH)
V1_LEFTOVERS = ("config.yml",)


class MigrationError(RuntimeError):
    """La migration ne peut pas se faire sans risque de perte (coffre non persistant, par exemple)."""


@dataclass
class MigrationReport:
    profiles: int = 0
    tokens: int = 0
    ssh_profiles: int = 0
    created_tokens: list[str] = field(default_factory=list[str])
    warnings: list[str] = field(default_factory=list[str])
    backup_dir: Path | None = None
    v1_files: list[Path] = field(default_factory=list[Path])
    cloudflared_path: str | None = None


def find_v1_files(data_dir: Path) -> list[Path]:
    return [data_dir / name for name in V1_FILES if (data_dir / name).is_file()]


def needs_migration(data_dir: Path) -> bool:
    return not (data_dir / "config.json").exists() and bool(find_v1_files(data_dir))


def _read_mapping(path: Path, report: MigrationReport) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    try:
        data = read_json_lenient(path)
    except Exception as exc:
        report.warnings.append(
            tr("{file} est illisible ({error}) : ignoré.").format(file=path.name, error=exc)
        )
        return {}
    if not isinstance(data, dict):
        report.warnings.append(tr("{file} n'a pas la structure attendue : ignoré.").format(file=path.name))
        return {}
    result: dict[str, dict[str, Any]] = {}
    for name, value in cast(dict[Any, Any], data).items():
        if isinstance(value, dict):
            result[str(name)] = value
        else:
            report.warnings.append(
                tr("Entrée « {name} » de {file} ignorée (format inattendu).").format(
                    name=name, file=path.name
                )
            )
    return result


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _port(value: Any) -> int | None:
    text = _text(value)
    if text.isdigit() and 0 < int(text) < 65536:
        return int(text)
    return None


_FIXABLE_PROFILE_FIELDS: dict[str, Any] = {
    "proxy": None,
    "hostname": "",
    "local_host": "127.0.0.1",
    "local_port": None,
}


def _build_profile(values: dict[str, Any], name: str, report: MigrationReport) -> CloudflareProfile:
    """Crée le profil ; un champ invalide est vidé et signalé plutôt que de perdre tout le profil."""
    for _attempt in range(len(_FIXABLE_PROFILE_FIELDS) + 1):
        try:
            return CloudflareProfile(**values)
        except ValidationError as exc:
            fields = {str(err["loc"][0]) for err in exc.errors() if err.get("loc")}
            to_fix = fields & _FIXABLE_PROFILE_FIELDS.keys()
            if not to_fix:
                raise
            for field_name in sorted(to_fix):
                values[field_name] = _FIXABLE_PROFILE_FIELDS[field_name]
                report.warnings.append(
                    tr("Profil « {name} » : champ « {field} » invalide, vidé.").format(
                        name=name, field=field_name
                    )
                )
    return CloudflareProfile(**values)


def _clip_name(name: str) -> str:
    return name.strip()[:120] or tr("Sans nom")


def backup_v1_files(data_dir: Path, files: list[Path]) -> Path:
    target = data_dir / f"backup-v1-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    target.mkdir(parents=True, exist_ok=False)
    for path in files:
        shutil.copy2(path, target / path.name)
    return target


def migrate_v1(
    data_dir: Path, secrets: SecretStore, *, backup: bool = True
) -> tuple[Config, MigrationReport]:
    """Construit une configuration v2 à partir des fichiers v1 de `data_dir`."""
    if not secrets.persistent:
        raise MigrationError(
            tr(
                "Le coffre de secrets n'est pas persistant : la migration attendra qu'un coffre soit disponible."
            )
        )
    report = MigrationReport(v1_files=find_v1_files(data_dir))
    if backup and report.v1_files:
        report.backup_dir = backup_v1_files(data_dir, report.v1_files)
    config = convert_v1(
        profiles=_read_mapping(data_dir / V1_PROFILES, report),
        tokens=_read_mapping(data_dir / V1_TOKENS, report),
        ssh=_read_mapping(data_dir / V1_SSH, report),
        secret_sink=secrets.set,
        report=report,
    )

    # Chemin de cloudflared.
    path_file = data_dir / V1_PATH
    if path_file.is_file():
        try:
            data = read_json_lenient(path_file)
            path = _text(cast(dict[str, Any], data).get("path")) if isinstance(data, dict) else ""
            if path:
                config.settings.cloudflared_path = path
                report.cloudflared_path = path
        except Exception as exc:
            report.warnings.append(
                tr("{file} est illisible ({error}) : ignoré.").format(file=V1_PATH, error=exc)
            )

    for leftover in V1_LEFTOVERS:
        if (data_dir / leftover).exists():
            report.warnings.append(
                tr("{file} n'est utilisé par aucune version : il n'est pas repris.").format(file=leftover)
            )

    log.info(
        "Migration v1 : %d profils, %d tokens (%d créés), %d profils SSH, %d avertissements",
        report.profiles,
        report.tokens,
        len(report.created_tokens),
        report.ssh_profiles,
        len(report.warnings),
    )
    return config, report


def convert_v1(
    *,
    profiles: dict[str, dict[str, Any]],
    tokens: dict[str, dict[str, Any]],
    ssh: dict[str, dict[str, Any]],
    secret_sink: Callable[[str, str], None],
    report: MigrationReport,
) -> Config:
    """Convertit les dictionnaires v1 en configuration v2. Les secrets sont confiés à `secret_sink(clé, valeur)`."""
    config = Config()
    v1_tokens, v1_profiles, v1_ssh = tokens, profiles, ssh

    # 1. Tokens : le secret part dans le coffre ; (ID, secret) sert à retrouver les copies dans les profils.
    by_pair: dict[tuple[str, str], ServiceToken] = {}
    for name, entry in v1_tokens.items():
        client_id = _text(entry.get("token_id"))
        secret = _text(entry.get("token_secret"))
        if not client_id:
            report.warnings.append(tr("Token « {name} » sans ID : ignoré.").format(name=name))
            continue
        token = ServiceToken(
            name=unique_name(_clip_name(name), [t.name for t in config.tokens]), client_id=client_id
        )
        if secret:
            secret_sink(token.secret_key, secret)
        else:
            report.warnings.append(tr("Token « {name} » sans secret : à compléter.").format(name=name))
        config.tokens.append(token)
        by_pair.setdefault((client_id, secret), token)

    # 2. Profils Cloudflare : référence au token au lieu d'une copie du secret.
    for name, entry in v1_profiles.items():
        client_id = _text(entry.get("token_id"))
        secret = _text(entry.get("token_secret"))
        auth = AuthMode.BROWSER
        token_id: str | None = None
        if client_id:
            token = by_pair.get((client_id, secret))
            if token is None:
                token = ServiceToken(
                    name=unique_name(
                        _clip_name(tr("{name} (migré)").format(name=name)), [t.name for t in config.tokens]
                    ),
                    client_id=client_id,
                )
                if secret:
                    secret_sink(token.secret_key, secret)
                config.tokens.append(token)
                by_pair[(client_id, secret)] = token
                report.created_tokens.append(token.name)
            auth = AuthMode.SERVICE_TOKEN
            token_id = token.id

        port = _port(entry.get("port"))
        if port is None:
            report.warnings.append(
                tr("Profil « {name} » : port local absent ou invalide, à compléter.").format(name=name)
            )

        hostname = normalize_hostname(_text(entry.get("hostname")))
        local_host = _text(entry.get("host")) or "127.0.0.1"
        if not is_valid_host(local_host):
            report.warnings.append(
                tr("Profil « {name} » : adresse locale « {host} » invalide, remplacée par 127.0.0.1.").format(
                    name=name, host=local_host
                )
            )
            local_host = "127.0.0.1"
        proxy = _text(entry.get("proxy")) or None

        profile_name = unique_name(_clip_name(name), [p.name for p in config.cloudflare_profiles])
        values: dict[str, Any] = {
            "name": profile_name,
            "hostname": hostname,
            "local_host": local_host,
            "local_port": port,
            "auth": auth,
            "token_id": token_id,
            "proxy": proxy,
            "service_type": guess_service_type(name, hostname, port),
        }
        profile = _build_profile(values, name, report)
        config.cloudflare_profiles.append(profile)

    # 3. Profils SSH.
    for name, entry in v1_ssh.items():
        host = _text(entry.get("host"))
        if host and not is_valid_host(host):
            report.warnings.append(
                tr("Profil SSH « {name} » : hôte « {host} » invalide, vidé.").format(name=name, host=host)
            )
            host = ""
        port = _port(entry.get("port")) or 22
        user = _text(entry.get("user"))
        try:
            ssh_profile = SshProfile(
                name=unique_name(_clip_name(name), [p.name for p in config.ssh_profiles]),
                host=host,
                port=port,
                user=user,
                auth=SshAuthMode.PASSWORD,
            )
        except ValidationError:
            report.warnings.append(
                tr("Profil SSH « {name} » : utilisateur invalide, vidé.").format(name=name)
            )
            ssh_profile = SshProfile(
                name=unique_name(_clip_name(name), [p.name for p in config.ssh_profiles]),
                host=host,
                port=port,
                auth=SshAuthMode.PASSWORD,
            )
        config.ssh_profiles.append(ssh_profile)

    report.tokens = len(config.tokens)
    report.profiles = len(config.cloudflare_profiles)
    report.ssh_profiles = len(config.ssh_profiles)
    return config


def delete_v1_files(data_dir: Path, *, include_backups: bool = True) -> list[Path]:
    """Supprime les fichiers v1 (secrets en clair) et, par défaut, leurs sauvegardes. À appeler après confirmation."""
    removed: list[Path] = []
    for name in (*V1_FILES, *V1_LEFTOVERS):
        path = data_dir / name
        if path.is_file():
            path.unlink()
            removed.append(path)
    if include_backups:
        for backup in data_dir.glob("backup-v1-*"):
            if backup.is_dir():
                shutil.rmtree(backup)
                removed.append(backup)
    return removed
