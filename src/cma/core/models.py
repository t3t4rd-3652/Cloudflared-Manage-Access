"""Modèles de données de CMA (schéma de configuration v2).

Aucun secret n'est stocké dans ces objets : les secrets vivent dans le coffre (voir secrets.py),
référencés par `secret_key`.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cma.i18n import tr

SCHEMA_VERSION = 2

Port = Annotated[int, Field(ge=1, le=65535)]
Name = Annotated[str, Field(min_length=1, max_length=120)]

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?$")
_HEADER_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+\s*:.*$")
_SSH_USER_RE = re.compile(r"^[A-Za-z0-9._@\\-]{1,64}$")


def new_id() -> str:
    return uuid.uuid4().hex


def utc_now() -> datetime:
    return datetime.now(UTC)


def is_valid_host(value: str) -> bool:
    """Adresse IPv4, IPv6 ou nom d'hôte DNS."""
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(value))


def normalize_hostname(value: str) -> str:
    """Accepte « https://app.exemple.fr/chemin » et ne garde que « app.exemple.fr »."""
    value = value.strip()
    value = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", value)
    value = value.split("/", 1)[0].split("?", 1)[0]
    return value.rstrip(".").lower()


class Model(BaseModel):
    model_config = ConfigDict(extra="ignore", validate_assignment=True, str_strip_whitespace=True)


class ServiceType(StrEnum):
    GENERIC = "generic"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    RDP = "rdp"
    SMB = "smb"
    MONGODB = "mongodb"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    REDIS = "redis"

    @property
    def label(self) -> str:
        return {
            ServiceType.GENERIC: tr("Autre (TCP)"),
            ServiceType.HTTP: "HTTP",
            ServiceType.HTTPS: "HTTPS",
            ServiceType.SSH: "SSH",
            ServiceType.RDP: tr("Bureau à distance (RDP)"),
            ServiceType.SMB: tr("Partage de fichiers (SMB)"),
            ServiceType.MONGODB: "MongoDB",
            ServiceType.POSTGRESQL: "PostgreSQL",
            ServiceType.MYSQL: "MySQL / MariaDB",
            ServiceType.REDIS: "Redis",
        }[self]


_PORT_SERVICE_TYPES = {
    22: ServiceType.SSH,
    80: ServiceType.HTTP,
    443: ServiceType.HTTPS,
    445: ServiceType.SMB,
    3306: ServiceType.MYSQL,
    3389: ServiceType.RDP,
    5432: ServiceType.POSTGRESQL,
    6379: ServiceType.REDIS,
    8080: ServiceType.HTTP,
    8443: ServiceType.HTTPS,
    27017: ServiceType.MONGODB,
}


def guess_service_type(name: str = "", hostname: str = "", port: int | None = None) -> ServiceType:
    """Devine le type de service d'un profil, pour proposer la bonne action rapide."""
    text = f"{name} {hostname}".lower()
    for keyword, service in (
        ("mongo", ServiceType.MONGODB),
        ("rdp", ServiceType.RDP),
        ("ssh", ServiceType.SSH),
        ("postgres", ServiceType.POSTGRESQL),
        ("mysql", ServiceType.MYSQL),
        ("maria", ServiceType.MYSQL),
        ("redis", ServiceType.REDIS),
        ("smb", ServiceType.SMB),
    ):
        if keyword in text:
            return service
    if port is not None and port in _PORT_SERVICE_TYPES:
        return _PORT_SERVICE_TYPES[port]
    return ServiceType.GENERIC


class AuthMode(StrEnum):
    BROWSER = "browser"
    SERVICE_TOKEN = "service_token"


class ServiceToken(Model):
    """Service token Cloudflare Access. Le secret est dans le coffre, sous `secret_key`."""

    id: str = Field(default_factory=new_id)
    name: Name
    client_id: str = Field(min_length=1, max_length=200)
    created: datetime = Field(default_factory=utc_now)
    notes: str = ""

    @property
    def secret_key(self) -> str:
        return f"token:{self.id}"


class CloudflareProfile(Model):
    """Paramètres d'une connexion `cloudflared access tcp`."""

    id: str = Field(default_factory=new_id)
    name: Name
    group: str = ""
    favorite: bool = False
    hostname: str = ""
    local_host: str = "127.0.0.1"
    local_port: Port | None = None
    auth: AuthMode = AuthMode.BROWSER
    token_id: str | None = None
    proxy: str | None = None
    headers: list[str] = Field(default_factory=list[str])
    service_type: ServiceType = ServiceType.GENERIC
    service_user: str = ""
    auto_start: bool = False
    auto_reconnect: bool = True
    notes: str = ""

    @field_validator("hostname")
    @classmethod
    def _check_hostname(cls, value: str) -> str:
        value = normalize_hostname(value)
        if value and not _HOSTNAME_RE.match(value):
            raise ValueError(tr("Hostname invalide : utilisez un nom comme app.exemple.fr"))
        return value

    @field_validator("local_host")
    @classmethod
    def _check_local_host(cls, value: str) -> str:
        value = value.strip().strip("[]") or "127.0.0.1"
        if not is_valid_host(value):
            raise ValueError(tr("Adresse locale invalide"))
        return value

    @field_validator("proxy")
    @classmethod
    def _check_proxy(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        value = value.strip()
        match = re.match(
            r"^(?:(?P<scheme>https?|socks5h?)://)?(?:[^@/\s]+@)?(?P<host>[^:/\s]+|\[[0-9a-fA-F:]+\]):(?P<port>\d{1,5})/?$",
            value,
        )
        if not match or not 0 < int(match.group("port")) < 65536:
            raise ValueError(tr("Proxy invalide : utilisez hôte:port ou http://hôte:port"))
        return value

    @field_validator("headers")
    @classmethod
    def _check_headers(cls, value: list[str]) -> list[str]:
        cleaned = [h.strip() for h in value if h.strip()]
        for header in cleaned:
            if not _HEADER_RE.match(header):
                raise ValueError(
                    tr("En-tête invalide : « {header} » (format Nom: valeur)").format(header=header)
                )
        return cleaned

    @model_validator(mode="after")
    def _token_consistency(self) -> CloudflareProfile:
        if self.auth == AuthMode.BROWSER and self.token_id is not None:
            object.__setattr__(self, "token_id", None)
        return self

    def readiness_problems(self, tokens: dict[str, ServiceToken]) -> list[str]:
        """Ce qui empêche de lancer la connexion (profil incomplet)."""
        problems: list[str] = []
        if not self.hostname:
            problems.append(tr("le hostname n'est pas renseigné"))
        if self.local_port is None:
            problems.append(tr("le port local n'est pas renseigné"))
        if self.auth == AuthMode.SERVICE_TOKEN and (not self.token_id or self.token_id not in tokens):
            problems.append(tr("aucun service token valide n'est choisi"))
        return problems


class SshAuthMode(StrEnum):
    PASSWORD = "password"
    KEY = "key"
    AGENT = "agent"


class SavedForward(Model):
    """Redirection enregistrée dans un profil SSH : port local → hôte:port vu du serveur."""

    id: str = Field(default_factory=new_id)
    remote_host: str = "127.0.0.1"
    remote_port: Port
    local_port: Port
    scheme: Literal["http", "https"] | None = None
    label: str = ""

    @field_validator("remote_host")
    @classmethod
    def _check_remote_host(cls, value: str) -> str:
        value = value.strip().strip("[]") or "127.0.0.1"
        if not is_valid_host(value):
            raise ValueError(tr("Adresse distante invalide"))
        return value


class SshProfile(Model):
    """Connexion SSH utilisée pour découvrir les ports d'un serveur et les rediriger."""

    id: str = Field(default_factory=new_id)
    name: Name
    group: str = ""
    favorite: bool = False
    host: str = ""
    port: Port = 22
    user: str = ""
    auth: SshAuthMode = SshAuthMode.PASSWORD
    key_path: str | None = None
    remember_password: bool = False
    via_cloudflare_profile: str | None = None
    saved_forwards: list[SavedForward] = Field(default_factory=list[SavedForward])
    notes: str = ""

    @field_validator("host")
    @classmethod
    def _check_host(cls, value: str) -> str:
        value = value.strip().strip("[]")
        if value and not is_valid_host(value):
            raise ValueError(tr("Hôte SSH invalide"))
        return value

    @field_validator("user")
    @classmethod
    def _check_user(cls, value: str) -> str:
        if value and not _SSH_USER_RE.match(value):
            raise ValueError(tr("Nom d'utilisateur SSH invalide"))
        return value

    @property
    def password_key(self) -> str:
        return f"ssh-password:{self.id}"

    @property
    def passphrase_key(self) -> str:
        return f"ssh-passphrase:{self.id}"

    def readiness_problems(self, cloudflare_profiles: dict[str, CloudflareProfile]) -> list[str]:
        problems: list[str] = []
        if not self.host and not self.via_cloudflare_profile:
            problems.append(tr("l'hôte n'est pas renseigné"))
        if not self.user:
            problems.append(tr("l'utilisateur n'est pas renseigné"))
        if self.auth == SshAuthMode.KEY and not self.key_path:
            problems.append(tr("aucune clé n'est choisie"))
        if self.via_cloudflare_profile and self.via_cloudflare_profile not in cloudflare_profiles:
            problems.append(tr("le profil Cloudflare de passage n'existe plus"))
        return problems


class Theme(StrEnum):
    SYSTEM = "system"
    LIGHT = "light"
    DARK = "dark"


class KnownHostsMode(StrEnum):
    APP = "app"
    USER = "user"


class Settings(Model):
    cloudflared_path: str | None = None
    theme: Theme = Theme.SYSTEM
    language: Literal["fr", "en"] = "fr"
    close_to_tray: bool = True
    start_minimized: bool = False
    start_with_system: bool = False
    notifications: bool = True
    confirm_exit: bool = True
    check_updates: bool = True
    auto_port_min: Port = 20000
    auto_port_max: Port = 29999
    known_hosts: KnownHostsMode = KnownHostsMode.APP
    log_level: Literal["DEBUG", "INFO", "WARNING"] = "INFO"
    cloudflared_log_level: Literal["debug", "info", "warn", "error"] = "info"
    window_geometry: str | None = None
    last_view: str = "dashboard"
    onboarding_done: bool = False
    v1_files_handled: bool = False

    @model_validator(mode="after")
    def _port_range(self) -> Settings:
        if self.auto_port_min > self.auto_port_max:
            raise ValueError(tr("La plage de ports automatique est inversée"))
        return self


class Config(Model):
    schema_version: int = SCHEMA_VERSION
    settings: Settings = Field(default_factory=Settings)
    tokens: list[ServiceToken] = Field(default_factory=list[ServiceToken])
    cloudflare_profiles: list[CloudflareProfile] = Field(default_factory=list[CloudflareProfile])
    ssh_profiles: list[SshProfile] = Field(default_factory=list[SshProfile])

    def token(self, token_id: str | None) -> ServiceToken | None:
        return next((t for t in self.tokens if t.id == token_id), None)

    def cloudflare_profile(self, profile_id: str | None) -> CloudflareProfile | None:
        return next((p for p in self.cloudflare_profiles if p.id == profile_id), None)

    def ssh_profile(self, profile_id: str | None) -> SshProfile | None:
        return next((p for p in self.ssh_profiles if p.id == profile_id), None)

    def tokens_by_id(self) -> dict[str, ServiceToken]:
        return {t.id: t for t in self.tokens}

    def cloudflare_by_id(self) -> dict[str, CloudflareProfile]:
        return {p.id: p for p in self.cloudflare_profiles}

    def profiles_using_token(self, token_id: str) -> list[CloudflareProfile]:
        return [
            p for p in self.cloudflare_profiles if p.auth == AuthMode.SERVICE_TOKEN and p.token_id == token_id
        ]

    def ssh_profiles_via(self, cloudflare_profile_id: str) -> list[SshProfile]:
        return [p for p in self.ssh_profiles if p.via_cloudflare_profile == cloudflare_profile_id]

    def find_profile_by_name(self, name: str) -> CloudflareProfile | SshProfile | None:
        """Recherche insensible à la casse, par identifiant ou par nom, dans tous les profils."""
        lowered = name.strip().lower()
        for profile in [*self.cloudflare_profiles, *self.ssh_profiles]:
            if profile.id == name or profile.name.lower() == lowered:
                return profile
        return None


def unique_name(base: str, existing: set[str] | list[str]) -> str:
    """« Nom », puis « Nom (2) », « Nom (3) »… en ignorant la casse."""
    taken = {name.lower() for name in existing}
    base = base.strip() or tr("Sans nom")
    if base.lower() not in taken:
        return base
    index = 2
    while f"{base} ({index})".lower() in taken:
        index += 1
    return f"{base} ({index})"
