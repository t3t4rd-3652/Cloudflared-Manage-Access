"""Import de `~/.ssh/config` : chaque bloc `Host` nommé devient un serveur SSH de CMA.

Repris : `HostName`, `User`, `Port`, `IdentityFile` (authentification par clé ; sans clé, par l'agent SSH),
`ProxyJump` (rebond par un autre serveur, importé avec lui ou déjà dans CMA) et un `ProxyCommand` du type
`cloudflared access ssh --hostname <nom>` (passage par le profil Cloudflare de ce nom, s'il existe). Les blocs
génériques (`Host *`, `Host *.lab`), les blocs `Match` et les options que CMA ne gère pas sont ignorés ; `Include`
est suivi (chemins relatifs à `~/.ssh`, motifs compris). Les mots de passe ne figurent jamais dans ce fichier.
"""

from __future__ import annotations

import glob
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from cma.core.models import Config, SshAuthMode, SshProfile, unique_name

MAX_INCLUDE_DEPTH = 5
_CLOUDFLARED_HOST = re.compile(r"--hostname[ =]([^\s]+)")


@dataclass
class SshHostEntry:
    alias: str
    host: str = ""
    user: str = ""
    port: int = 22
    identity: str = ""
    proxy_jump: str = ""
    cloudflare_hostname: str = ""
    ignored: list[str] = field(default_factory=list[str])  # options non reprises, pour l'aperçu

    @property
    def target(self) -> str:
        return self.host or self.alias


def default_path() -> Path:
    return Path.home() / ".ssh" / "config"


def _expand(value: str, base: Path) -> Path:
    path = Path(os.path.expanduser(value))
    return path if path.is_absolute() else base / path


def _lines(path: Path, depth: int = 0) -> list[tuple[str, str]]:
    """(mot-clé en minuscules, valeur) de chaque ligne utile, `Include` résolus."""
    if depth > MAX_INCLUDE_DEPTH or not path.is_file():
        return []
    result: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s*=\s*|\s+", line, maxsplit=1)
        keyword, value = parts[0].lower(), (parts[1].strip() if len(parts) > 1 else "")
        if keyword == "include":
            for pattern in shlex.split(value):
                for found in sorted(glob.glob(str(_expand(pattern, path.parent)))):
                    result.extend(_lines(Path(found), depth + 1))
            continue
        result.append((keyword, value.strip('"')))
    return result


def parse_ssh_config(path: Path | None = None) -> list[SshHostEntry]:
    """Blocs `Host` nommés du fichier, dans leur ordre. Le premier réglage rencontré l'emporte, comme pour ssh."""
    entries: list[SshHostEntry] = []
    current: list[SshHostEntry] = []
    for keyword, value in _lines(path or default_path()):
        if keyword == "host":
            names = [n for n in value.split() if not any(c in n for c in "*?!")]
            current = [SshHostEntry(alias=n) for n in names]
            entries.extend(current)
            continue
        if keyword == "match":
            current = []
            continue
        for entry in current:
            if keyword == "hostname" and not entry.host:
                entry.host = value
            elif keyword == "user" and not entry.user:
                entry.user = value
            elif keyword == "port" and entry.port == 22 and value.isdigit():
                entry.port = int(value)
            elif keyword == "identityfile" and not entry.identity:
                entry.identity = os.path.expanduser(value)
            elif keyword == "proxyjump" and not entry.proxy_jump:
                entry.proxy_jump = value.split(",")[0].split("@")[-1].split(":")[0]
            elif keyword == "proxycommand" and "cloudflared" in value and not entry.cloudflare_hostname:
                if match := _CLOUDFLARED_HOST.search(value):
                    entry.cloudflare_hostname = match.group(1).strip("'\"")
            elif keyword not in ("hostname", "user", "port", "identityfile", "proxyjump", "proxycommand"):
                entry.ignored.append(keyword)
    return entries


def already_known(entry: SshHostEntry, config: Config) -> bool:
    """Le serveur est-il déjà dans CMA (même nom, ou même hôte, utilisateur et port) ?"""
    for profile in config.ssh_profiles:
        if profile.name.lower() == entry.alias.lower():
            return True
        if (
            profile.host.lower() == entry.target.lower()
            and profile.port == entry.port
            and profile.user == entry.user
        ):
            return True
    return False


def profiles_from_entries(entries: list[SshHostEntry], config: Config) -> list[SshProfile]:
    """Serveurs SSH à créer ; un rebond vise le serveur importé avec lui ou déjà présent sous ce nom."""
    names = [p.name for p in [*config.cloudflare_profiles, *config.ssh_profiles]]
    created: dict[str, SshProfile] = {}
    for entry in entries:
        via = next(
            (
                p.id
                for p in config.cloudflare_profiles
                if entry.cloudflare_hostname and p.hostname == entry.cloudflare_hostname.lower()
            ),
            None,
        )
        try:
            profile = SshProfile(
                name=unique_name(entry.alias, names),
                host=entry.target,
                port=entry.port,
                user=entry.user,
                auth=SshAuthMode.KEY if entry.identity else SshAuthMode.AGENT,
                key_path=entry.identity or None,
                via_cloudflare_profile=via,
            )
        except ValidationError:
            continue  # hôte que CMA ne sait pas lire (variable %h, motif…) : l'aperçu le signale
        names.append(profile.name)
        created[entry.alias.lower()] = profile
    existing = {p.name.lower(): p for p in config.ssh_profiles}
    result: list[SshProfile] = []
    for entry in entries:
        profile = created.get(entry.alias.lower())
        if profile is None:
            continue
        jump = created.get(entry.proxy_jump.lower()) or existing.get(entry.proxy_jump.lower())
        if entry.proxy_jump and jump is not None and jump is not profile:
            profile = profile.model_copy(update={"jump_profile": jump.id})
        result.append(profile)
    return result
