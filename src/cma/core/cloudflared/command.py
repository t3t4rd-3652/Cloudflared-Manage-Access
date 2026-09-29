"""Construction des commandes cloudflared.

Aucun shell n'intervient : les arguments forment une liste, et les valeurs sensibles
(service token, proxy) passent par l'environnement du processus. cloudflared lit
TUNNEL_SERVICE_TOKEN_ID et TUNNEL_SERVICE_TOKEN_SECRET (vérifié avec la version 2026.7.2) :
le secret n'apparaît donc jamais dans la ligne de commande.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from cma.core.models import AuthMode, CloudflareProfile
from cma.core.netutil import format_host_port
from cma.i18n import tr

TOKEN_ENV_VARS = ("TUNNEL_SERVICE_TOKEN_ID", "TUNNEL_SERVICE_TOKEN_SECRET")
# Variables qui changeraient silencieusement le comportement de `access tcp` si elles étaient héritées.
INHERITED_TUNNEL_VARS = ("TUNNEL_SERVICE_HOSTNAME", "TUNNEL_SERVICE_URL", "TUNNEL_SERVICE_DESTINATION")
PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


class CommandError(ValueError):
    """Le profil ne permet pas de construire la commande."""


@dataclass(frozen=True)
class CommandSpec:
    args: tuple[str, ...]
    env: dict[str, str] = field(default_factory=dict[str, str])

    def display(self) -> str:
        """Ligne de commande lisible, pour les journaux. Elle ne contient aucun secret."""
        return " ".join(f'"{a}"' if (" " in a or not a) else a for a in self.args)


def normalize_proxy_url(proxy: str) -> str:
    proxy = proxy.strip()
    return proxy if "://" in proxy else f"http://{proxy}"


def proxy_host_port(proxy: str | None) -> str | None:
    """« hôte:port » du proxy, tel que cloudflared l'affiche dans ses erreurs de connexion."""
    if not proxy:
        return None
    rest = normalize_proxy_url(proxy).split("://", 1)[1].rstrip("/")
    return rest.rsplit("@", 1)[-1]


def _base_env(base_env: Mapping[str, str] | None) -> dict[str, str]:
    env = dict(os.environ if base_env is None else base_env)
    for name in (*TOKEN_ENV_VARS, *INHERITED_TUNNEL_VARS):
        env.pop(name, None)
    return env


def build_access_tcp(
    binary: str | Path,
    profile: CloudflareProfile,
    *,
    client_id: str | None = None,
    client_secret: str | None = None,
    log_level: str = "info",
    base_env: Mapping[str, str] | None = None,
) -> CommandSpec:
    if not profile.hostname:
        raise CommandError(tr("Le hostname n'est pas renseigné."))
    if profile.local_port is None:
        raise CommandError(tr("Le port local n'est pas renseigné."))
    args = [
        str(binary),
        "access",
        "tcp",
        "--hostname",
        profile.hostname,
        "--url",
        format_host_port(profile.local_host, profile.local_port),
        "--loglevel",
        log_level,
    ]
    for header in profile.headers:
        args += ["--header", header]

    env = _base_env(base_env)
    if profile.auth == AuthMode.SERVICE_TOKEN:
        if not client_id or not client_secret:
            raise CommandError(tr("Le service token est incomplet (ID ou secret manquant)."))
        env["TUNNEL_SERVICE_TOKEN_ID"] = client_id
        env["TUNNEL_SERVICE_TOKEN_SECRET"] = client_secret
    if profile.proxy:
        proxy_url = normalize_proxy_url(profile.proxy)
        for name in PROXY_ENV_VARS:
            env[name] = proxy_url
    return CommandSpec(tuple(args), env)


def build_access_login(
    binary: str | Path, hostname: str, *, base_env: Mapping[str, str] | None = None
) -> CommandSpec:
    """`cloudflared access login` : authentification Access dans le navigateur, jeton mis en cache par cloudflared."""
    return CommandSpec((str(binary), "access", "login", f"https://{hostname}"), _base_env(base_env))


def build_access_token(
    binary: str | Path, hostname: str, *, base_env: Mapping[str, str] | None = None
) -> CommandSpec:
    """`cloudflared access token` : affiche le jeton en cache, ou échoue s'il n'y en a pas."""
    return CommandSpec((str(binary), "access", "token", f"-app=https://{hostname}"), _base_env(base_env))


def build_ssh_config(binary: str | Path, hostname: str) -> CommandSpec:
    return CommandSpec((str(binary), "access", "ssh-config", "--hostname", hostname), _base_env(None))
