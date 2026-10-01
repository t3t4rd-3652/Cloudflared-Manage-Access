"""Diagnostic guidé d'un accès Cloudflare : contrôles explicites, bornés, lancés à la demande (spécification §9).

Chaque contrôle a une durée maximale et rapporte ce qu'il a réellement constaté, sans transformer un symptôme
en certitude. Rien n'est lancé en arrière-plan : l'utilisateur déclenche le diagnostic.

1. cloudflared présent et sa version ;
2. port local libre (ou déjà ouvert par la session de ce profil) ;
3. résolution DNS du nom d'hôte ;
4. proxy joignable, s'il y en a un ;
5. HTTPS jusqu'à Cloudflare : certificat valide et réponse d'Access ;
6. authentification : service token accepté, ou jeton Access en cache pour le navigateur.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from cma.core.cloudflared.binary import read_version
from cma.core.models import AuthMode, CloudflareProfile
from cma.core.netutil import PortStatus, check_local_port
from cma.i18n import tr

if TYPE_CHECKING:
    from cma.core.manager import SessionManager

Status = Literal["ok", "warning", "error", "skipped"]
TIMEOUT = 6.0
_PROXY_RE = re.compile(
    r"^(?:(?P<scheme>https?|socks5h?)://)?(?:[^@/\s]+@)?(?P<host>[^:/\s]+|\[[0-9a-fA-F:]+\]):(?P<port>\d+)"
)


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    detail: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def _https_head(hostname: str, proxy: str | None, timeout: float) -> tuple[int, str]:
    """(statut HTTP, en-tête Location) d'une requête HEAD vers https://hostname/, sans suivre les redirections."""
    handlers: list[urllib.request.BaseHandler] = [_NoRedirect()]
    proxies = {"https": proxy if "://" in proxy else f"http://{proxy}"} if proxy else {}
    handlers.append(urllib.request.ProxyHandler(proxies))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(f"https://{hostname}/", method="HEAD", headers={"User-Agent": "CMA"})
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.headers.get("Location", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Location", "") if exc.headers else ""


async def _cloudflared(manager: SessionManager) -> Check:
    name = tr("cloudflared")
    binary = manager.cloudflared_path()
    if binary is None:
        return Check(
            name, "error", tr("Introuvable : téléchargez-le ou indiquez son chemin dans Paramètres.")
        )
    version = await read_version(binary)
    return Check(name, "ok", tr("Version {version} · {path}").format(version=version or "?", path=binary))


def _local_port(manager: SessionManager, profile: CloudflareProfile) -> Check:
    name = tr("Port local")
    if profile.local_port is None:
        return Check(name, "error", tr("Aucun port local n'est choisi."))
    if manager.active_session_for(profile.id) is not None:
        return Check(
            name, "ok", tr("Ouvert par la session de ce profil ({port}).").format(port=profile.local_port)
        )
    check = check_local_port(profile.local_host, profile.local_port)
    if check.status == PortStatus.FREE:
        return Check(name, "ok", tr("Le port {port} est libre.").format(port=profile.local_port))
    return Check(name, "error", check.message)


async def _dns(hostname: str) -> Check:
    name = tr("Résolution DNS")
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(hostname, 443), TIMEOUT)
    except (OSError, TimeoutError) as exc:
        return Check(
            name,
            "error",
            tr("{host} ne se résout pas : {error}").format(
                host=hostname, error=str(exc) or tr("délai dépassé")
            ),
        )
    addresses = list(dict.fromkeys(str(info[4][0]) for info in infos))
    return Check(name, "ok", ", ".join(addresses[:4]) + (" …" if len(addresses) > 4 else ""))


async def _proxy(proxy: str | None) -> Check:
    name = tr("Proxy")
    if not proxy:
        return Check(name, "skipped", tr("Aucun proxy pour ce profil."))
    match = _PROXY_RE.match(proxy)
    if match is None:
        return Check(name, "error", tr("Adresse de proxy illisible."))
    host, port = match.group("host").strip("[]"), int(match.group("port"))
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), TIMEOUT)
    except (OSError, TimeoutError) as exc:
        return Check(
            name,
            "error",
            tr("{proxy} ne répond pas : {error}").format(proxy=proxy, error=str(exc) or tr("délai dépassé")),
        )
    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()
    return Check(name, "ok", tr("{proxy} accepte les connexions.").format(proxy=proxy))


async def _access(profile: CloudflareProfile) -> Check:
    name = tr("HTTPS et Cloudflare Access")
    if profile.proxy and profile.proxy.startswith("socks"):
        return Check(name, "skipped", tr("Contrôle non effectué à travers un proxy SOCKS."))
    try:
        status, location = await asyncio.to_thread(_https_head, profile.hostname, profile.proxy, TIMEOUT)
    except ssl.SSLError as exc:
        hint = (
            tr(" Un proxy d'entreprise qui inspecte le trafic peut en être la cause.")
            if profile.proxy
            else ""
        )
        return Check(name, "error", tr("Échec TLS : {error}.").format(error=exc.reason or exc) + hint)
    except (OSError, urllib.error.URLError) as exc:
        reason = getattr(exc, "reason", exc)
        return Check(name, "error", tr("Connexion HTTPS impossible : {error}").format(error=reason))
    if "cloudflareaccess.com" in location:
        return Check(name, "ok", tr("Access protège ce nom d'hôte (redirection vers la page de connexion)."))
    if status in (401, 403):
        return Check(name, "ok", tr("Access protège ce nom d'hôte (réponse {status}).").format(status=status))
    return Check(
        name,
        "warning",
        tr(
            "Réponse {status} sans redirection Access : ce nom d'hôte n'est peut-être pas protégé par Access."
        ).format(status=status),
    )


async def _authentication(manager: SessionManager, profile: CloudflareProfile) -> Check:
    name = tr("Authentification")
    if profile.auth == AuthMode.SERVICE_TOKEN:
        token = manager.store.snapshot().token(profile.token_id)
        if token is None:
            return Check(name, "error", tr("Le service token choisi n'existe plus."))
        if not manager.secrets.get(token.secret_key):
            return Check(name, "error", tr("Le secret du service token est absent du coffre."))
        ok, message = await manager.test_cloudflare_profile(profile.id)
        return Check(name, "ok" if ok else "error", message)
    if await manager.access_token_valid(profile.id):
        return Check(name, "ok", tr("cloudflared a un jeton Access valide en cache."))
    return Check(
        name, "warning", tr("Aucun jeton en cache : le navigateur s'ouvrira à la prochaine connexion.")
    )


async def diagnose_cloudflare_profile(manager: SessionManager, profile_id: str) -> list[Check]:
    profile = manager.store.snapshot().cloudflare_profile(profile_id)
    if profile is None:
        return [Check(tr("Profil"), "error", tr("Profil introuvable."))]
    checks = [await _cloudflared(manager), _local_port(manager, profile)]
    if not profile.hostname:
        return [*checks, Check(tr("Nom d'hôte"), "error", tr("Le nom d'hôte n'est pas renseigné."))]
    checks += [await _dns(profile.hostname), await _proxy(profile.proxy), await _access(profile)]
    if checks[0].status == "ok":
        try:
            checks.append(await _authentication(manager, profile))
        except Exception as exc:
            checks.append(Check(tr("Authentification"), "error", str(exc)))
    else:
        checks.append(Check(tr("Authentification"), "skipped", tr("Impossible sans cloudflared.")))
    return checks


def format_report(profile_name: str, checks: list[Check]) -> str:
    symbols = {"ok": "✓", "warning": "!", "error": "×", "skipped": "–"}
    lines = [tr("Diagnostic de « {name} »").format(name=profile_name)]
    lines += [f"{symbols[c.status]} {c.name} : {c.detail}" for c in checks]
    return "\n".join(lines)
