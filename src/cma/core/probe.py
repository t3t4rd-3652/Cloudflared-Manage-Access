"""Test explicite du service distant à travers le port local d'une session (« Tester le service »).

Un port local à l'écoute ne prouve pas que le service distant répond : cloudflared ou le relais SSH acceptent
la connexion avant de joindre la cible. Ce test ouvre une vraie connexion, bornée dans le temps, et interprète
la réponse selon le type de service. Il n'est jamais lancé en arrière-plan sans demande de l'utilisateur.

- SSH : la bannière « SSH-2.0-… » prouve que le serveur répond.
- HTTP / HTTPS : une ligne de statut « HTTP/1.1 302 » prouve qu'un serveur web répond.
- Autres (RDP, SMB, bases de données) : ces services attendent que le client parle en premier. Une connexion
  qui reste ouverte est plausible, mais pas une preuve ; une fermeture immédiate signale une cible injoignable.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from dataclasses import dataclass

from cma.core.models import ServiceType
from cma.i18n import tr

TIMEOUT = 6.0
SILENT_WAIT = 3.0


@dataclass(frozen=True)
class ProbeResult:
    """`ok` : True le service répond, False il ne répond pas, None indéterminé (connexion acceptée, silence)."""

    ok: bool | None
    message: str


def probe_kind(service_type: ServiceType, scheme: str | None) -> str:
    if scheme in ("http", "https"):
        return scheme
    if service_type in (ServiceType.HTTP, ServiceType.HTTPS):
        return service_type.value
    if service_type == ServiceType.SSH:
        return "ssh"
    return "tcp"


async def _read(reader: asyncio.StreamReader, timeout: float) -> bytes | None:
    """Premiers octets reçus ; b"" si la connexion est fermée ; None si rien n'arrive à temps."""
    try:
        return await asyncio.wait_for(reader.read(256), timeout)
    except TimeoutError:
        return None


async def probe_service(host: str, port: int, kind: str, *, timeout: float = TIMEOUT) -> ProbeResult:
    context: ssl.SSLContext | None = None
    if kind == "https":
        # Le certificat présenté est celui du service distant, pour son vrai nom : on teste la réponse, pas l'identité.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=context), timeout)
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        return ProbeResult(
            False,
            tr("Connexion impossible au port local : {error}").format(error=str(exc) or tr("délai dépassé")),
        )
    try:
        if kind in ("http", "https"):
            writer.write(
                b"HEAD / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: CMA\r\nConnection: close\r\n\r\n"
            )
            await writer.drain()
            data = await _read(reader, timeout)
            if data and data.startswith(b"HTTP/"):
                status = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                return ProbeResult(True, tr("Le service web répond ({status}).").format(status=status))
            if data == b"":
                return ProbeResult(
                    False, tr("La connexion a été fermée sans réponse : le service est injoignable.")
                )
            return ProbeResult(None, tr("Aucune réponse HTTP reçue en {s} s.").format(s=int(timeout)))
        if kind == "ssh":
            data = await _read(reader, timeout)
            if data and data.startswith(b"SSH-"):
                banner = data.split(b"\r\n", 1)[0].split(b"\n", 1)[0].decode("latin-1", "replace")
                return ProbeResult(True, tr("Le serveur SSH répond ({banner}).").format(banner=banner))
            if data == b"":
                return ProbeResult(
                    False, tr("La connexion a été fermée sans réponse : le service est injoignable.")
                )
            return ProbeResult(None, tr("Aucune bannière SSH reçue en {s} s.").format(s=int(timeout)))
        data = await _read(reader, SILENT_WAIT)
        if data == b"":
            return ProbeResult(
                False, tr("La connexion a été fermée aussitôt : le service distant ne répond pas.")
            )
        if data:
            return ProbeResult(True, tr("Le service a répondu ({n} octets reçus).").format(n=len(data)))
        return ProbeResult(
            None,
            tr(
                "Connexion acceptée ; ce service attend que le client parle en premier (normal pour RDP, SMB "
                "ou une base de données). Le journal signalera un échec d'accès."
            ),
        )
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 2)
