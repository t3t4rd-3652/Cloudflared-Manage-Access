"""Poignée de main SOCKS 5 (et 4/4a) côté serveur, pour la redirection dynamique (-D).

Seule la commande CONNECT est prise en charge, sans authentification : le proxy n'écoute que sur ce poste.
La cible demandée par le client est ensuite ouverte depuis le serveur SSH.
"""

from __future__ import annotations

import asyncio
import ipaddress

SOCKS5_SUCCESS = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
SOCKS4_SUCCESS = b"\x00\x5a\x00\x00\x00\x00\x00\x00"
SOCKS4_FAILURE = b"\x00\x5b\x00\x00\x00\x00\x00\x00"


class SocksError(Exception):
    """Demande SOCKS invalide ou non prise en charge (la réponse d'erreur a déjà été envoyée)."""


def socks5_failure(code: int = 0x01) -> bytes:
    """0x01 échec général, 0x05 connexion refusée, 0x07 commande non prise en charge, 0x08 adresse non prise en charge."""
    return bytes((0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0))


async def _read_until_nul(reader: asyncio.StreamReader, limit: int = 255) -> bytes:
    data = await reader.readuntil(b"\x00")
    if len(data) > limit + 1:
        raise SocksError("champ trop long")
    return data[:-1]


async def negotiate(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> tuple[str, int, int]:
    """Lit la demande du client : (hôte, port, version SOCKS). Répond lui-même aux demandes refusées."""
    version = (await reader.readexactly(1))[0]
    if version == 5:
        count = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(count)
        if 0x00 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            raise SocksError("aucune méthode sans authentification")
        writer.write(b"\x05\x00")
        await writer.drain()
        _ver, command, _reserved, address_type = await reader.readexactly(4)
        if command != 0x01:
            writer.write(socks5_failure(0x07))
            await writer.drain()
            raise SocksError("commande non prise en charge")
        if address_type == 0x01:
            host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
        elif address_type == 0x03:
            length = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(length)).decode("ascii", "replace")
        elif address_type == 0x04:
            host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
        else:
            writer.write(socks5_failure(0x08))
            await writer.drain()
            raise SocksError("type d'adresse non pris en charge")
        port = int.from_bytes(await reader.readexactly(2), "big")
        return host, port, 5
    if version == 4:
        command = (await reader.readexactly(1))[0]
        port = int.from_bytes(await reader.readexactly(2), "big")
        raw_ip = await reader.readexactly(4)
        await _read_until_nul(reader)  # identifiant utilisateur, ignoré
        if command != 0x01:
            writer.write(SOCKS4_FAILURE)
            await writer.drain()
            raise SocksError("commande non prise en charge")
        if raw_ip[:3] == b"\x00\x00\x00" and raw_ip[3] != 0:
            host = (await _read_until_nul(reader)).decode("ascii", "replace")  # SOCKS 4a : nom d'hôte
        else:
            host = str(ipaddress.IPv4Address(raw_ip))
        return host, port, 4
    raise SocksError(f"version SOCKS {version} inconnue")


def success_reply(version: int) -> bytes:
    return SOCKS5_SUCCESS if version == 5 else SOCKS4_SUCCESS


def failure_reply(version: int) -> bytes:
    return socks5_failure(0x05) if version == 5 else SOCKS4_FAILURE
