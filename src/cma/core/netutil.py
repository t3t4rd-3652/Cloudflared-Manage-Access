"""Utilitaires réseau : disponibilité d'un port local, choix d'un port libre, format des adresses."""

from __future__ import annotations

import errno
import ipaddress
import random
import socket
import subprocess
import sys
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache

from cma.i18n import tr


class PortStatus(StrEnum):
    FREE = "free"
    IN_USE = "in_use"
    RESERVED = "reserved"
    INVALID = "invalid"


@dataclass(frozen=True)
class PortCheck:
    status: PortStatus
    message: str = ""

    @property
    def free(self) -> bool:
        return self.status == PortStatus.FREE


def _family(host: str) -> socket.AddressFamily:
    try:
        return socket.AF_INET6 if ipaddress.ip_address(host.strip("[]")).version == 6 else socket.AF_INET
    except ValueError:
        return socket.AF_INET


def format_host_port(host: str, port: int) -> str:
    """« 127.0.0.1:8080 », ou « [::1]:8080 » pour une adresse IPv6."""
    host = host.strip("[]")
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def check_local_port(host: str, port: int) -> PortCheck:
    """Tente un bind pour savoir si le port est libre, occupé, ou réservé par le système."""
    if not 0 < port < 65536:
        return PortCheck(PortStatus.INVALID, tr("Le port doit être compris entre 1 et 65535."))
    family = _family(host)
    bind_host = host.strip("[]")
    if bind_host == "localhost":
        bind_host = "127.0.0.1"
    # Bind simple, sans option de réutilisation : c'est exactement ce que fera cloudflared.
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((bind_host, port))
        except PermissionError:
            return PortCheck(PortStatus.RESERVED, reserved_port_message(port))
        except OSError as exc:
            if exc.errno in (errno.EADDRINUSE, 10048):
                return PortCheck(PortStatus.IN_USE, tr("Le port {port} est déjà utilisé.").format(port=port))
            if exc.errno in (errno.EACCES, 10013):
                return PortCheck(PortStatus.RESERVED, reserved_port_message(port))
            if exc.errno in (errno.EADDRNOTAVAIL, 10049):
                return PortCheck(
                    PortStatus.INVALID,
                    tr("L'adresse locale {host} n'existe pas sur ce poste.").format(host=host),
                )
            return PortCheck(PortStatus.IN_USE, str(exc))
    return PortCheck(PortStatus.FREE)


def reserved_port_message(port: int) -> str:
    ranges = excluded_port_ranges()
    for low, high in ranges:
        if low <= port <= high:
            return tr(
                "Le port {port} est réservé par Windows (plage {low}-{high}, souvent Hyper-V ou WSL). Choisissez-en un autre."
            ).format(port=port, low=low, high=high)
    return tr("Le port {port} est réservé ou interdit par le système. Choisissez-en un autre.").format(
        port=port
    )


@lru_cache(maxsize=1)
def excluded_port_ranges() -> tuple[tuple[int, int], ...]:
    """Plages de ports TCP réservées par Windows (netsh). Vide ailleurs ou en cas d'échec."""
    if sys.platform != "win32":
        return ()
    try:
        output = subprocess.run(
            ["netsh", "interface", "ipv4", "show", "excludedportrange", "protocol=tcp"],
            capture_output=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        ).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return ()
    ranges: list[tuple[int, int]] = []
    for line in output.splitlines():
        parts = line.replace("*", " ").split()
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            ranges.append((int(parts[0]), int(parts[1])))
    return tuple(ranges)


def is_excluded(port: int) -> bool:
    return any(low <= port <= high for low, high in excluded_port_ranges())


def find_free_port(
    host: str = "127.0.0.1",
    *,
    preferred: int | None = None,
    port_range: tuple[int, int] = (20000, 29999),
    avoid: set[int] | None = None,
    attempts: int = 200,
) -> int | None:
    """Port libre : d'abord `preferred` s'il est disponible, sinon un port de la plage donnée."""
    avoid = avoid or set()
    if (
        preferred
        and preferred not in avoid
        and not is_excluded(preferred)
        and check_local_port(host, preferred).free
    ):
        return preferred
    low, high = port_range
    candidates = list(range(low, high + 1))
    random.shuffle(candidates)
    for port in candidates[:attempts]:
        if port in avoid or is_excluded(port):
            continue
        if check_local_port(host, port).free:
            return port
    return None


def is_port_listening(host: str, port: int) -> bool:
    """Vrai si un processus écoute déjà sur ce port. Ne se connecte pas : il tente un bind exclusif."""
    return check_local_port(host, port).status == PortStatus.IN_USE
