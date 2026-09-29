"""Clés d'hôte SSH : fichier known_hosts de l'application (ou celui de l'utilisateur) et confiance au premier contact.

L'identité d'un serveur est (hôte, port) au format OpenSSH : « hôte » pour le port 22, « [hôte]:port » sinon.
Quand le SSH passe par un tunnel Cloudflare, l'identité reste celle du vrai serveur (alias),
et non 127.0.0.1 avec un port local qui peut changer.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import asyncssh
else:
    from cma.core.ssh._lazy import asyncssh

log = logging.getLogger(__name__)


def host_pattern(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


@dataclass(frozen=True)
class HostKeyPrompt:
    """Ce qu'on montre à l'utilisateur avant de faire confiance à une clé d'hôte."""

    host: str
    port: int
    algorithm: str
    fingerprint: str
    changed: bool
    previous_fingerprints: tuple[str, ...] = ()
    via: str | None = None

    @property
    def identity(self) -> str:
        return host_pattern(self.host, self.port)


@dataclass(frozen=True)
class KnownHostEntry:
    pattern: str
    algorithm: str
    fingerprint: str
    line_number: int


def _fingerprint(algorithm: str, blob: str) -> str | None:
    try:
        return asyncssh.import_public_key(f"{algorithm} {blob}").get_fingerprint("sha256")
    except (asyncssh.KeyImportError, ValueError):
        return None


class KnownHostsFile:
    """Lecture et modification d'un fichier known_hosts au format OpenSSH."""

    def __init__(self, path: Path, extra_read_only: list[Path] | None = None) -> None:
        self.path = Path(path)
        self._extra = [p for p in (extra_read_only or []) if p != self.path]
        self._lock = threading.Lock()

    def _files(self) -> list[str]:
        return [str(p) for p in [self.path, *self._extra] if p.is_file()]

    def trusted_for(self, host: str, port: int) -> tuple[object, ...]:
        """Clés de confiance pour (hôte, port), au format accepté par l'option `known_hosts` d'asyncssh."""
        files = self._files()
        known = asyncssh.read_known_hosts(files) if files else asyncssh.import_known_hosts("")
        return tuple(known.match(host, "", port))

    def entries(self) -> list[KnownHostEntry]:
        """Entrées lisibles du fichier de l'application (les entrées hachées sont ignorées)."""
        if not self.path.is_file():
            return []
        result: list[KnownHostEntry] = []
        for number, line in enumerate(
            self.path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            parts = line.split()
            if len(parts) < 3 or line.startswith(("#", "@", "|")):
                continue
            fingerprint = _fingerprint(parts[1], parts[2])
            if fingerprint:
                result.append(KnownHostEntry(parts[0], parts[1], fingerprint, number))
        return result

    def fingerprints_for(self, host: str, port: int) -> tuple[str, ...]:
        pattern = host_pattern(host, port)
        return tuple(e.fingerprint for e in self.entries() if pattern in e.pattern.split(","))

    def add(self, host: str, port: int, key: asyncssh.SSHKey, *, replace: bool) -> None:
        """Ajoute la clé ; avec `replace`, retire d'abord les anciennes clés du même type pour cet hôte."""
        pattern = host_pattern(host, port)
        key_line = key.export_public_key("openssh").decode("ascii").strip().split()
        algorithm, blob = key_line[0], key_line[1]
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            lines: list[str] = []
            if self.path.is_file():
                lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
            if replace:
                kept: list[str] = []
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2 and pattern in parts[0].split(",") and parts[1] == algorithm:
                        log.warning("Clé d'hôte remplacée pour %s (%s)", pattern, algorithm)
                        continue
                    kept.append(line)
                lines = kept
            lines.append(f"{pattern} {algorithm} {blob}")
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
            tmp.replace(self.path)

    def remove(self, pattern: str) -> int:
        """Retire toutes les clés d'un hôte ; renvoie le nombre de lignes supprimées."""
        with self._lock:
            if not self.path.is_file():
                return 0
            lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
            kept = [line for line in lines if not (line.split() and pattern in line.split()[0].split(","))]
            removed = len(lines) - len(kept)
            if removed:
                self.path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
            return removed
