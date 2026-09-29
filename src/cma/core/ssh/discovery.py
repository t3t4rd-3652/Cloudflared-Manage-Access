"""Découverte des ports en écoute sur un serveur SSH, sans rien installer dessus.

Le script ports-report est envoyé par l'entrée standard (`bash -s -- --json`) : le serveur exécute
toujours la version livrée avec l'application. Sans bash, on se rabat sur `ss -tln`.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import asyncssh

from cma.core.models import guess_service_type
from cma.i18n import tr
from cma.paths import ports_report_script

log = logging.getLogger(__name__)


class DiscoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class RemotePort:
    port: int
    bind: tuple[str, ...]
    service: str | None = None
    container: str | None = None
    scheme: str | None = None
    http_code: int | None = None
    final_url: str | None = None

    @property
    def forward_host(self) -> str:
        """Adresse à viser depuis le serveur : celle où le service écoute réellement."""
        if not self.bind or "0.0.0.0" in self.bind:
            return "127.0.0.1"
        if "::" in self.bind:
            return "::1"
        ipv4 = [b for b in self.bind if ":" not in b]
        return ipv4[0] if ipv4 else self.bind[0]

    @property
    def local_only(self) -> bool:
        return all(b in ("127.0.0.1", "::1") or b.startswith("127.") for b in self.bind)

    @property
    def display_name(self) -> str:
        return self.container or self.service or guess_service_type(port=self.port).label

    @property
    def web_label(self) -> str:
        if self.scheme and self.http_code:
            return f"{self.scheme.upper()} {self.http_code}"
        return "-"


@dataclass(frozen=True)
class DiscoveryResult:
    ports: list[RemotePort]
    script_version: str | None = None
    docker: str | None = None
    web_probe: bool = True
    mode: str = "script"
    warnings: list[str] = field(default_factory=list[str])


def parse_ndjson(text: str) -> DiscoveryResult:
    ports: list[RemotePort] = []
    meta: dict[str, Any] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            log.warning("Ligne ports-report ignorée : %s", line[:200])
            continue
        if "meta" in item:
            meta = item["meta"] or {}
            continue
        try:
            ports.append(
                RemotePort(
                    port=int(item["port"]),
                    bind=tuple(str(b) for b in item.get("bind") or ()),
                    service=item.get("service"),
                    container=item.get("container"),
                    scheme=item.get("scheme"),
                    http_code=item.get("http_code"),
                    final_url=item.get("final_url"),
                )
            )
        except (KeyError, TypeError, ValueError):
            log.warning("Ligne ports-report invalide : %s", line[:200])
    warnings: list[str] = []
    docker = meta.get("docker")
    if docker == "denied":
        warnings.append(
            tr(
                "Noms des conteneurs Docker indisponibles : installez le helper avec server/install.sh (voir docs/SERVEUR.md)."
            )
        )
    return DiscoveryResult(
        ports=sorted(ports, key=lambda p: p.port),
        script_version=meta.get("version"),
        docker=docker,
        web_probe=bool(meta.get("web_probe", True)),
        warnings=warnings,
    )


def parse_ss(text: str) -> list[RemotePort]:
    """Sortie de `ss -tln` : repli quand bash est absent. Même logique que le awk de ports-report."""
    binds: dict[int, list[str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] != "LISTEN":
            continue
        address = parts[3]
        host, _, port_text = address.rpartition(":")
        if not port_text.isdigit():
            continue
        host = host.strip("[]").split("%", 1)[0]
        if host in ("*", ""):
            host = "0.0.0.0"
        binds.setdefault(int(port_text), [])
        if host not in binds[int(port_text)]:
            binds[int(port_text)].append(host)
    return [RemotePort(port=port, bind=tuple(hosts)) for port, hosts in sorted(binds.items())]


async def discover(
    conn: asyncssh.SSHClientConnection, *, timeout: float = 90, probe_web: bool = True
) -> DiscoveryResult:
    args = "--json" if probe_web else "--json --no-web"
    script = ports_report_script()
    try:
        async with conn.create_process(f"bash -s -- {args}") as process:
            try:
                process.stdin.write(script)
                process.stdin.write_eof()
            except (BrokenPipeError, ConnectionResetError, asyncssh.Error):
                # bash absent : le serveur a fermé l'entrée avant de lire le script.
                pass
            result = await process.wait(check=False, timeout=timeout)
    except asyncssh.TimeoutError as exc:
        raise DiscoveryError(tr("La découverte des ports a dépassé {s} s.").format(s=int(timeout))) from exc
    stdout = str(result.stdout or "")
    stderr = str(result.stderr or "").strip()
    if result.exit_status == 0 and '"v":2' in stdout:
        return parse_ndjson(stdout)
    if result.exit_status == 127 or "not found" in stderr.lower():
        fallback = await conn.run("ss -tlnH 2>/dev/null || ss -tln", check=False, timeout=30)
        if fallback.exit_status == 0:
            return DiscoveryResult(
                ports=parse_ss(str(fallback.stdout or "")),
                mode="ss",
                web_probe=False,
                warnings=[tr("bash est absent du serveur : liste simplifiée, sans services ni statut HTTP.")],
            )
        raise DiscoveryError(
            tr("Ni bash ni ss ne sont disponibles : le serveur n'est pas un Linux compatible.")
        )
    raise DiscoveryError(
        tr("ports-report a échoué (code {code}) : {error}").format(
            code=result.exit_status, error=stderr[-500:] or "-"
        )
    )
