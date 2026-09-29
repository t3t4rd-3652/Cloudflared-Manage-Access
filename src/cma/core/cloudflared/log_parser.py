"""Analyse des lignes de journal de `cloudflared access tcp`.

Les motifs viennent de messages réels capturés avec cloudflared 2026.7.2 (Windows, en français) :
  INF Start Websocket listener host=127.0.0.1:38301
      (écrit AVANT l'ouverture du port : l'écoute doit être confirmée à part)
  ERR Error on Websocket listener error="failed to start forwarding server: listen tcp …: bind: Une seule utilisation…"
  ERR failed to connect to origin error="dial tcp: lookup x.invalid: no such host" originURL=…
  ERR failed to connect to origin error="dial tcp 127.0.0.1:9: connectex: …"   (proxy injoignable)
  ERR failed to connect to origin error="websocket: bad handshake" originURL=…
  Incorrect Usage: flag provided but not defined: -nope                        (code de sortie 0 !)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from cma.core.events import Level
from cma.i18n import tr

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(?P<level>DBG|INF|WRN|ERR|FTL)\s+(?P<msg>.*)$"
)
LEVELS: dict[str, Level] = {"DBG": "DEBUG", "INF": "INFO", "WRN": "WARNING", "ERR": "ERROR", "FTL": "ERROR"}
URL_RE = re.compile(r"https://\S+")


class LogKind(StrEnum):
    LISTENER_STARTING = "listener_starting"
    PORT_IN_USE = "port_in_use"
    PORT_FORBIDDEN = "port_forbidden"
    LISTEN_FAILED = "listen_failed"
    USAGE_ERROR = "usage_error"
    AUTH_DENIED = "auth_denied"
    AUTH_REQUIRED = "auth_required"
    AUTH_OK = "auth_ok"
    DNS_ERROR = "dns_error"
    PROXY_ERROR = "proxy_error"
    ORIGIN_UNREACHABLE = "origin_unreachable"
    TLS_ERROR = "tls_error"
    OTHER = "other"


FATAL_KINDS = {LogKind.PORT_IN_USE, LogKind.PORT_FORBIDDEN, LogKind.LISTEN_FAILED, LogKind.USAGE_ERROR}
CONNECTION_ERROR_KINDS = {
    LogKind.AUTH_DENIED,
    LogKind.DNS_ERROR,
    LogKind.PROXY_ERROR,
    LogKind.ORIGIN_UNREACHABLE,
    LogKind.TLS_ERROR,
}

_PORT_IN_USE = (
    "address already in use",
    "only one usage of each socket address",
    "une seule utilisation de chaque adresse",
)
_PORT_FORBIDDEN = (
    "forbidden by its access permissions",
    "interdite par ses autorisations",
    "permission denied",
)


@dataclass(frozen=True)
class ParsedLine:
    raw: str
    level: Level
    kind: LogKind
    hint: str | None = None
    url: str | None = None

    @property
    def fatal(self) -> bool:
        return self.kind in FATAL_KINDS

    @property
    def connection_error(self) -> bool:
        return self.kind in CONNECTION_ERROR_KINDS


def parse_line(line: str, *, proxy_host_port: str | None = None) -> ParsedLine:
    raw = line.rstrip("\r\n")
    match = LINE_RE.match(raw)
    level: Level = LEVELS[match.group("level")] if match else "DEBUG"
    text = (match.group("msg") if match else raw).strip()
    lowered = text.lower()

    def result(
        kind: LogKind, hint: str | None = None, forced_level: Level | None = None, url: str | None = None
    ) -> ParsedLine:
        return ParsedLine(raw=raw, level=forced_level or level, kind=kind, hint=hint, url=url)

    if "start websocket listener" in lowered:
        return result(LogKind.LISTENER_STARTING)

    if "failed to start forwarding server" in lowered or "error on websocket listener" in lowered:
        if any(marker in lowered for marker in _PORT_IN_USE):
            return result(
                LogKind.PORT_IN_USE, tr("Le port local est déjà utilisé par un autre programme."), "ERROR"
            )
        if any(marker in lowered for marker in _PORT_FORBIDDEN):
            return result(
                LogKind.PORT_FORBIDDEN,
                tr(
                    "Le port local est réservé par le système (plage Hyper-V ou WSL). Choisissez-en un autre."
                ),
                "ERROR",
            )
        return result(LogKind.LISTEN_FAILED, tr("cloudflared n'a pas pu ouvrir le port local."), "ERROR")

    if lowered.startswith("incorrect usage"):
        return result(
            LogKind.USAGE_ERROR,
            tr("cloudflared a refusé la commande : {detail}").format(detail=text),
            "ERROR",
        )

    if "bad handshake" in lowered:
        return result(
            LogKind.AUTH_DENIED,
            tr(
                "Cloudflare Access a refusé la connexion : token invalide ou non autorisé, "
                "ou application qui n'est pas protégée par Access."
            ),
        )

    if (
        proxy_host_port
        and proxy_host_port.lower() in lowered
        and ("dial tcp" in lowered or "no such host" in lowered)
    ):
        return result(
            LogKind.PROXY_ERROR, tr("Le proxy {proxy} ne répond pas.").format(proxy=proxy_host_port)
        )

    if "no such host" in lowered:
        return result(LogKind.DNS_ERROR, tr("Le hostname est introuvable (DNS). Vérifiez son orthographe."))

    if "x509" in lowered or "tls: " in lowered or "certificate" in lowered:
        return result(
            LogKind.TLS_ERROR,
            tr(
                "Erreur de certificat TLS. Un proxy d'entreprise qui inspecte le trafic peut en être la cause."
            ),
        )

    if "failed to connect to origin" in lowered or "dial tcp" in lowered:
        return result(
            LogKind.ORIGIN_UNREACHABLE,
            tr("Impossible de joindre Cloudflare : réseau, pare-feu ou proxy à vérifier."),
        )

    if "browser window should have opened" in lowered or "please open the following url" in lowered:
        url_match = URL_RE.search(text)
        return result(
            LogKind.AUTH_REQUIRED,
            tr("Authentification Cloudflare Access requise : terminez-la dans le navigateur."),
            "WARNING",
            url_match.group(0) if url_match else None,
        )

    if "successfully fetched your token" in lowered:
        return result(LogKind.AUTH_OK, tr("Authentification Cloudflare Access réussie."))

    return result(LogKind.OTHER)
