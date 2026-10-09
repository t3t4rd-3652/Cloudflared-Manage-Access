"""Surveillance des services publiés : le nom d'hôte répond-il encore, vu d'Internet ?

La surveillance des tunnels ne voit pas un service arrêté derrière un tunnel en bonne santé : relevé sur un vrai
compte, quatre noms d'hôte renvoyaient 502 sans que rien ne l'ait signalé. Ici, chaque nom d'hôte HTTP d'un tunnel
actif est demandé comme le ferait un visiteur (`cma.core.hostprobe`), avec le service token du profil CMA quand il y
en a un, et le résultat est comparé au relevé précédent.

Gravité des réponses :
- « origin_down » (502, 504 : le service derrière le tunnel ne répond pas) : avertissement ;
- « no_connector » (1033) et « not_found » (nom absent du DNS public) : erreur ;
- « unreachable » (pas de réponse du tout) : inconnu, l'état précédent est gardé. C'est le plus souvent le réseau
  du poste qui est coupé, et tous les noms tomberaient d'un coup ;
- tout le reste (le service répond, page Access, vérification de navigateur, refus du token) : normal.
Les noms des tunnels inactifs ou hors ligne ne sont pas testés : la surveillance des tunnels en parle déjà.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import datetime

from cma.core.cfapi import IngressRule, Tunnel
from cma.core.hostprobe import HostProbe, probe_hostname_async
from cma.core.models import AuthMode, Config
from cma.core.secrets import SecretStore
from cma.i18n import tr

# Tests simultanés : chacun attend surtout la réponse de Cloudflare.
PROBE_CONCURRENCY = 8
# États qui méritent une alerte, et leur gravité ; « unreachable » n'en a pas (inconnu).
SEVERITY = {"origin_down": 1, "no_connector": 2, "not_found": 2}
WATCHED_TUNNEL_STATES = ("healthy", "degraded")

Token = tuple[str, str]
Prober = Callable[..., Awaitable[HostProbe]]


def severity(state: str) -> int:
    return SEVERITY.get(state, 0)


@dataclass(frozen=True)
class ServiceTarget:
    hostname: str
    path: str
    service: str
    tunnel_id: str
    tunnel_name: str

    @property
    def key(self) -> str:
        return self.hostname.lower() + self.path

    @property
    def label(self) -> str:
        return self.hostname + self.path

    @property
    def web(self) -> bool:
        """Service HTTP : la requête de test va jusqu'à lui (sinon, seulement jusqu'à Access)."""
        return self.service.lower().startswith(("http://", "https://"))

    @property
    def probe_path(self) -> str:
        # Un chemin d'ingress est une expression régulière : seul un chemin simple se demande tel quel.
        path = self.path.lstrip("^").rstrip("$")
        return path if path.startswith("/") and not any(c in path for c in "*+?[](){}|\\") else "/"


def targets_of(
    tunnels: Iterable[tuple[Tunnel, list[IngressRule]]], *, web_only: bool = True, active_only: bool = True
) -> list[ServiceTarget]:
    """Noms d'hôte à tester, sans les noms génériques. La surveillance ne prend que les services HTTP des tunnels
    en service ; « Tester tous les noms d'hôte » prend tout."""
    found: list[ServiceTarget] = []
    for tunnel, rules in tunnels:
        if active_only and tunnel.status not in WATCHED_TUNNEL_STATES:
            continue
        for rule in rules:
            target = ServiceTarget(rule.hostname, rule.path, rule.service, tunnel.id, tunnel.name)
            if rule.hostname and not rule.hostname.startswith("*.") and (target.web or not web_only):
                found.append(target)
    return found


def probe_token(config: Config, secrets: SecretStore, hostname: str) -> Token | None:
    """(Client ID, secret) du service token du profil CMA de ce nom d'hôte, si son secret est dans le coffre : la
    requête de test passe alors Access et atteint le service."""
    for profile in config.cloudflare_profiles:
        if profile.hostname.lower() != hostname.lower() or profile.auth != AuthMode.SERVICE_TOKEN:
            continue
        token = config.token(profile.token_id)
        secret = secrets.get(token.secret_key) if token is not None else None
        if token is not None and secret:
            return token.client_id, secret
    return None


async def probe_targets(
    targets: list[ServiceTarget],
    token_for: Callable[[str], Token | None],
    *,
    concurrency: int = PROBE_CONCURRENCY,
    prober: Prober | None = None,
) -> list[tuple[ServiceTarget, HostProbe]]:
    """Teste chaque cible (au plus `concurrency` à la fois), dans l'ordre reçu. Le token ne sert qu'aux services
    HTTP : pour SSH ou RDP, la requête s'arrête de toute façon à Access."""
    limit = asyncio.Semaphore(concurrency)
    run = prober or probe_hostname_async

    async def one(target: ServiceTarget) -> HostProbe:
        token = token_for(target.hostname) if target.web else None
        async with limit:
            return await run(target.hostname, token=token, path=target.probe_path)

    probes = await asyncio.gather(*(one(t) for t in targets))
    return list(zip(targets, probes, strict=True))


@dataclass(frozen=True)
class ServiceChange:
    target: ServiceTarget
    probe: HostProbe
    previous: str | None  # état au relevé précédent ; None si le nom n'avait pas encore été testé

    @property
    def recovered(self) -> bool:
        return severity(self.probe.state) == 0

    @property
    def level(self) -> str:
        return {0: "success", 1: "warning"}.get(severity(self.probe.state), "error")

    def message(self) -> str:
        if self.recovered:
            return tr("{host} répond de nouveau.").format(host=self.target.label)
        return self.probe.summary(self.target.label)


@dataclass(frozen=True)
class ServiceResult:
    target: ServiceTarget
    probe: HostProbe
    at: datetime


class ServiceWatch:
    """Résultats des derniers tests, et ce qui a changé d'un relevé à l'autre. Un service déjà en panne au premier
    relevé est signalé une fois ; un service qui reste en panne ne l'est plus."""

    def __init__(self) -> None:
        self._results: dict[str, ServiceResult] = {}

    def update(
        self, results: list[tuple[ServiceTarget, HostProbe]], at: datetime | None = None
    ) -> list[ServiceChange]:
        """Relevé complet : les noms absents (retirés, tunnel arrêté) sont oubliés."""
        changes = self.record(results, at)
        tested = {target.key for target, _probe in results}
        for key in list(self._results):
            if key not in tested:
                del self._results[key]
        return changes

    def record(
        self, results: list[tuple[ServiceTarget, HostProbe]], at: datetime | None = None
    ) -> list[ServiceChange]:
        """Ajoute des résultats (test d'un seul nom, ou de tous) sans oublier les autres."""
        when = at or datetime.now()
        changes: list[ServiceChange] = []
        for target, probe in results:
            known = self._results.get(target.key)
            if probe.state == "unreachable" and known is not None:
                # Inconnu : l'état précédent reste celui qu'on connaît, avec sa date.
                continue
            previous = known.probe.state if known is not None else None
            now, before = severity(probe.state), severity(previous) if previous is not None else 0
            if now > before or (now == 0 and before > 0 and probe.state != "unreachable"):
                changes.append(ServiceChange(target, probe, previous))
            self._results[target.key] = ServiceResult(target, probe, when)
        return changes

    def result(self, hostname: str, path: str = "") -> ServiceResult | None:
        return self._results.get(hostname.lower() + path)

    @property
    def troubled(self) -> list[ServiceResult]:
        """Services en panne au dernier relevé, du plus grave au moins grave."""
        bad = [r for r in self._results.values() if severity(r.probe.state) > 0]
        return sorted(bad, key=lambda r: (-severity(r.probe.state), r.target.label.lower()))

    def forget(self) -> None:
        self._results.clear()


def troubled_services_summary(results: list[ServiceResult]) -> str:
    """« app.exemple.fr ne répond plus », « 3 services en panne » ; vide si tout va bien."""
    if not results:
        return ""
    if len(results) == 1:
        return tr("{host} ne répond plus").format(host=results[0].target.label)
    return tr("{n} services en panne").format(n=len(results))
