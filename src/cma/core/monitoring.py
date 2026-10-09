"""Suites d'un relevé de surveillance, communes à CMA ouvert et à la tâche planifiée : journal de disponibilité,
sourdine, alertes vers l'extérieur.

- Chaque relevé alimente le journal (`AvailabilityLog`) : un test par objet, et l'ouverture ou la fermeture des
  incidents. La tâche planifiée s'en sert comme mémoire : elle ne prévient qu'à un changement.
- Un objet en sourdine (maintenance) est toujours relevé et journalisé, mais ne déclenche ni notification ni alerte.
  La sourdine d'un tunnel couvre aussi ses noms d'hôte.
- Les alertes partent vers chaque canal actif ; un canal en échec n'empêche pas les autres.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cma.core.alerts import Alert, AlertError, secret_key, send_alert
from cma.core.availability import AvailabilityLog
from cma.core.cfapi import Tunnel
from cma.core.hostprobe import HostProbe
from cma.core.models import Config
from cma.core.secrets import SecretStore
from cma.core.servicewatch import ServiceTarget
from cma.core.servicewatch import severity as service_severity
from cma.core.tunnelwatch import severity as tunnel_severity
from cma.i18n import tr

Sender = Callable[[str, str, Alert], None]


def tunnel_key(tunnel_id: str) -> str:
    return f"tunnel:{tunnel_id}"


def service_key(target: ServiceTarget) -> str:
    return f"service:{target.key}"


def muted_until(config: Config, key: str, now: datetime | None = None) -> datetime | None:
    value = config.settings.muted.get(key)
    if not value:
        return None
    try:
        until = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None
    return until if until > (now or datetime.now(UTC)) else None


def is_muted(config: Config, key: str, tunnel_id: str | None = None, now: datetime | None = None) -> bool:
    """Objet en sourdine, lui ou (pour un nom d'hôte) son tunnel."""
    if muted_until(config, key, now) is not None:
        return True
    return tunnel_id is not None and muted_until(config, tunnel_key(tunnel_id), now) is not None


def mute(config: Config, key: str, duration: timedelta | None, now: datetime | None = None) -> None:
    """Met en sourdine pour `duration` ; None retire la sourdine. Les sourdines échues sont nettoyées."""
    moment = now or datetime.now(UTC)
    kept = {k: v for k, v in config.settings.muted.items() if muted_until(config, k, moment) is not None}
    if duration is None:
        kept.pop(key, None)
    else:
        kept[key] = (moment + duration).strftime("%Y-%m-%dT%H:%M:%SZ")
    config.settings.muted = kept


@dataclass(frozen=True)
class Event:
    """Changement à annoncer : panne (nouvel incident) ou retour."""

    key: str
    label: str
    level: str  # error, warning, success
    text: str
    muted: bool
    recovered: bool


def record_tunnels(
    log: AvailabilityLog, config: Config, tunnels: list[Tunnel], now: datetime | None = None
) -> list[Event]:
    """Relevé des tunnels → journal ; renvoie les incidents ouverts et fermés. Un tunnel inactif n'est pas suivi."""
    events: list[Event] = []
    for tunnel in tunnels:
        if tunnel.status == "inactive":
            continue
        key = tunnel_key(tunnel.id)
        level = tunnel_severity(tunnel.status)
        log.record_check(key, tunnel.name, level == 0, None, now)
        muted = is_muted(config, key, now=now)
        if level > 0 and log.start("tunnel", key, tunnel.name, tunnel.status, now):
            text = (
                tr("Le tunnel « {name} » est hors ligne : plus aucun connecteur ne le relie à Cloudflare.")
                if tunnel.status == "down"
                else tr(
                    "Le tunnel « {name} » est dégradé : ses connecteurs n'ont pas toutes leurs connexions."
                )
            ).format(name=tunnel.name)
            events.append(Event(key, tunnel.name, "error" if level > 1 else "warning", text, muted, False))
        elif level == 0 and tunnel.status == "healthy" and log.end("tunnel", key, now) is not None:
            text = tr("Le tunnel « {name} » est de nouveau en ligne.").format(name=tunnel.name)
            events.append(Event(key, tunnel.name, "success", text, muted, True))
    return events


def record_services(
    log: AvailabilityLog,
    config: Config,
    results: list[tuple[ServiceTarget, HostProbe]],
    now: datetime | None = None,
) -> list[Event]:
    """Relevé des services → journal ; « sans réponse » (réseau du poste) n'est ni compté ni annoncé."""
    events: list[Event] = []
    for target, probe in results:
        if probe.state == "unreachable":
            continue
        key = service_key(target)
        level = service_severity(probe.state)
        log.record_check(key, target.label, level == 0, probe.ms, now)
        muted = is_muted(config, key, target.tunnel_id, now)
        if level > 0 and log.start("service", key, target.label, probe.state, now):
            text = probe.summary(target.label)
            events.append(Event(key, target.label, "error" if level > 1 else "warning", text, muted, False))
        elif level == 0 and log.end("service", key, now) is not None:
            text = tr("{host} répond de nouveau.").format(host=target.label)
            events.append(Event(key, target.label, "success", text, muted, True))
    return events


def channels(config: Config, secrets: SecretStore) -> list[tuple[str, str, str, bool]]:
    """(nom, type, adresse, retours aussi ?) des canaux actifs dont l'adresse est dans le coffre."""
    found: list[tuple[str, str, str, bool]] = []
    for channel in config.settings.alert_channels:
        url = secrets.get(secret_key(channel.id)) if channel.enabled else None
        if url:
            found.append((channel.name, channel.kind, url, channel.recoveries))
    return found


def send_events(
    events: list[Event], config: Config, secrets: SecretStore, sender: Sender | None = None
) -> list[str]:
    """Envoie chaque événement non mis en sourdine à chaque canal ; renvoie les erreurs (« canal : raison »)."""
    errors: list[str] = []
    send = sender or send_alert
    targets = channels(config, secrets)
    for event in events:
        if event.muted:
            continue
        title = (
            tr("CMA — {name} rétabli").format(name=event.label)
            if event.recovered
            else tr("CMA — panne : {name}").format(name=event.label)
        )
        alert = Alert(title, event.text, event.level)
        for name, kind, url, recoveries in targets:
            if event.recovered and not recoveries:
                continue
            try:
                send(kind, url, alert)
            except AlertError as exc:
                errors.append(f"{name} : {exc}")
    return errors
