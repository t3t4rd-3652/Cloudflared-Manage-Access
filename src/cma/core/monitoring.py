"""Suites d'un relevé de surveillance, communes à CMA ouvert et à la tâche planifiée : journal de disponibilité,
sourdine, alertes vers l'extérieur.

- Chaque relevé alimente le journal (`AvailabilityLog`) : un test par objet, et l'ouverture ou la fermeture des
  incidents. La tâche planifiée s'en sert comme mémoire : elle ne prévient qu'à un changement.
- Un objet en sourdine (maintenance) est toujours relevé et journalisé, mais ne déclenche ni notification ni alerte.
  La sourdine d'un tunnel couvre aussi ses noms d'hôte.
- Une maintenance hebdomadaire (`MaintenanceWindow`) met en sourdine, pendant son créneau, un objet ou tout le compte.
- Les alertes partent vers chaque canal actif ; un canal en échec n'empêche pas les autres.
- Une panne qui dure est rappelée toutes les N heures, et le résumé hebdomadaire part le lundi (état des envois dans
  `alert_state.json`, ADR 0002) : mêmes règles CMA ouvert et tâche planifiée.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo

from cma.core.alerts import Alert, AlertError, elapsed_text, secret_key, send_alert
from cma.core.alertstate import AlertState
from cma.core.availability import AvailabilityLog
from cma.core.cfapi import Tunnel
from cma.core.digest import build_digest, digest_due, week_id
from cma.core.hostprobe import HostProbe
from cma.core.models import Config, MaintenanceWindow
from cma.core.secrets import SecretStore
from cma.core.servicewatch import ServiceTarget
from cma.core.servicewatch import severity as service_severity
from cma.core.tunnelwatch import severity as tunnel_severity
from cma.i18n import tr

logger = logging.getLogger(__name__)

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


def _minutes(clock: str) -> int:
    hours, minutes = clock.split(":")
    return int(hours) * 60 + int(minutes)


def window_active(window: MaintenanceWindow, local: datetime) -> bool:
    """Le créneau couvre-t-il cet instant (heure locale) ? Un créneau dont la fin n'est pas après le début passe
    minuit : le soir de son jour, puis le matin du jour suivant."""
    start, end = _minutes(window.start), _minutes(window.end)
    minute = local.hour * 60 + local.minute
    today = local.weekday()
    if start < end:
        return today == window.weekday and start <= minute < end
    return (today == window.weekday and minute >= start) or (
        today == (window.weekday + 1) % 7 and minute < end
    )


def maintenance_window(
    config: Config,
    key: str,
    tunnel_id: str | None = None,
    now: datetime | None = None,
    tz: tzinfo | None = None,
) -> MaintenanceWindow | None:
    """Maintenance en cours qui vise l'objet, son tunnel ou tout le compte ; `tz` : fuseau (local par défaut)."""
    windows = config.settings.maintenance_windows
    if not windows:
        return None
    local = (now or datetime.now(UTC)).astimezone(tz)
    tunnel = tunnel_key(tunnel_id) if tunnel_id is not None else None
    for window in windows:
        if window.target in ("", key, tunnel) and window_active(window, local):
            return window
    return None


def is_muted(
    config: Config,
    key: str,
    tunnel_id: str | None = None,
    now: datetime | None = None,
    tz: tzinfo | None = None,
) -> bool:
    """Objet en sourdine ou en maintenance, lui ou (pour un nom d'hôte) son tunnel, ou tout le compte."""
    if muted_until(config, key, now) is not None:
        return True
    if tunnel_id is not None and muted_until(config, tunnel_key(tunnel_id), now) is not None:
        return True
    return maintenance_window(config, key, tunnel_id, now, tz) is not None


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
    """Changement à annoncer : panne (nouvel incident), retour, ou rappel d'une panne qui dure."""

    key: str
    label: str
    level: str  # error, warning, success
    text: str
    muted: bool
    recovered: bool
    reminder: bool = False


def _close_unwatched(log: AvailabilityLog, kind: str, watched: set[str], now: datetime | None) -> None:
    """Clôt, sans l'annoncer, l'incident ouvert de chaque objet qui n'est plus relevé : sinon il resterait ouvert
    pour toujours, avec un rappel toutes les N heures et une ligne « En cours » dans chaque résumé."""
    for incident in [i for i in log.incidents if i.open and i.kind == kind and i.key not in watched]:
        log.end(kind, incident.key, now)


def record_tunnels(
    log: AvailabilityLog,
    config: Config,
    tunnels: list[Tunnel],
    now: datetime | None = None,
    *,
    complete: bool = True,
) -> list[Event]:
    """Relevé des tunnels → journal ; renvoie les incidents ouverts et fermés. Un tunnel inactif n'est pas suivi.

    `complete` : le relevé a réussi et liste tous les tunnels du compte. L'incident ouvert d'un tunnel devenu
    inactif (arrêté pour de bon) ou supprimé est alors clos sans événement ; un relevé en échec (`complete=False`)
    ne ferme rien."""
    events: list[Event] = []
    watched: set[str] = set()
    for tunnel in tunnels:
        if tunnel.status == "inactive":
            continue
        key = tunnel_key(tunnel.id)
        watched.add(key)
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
    if complete:
        _close_unwatched(log, "tunnel", watched, now)
    return events


def record_services(
    log: AvailabilityLog,
    config: Config,
    results: list[tuple[ServiceTarget, HostProbe]],
    now: datetime | None = None,
    *,
    complete: bool | None = None,
) -> list[Event]:
    """Relevé des services → journal ; « sans réponse » (réseau du poste) n'est ni compté ni annoncé.

    `complete` : le relevé a réussi. L'incident ouvert d'un service absent d'un relevé réussi (nom d'hôte retiré,
    tunnel supprimé ou plus en service) est clos sans événement. Un service « sans réponse » reste suivi : son état
    connu ne change pas. Par défaut (`None`), seul un relevé non vide compte comme réussi : une liste vide peut
    venir d'un échec ou d'un relevé non demandé (tâche planifiée), jamais de quoi tout fermer."""
    events: list[Event] = []
    watched: set[str] = set()
    for target, probe in results:
        key = service_key(target)
        watched.add(key)
        if probe.state == "unreachable":
            continue
        level = service_severity(probe.state)
        log.record_check(key, target.label, level == 0, probe.ms, now)
        muted = is_muted(config, key, target.tunnel_id, now)
        if level > 0 and log.start("service", key, target.label, probe.state, now):
            text = probe.summary(target.label)
            events.append(Event(key, target.label, "error" if level > 1 else "warning", text, muted, False))
        elif level == 0 and log.end("service", key, now) is not None:
            text = tr("{host} répond de nouveau.").format(host=target.label)
            events.append(Event(key, target.label, "success", text, muted, True))
    if complete is None:
        complete = bool(results)
    if complete:
        _close_unwatched(log, "service", watched, now)
    return events


def channels(config: Config, secrets: SecretStore) -> list[tuple[str, str, str, bool]]:
    """(nom, type, adresse, retours aussi ?) des canaux actifs dont l'adresse est dans le coffre."""
    found: list[tuple[str, str, str, bool]] = []
    for channel in config.settings.alert_channels:
        url = secrets.get(secret_key(channel.id)) if channel.enabled else None
        if url:
            found.append((channel.name, channel.kind, url, channel.recoveries))
    return found


def event_alert(event: Event) -> Alert:
    """L'alerte d'un événement : le titre dit s'il s'agit d'une panne, d'un retour ou d'un rappel."""
    if event.recovered:
        title = tr("CMA — {name} rétabli").format(name=event.label)
    elif event.reminder:
        title = tr("CMA — toujours en panne : {name}").format(name=event.label)
    else:
        title = tr("CMA — panne : {name}").format(name=event.label)
    return Alert(title, event.text, event.level)


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
        alert = event_alert(event)
        for name, kind, url, recoveries in targets:
            if event.recovered and not recoveries:
                continue
            try:
                send(kind, url, alert)
            except AlertError as exc:
                errors.append(f"{name} : {exc}")
    return errors


def broadcast(
    alert: Alert, config: Config, secrets: SecretStore, sender: Sender | None = None
) -> tuple[int, list[str]]:
    """Envoie l'alerte à chaque canal actif : (nombre de canaux atteints, erreurs « canal : raison »)."""
    send = sender or send_alert
    reached = 0
    errors: list[str] = []
    for name, kind, url, _recoveries in channels(config, secrets):
        try:
            send(kind, url, alert)
        except AlertError as exc:
            errors.append(f"{name} : {exc}")
        else:
            reached += 1
    return reached, errors


# --- Rappels des pannes qui durent et résumé hebdomadaire ---------------------------------------------------------


def reminder_events(
    log: AvailabilityLog,
    config: Config,
    state: AlertState,
    now: datetime | None = None,
    tz: tzinfo | None = None,
    tunnel_of: Mapping[str, str] | None = None,
) -> list[Event]:
    """Rappels dus : incidents encore ouverts depuis plus de N heures (`alert_repeat_hours`) dont le dernier rappel,
    ou à défaut le début, date de plus de N heures. Rien pour un objet en sourdine ou en maintenance (un nom d'hôte
    suit son tunnel : `tunnel_of` donne l'identifiant du tunnel de chaque clé de service). L'état n'est pas modifié
    ici : il l'est quand l'envoi a réussi (`send_reminders`)."""
    moment = now or datetime.now(UTC)
    opened = [i for i in log.incidents if i.open]
    state.keep_only(i.key for i in opened)
    hours = config.settings.alert_repeat_hours
    if hours <= 0:
        return []
    period = timedelta(hours=hours)
    events: list[Event] = []
    for incident in opened:
        elapsed = incident.duration(moment)
        last = state.last_reminder(incident.key)
        if (moment - last if last is not None else elapsed) < period:
            continue
        if is_muted(config, incident.key, (tunnel_of or {}).get(incident.key), moment, tz):
            continue
        rank = (tunnel_severity if incident.kind == "tunnel" else service_severity)(incident.state)
        text = tr("{name} est toujours en panne depuis {duration}.").format(
            name=incident.label, duration=elapsed_text(elapsed)
        )
        events.append(
            Event(incident.key, incident.label, "error" if rank > 1 else "warning", text, False, False, True)
        )
    return events


def send_reminders(
    events: list[Event],
    config: Config,
    secrets: SecretStore,
    state: AlertState,
    now: datetime | None = None,
    sender: Sender | None = None,
) -> list[str]:
    """Envoie les rappels ; l'état note la date de ceux qu'au moins un canal a reçus (les autres repartiront)."""
    moment = now or datetime.now(UTC)
    errors: list[str] = []
    for event in events:
        reached, failed = broadcast(event_alert(event), config, secrets, sender)
        errors += failed
        if reached:
            state.mark_reminder(event.key, moment)
    return errors


@dataclass
class FollowUp:
    """Ce qu'un relevé laisse à envoyer en plus des pannes et des retours : rappels et résumé de la semaine."""

    state: AlertState
    reminders: list[Event]
    digest: Alert | None = None
    week: str = ""

    @property
    def empty(self) -> bool:
        return not self.reminders and self.digest is None


def prepare_follow_up(
    log: AvailabilityLog,
    config: Config,
    state: AlertState,
    *,
    check_digest: bool,
    now: datetime | None = None,
    tz: tzinfo | None = None,
    tunnel_of: Mapping[str, str] | None = None,
) -> FollowUp:
    """Rappels dus et, si `check_digest` et que le résumé est dû cette semaine, son contenu. Rapide et sans réseau :
    la fenêtre peut l'appeler sur son fil, puis envoyer (`deliver_follow_up`) dans un autre."""
    moment = now or datetime.now(UTC)
    plan = FollowUp(state, reminder_events(log, config, state, moment, tz, tunnel_of))
    if check_digest and digest_due(config, state, moment, tz):
        plan.digest = build_digest(log, config, moment, tz)
        plan.week = week_id(moment.astimezone(tz))
    return plan


def deliver_follow_up(
    plan: FollowUp,
    config: Config,
    secrets: SecretStore,
    now: datetime | None = None,
    sender: Sender | None = None,
) -> list[str]:
    """Envoie rappels et résumé, note ce qui est parti dans `alert_state.json` ; renvoie les erreurs."""
    errors = send_reminders(plan.reminders, config, secrets, plan.state, now, sender)
    if plan.digest is not None:
        reached, failed = broadcast(plan.digest, config, secrets, sender)
        errors += failed
        if reached:
            plan.state.mark_digest(plan.week)
    try:
        plan.state.save()
    except OSError as exc:
        logger.warning("État des alertes non enregistré : %s", exc)
    return errors
