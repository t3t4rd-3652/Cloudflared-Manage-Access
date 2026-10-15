"""Suites d'un relevé de surveillance, communes à CMA ouvert et à la tâche planifiée : journal de disponibilité,
sourdine, alertes vers l'extérieur.

- Chaque relevé alimente le journal (`AvailabilityLog`) : un test par objet, et l'ouverture ou la fermeture des
  incidents. La tâche planifiée s'en sert comme mémoire : elle ne prévient qu'à un changement.
- Un objet en sourdine (maintenance) est toujours relevé et journalisé, mais ne déclenche ni notification ni alerte.
  La sourdine d'un tunnel couvre aussi ses noms d'hôte.
- Une maintenance hebdomadaire (`MaintenanceWindow`) met en sourdine, pendant son créneau, un objet ou tout le compte.
- Une surveillance coupée (`watch_tunnels`, `watch_services`) clôt les incidents ouverts de son type, sans événement
  (`close_unwatched_kinds`) ; `digest.watched` reste le filet des rappels.
- Les alertes partent vers chaque canal actif ; un canal en échec n'empêche pas les autres.
- Une panne qui dure est rappelée toutes les N heures, et le résumé hebdomadaire part le lundi (état des envois dans
  `alert_state.json`, ADR 0002) : mêmes règles CMA ouvert et tâche planifiée.
- Un objet qui passe sous son objectif de disponibilité sur 30 jours (`cma.core.slo`) est annoncé une fois, puis son
  retour au-dessus ; ces annonces suivent les rappels (nature « slo » dans le journal des envois).
- Chaque envoi vers un canal, réussi ou non, est noté dans `alert_log.json` (`cma.core.alertlog`, ADR 0002) quand
  l'appelant donne un `journal` : jamais l'adresse du canal.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, tzinfo

from cma.core.alertlog import AlertLog, send_and_note
from cma.core.alerts import Alert, elapsed_text, secret_key, send_alert
from cma.core.alertstate import AlertState
from cma.core.availability import AvailabilityLog
from cma.core.cfapi import Tunnel
from cma.core.digest import build_digest, digest_due, watched, week_id
from cma.core.hostprobe import HostProbe
from cma.core.models import Config, MaintenanceWindow
from cma.core.secrets import SecretStore
from cma.core.servicewatch import ServiceTarget
from cma.core.servicewatch import severity as service_severity
from cma.core.slo import Crossing, crossings, has_targets, percent_text, target_text
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


def window_end(window: MaintenanceWindow, local: datetime) -> datetime:
    """Fin de l'occurrence du créneau qui couvre `local` (heure locale) : à n'appeler que si `window_active`. Un
    créneau qui passe minuit finit le lendemain de son jour, donc encore à venir le soir, déjà là le matin."""
    hours, minutes = window.end.split(":")
    end = local.replace(hour=int(hours), minute=int(minutes), second=0, microsecond=0)
    if _minutes(window.start) >= _minutes(window.end) and local.weekday() == window.weekday:
        end += timedelta(days=1)
    return end


def maintenance_until(
    config: Config,
    key: str,
    tunnel_id: str | None = None,
    now: datetime | None = None,
    tz: tzinfo | None = None,
) -> tuple[datetime, MaintenanceWindow] | None:
    """(fin, fenêtre) de la maintenance en cours qui vise l'objet, son tunnel ou tout le compte ; None hors fenêtre.
    La fin est une heure locale (`tz`, par défaut celle du poste)."""
    moment = now or datetime.now(UTC)
    window = maintenance_window(config, key, tunnel_id, moment, tz)
    if window is None:
        return None
    return window_end(window, moment.astimezone(tz)), window


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
    """Changement à annoncer : panne (nouvel incident), retour, rappel d'une panne qui dure, ou franchissement de
    l'objectif de disponibilité (`slo` : `recovered` dit alors si l'objet est remonté au-dessus)."""

    key: str
    label: str
    level: str  # error, warning, success
    text: str
    muted: bool
    recovered: bool
    reminder: bool = False
    slo: bool = False


def _close_unwatched(log: AvailabilityLog, kind: str, watched: set[str], now: datetime | None) -> None:
    """Clôt, sans l'annoncer, l'incident ouvert de chaque objet qui n'est plus relevé : sinon il resterait ouvert
    pour toujours, avec un rappel toutes les N heures et une ligne « En cours » dans chaque résumé."""
    for incident in [i for i in log.incidents if i.open and i.kind == kind and i.key not in watched]:
        log.end(kind, incident.key, now)


def close_unwatched_kinds(log: AvailabilityLog, config: Config, now: datetime | None = None) -> int:
    """Clôt, sans événement ni notification, les incidents ouverts d'un type dont la surveillance est coupée
    (`watch_tunnels`, `watch_services`) : rien ne les clôturerait plus, et ils resteraient « en cours » pour toujours.
    Renvoie le nombre d'incidents clos ; l'appelant enregistre le journal s'il est non nul. Une coupure brève clôt
    donc un incident qui sera rouvert au relevé suivant si l'objet est toujours en panne."""
    closed = 0
    for incident in [i for i in log.incidents if i.open and not watched(config, i.kind)]:
        if log.end(incident.kind, incident.key, now) is not None:
            closed += 1
    return closed


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
    """L'alerte d'un événement : le titre dit s'il s'agit d'une panne, d'un retour, d'un rappel ou de l'objectif."""
    if event.slo:
        title = (
            tr("CMA — objectif retrouvé : {name}")
            if event.recovered
            else tr("CMA — objectif manqué : {name}")
        ).format(name=event.label)
    elif event.recovered:
        title = tr("CMA — {name} rétabli").format(name=event.label)
    elif event.reminder:
        title = tr("CMA — toujours en panne : {name}").format(name=event.label)
    else:
        title = tr("CMA — panne : {name}").format(name=event.label)
    return Alert(title, event.text, event.level)


def event_nature(event: Event) -> str:
    """Nature d'un envoi dans le journal (`cma.core.alertlog`) : objectif, retour, rappel ou panne."""
    if event.slo:
        return "slo"
    return "recovery" if event.recovered else "reminder" if event.reminder else "alert"


def send_events(
    events: list[Event],
    config: Config,
    secrets: SecretStore,
    sender: Sender | None = None,
    journal: AlertLog | None = None,
) -> list[str]:
    """Envoie chaque événement non mis en sourdine à chaque canal ; renvoie les erreurs (« canal : raison »).
    Chaque envoi, réussi ou non, est noté dans `journal` s'il est donné."""
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
            failure = send_and_note(
                journal, send, name, kind, url, alert, nature=event_nature(event), subject=event.label
            )
            if failure is not None:
                errors.append(f"{name} : {failure}")
    return errors


def broadcast(
    alert: Alert,
    config: Config,
    secrets: SecretStore,
    sender: Sender | None = None,
    journal: AlertLog | None = None,
    *,
    nature: str = "alert",
    subject: str = "",
) -> tuple[int, list[str]]:
    """Envoie l'alerte à chaque canal actif : (nombre de canaux atteints, erreurs « canal : raison »)."""
    send = sender or send_alert
    reached = 0
    errors: list[str] = []
    for name, kind, url, _recoveries in channels(config, secrets):
        failure = send_and_note(journal, send, name, kind, url, alert, nature=nature, subject=subject)
        if failure is None:
            reached += 1
        else:
            errors.append(f"{name} : {failure}")
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
        if not watched(config, incident.kind):
            continue
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
    journal: AlertLog | None = None,
) -> list[str]:
    """Envoie les rappels ; l'état note la date de ceux qu'au moins un canal a reçus (les autres repartiront)."""
    moment = now or datetime.now(UTC)
    errors: list[str] = []
    for event in events:
        reached, failed = broadcast(
            event_alert(event), config, secrets, sender, journal, nature="reminder", subject=event.label
        )
        errors += failed
        if reached:
            state.mark_reminder(event.key, moment)
    return errors


def slo_events(
    log: AvailabilityLog,
    config: Config,
    state: AlertState,
    now: datetime | None = None,
    tz: tzinfo | None = None,
    tunnel_of: Mapping[str, str] | None = None,
) -> list[Event]:
    """Franchissements de l'objectif de disponibilité dus (`cma.core.slo.crossings`). Rien pour un objet en sourdine
    ou en maintenance (un nom d'hôte suit son tunnel : `tunnel_of`). L'état n'est pas modifié ici : il l'est quand
    l'envoi a réussi (`send_slo`)."""
    moment = now or datetime.now(UTC)
    if not has_targets(config):
        state.keep_only_slo(
            ()
        )  # plus d'objectif : un futur passage sous un objectif posé plus tard repart à zéro
        return []

    def muted(key: str) -> bool:
        return is_muted(config, key, (tunnel_of or {}).get(key), moment, tz)

    return [_slo_event(c) for c in crossings(log, config, state, moment, tz, muted)]


def _slo_event(crossing: Crossing) -> Event:
    values = {
        "name": crossing.label,
        "uptime": percent_text(crossing.uptime),
        "target": target_text(crossing.target),
    }
    if crossing.recovered:
        text = tr(
            "{name} : disponibilité de {uptime} sur 30 jours, de nouveau au-dessus de l'objectif ({target})."
        )
        return Event(crossing.key, crossing.label, "success", text.format(**values), False, True, slo=True)
    text = tr("{name} : disponibilité de {uptime} sur 30 jours, sous l'objectif ({target}).")
    return Event(crossing.key, crossing.label, "warning", text.format(**values), False, False, slo=True)


def send_slo(
    events: list[Event],
    config: Config,
    secrets: SecretStore,
    state: AlertState,
    now: datetime | None = None,
    sender: Sender | None = None,
    journal: AlertLog | None = None,
) -> list[str]:
    """Envoie les franchissements aux canaux (le retour seulement à ceux qui le veulent) ; l'état note ce qui est
    parti : un passage sous l'objectif quand au moins un canal l'a reçu (sinon il repart au relevé suivant), un
    retour dans tous les cas (sans quoi l'objet resterait « annoncé » et son prochain passage dessous muet)."""
    moment = now or datetime.now(UTC)
    send = sender or send_alert
    targets = channels(config, secrets)
    errors: list[str] = []
    for event in events:
        alert = event_alert(event)
        reached = 0
        for name, kind, url, recoveries in targets:
            if event.recovered and not recoveries:
                continue
            failure = send_and_note(journal, send, name, kind, url, alert, nature="slo", subject=event.label)
            if failure is None:
                reached += 1
            else:
                errors.append(f"{name} : {failure}")
        if event.recovered:
            state.mark_slo(event.key, False, moment)
        elif reached:
            state.mark_slo(event.key, True, moment)
    return errors


@dataclass
class FollowUp:
    """Ce qu'un relevé laisse à envoyer en plus des pannes et des retours : rappels, franchissements de l'objectif
    de disponibilité et résumé de la semaine."""

    state: AlertState
    reminders: list[Event]
    digest: Alert | None = None
    week: str = ""
    slo: list[Event] = field(default_factory=list[Event])

    @property
    def empty(self) -> bool:
        return not self.reminders and self.digest is None and not self.slo


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
    """Rappels et franchissements d'objectif dus et, si `check_digest` et que le résumé est dû cette semaine, son
    contenu. Rapide et sans réseau :
    la fenêtre peut l'appeler sur son fil, puis envoyer (`deliver_follow_up`) dans un autre."""
    moment = now or datetime.now(UTC)
    # Tunnel de chaque nom d'hôte : mémorisé d'un relevé à l'autre, pour qu'une maintenance ou une sourdine du tunnel
    # couvre ses noms même avant le premier relevé des services (démarrage, tâche planifiée sans services).
    state.remember_tunnels(tunnel_of or {})
    plan = FollowUp(state, reminder_events(log, config, state, moment, tz, state.tunnels))
    plan.slo = slo_events(log, config, state, moment, tz, state.tunnels)
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
    journal: AlertLog | None = None,
) -> list[str]:
    """Envoie rappels, franchissements d'objectif et résumé, note ce qui est parti dans `alert_state.json` (et chaque envoi dans `journal`) ;
    renvoie les erreurs."""
    errors = send_reminders(plan.reminders, config, secrets, plan.state, now, sender, journal)
    errors += send_slo(plan.slo, config, secrets, plan.state, now, sender, journal)
    if plan.digest is not None:
        reached, failed = broadcast(plan.digest, config, secrets, sender, journal, nature="digest")
        errors += failed
        if reached:
            plan.state.mark_digest(plan.week)
    try:
        plan.state.save()
    except OSError as exc:
        logger.warning("État des alertes non enregistré : %s", exc)
    return errors
