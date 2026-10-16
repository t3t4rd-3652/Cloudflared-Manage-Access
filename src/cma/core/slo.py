"""Objectifs de disponibilité (P33) : un service tient-il ce qu'on attend de lui ?

- Un objectif est un pourcentage (50 à 100) par objet (`Settings.availability_targets`, clé « tunnel:<id> » ou
  « service:<nom d'hôte et chemin> »), ou à défaut `Settings.default_availability_target`.
- La disponibilité comparée à l'objectif est celle des 30 derniers jours locaux du journal (`AvailabilityLog.stats`).
  Sans aucun relevé sur la période, il n'y a ni état ni événement : un trou n'est pas une panne.
- `crossings` donne les franchissements à annoncer : le passage sous l'objectif, **une seule fois** tant que l'objet
  reste dessous, puis le retour au-dessus. Ce qui a déjà été annoncé est dans `alert_state.json` (ADR 0002).
- Marge de retour (P40, `Settings.availability_margin`) : l'alerte part dès que la disponibilité passe sous l'objectif,
  mais le retour n'est annoncé qu'à objectif + marge (100 % au plus). Entre les deux, l'état annoncé ne change pas :
  un objet qui oscille autour de l'objectif ne fait plus alterner alerte et retour.
- `month_report` : rapport d'un mois civil en jours locaux, avec l'objectif et l'écart ; le mois en cours va jusqu'à
  aujourd'hui. Le calcul porte sur des dates locales : le jour d'un changement d'heure reste un seul jour.

Ce module ne connaît ni la sourdine ni l'envoi : l'appelant (`cma.core.monitoring`) fournit la sourdine.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta, tzinfo

from cma.core.alertstate import AlertState
from cma.core.availability import AvailabilityLog, Incident, Stats, local_date
from cma.core.digest import watched
from cma.core.models import MAX_TARGET, Config, clamp_target
from cma.i18n import tr

WINDOW_DAYS = 30


def target_of(config: Config, key: str) -> float | None:
    """Objectif (en %) d'un objet : le sien, sinon l'objectif par défaut ; None sans objectif."""
    settings = config.settings
    return settings.availability_targets.get(key, settings.default_availability_target)


def has_targets(config: Config) -> bool:
    """Un objectif au moins est défini (l'appelant peut sauter le calcul des franchissements sinon)."""
    settings = config.settings
    return bool(settings.availability_targets) or settings.default_availability_target is not None


def set_target(config: Config, key: str, value: float | None) -> None:
    """Pose (borné de 50 à 100) ou retire (`None`) l'objectif propre d'un objet."""
    targets = dict(config.settings.availability_targets)
    if value is None:
        targets.pop(key, None)
    else:
        targets[key] = clamp_target(value)
    config.settings.availability_targets = targets


def percent_text(value: float) -> str:
    """« 99.50 % » : arrondi vers le bas, pour qu'une valeur sous l'objectif ne s'affiche jamais à sa hauteur."""
    return f"{math.floor(value * 100 + 1e-6) / 100:.2f} %"


def target_text(value: float | None) -> str:
    return "—" if value is None else f"{value:g} %"


def is_below(percent: float | None, target: float | None) -> bool:
    """Disponibilité (en %) sous l'objectif ; faux sans objectif ou sans relevé."""
    return percent is not None and target is not None and percent + 1e-9 < target


def recovery_level(target: float, margin: float) -> float:
    """Disponibilité (en %) à atteindre pour annoncer le retour : objectif + marge, plafonnée à 100 %."""
    return min(MAX_TARGET, target + margin)


def is_recovered(percent: float | None, target: float | None, margin: float) -> bool:
    """Disponibilité (en %) revenue au niveau de retour (objectif + marge) ; faux sans objectif ou sans relevé."""
    return percent is not None and target is not None and percent + 1e-9 >= recovery_level(target, margin)


def kind_of(key: str) -> str:
    return "tunnel" if key.startswith("tunnel:") else "service"


@dataclass(frozen=True)
class SloStatus:
    key: str
    target: float | None
    uptime: float | None  # en %, None sans relevé sur la période
    checks: int

    @property
    def below(self) -> bool:
        return is_below(self.uptime, self.target)

    @property
    def gap(self) -> float | None:
        """Écart à l'objectif en points de pourcentage (négatif : sous l'objectif) ; None sans objectif ou relevé."""
        if self.uptime is None or self.target is None:
            return None
        return self.uptime - self.target


def status(
    log: AvailabilityLog,
    config: Config,
    key: str,
    now: datetime | None = None,
    tz: tzinfo | None = None,
) -> SloStatus:
    """Disponibilité de l'objet sur les 30 derniers jours locaux, face à son objectif."""
    stats = log.stats(key, WINDOW_DAYS, now, tz)
    uptime = stats.uptime * 100 if stats.uptime is not None else None
    return SloStatus(key, target_of(config, key), uptime, stats.checks)


@dataclass(frozen=True)
class Crossing:
    """Franchissement de l'objectif à annoncer : passage dessous (`recovered` faux) ou retour au-dessus."""

    key: str
    label: str
    target: float
    uptime: float  # en %
    recovered: bool


def crossings(
    log: AvailabilityLog,
    config: Config,
    state: AlertState,
    now: datetime | None = None,
    tz: tzinfo | None = None,
    muted: Callable[[str], bool] | None = None,
) -> list[Crossing]:
    """Franchissements dus : un objet sous son objectif qui n'a pas encore été annoncé, ou annoncé qui est remonté.

    - Seuls les objets d'un type surveillé, avec un objectif et au moins un relevé sur 30 jours comptent.
    - Le retour exige objectif + `Settings.availability_margin` (`recovery_level`) : tant que la disponibilité reste
      entre l'objectif et ce niveau, un objet annoncé reste « sous l'objectif » et un objet correct reste correct.
    - `muted(clé)` : objet en sourdine ou en maintenance → ni alerte ni retour (ils viendront à la fin de la sourdine
      si la situation dure).
    - L'état n'est pas modifié ici, sauf l'oubli des objets qui n'ont plus d'objectif ou de relevé connu : il l'est
      quand l'envoi a réussi (`AlertState.mark_slo`)."""
    moment = now or datetime.now(UTC)
    margin = config.settings.availability_margin
    found: list[Crossing] = []
    known: set[str] = set()
    for key in log.keys():  # noqa: SIM118 (méthode du journal, pas un dictionnaire)
        if not watched(config, kind_of(key)):
            continue
        current = status(log, config, key, moment, tz)
        if current.target is None:
            continue
        known.add(key)
        if current.uptime is None:
            continue  # aucun relevé : pas de conclusion, l'état annoncé reste tel quel
        announced = state.slo_below(key)
        # Sous l'objectif, on alerte ; une fois annoncé, on ne revient qu'à objectif + marge (entre les deux : rien).
        if announced:
            if not is_recovered(current.uptime, current.target, margin):
                continue
        elif not current.below:
            continue
        if muted is not None and muted(key):
            continue
        found.append(Crossing(key, log.label(key), current.target, current.uptime, recovered=announced))
    state.keep_only_slo(known)
    return found


# --- Rapport d'un mois civil -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class MonthRow:
    key: str
    label: str
    kind: str  # « tunnel » ou « service »
    stats: Stats
    target: float | None
    incidents: int
    downtime: timedelta  # durée cumulée des incidents dans la période (bornée à la période)

    @property
    def uptime(self) -> float | None:
        """Disponibilité en % ; None sans relevé."""
        return self.stats.uptime * 100 if self.stats.uptime is not None else None

    @property
    def below(self) -> bool:
        return is_below(self.uptime, self.target)

    @property
    def gap(self) -> float | None:
        """Écart à l'objectif en points de pourcentage ; None sans objectif ou sans relevé."""
        if self.uptime is None or self.target is None:
            return None
        return self.uptime - self.target


@dataclass(frozen=True)
class MonthReport:
    month: str  # AAAA-MM
    first: date
    last: date  # dernier jour compté : la fin du mois, ou aujourd'hui pour le mois en cours
    rows: list[MonthRow]
    incidents: list[Incident]  # ceux qui touchent le mois, du plus ancien au plus récent


def parse_month(text: str) -> tuple[int, int]:
    """« 2026-10 » → (2026, 10) ; ValueError si le texte n'est pas un mois AAAA-MM."""
    parts = text.strip().split("-")
    if len(parts) != 2 or len(parts[0]) != 4 or len(parts[1]) != 2 or not all(p.isdigit() for p in parts):
        raise ValueError(
            tr("Mois invalide « {text} » : attendu AAAA-MM, par exemple 2026-10.").format(text=text)
        )
    year, month = int(parts[0]), int(parts[1])
    if not 1 <= month <= 12 or year < 1:
        raise ValueError(
            tr("Mois invalide « {text} » : attendu AAAA-MM, par exemple 2026-10.").format(text=text)
        )
    return year, month


def month_bounds(text: str, today: date) -> tuple[date, date]:
    """(premier jour, dernier jour compté) d'un mois civil ; le mois en cours s'arrête à `today`.
    ValueError si le texte n'est pas un mois ou si le mois est à venir."""
    year, month = parse_month(text)
    first = date(year, month, 1)
    if first > today:
        raise ValueError(
            tr("Le mois {text} n'a pas commencé : le rapport ne porte que sur le passé.").format(text=text)
        )
    following = date(year + 1, 1, 1) if month == 12 else date(year, month + 1, 1)
    return first, min(following - timedelta(days=1), today)


def _utc(day: date, tz: tzinfo | None) -> datetime:
    """Minuit local du jour `day`, en UTC (le calcul passe par la date : un jour de 23 ou 25 h reste un jour)."""
    return datetime.combine(day, time.min, tzinfo=tz).astimezone(UTC)


def _parse(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def month_report(
    log: AvailabilityLog,
    config: Config,
    month: str,
    now: datetime | None = None,
    tz: tzinfo | None = None,
) -> MonthReport:
    """Rapport d'un mois civil (jours locaux) : une ligne par objet relevé ou en incident dans la période, les moins
    disponibles d'abord ; rapport vide si rien n'a été relevé ce mois-là. ValueError : mois invalide ou à venir."""
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    first, last = month_bounds(month, local_date(moment, tz))
    day_from, day_to = first.isoformat(), last.isoformat()
    start = _utc(first, tz)
    end = min(_utc(last + timedelta(days=1), tz), moment)
    rows: list[MonthRow] = []
    listed: list[Incident] = []
    for key in log.keys():  # noqa: SIM118 (méthode du journal, pas un dictionnaire)
        counts = [v for d, v in log.days.get(key, {}).items() if day_from <= d <= day_to]
        ok, total = sum(c[0] for c in counts), sum(c[1] for c in counts)
        timed = sum(c[4] for c in counts)
        incidents = [
            i
            for i in log.incidents
            if i.key == key and _parse(i.started) < end and (i.ended is None or _parse(i.ended) > start)
        ]
        if not total and not incidents:
            continue
        downtime = timedelta()
        for incident in incidents:
            began = max(_parse(incident.started), start)
            finished = min(_parse(incident.ended), end) if incident.ended else end
            if finished > began:
                downtime += finished - began
            listed.append(incident)
        stats = Stats(
            uptime=ok / total if total else None,
            mean_ms=sum(c[2] for c in counts) / timed if timed else None,
            max_ms=max((c[3] for c in counts if c[4]), default=None),
            checks=int(total),
        )
        rows.append(
            MonthRow(
                key, log.label(key), kind_of(key), stats, target_of(config, key), len(incidents), downtime
            )
        )
    rows.sort(key=lambda r: (r.stats.uptime if r.stats.uptime is not None else 2.0, r.label.lower()))
    listed.sort(key=lambda i: i.started)
    return MonthReport(f"{first.year:04d}-{first.month:02d}", first, last, rows, listed)
