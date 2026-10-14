"""Résumé hebdomadaire envoyé aux canaux d'alerte : disponibilité des 7 derniers jours de chaque objet (les moins
disponibles d'abord), incidents et durée des pannes, service tokens à renouveler.

Le résumé est dû le lundi à partir de 9 h (heure locale), une fois par semaine ISO : la semaine du dernier envoi est
dans `alert_state.json` (ADR 0002). Le texte reste sous la limite de Discord (2000 caractères pour le message entier) :
la liste des objets est coupée par lignes entières, avec « … et N autres ».
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, tzinfo

from cma.core.alerts import Alert, elapsed_text
from cma.core.alertstate import AlertState
from cma.core.availability import AvailabilityLog
from cma.core.availability_report import build
from cma.core.expiry import expiring_tokens
from cma.core.models import Config
from cma.i18n import tr

DAYS = 7
LIMIT = 1900  # texte seul : le titre et la mise en forme du canal viennent en plus (Discord : 2000 au total)
MAX_TOKENS = 8
DIGEST_WEEKDAY = 0  # lundi
DIGEST_HOUR = 9


def week_id(local: datetime) -> str:
    """Semaine ISO d'un instant local : « 2026-W42 »."""
    iso = local.isocalendar()
    return f"{iso.year}-W{iso.week:02d}"


def digest_due(
    config: Config, state: AlertState, now: datetime | None = None, tz: tzinfo | None = None
) -> bool:
    """Résumé activé, lundi à partir de 9 h (heure locale) et pas encore envoyé cette semaine ISO."""
    if not config.settings.weekly_digest:
        return False
    local = (now or datetime.now(UTC)).astimezone(tz)
    if local.weekday() != DIGEST_WEEKDAY or local.hour < DIGEST_HOUR:
        return False
    return state.digest_week != week_id(local)


def _percent(value: float | None) -> str:
    if value is None:
        return "—"
    return "100 %" if value >= 1.0 else f"{value * 100:.2f} %"


def truncate(text: str, limit: int = LIMIT) -> str:
    """Coupe à `limit` caractères au plus, sur une fin de ligne si possible, avec « … »."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    newline = cut.rfind("\n")
    if newline > limit // 2:
        cut = cut[:newline]
    return cut.rstrip() + "…"


def build_digest(
    log: AvailabilityLog, config: Config, now: datetime | None = None, tz: tzinfo | None = None
) -> Alert:
    """Le résumé de la semaine écoulée, prêt à envoyer."""
    moment = now or datetime.now(UTC)
    local = moment.astimezone(tz)
    rows, incidents = build(log, DAYS, moment)
    rows = [r for r in rows if r.stats.checks or r.incidents]
    title = tr("CMA — semaine du {date}").format(date=(local - timedelta(days=DAYS)).strftime("%d/%m/%Y"))
    total = sum((r.downtime for r in rows), timedelta())
    count = sum(r.incidents for r in rows)
    head = [tr("Disponibilité sur 7 jours.")]
    if rows:
        head.append(
            tr("Incidents : {n} · pannes cumulées : {duration}").format(
                n=count, duration=elapsed_text(total) if count else "0"
            )
        )
    else:
        head.append(tr("Aucun relevé sur la période : la surveillance n'a rien enregistré."))
    still = [i.label for i in incidents if i.open]
    if still:
        head.append(tr("En cours : {list}").format(list=", ".join(still)))
    tokens = expiring_tokens(config, moment)
    if tokens:
        head.append(tr("Service tokens à renouveler :"))
        for item in tokens[:MAX_TOKENS]:
            head.append(
                tr("• {name} : expiré depuis {days} j").format(name=item.token.name, days=-item.days_left)
                if item.expired
                else tr("• {name} : expire dans {days} j").format(name=item.token.name, days=item.days_left)
            )
        if len(tokens) > MAX_TOKENS:
            head.append(tr("… et {n} autres").format(n=len(tokens) - MAX_TOKENS))
    lines: list[str] = []
    for row in rows:
        uptime = _percent(row.stats.uptime)
        if row.incidents:
            lines.append(
                tr("• {label} : {uptime}, {incidents} incident(s), pannes {duration}").format(
                    label=row.label,
                    uptime=uptime,
                    incidents=row.incidents,
                    duration=elapsed_text(row.downtime),
                )
            )
        else:
            lines.append(tr("• {label} : {uptime}").format(label=row.label, uptime=uptime))
    kept = list(head)
    for index, line in enumerate(lines):
        left = len(lines) - index - 1
        tail = [tr("… et {n} autres").format(n=left)] if left else []
        if len("\n".join([*kept, line, *tail])) > LIMIT:
            kept.append(tr("… et {n} autres").format(n=len(lines) - index))
            break
        kept.append(line)
    level = "warning" if count or still or tokens else "success"
    return Alert(title, truncate("\n".join(kept)), level)
