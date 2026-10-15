"""Résumé hebdomadaire envoyé aux canaux d'alerte : disponibilité des 7 derniers jours de chaque objet (les moins
disponibles d'abord), incidents et durée des pannes, service tokens à renouveler.

Le résumé est dû le lundi à partir de 9 h (heure locale), une fois par semaine ISO : la semaine du dernier envoi est
dans `alert_state.json` (ADR 0002). Le texte reste sous la limite de Discord (2000 caractères pour le message entier) :
chaque section est bornée (quelques noms, puis « … et N autres »), la liste des objets est coupée par lignes entières
et la coupe finale ne tranche jamais une ligne : même avec des dizaines d'incidents ouverts, les objets les moins
disponibles et les service tokens restent présents.
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
MAX_STILL = 4  # noms cités dans « En cours »
NAME_WIDTH = 40  # un nom plus long est abrégé : une section bornée en nombre l'est aussi en taille
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


def _short(name: str, width: int = NAME_WIDTH) -> str:
    """Un nom abrégé à `width` caractères au plus (« … » à la fin)."""
    return name if len(name) <= width else name[: width - 1] + "…"


def _more(count: int) -> str:
    return tr("… et {n} autres").format(n=count)


def truncate(text: str, limit: int = LIMIT) -> str:
    """Coupe à `limit` caractères au plus, par lignes entières (« … » à la fin) ; une ligne seule trop longue est
    coupée net, faute de mieux."""
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    newline = cut.rfind("\n")
    if newline > 0:
        cut = cut[:newline]
    return cut.rstrip() + "…"


def build_digest(
    log: AvailabilityLog, config: Config, now: datetime | None = None, tz: tzinfo | None = None
) -> Alert:
    """Le résumé de la semaine écoulée, prêt à envoyer."""
    moment = now or datetime.now(UTC)
    local = moment.astimezone(tz)
    rows, incidents = build(log, DAYS, moment, tz)
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
        names = [_short(name) for name in still[:MAX_STILL]]
        if len(still) > MAX_STILL:
            names.append(_more(len(still) - MAX_STILL))
        head.append(tr("En cours : {list}").format(list=", ".join(names)))
    tokens = expiring_tokens(config, moment)
    if tokens:
        head.append(tr("Service tokens à renouveler :"))
        for item in tokens[:MAX_TOKENS]:
            head.append(
                tr("• {name} : expiré depuis {days} j").format(
                    name=_short(item.token.name), days=-item.days_left
                )
                if item.expired
                else tr("• {name} : expire dans {days} j").format(
                    name=_short(item.token.name), days=item.days_left
                )
            )
        if len(tokens) > MAX_TOKENS:
            head.append(_more(len(tokens) - MAX_TOKENS))
    lines: list[str] = []
    for row in rows:
        uptime = _percent(row.stats.uptime)
        if row.incidents:
            lines.append(
                tr("• {label} : {uptime}, {incidents} incident(s), pannes {duration}").format(
                    label=_short(row.label),
                    uptime=uptime,
                    incidents=row.incidents,
                    duration=elapsed_text(row.downtime),
                )
            )
        else:
            lines.append(tr("• {label} : {uptime}").format(label=_short(row.label), uptime=uptime))
    kept = list(head)
    for index, line in enumerate(lines):
        left = len(lines) - index - 1
        tail = [_more(left)] if left else []
        if len("\n".join([*kept, line, *tail])) > LIMIT:
            kept.append(_more(len(lines) - index))
            break
        kept.append(line)
    level = "warning" if count or still or tokens else "success"
    return Alert(title, truncate("\n".join(kept)), level)
