"""Rapport de disponibilité : CSV pour un tableur, HTML autonome à imprimer ou à joindre, JSON pour un script.

Une ligne par tunnel et service relevé (taux, temps de réponse, incidents, durée cumulée des pannes), puis la liste
des incidents de la période. Le HTML n'appelle rien à l'extérieur (styles intégrés) et échappe chaque texte.
"""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from cma import APP_NAME, __version__
from cma.core.availability import AvailabilityLog, Incident, ReportRow, report
from cma.i18n import get_language, tr


def _percent(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value * 100:.0f} %" if value in (0.0, 1.0) else f"{value * 100:.2f} %"


def _duration(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    if not minutes:
        return "0 min" if delta.total_seconds() < 1 else "< 1 min"
    hours, minutes = divmod(minutes, 60)
    if not hours:
        return f"{minutes} min"
    days, hours = divmod(hours, 24)
    return f"{days} j {hours} h {minutes:02d}" if days else f"{hours} h {minutes:02d}"


def _kind(kind: str) -> str:
    return tr("Tunnel") if kind == "tunnel" else tr("Service")


def _ms(value: float | None) -> str:
    return f"{value:.0f}" if value is not None else ""


def report_csv(rows: list[ReportRow], incidents: list[Incident]) -> str:
    """Deux tableaux séparés par une ligne vide : objets, puis incidents (« ; », dates ISO en UTC)."""
    out = io.StringIO()
    writer = csv.writer(out, delimiter=";", lineterminator="\r\n")
    writer.writerow(
        [
            tr("Objet"),
            tr("Type"),
            tr("Disponibilité"),
            tr("Temps moyen (ms)"),
            tr("Incidents"),
            tr("Durée des pannes"),
        ]
    )
    for row in rows:
        writer.writerow(
            [
                row.label,
                _kind(row.kind),
                _percent(row.stats.uptime),
                _ms(row.stats.mean_ms),
                row.incidents,
                _duration(row.downtime),
            ]
        )
    writer.writerow([])
    writer.writerow([tr("Début"), tr("Fin"), tr("Objet"), tr("Cause")])
    for incident in incidents:
        writer.writerow([incident.started, incident.ended or tr("en cours"), incident.label, incident.state])
    return out.getvalue()


def report_json(rows: list[ReportRow], incidents: list[Incident], days: int) -> str:
    data: dict[str, Any] = {
        "days": days,
        "objects": [
            {
                "key": row.key,
                "label": row.label,
                "kind": row.kind,
                "uptime": row.stats.uptime,
                "mean_ms": row.stats.mean_ms,
                "max_ms": row.stats.max_ms,
                "checks": row.stats.checks,
                "incidents": row.incidents,
                "downtime_s": int(row.downtime.total_seconds()),
            }
            for row in rows
        ],
        "incidents": [
            {"key": i.key, "label": i.label, "state": i.state, "started": i.started, "ended": i.ended}
            for i in incidents
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


STYLE = """
body { font-family: Segoe UI, system-ui, sans-serif; color: #1e293b; margin: 32px; }
h1 { font-size: 22px; margin-bottom: 4px; } h2 { font-size: 16px; margin-top: 28px; }
p.meta { color: #64748b; margin-top: 0; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { border-bottom: 1px solid #e2e8f0; padding: 6px 8px; text-align: left; }
th { background: #f1f5f9; } td.num { text-align: right; font-variant-numeric: tabular-nums; }
.ok { color: #15803d; } .warn { color: #b45309; } .bad { color: #b91c1c; } .open { color: #b91c1c; font-weight: 600; }
"""


def _tone(uptime: float | None) -> str:
    if uptime is None:
        return ""
    return "ok" if uptime >= 0.999 else "warn" if uptime >= 0.98 else "bad"


def report_html(
    rows: list[ReportRow],
    incidents: list[Incident],
    days: int,
    account: str = "",
    now: datetime | None = None,
) -> str:
    """Page HTML autonome (aucune ressource externe), textes échappés."""
    moment = (now or datetime.now(UTC)).astimezone()
    e = html.escape
    heading = tr("Disponibilité des {days} derniers jours").format(days=days)
    meta = tr("Généré le {date} par {app} {version}").format(
        date=moment.strftime("%d/%m/%Y %H:%M"), app=APP_NAME, version=__version__
    )
    if account:
        meta = f"{account} · {meta}"
    lines = [
        "<!doctype html>",
        f'<html lang="{get_language()}"><head><meta charset="utf-8">',
        f"<title>{e(heading)}</title><style>{STYLE}</style></head><body>",
        f"<h1>{e(heading)}</h1>",
        f'<p class="meta">{e(meta)}</p>',
        "<table><thead><tr>",
        "".join(
            f"<th>{e(t)}</th>"
            for t in (
                tr("Objet"),
                tr("Type"),
                tr("Disponibilité"),
                tr("Temps moyen"),
                tr("Incidents"),
                tr("Durée des pannes"),
            )
        ),
        "</tr></thead><tbody>",
    ]
    for row in rows:
        mean = f"{row.stats.mean_ms:.0f} ms" if row.stats.mean_ms is not None else "—"
        lines.append(
            "<tr>"
            f"<td>{e(row.label)}</td><td>{e(_kind(row.kind))}</td>"
            f'<td class="num {_tone(row.stats.uptime)}">{e(_percent(row.stats.uptime))}</td>'
            f'<td class="num">{e(mean)}</td><td class="num">{row.incidents}</td>'
            f'<td class="num">{e(_duration(row.downtime))}</td>'
            "</tr>"
        )
    lines.append("</tbody></table>")
    lines.append(f"<h2>{e(tr('Incidents'))}</h2>")
    if not incidents:
        lines.append(f'<p class="meta">{e(tr("Aucun incident sur la période."))}</p>')
    else:
        lines.append("<table><thead><tr>")
        lines.append("".join(f"<th>{e(t)}</th>" for t in (tr("Début"), tr("Fin"), tr("Objet"), tr("Cause"))))
        lines.append("</tr></thead><tbody>")
        for incident in incidents:
            ended = (
                f"<td>{e(_local(incident.ended))}</td>"
                if incident.ended
                else f'<td class="open">{e(tr("en cours"))}</td>'
            )
            lines.append(
                f"<tr><td>{e(_local(incident.started))}</td>{ended}"
                f"<td>{e(incident.label)}</td><td>{e(incident.state)}</td></tr>"
            )
        lines.append("</tbody></table>")
    lines.append("</body></html>")
    return "\n".join(lines) + "\n"


def _local(value: str) -> str:
    try:
        moment = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).astimezone()
    except ValueError:
        return value
    return moment.strftime("%d/%m/%Y %H:%M")


def build(
    log: AvailabilityLog, days: int, now: datetime | None = None
) -> tuple[list[ReportRow], list[Incident]]:
    return report(log, days, now), log.history(days=days, now=now)
