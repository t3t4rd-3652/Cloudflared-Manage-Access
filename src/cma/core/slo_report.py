"""Rapport mensuel de disponibilité (P33) : texte, CSV, JSON et HTML d'un `cma.core.slo.MonthReport`.

Une ligne par tunnel et service relevé dans le mois (disponibilité, objectif, écart, temps de réponse, incidents,
durée des pannes), puis les incidents qui touchent le mois. Même conventions que `availability_report` : CSV « ; »
(à ouvrir avec Excel, BOM ajouté par l'appelant), HTML autonome sans ressource externe, tous les textes échappés.
"""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from cma import APP_NAME, __version__
from cma.core.availability_report import STYLE
from cma.core.slo import MonthReport, MonthRow, percent_text, target_text
from cma.i18n import get_language, tr


def _gap(value: float | None) -> str:
    """Écart à l'objectif en points : « +0.12 » ou « -0.40 » ; « — » sans objectif ou sans relevé."""
    return "—" if value is None else f"{value:+.2f}"


def _uptime(row: MonthRow) -> str:
    return "—" if row.uptime is None else percent_text(row.uptime)


def _kind(kind: str) -> str:
    return tr("Tunnel") if kind == "tunnel" else tr("Service")


def _duration(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    if not minutes:
        return "0 min" if delta.total_seconds() < 1 else "< 1 min"
    hours, minutes = divmod(minutes, 60)
    if not hours:
        return f"{minutes} min"
    days, hours = divmod(hours, 24)
    return f"{days} j {hours} h {minutes:02d}" if days else f"{hours} h {minutes:02d}"


def _local(value: str) -> str:
    try:
        moment = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).astimezone()
    except ValueError:
        return value
    return moment.strftime("%d/%m/%Y %H:%M")


def _ms(value: float | None) -> str:
    return f"{value:.0f}" if value is not None else ""


def period_text(report: MonthReport) -> str:
    """« 01/10/2026 au 15/10/2026 »."""
    return tr("{first} au {last}").format(
        first=report.first.strftime("%d/%m/%Y"), last=report.last.strftime("%d/%m/%Y")
    )


def report_lines(report: MonthReport) -> list[str]:
    """Texte de la console : un en-tête, puis une ligne par objet (disponibilité, objectif, écart, temps moyen,
    incidents, nom). Liste vide si rien n'a été relevé."""
    lines: list[str] = []
    for row in report.rows:
        uptime = f"{row.uptime:6.2f} %" if row.uptime is not None else "     — "
        mean = f"{row.stats.mean_ms:5.0f} ms" if row.stats.mean_ms is not None else "        "
        target = target_text(row.target).rjust(8)
        lines.append(f"{uptime}  {target}  {_gap(row.gap):>6}  {mean}  {row.incidents:>3}  {row.label}")
    return lines


def report_header() -> str:
    """En-tête des colonnes de `report_lines`, aligné sur les lignes."""
    return f"{tr('dispo.'):>8}  {tr('objectif'):>8}  {tr('écart'):>6}  {tr('moyen'):>8}  {tr('inc.'):>3}  {tr('objet')}"


def month_csv(report: MonthReport) -> str:
    """Deux tableaux séparés par une ligne vide : objets, puis incidents (« ; », dates ISO en UTC)."""
    out = io.StringIO()
    writer = csv.writer(out, delimiter=";", lineterminator="\r\n")
    writer.writerow(
        [
            tr("Objet"),
            tr("Type"),
            tr("Disponibilité"),
            tr("Objectif"),
            tr("Écart (points)"),
            tr("Temps moyen (ms)"),
            tr("Incidents"),
            tr("Durée des pannes"),
        ]
    )
    for row in report.rows:
        writer.writerow(
            [
                row.label,
                _kind(row.kind),
                _uptime(row),
                target_text(row.target),
                _gap(row.gap),
                _ms(row.stats.mean_ms),
                row.incidents,
                _duration(row.downtime),
            ]
        )
    writer.writerow([])
    writer.writerow([tr("Début"), tr("Fin"), tr("Objet"), tr("Cause")])
    for incident in report.incidents:
        writer.writerow([incident.started, incident.ended or tr("en cours"), incident.label, incident.state])
    return out.getvalue()


def month_json(report: MonthReport) -> str:
    data: dict[str, Any] = {
        "month": report.month,
        "from": report.first.isoformat(),
        "to": report.last.isoformat(),
        "objects": [
            {
                "key": row.key,
                "label": row.label,
                "kind": row.kind,
                "uptime": row.stats.uptime,
                "target": row.target,
                "gap": row.gap,
                "below": row.below,
                "mean_ms": row.stats.mean_ms,
                "max_ms": row.stats.max_ms,
                "checks": row.stats.checks,
                "incidents": row.incidents,
                "downtime_s": int(row.downtime.total_seconds()),
            }
            for row in report.rows
        ],
        "incidents": [
            {"key": i.key, "label": i.label, "state": i.state, "started": i.started, "ended": i.ended}
            for i in report.incidents
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def month_html(report: MonthReport, now: datetime | None = None) -> str:
    """Page HTML autonome (aucune ressource externe), textes échappés."""
    moment = (now or datetime.now(UTC)).astimezone()
    e = html.escape
    heading = tr("Disponibilité de {month}").format(month=report.month)
    meta = tr("Du {period} · généré le {date} par {app} {version}").format(
        period=period_text(report),
        date=moment.strftime("%d/%m/%Y %H:%M"),
        app=APP_NAME,
        version=__version__,
    )
    lines = [
        "<!doctype html>",
        f'<html lang="{get_language()}"><head><meta charset="utf-8">',
        f"<title>{e(heading)}</title><style>{STYLE}</style></head><body>",
        f"<h1>{e(heading)}</h1>",
        f'<p class="meta">{e(meta)}</p>',
    ]
    if not report.rows:
        lines.append(f'<p class="meta">{e(tr("Aucun relevé sur la période."))}</p>')
    else:
        lines += ["<table><thead><tr>"]
        lines.append(
            "".join(
                f"<th>{e(t)}</th>"
                for t in (
                    tr("Objet"),
                    tr("Type"),
                    tr("Disponibilité"),
                    tr("Objectif"),
                    tr("Écart (points)"),
                    tr("Temps moyen"),
                    tr("Incidents"),
                    tr("Durée des pannes"),
                )
            )
        )
        lines.append("</tr></thead><tbody>")
        for row in report.rows:
            mean = f"{row.stats.mean_ms:.0f} ms" if row.stats.mean_ms is not None else "—"
            tone = "bad" if row.below else "ok" if row.target is not None and row.uptime is not None else ""
            lines.append(
                "<tr>"
                f"<td>{e(row.label)}</td><td>{e(_kind(row.kind))}</td>"
                f'<td class="num {tone}">{e(_uptime(row))}</td>'
                f'<td class="num">{e(target_text(row.target))}</td>'
                f'<td class="num {tone}">{e(_gap(row.gap))}</td>'
                f'<td class="num">{e(mean)}</td><td class="num">{row.incidents}</td>'
                f'<td class="num">{e(_duration(row.downtime))}</td>'
                "</tr>"
            )
        lines.append("</tbody></table>")
    lines.append(f"<h2>{e(tr('Incidents'))}</h2>")
    if not report.incidents:
        lines.append(f'<p class="meta">{e(tr("Aucun incident sur la période."))}</p>')
    else:
        lines.append("<table><thead><tr>")
        lines.append("".join(f"<th>{e(t)}</th>" for t in (tr("Début"), tr("Fin"), tr("Objet"), tr("Cause"))))
        lines.append("</tr></thead><tbody>")
        for incident in report.incidents:
            end = (
                f"<td>{e(_local(incident.ended))}</td>"
                if incident.ended
                else f'<td class="open">{e(tr("en cours"))}</td>'
            )
            lines.append(
                f"<tr><td>{e(_local(incident.started))}</td>{end}"
                f"<td>{e(incident.label)}</td><td>{e(incident.state)}</td></tr>"
            )
        lines.append("</tbody></table>")
    lines.append("</body></html>")
    return "\n".join(lines) + "\n"
