"""Mise en forme lisible : tailles, durées, dates."""

from __future__ import annotations

from datetime import datetime

from cma.i18n import tr


def human_bytes(value: int) -> str:
    size = float(value)
    for unit in ("o", "Kio", "Mio", "Gio"):
        if size < 1024 or unit == "Gio":
            return f"{size:.0f} {unit}" if unit == "o" else f"{size:.1f} {unit}".replace(".", ",")
        size /= 1024
    return f"{size:.1f} Tio"


def human_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    if days:
        return tr("{d} j {h} h").format(d=days, h=hours)
    if hours:
        return tr("{h} h {m:02d}").format(h=hours, m=minutes)
    if minutes:
        return tr("{m} min {s:02d}").format(m=minutes, s=secs)
    return tr("{s} s").format(s=secs)


def since(moment: datetime | None) -> str:
    if moment is None:
        return ""
    return human_duration((datetime.now() - moment).total_seconds())


def short_datetime(moment: datetime) -> str:
    return moment.astimezone().strftime("%d/%m/%Y %H:%M")
