"""Tuile « Disponibilité » de la page Sessions : la tenue des 7 derniers jours des tunnels et des services publiés, et
l'ouverture de la boîte Disponibilité des outils du compte déjà positionnée sur un objet.

- Le calcul lit le journal que tient la surveillance **en mémoire** (`Monitor.availability`) : aucune lecture de
  `availability.json` à l'affichage de la page, donc rien de plus au démarrage ; la tuile se met à jour après chaque
  relevé et à l'ouverture de la page.
- Cachée quand le journal n'a aucun test sur la période.
- La boîte (`cloud/availability.py`) n'est importée qu'à l'ouverture, comme les autres outils du compte.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, tzinfo
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from cma.core.availability import AvailabilityLog
from cma.i18n import tr
from cma.ui.icons import set_glyph
from cma.ui.states import plural
from cma.ui.widgets import button, label

if TYPE_CHECKING:
    from cma.ui.views.cloud.availability import AvailabilityDialog

PERIOD_DAYS = 7


@dataclass(frozen=True)
class UptimeSummary:
    uptime: float  # taux global (0 à 1) : tests réussis sur tests faits, tous objets confondus
    checks: int
    incidents: int  # incidents commencés ou en cours sur la période
    worst_key: str | None  # objet le moins disponible, None quand aucun n'a eu d'échec
    worst_label: str
    worst_uptime: float | None


def summarize(
    log: AvailabilityLog, now: datetime | None = None, tz: tzinfo | None = None, days: int = PERIOD_DAYS
) -> UptimeSummary | None:
    """Taux global et objet le moins disponible sur `days` jours ; None sans aucun test sur la période.

    Calcul volontairement léger (un taux par objet, un seul passage sur les incidents) : il a lieu à chaque relevé.
    """
    ok = total = 0.0
    worst: tuple[float, str, str] | None = None
    for key in log.keys():  # noqa: SIM118 (méthode du journal, pas un dictionnaire)
        stats = log.stats(key, days, now, tz)
        if stats.uptime is None:
            continue
        ok += stats.uptime * stats.checks
        total += stats.checks
        name = log.label(key)
        if stats.uptime < 1 and (
            worst is None or (stats.uptime, name.lower()) < (worst[0], worst[1].lower())
        ):
            worst = (stats.uptime, name, key)
    if not total:
        return None
    incidents = len(log.history(None, days, now))
    return UptimeSummary(
        uptime=ok / total,
        checks=int(total),
        incidents=incidents,
        worst_key=worst[2] if worst else None,
        worst_label=worst[1] if worst else "",
        worst_uptime=worst[0] if worst else None,
    )


def percent_text(value: float) -> str:
    """Même écriture que la boîte Disponibilité : « 100 % », « 99.87 % »."""
    percent = value * 100
    return f"{percent:.0f} %" if percent in (0, 100) else f"{percent:.2f} %"


def tone_of(value: float) -> str:
    """Mêmes seuils que la boîte Disponibilité (vert à 99,9 %, orange à 98 %)."""
    return "success" if value >= 0.999 else "warning" if value >= 0.98 else "danger"


class UptimeTile(QFrame):
    """Carte d'une ligne : taux sur 7 jours, incidents, objet le moins disponible, et un lien vers la boîte."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("Card")
        # Branchés par la fenêtre principale : le journal de la surveillance et l'ouverture de la boîte.
        self.log_source: Callable[[], AvailabilityLog | None] = lambda: None
        self.open_object: Callable[[str | None], None] = lambda _key: None
        self.summary: UptimeSummary | None = None
        row = QHBoxLayout(self)
        row.setContentsMargins(16, 10, 16, 10)
        row.setSpacing(12)
        self.glyph = QLabel()
        row.addWidget(self.glyph, 0, Qt.AlignmentFlag.AlignTop)
        texts = QVBoxLayout()
        texts.setSpacing(2)
        self.heading = label("", "section")
        texts.addWidget(self.heading)
        self.detail = label("", "meta", wrap=True)
        self.detail.setMinimumWidth(
            200
        )  # un libellé à retour à la ligne bloquerait le rétrécissement de la fenêtre
        texts.addWidget(self.detail)
        row.addLayout(texts, 1)
        self.action = button(tr("Détail"), "arrow-right")
        self.action.clicked.connect(self._open)
        row.addWidget(self.action, 0, Qt.AlignmentFlag.AlignVCenter)
        self.hide()

    def refresh(self) -> None:
        log = self.log_source()
        summary = summarize(log) if log is not None else None
        self.summary = summary
        if summary is None:
            self.hide()
            return
        rate = percent_text(summary.uptime)
        tone = tone_of(summary.uptime)
        set_glyph(self.glyph, "circle-check" if tone == "success" else "alert-triangle", tone, 20)
        self.heading.setText(tr("Disponibilité sur 7 jours : {percent}").format(percent=rate))
        parts = [
            plural(summary.incidents, tr("{n} incident"), tr("{n} incidents"))
            if summary.incidents
            else tr("Aucun incident")
        ]
        if summary.worst_uptime is not None:
            parts.append(
                tr("Moins disponible : {name} ({percent})").format(
                    name=summary.worst_label, percent=percent_text(summary.worst_uptime)
                )
            )
        self.detail.setText(" · ".join(parts))
        target = summary.worst_label or tr("tous les objets")
        action_name = tr("Ouvrir la disponibilité : {name}").format(name=target)
        self.action.setAccessibleName(action_name)
        self.action.setToolTip(action_name)
        self.setAccessibleName(
            tr("Disponibilité sur 7 jours : {percent}, {detail}").format(
                percent=rate, detail=self.detail.text()
            )
        )
        self.show()

    def _open(self) -> None:
        self.open_object(self.summary.worst_key if self.summary else None)


def select_key(dialog: AvailabilityDialog, key: str | None) -> bool:
    """Positionne la boîte Disponibilité sur la ligne de `key` ; False si l'objet n'y figure pas."""
    if key is None or key not in dialog.keys:
        return False
    row = dialog.keys.index(key)
    dialog.table.setCurrentCell(row, 0)
    dialog.table.selectRow(row)
    return True


def show_availability_on(parent: QWidget, path: Path, key: str | None) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale. Importée à l'ouverture."""
    from cma.ui.views.cloud.availability import AvailabilityDialog

    # Le contexte de la fenêtre (objectifs lus et modifiables), comme `show_availability` depuis les outils du compte.
    dialog = AvailabilityDialog(parent, path, getattr(parent, "ctx", None))
    select_key(dialog, key)
    dialog.exec()
