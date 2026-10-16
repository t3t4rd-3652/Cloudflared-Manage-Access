"""Disponibilité (Outils) : taux sur 7 et 30 jours, temps de réponse et incidents de chaque tunnel et service publié,
lus dans le journal tenu par la surveillance (CMA ouvert et tâche planifiée), avec l'objectif de chaque objet
(`cma.core.slo`) : colonne « Objectif », teinte d'alerte sous l'objectif, boîte « Définir l'objectif… »."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QPointF, QRectF, QSize, Qt
from PySide6.QtGui import QBrush, QColor, QMouseEvent, QPainter, QPaintEvent, QPen, QPolygonF
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QSplitter,
    QTableWidgetItem,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from cma.core.availability import AvailabilityLog, DayStats, Incident, Stats, daily
from cma.core.availability_report import build, report_csv, report_html
from cma.core.fsutil import atomic_write_text
from cma.core.models import MAX_MARGIN, MAX_TARGET, MIN_MARGIN, MIN_TARGET, Config, clamp_margin
from cma.core.slo import SloStatus, set_target, status, target_text
from cma.i18n import tr
from cma.ui.icons import app_icon
from cma.ui.theme import current_tokens, status_colors
from cma.ui.views.cloud.access_log import request_time
from cma.ui.views.cloud.helpers import data_table, dialog_buttons
from cma.ui.widgets import button, clear_items, label, title

if TYPE_CHECKING:
    from cma.ui.context import GuiContext

TARGET_COLUMN = 6  # « Objectif » : dernière colonne, les autres gardent leur place
SUGGESTED_TARGET = 99.9


def percent(stats: Stats) -> str:
    if stats.uptime is None:
        return "—"
    value = stats.uptime * 100
    return f"{value:.0f} %" if value in (0, 100) else f"{value:.2f} %"


def uptime_tone(stats: Stats) -> str:
    if stats.uptime is None:
        return "neutral"
    return "success" if stats.uptime >= 0.999 else "warning" if stats.uptime >= 0.98 else "danger"


def duration_text(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    if minutes < 60:
        return tr("{n} min").format(n=max(1, minutes))
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return tr("{h} h {m:02d}").format(h=hours, m=minutes)
    return tr("{d} j {h} h").format(d=hours // 24, h=hours % 24)


def state_text(state: str) -> str:
    return {
        "down": tr("Hors ligne"),
        "degraded": tr("Dégradé"),
        "origin_down": tr("Service injoignable"),
        "no_connector": tr("Aucun connecteur"),
        "not_found": tr("Nom introuvable"),
    }.get(state, state)


class UptimeChart(QWidget):
    """Un jour par barre : couleur selon le taux de disponibilité (vert, orange, rouge ; gris sans relevé) ;
    courbe du temps de réponse moyen par-dessus. Le survol donne le détail du jour."""

    def __init__(self) -> None:
        super().__init__()
        self.series: list[DayStats] = []
        self.setMouseTracking(True)
        self.setMinimumHeight(120)
        self.setAccessibleName(tr("Graphique de disponibilité par jour"))

    def sizeHint(self) -> QSize:
        return QSize(600, 140)

    def set_series(self, series: list[DayStats]) -> None:
        self.series = series
        measured = [d for d in series if d.uptime is not None]
        if measured:
            worst = min(measured, key=lambda d: d.uptime or 0.0)
            self.setAccessibleDescription(
                tr("{n} jours relevés ; le plus bas : {percent} le {day}.").format(
                    n=len(measured), percent=percent(Stats(worst.uptime, None, None, 1)), day=_day(worst.day)
                )
            )
        else:
            self.setAccessibleDescription(tr("Aucun relevé sur la période."))
        self.update()

    def _bar(self, index: int) -> QRectF:
        width = self.width() / max(1, len(self.series))
        return QRectF(index * width + 1, 8, max(1.0, width - 2), self.height() - 16)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        tokens = current_tokens()
        for index, day in enumerate(self.series):
            tone = "neutral" if day.uptime is None else uptime_tone(Stats(day.uptime, None, None, 1))
            # Teinte du texte, en transparence : lisible en clair comme en sombre (le fond de pastille est trop pâle).
            color = QColor(status_colors(tone, tokens)[0])
            color.setAlpha(70 if tone == "neutral" else 110)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(color)
            painter.drawRoundedRect(self._bar(index), 3, 3)
        timed = [(i, d.mean_ms) for i, d in enumerate(self.series) if d.mean_ms is not None]
        top = max((ms for _i, ms in timed), default=0.0)
        if len(timed) > 1 and top > 0:
            points = QPolygonF()
            for index, ms in timed:
                bar = self._bar(index)
                points.append(
                    QPointF(bar.center().x(), bar.bottom() - (ms or 0.0) / top * (bar.height() - 8))
                )
            painter.setPen(QPen(QColor(tokens.accent), 2))
            painter.drawPolyline(points)
        painter.end()

    def text_at(self, x: float) -> str | None:
        """Détail du jour sous l'abscisse `x` (info-bulle du survol) ; None hors des barres."""
        index = int(x / max(1.0, self.width() / max(1, len(self.series))))
        if not 0 <= index < len(self.series):
            return None
        day = self.series[index]
        if day.uptime is None:
            return tr("{day} : aucun relevé").format(day=_day(day.day))
        text = tr("{day} : {percent} · {n} tests").format(
            day=_day(day.day), percent=percent(Stats(day.uptime, None, None, 1)), n=day.checks
        )
        return text + (f" · {day.mean_ms:.0f} ms" if day.mean_ms is not None else "")

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        text = self.text_at(event.position().x())
        if text is not None:
            QToolTip.showText(event.globalPosition().toPoint(), text, self)
        super().mouseMoveEvent(event)


def _day(day: str) -> str:
    return f"{day[8:10]}/{day[5:7]}"


def ask_report_path(parent: QWidget, days: int) -> Path | None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale. HTML ou CSV selon le choix."""
    name = f"disponibilite-{days}j"
    path, _filter = QFileDialog.getSaveFileName(
        parent,
        tr("Exporter le rapport de disponibilité"),
        str(Path.home() / f"{name}.html"),
        tr("Page HTML (*.html);;CSV pour un tableur (*.csv)"),
    )
    return Path(path) if path else None


@dataclass(frozen=True)
class TargetChoice:
    """Réponse de la boîte d'objectif : `value` en %, ou None pour retirer l'objectif. `margin` : marge de retour en
    points de pourcentage, seulement quand la boîte la proposait (objectif par défaut), sinon None."""

    value: float | None
    margin: float | None = None


class TargetDialog(QDialog):
    """Objectif de disponibilité sur 30 jours d'un objet (ou objectif par défaut), de 50 à 100 %. Avec `margin`
    (la marge de retour actuelle, réglage commun à tous les objets), la boîte propose aussi de la régler."""

    def __init__(
        self,
        parent: QWidget | None,
        name: str,
        current: float | None,
        *,
        for_default: bool,
        margin: float | None = None,
    ) -> None:
        super().__init__(parent)
        self.removed = False
        self.setWindowTitle(tr("Objectif de disponibilité"))
        self.setWindowIcon(app_icon())
        self.resize(520, 260 if margin is None else 360)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Objectif de disponibilité : {name}").format(name=name), "SectionTitle"))
        layout.addWidget(
            label(
                (
                    tr("S'applique aux tunnels et aux services qui n'ont pas d'objectif propre.")
                    if for_default
                    else tr("Disponibilité minimale attendue de cet objet.")
                )
                + " "
                + tr(
                    "Sur les 30 derniers jours, CMA prévient une fois quand elle passe dessous, puis quand elle "
                    "remonte (canaux d'alerte)."
                ),
                "muted",
                wrap=True,
            )
        )
        self.spin = QDoubleSpinBox()
        self.spin.setAccessibleName(tr("Objectif de disponibilité (%)"))
        self.spin.setRange(MIN_TARGET, MAX_TARGET)
        self.spin.setDecimals(2)
        self.spin.setSingleStep(0.1)
        self.spin.setSuffix(" %")
        self.spin.setValue(current if current is not None else SUGGESTED_TARGET)
        layout.addWidget(self.spin)
        self.margin_spin: QDoubleSpinBox | None = None
        if margin is not None:
            layout.addWidget(title(tr("Marge de retour"), "SectionTitle"))
            layout.addWidget(
                label(
                    tr(
                        "Le retour n'est annoncé que lorsque la disponibilité atteint l'objectif plus cette marge "
                        "(100 % au plus) : une disponibilité qui oscille autour de l'objectif ne fait plus alterner "
                        "alertes et retours. 0 : retour dès l'objectif."
                    ),
                    "muted",
                    wrap=True,
                )
            )
            self.margin_spin = QDoubleSpinBox()
            self.margin_spin.setAccessibleName(tr("Marge de retour (points de pourcentage)"))
            self.margin_spin.setRange(MIN_MARGIN, MAX_MARGIN)
            self.margin_spin.setDecimals(2)
            self.margin_spin.setSingleStep(0.01)
            self.margin_spin.setSuffix(" " + tr("pt"))
            self.margin_spin.setValue(clamp_margin(margin))
            layout.addWidget(self.margin_spin)
        layout.addStretch()
        buttons, self.ok_button = dialog_buttons(self, tr("Enregistrer"))
        self.ok_button.clicked.connect(self.accept)
        self.remove_button = buttons.addButton(
            tr("Retirer l'objectif"), QDialogButtonBox.ButtonRole.ActionRole
        )
        self.remove_button.setEnabled(current is not None)
        self.remove_button.clicked.connect(self._remove)
        layout.addWidget(buttons)

    def _remove(self) -> None:
        self.removed = True
        self.accept()

    def value(self) -> TargetChoice:
        margin = None if self.margin_spin is None else round(float(self.margin_spin.value()), 2)
        return TargetChoice(None if self.removed else float(self.spin.value()), margin)


def ask_target(
    parent: QWidget,
    name: str,
    current: float | None,
    *,
    for_default: bool = False,
    margin: float | None = None,
) -> TargetChoice | None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale. None : annulé."""
    dialog = TargetDialog(parent, name, current, for_default=for_default, margin=margin)
    return dialog.value() if dialog.exec() == QDialog.DialogCode.Accepted else None


class AvailabilityDialog(QDialog):
    def __init__(self, parent: QWidget | None, path: Path, ctx: GuiContext | None = None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.log = AvailabilityLog(path)
        self.keys = self.log.keys()
        self.setWindowTitle(tr("Disponibilité"))
        self.setWindowIcon(app_icon())
        self.resize(1000, 760)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Disponibilité des tunnels et des services"), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Relevés de la surveillance (toutes les 5 minutes pour les tunnels, 15 pour les services, CMA "
                    "ouvert ou fermé), gardés 90 jours. Un test « sans réponse » (réseau de ce poste) n'est pas compté."
                ),
                "muted",
                wrap=True,
            )
        )
        chart_row = QHBoxLayout()
        self.chart_title = label("", "meta")
        chart_row.addWidget(self.chart_title, 1)
        self.period = QComboBox()
        self.period.setAccessibleName(tr("Période"))
        for days in (7, 30, 90):
            self.period.addItem(tr("{n} derniers jours").format(n=days), days)
        self.period.setCurrentIndex(1)
        self.period.currentIndexChanged.connect(lambda _i: self._show_chart())
        chart_row.addWidget(self.period)
        layout.addLayout(chart_row)
        self.chart = UptimeChart()
        layout.addWidget(self.chart)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = data_table(
            [
                tr("Objet"),
                tr("Type"),
                tr("7 jours"),
                tr("30 jours"),
                tr("Temps moyen"),
                tr("Incidents (30 j)"),
                tr("Objectif"),
            ],
            tr("Disponibilité par objet"),
        )
        for column, width in enumerate((300, 90, 100, 100, 120)):
            self.table.horizontalHeader().resizeSection(column, width)
        # À la largeur de son en-tête et de son contenu : « Incidentes (30 d) » (es) ne tient pas dans 110 px.
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.itemSelectionChanged.connect(self._show_incidents)
        splitter.addWidget(self.table)
        self.incidents = data_table(
            [tr("Début"), tr("Fin"), tr("Durée"), tr("Cause"), tr("Objet")], tr("Incidents")
        )
        for column, width in enumerate((140, 140, 100, 180)):
            self.incidents.horizontalHeader().resizeSection(column, width)
        splitter.addWidget(self.incidents)
        layout.addWidget(splitter, 1)
        self.empty = label(
            tr("Aucun relevé pour l'instant : la surveillance remplit ce tableau au fil des tests."), "muted"
        )
        layout.addWidget(self.empty)
        footer = QHBoxLayout()
        self.all_button = button(tr("Tous les incidents"), "history")
        self.all_button.clicked.connect(lambda: self.fill_incidents(None))
        footer.addWidget(self.all_button)
        self.target_button = button(tr("Définir l'objectif…"), "pencil")
        self.target_button.clicked.connect(self.define_target)
        footer.addWidget(self.target_button)
        self.default_button = button(tr("Objectif par défaut…"), "shield-check")
        self.default_button.clicked.connect(self.define_default_target)
        footer.addWidget(self.default_button)
        self.export_button = button(tr("Exporter le rapport…"), "file-export")
        self.export_button.clicked.connect(self.export_report)
        footer.addWidget(self.export_button)
        self.export_note = label("", "muted")
        footer.addWidget(self.export_note, 1)
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)
        self._fill()

    def _config(self) -> Config:
        return self.ctx.config() if self.ctx is not None else Config()

    def _selected_key(self) -> str | None:
        row = self.table.currentRow()
        return self.keys[row] if 0 <= row < len(self.keys) else None

    def _update_buttons(self) -> None:
        self.target_button.setEnabled(self.ctx is not None and self._selected_key() is not None)
        self.default_button.setEnabled(self.ctx is not None)

    def define_target(self) -> None:
        """« Définir l'objectif… » pour l'objet choisi : pose, change ou retire son objectif propre."""
        key = self._selected_key()
        if key is None or self.ctx is None:
            return
        current = self._config().settings.availability_targets.get(key)
        answer = ask_target(self, self.log.label(key), current)
        if answer is None:
            return
        if self.ctx.update_config(lambda config: set_target(config, key, answer.value)):
            self._fill(key)

    def define_default_target(self) -> None:
        """« Objectif par défaut… » : celui des objets sans objectif propre."""
        if self.ctx is None:
            return
        current = self._config().settings.default_availability_target
        answer = ask_target(
            self,
            tr("tous les objets sans objectif propre"),
            current,
            for_default=True,
            margin=self._config().settings.availability_margin,
        )
        if answer is None:
            return

        def apply(config: Config) -> None:
            config.settings.default_availability_target = answer.value
            if answer.margin is not None:
                config.settings.availability_margin = answer.margin

        if self.ctx.update_config(apply):
            self._fill(self._selected_key())

    def _target_item(self, current: SloStatus) -> QTableWidgetItem:
        """Case « Objectif » : la valeur, ou « — » ; sous l'objectif, un ▼ et la teinte d'alerte (le texte seul dit
        déjà la situation, la couleur ne porte rien d'essentiel)."""
        if current.target is None:
            item = QTableWidgetItem("—")
            item.setToolTip(tr("Aucun objectif : « Définir l'objectif… » en pose un."))
            return item
        shown = target_text(current.target)
        if not current.below:
            item = QTableWidgetItem(shown)
            item.setToolTip(tr("Objectif de disponibilité sur 30 jours."))
            return item
        item = QTableWidgetItem(f"▼ {shown}")
        item.setForeground(QBrush(QColor(status_colors("danger", current_tokens())[0])))
        item.setToolTip(
            tr("Sous l'objectif : {percent} sur 30 jours pour {target}.").format(
                percent=percent(Stats((current.uptime or 0.0) / 100, None, None, current.checks)),
                target=shown,
            )
        )
        item.setData(Qt.ItemDataRole.AccessibleTextRole, tr("{target}, sous l'objectif").format(target=shown))
        return item

    def _fill(self, select: str | None = None) -> None:
        tokens = current_tokens()
        config = self._config()
        clear_items(self.table, len(self.keys))
        for row, key in enumerate(self.keys):
            week, month = self.log.stats(key, 7), self.log.stats(key, 30)
            slo = status(self.log, config, key)
            mean = f"{month.mean_ms:.0f} ms" if month.mean_ms is not None else "—"
            kind = tr("Tunnel") if key.startswith("tunnel:") else tr("Service")
            count = len(self.log.history(key, 30))
            values = (self.log.label(key), kind, percent(week), percent(month), mean, str(count))
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column in (2, 3):
                    stats = week if column == 2 else month
                    tone = "danger" if column == 3 and slo.below else uptime_tone(stats)
                    item.setForeground(QBrush(QColor(status_colors(tone, tokens)[0])))
                    item.setToolTip(tr("{n} tests").format(n=stats.checks))
                if column == 4 and month.max_ms is not None:
                    item.setToolTip(tr("Maximum : {ms:.0f} ms").format(ms=month.max_ms))
                self.table.setItem(row, column, item)
            self.table.setItem(row, TARGET_COLUMN, self._target_item(slo))
        if select in self.keys:
            self.table.selectRow(self.keys.index(select))
        self._update_buttons()
        self.table.setVisible(bool(self.keys))
        self.empty.setVisible(not self.keys)
        self.fill_incidents(None)
        self._show_chart()

    def _show_incidents(self) -> None:
        self._update_buttons()
        row = self.table.currentRow()
        self.fill_incidents(self.keys[row] if 0 <= row < len(self.keys) else None)
        self._show_chart()

    def days(self) -> int:
        data = self.period.currentData()
        return int(data) if isinstance(data, int) else 30

    def _show_chart(self) -> None:
        row = self.table.currentRow()
        key = self.keys[row] if 0 <= row < len(self.keys) else None
        self.chart.setVisible(key is not None)
        if key is None:
            self.chart_title.setText(tr("Choisissez un tunnel ou un service pour voir son graphique."))
            return
        self.chart_title.setText(
            tr("{name} : disponibilité par jour (barres) et temps de réponse moyen (courbe)").format(
                name=self.log.label(key)
            )
        )
        self.chart.set_series(daily(self.log, key, self.days()))

    def export_report(self) -> None:
        days = self.days()
        path = ask_report_path(self, days)
        if path is None:
            return
        rows, incidents = build(self.log, days)
        text = (
            report_csv(rows, incidents)
            if path.suffix.lower() == ".csv"
            else report_html(rows, incidents, days)
        )
        try:
            atomic_write_text(path, ("\ufeff" + text) if path.suffix.lower() == ".csv" else text)
        except OSError as exc:
            self.export_note.setText(tr("Export impossible : {error}").format(error=exc))
            return
        self.export_note.setText(tr("Rapport enregistré : {file}").format(file=path.name))

    def fill_incidents(self, key: str | None) -> None:
        rows: list[Incident] = self.log.history(key)
        tokens = current_tokens()
        clear_items(self.incidents, len(rows))
        for index, incident in enumerate(rows):
            values = (
                request_time(incident.started),
                request_time(incident.ended) if incident.ended else tr("en cours"),
                duration_text(incident.duration()),
                state_text(incident.state),
                incident.label,
            )
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 1 and incident.open:
                    item.setForeground(QBrush(QColor(status_colors("danger", tokens)[0])))
                self.incidents.setItem(index, column, item)


def show_availability(parent: QWidget, path: Path) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale. Le contexte de l'application
    (pour lire et poser les objectifs) est celui de la vue Cloudflare qui l'ouvre."""
    ctx = getattr(parent, "ctx", None)
    AvailabilityDialog(parent, path, ctx).exec()
