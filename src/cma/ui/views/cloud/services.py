"""État des services publiés dans la vue Cloudflare : pastille d'une carte de nom d'hôte, info-bulle, et tableau
« Tester tous les noms d'hôte »."""

from __future__ import annotations

from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QDialog, QHBoxLayout, QTableWidgetItem, QVBoxLayout, QWidget

from cma.core.hostprobe import HostProbe
from cma.core.servicewatch import ServiceResult, ServiceTarget
from cma.i18n import tr
from cma.ui.icons import app_icon
from cma.ui.states import plural
from cma.ui.theme import current_tokens, status_colors
from cma.ui.views.cloud.helpers import data_table
from cma.ui.widgets import button, clear_items, label, title


def probe_label(probe: HostProbe) -> str:
    """Résultat en quelques mots, pour une pastille ou une colonne."""
    return {
        "ok": tr("Répond"),
        "access": tr("Page Access"),
        "challenge": tr("Vérification de navigateur"),
        "no_connector": tr("Aucun connecteur"),
        "origin_down": tr("Service injoignable"),
        "refused": tr("Token refusé"),
        "not_found": tr("Nom introuvable"),
        "wildcard": tr("Nom générique"),
        "unreachable": tr("Sans réponse"),
    }.get(probe.state, probe.state)


def probe_tone(probe: HostProbe) -> str:
    """Teinte de la pastille : les pannes en couleur, le reste discret."""
    return {
        "ok": "success",
        "origin_down": "warning",
        "refused": "warning",
        "no_connector": "danger",
        "not_found": "danger",
    }.get(probe.state, "neutral")


def service_badge(result: ServiceResult | None) -> tuple[str, str, str] | None:
    """(texte, icône, teinte) de la pastille d'une carte. La page Access n'en a pas : la carte dit déjà « Access »."""
    if result is None or result.probe.state in ("access", "wildcard"):
        return None
    probe = result.probe
    icon = {
        "ok": "circle-check",
        "origin_down": "plug-connected-x",
        "no_connector": "plug-connected-x",
        "not_found": "circle-x",
        "challenge": "shield-check",
        "refused": "key-off",
    }.get(probe.state, "alert-circle")
    return probe_label(probe), icon, probe_tone(probe)


def service_tooltip(result: ServiceResult) -> str:
    """Résumé, conseil et heure du test, pour l'info-bulle d'une carte."""
    lines = [result.probe.summary(result.target.label)]
    if advice := result.probe.advice():
        lines.append(advice)
    lines.append(tr("Testé depuis Internet à {time}.").format(time=result.at.strftime("%H:%M")))
    return "\n".join(lines)


class ServiceTestsDialog(QDialog):
    """Résultat de « Tester tous les noms d'hôte » : un nom par ligne, pannes en premier, conseil de la ligne
    choisie en bas."""

    def __init__(self, parent: QWidget | None, results: list[tuple[ServiceTarget, HostProbe]]) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Test des noms d'hôte depuis Internet"))
        self.setWindowIcon(app_icon())
        self.resize(900, 520)
        order = {"no_connector": 0, "not_found": 0, "origin_down": 1, "refused": 1, "unreachable": 2}
        self.results = sorted(results, key=lambda r: (order.get(r[1].state, 3), r[0].label.lower()))
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Test des noms d'hôte depuis Internet"), "SectionTitle"))
        problems = sum(1 for _t, p in self.results if probe_tone(p) in ("warning", "danger"))
        summary = plural(len(self.results), tr("{n} nom testé"), tr("{n} noms testés"))
        if problems:
            summary += " · " + plural(problems, tr("{n} en panne"), tr("{n} en panne"))
        layout.addWidget(label(summary, "muted"))
        self.table = data_table(
            [tr("Nom d'hôte"), tr("Tunnel"), tr("Résultat"), tr("Code")], tr("Résultats des tests")
        )
        for column, width in enumerate((300, 140, 190)):
            self.table.horizontalHeader().resizeSection(column, width)
        self.table.itemSelectionChanged.connect(self._show_advice)
        layout.addWidget(self.table, 1)
        self.advice = label("", "meta", wrap=True, selectable=True)
        self.advice.setMinimumWidth(200)
        layout.addWidget(self.advice)
        footer = QHBoxLayout()
        footer.addStretch()
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)
        self._fill()

    def _fill(self) -> None:
        tokens = current_tokens()
        clear_items(self.table, len(self.results))
        for row, (target, probe) in enumerate(self.results):
            values = (target.label, target.tunnel_name, probe_label(probe), str(probe.status or ""))
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(probe.summary(target.label))
                if column == 2:
                    item.setForeground(QBrush(QColor(status_colors(probe_tone(probe), tokens)[0])))
                self.table.setItem(row, column, item)
        if self.results:
            self.table.selectRow(0)

    def _show_advice(self) -> None:
        row = self.table.currentRow()
        if not 0 <= row < len(self.results):
            self.advice.setText("")
            return
        target, probe = self.results[row]
        parts = [probe.summary(target.label)]
        if not target.web:
            parts.append(
                tr(
                    "Service non HTTP : seuls le DNS et Access sont testés ; la connexion complète se teste avec "
                    "une session (« Tester le service »)."
                )
            )
        if advice := probe.advice():
            parts.append(advice)
        self.advice.setText("\n".join(parts))


def show_service_tests(parent: QWidget, results: list[tuple[ServiceTarget, HostProbe]]) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    ServiceTestsDialog(parent, results).exec()
