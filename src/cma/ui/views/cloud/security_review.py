"""Bilan de sécurité du compte (Outils) : constats classés par gravité ; ceux que CMA sait corriger se cochent et se
corrigent ensemble, après une confirmation qui liste chaque action."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QCheckBox, QDialog, QHBoxLayout, QTableWidgetItem, QVBoxLayout, QWidget

from cma.core.cfadmin import CloudflareAdmin
from cma.core.models import Config
from cma.core.security import Finding, severity_label
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.icons import app_icon
from cma.ui.states import plural
from cma.ui.theme import current_tokens, status_colors
from cma.ui.views.cloud.helpers import data_table, describe_api_error
from cma.ui.views.common import confirm
from cma.ui.widgets import button, clear_items, label, primary_button, title

TONE_OF_SEVERITY = {"high": "danger", "medium": "warning", "low": "neutral"}


class SecurityReviewDialog(QDialog):
    def __init__(
        self,
        parent: QWidget | None,
        ctx: GuiContext,
        admin: CloudflareAdmin,
        on_change: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.admin = admin
        self.on_change = on_change
        self.findings: list[Finding] = []
        self.all_findings: list[Finding] = []
        self.setWindowTitle(tr("Bilan de sécurité"))
        self.setWindowIcon(app_icon())
        self.resize(1000, 560)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Bilan de sécurité du compte"), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Ce qui expose un service, ce qui traîne et ce qui est cassé. Cochez les constats que CMA sait "
                    "corriger, puis « Corriger la sélection… » : chaque action est listée avant d'être faite."
                ),
                "muted",
                wrap=True,
            )
        )
        self.table = data_table(
            [tr("Gravité"), tr("Constat"), tr("Objet"), tr("Correction")], tr("Constats du bilan de sécurité")
        )
        for column, width in enumerate((110, 260, 300)):
            self.table.horizontalHeader().resizeSection(column, width)
        self.table.itemSelectionChanged.connect(self._show_detail)
        self.table.itemChanged.connect(lambda _item: self._update_actions())
        layout.addWidget(self.table, 1)
        self.detail = label("", "meta", wrap=True, selectable=True)
        self.detail.setMinimumWidth(200)
        layout.addWidget(self.detail)
        self.summary = label("", "meta", wrap=True)
        layout.addWidget(self.summary)
        footer = QHBoxLayout()
        self.fix_button = primary_button(tr("Corriger la sélection…"), "circle-check")
        self.fix_button.clicked.connect(self.fix_selected)
        footer.addWidget(self.fix_button)
        self.rerun_button = button(tr("Refaire le bilan"), "refresh")
        self.rerun_button.clicked.connect(self.run_review)
        footer.addWidget(self.rerun_button)
        self.ignore_button = button(tr("Ignorer ce constat"), "eye-off")
        self.ignore_button.setToolTip(
            tr("Accepter ce constat (par exemple un site public voulu) : il ne sera plus compté ni proposé.")
        )
        self.ignore_button.clicked.connect(self.toggle_ignored)
        footer.addWidget(self.ignore_button)
        self.show_ignored = QCheckBox(tr("Afficher les constats ignorés"))
        self.show_ignored.toggled.connect(lambda _c: self.show_findings(self.all_findings))
        footer.addWidget(self.show_ignored)
        footer.addStretch()
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)
        self.run_review()

    def _busy(self, busy: bool, text: str = "") -> None:
        self.rerun_button.setEnabled(not busy)
        self.fix_button.setEnabled(not busy and bool(self.checked()))
        if text:
            self.summary.setText(text)

    def _failed(self, error: BaseException) -> None:
        self._busy(False)
        self.summary.setText(describe_api_error(error))

    def run_review(self) -> None:
        self._busy(True, tr("Lecture du compte pour le bilan…"))
        self.ctx.run(self.admin.security_review(), self.show_findings, self._failed)

    def ignored(self) -> set[str]:
        return set(self.ctx.config().settings.ignored_findings)

    def show_findings(self, findings: list[Finding]) -> None:
        self.all_findings = findings
        ignored = self.ignored()
        hidden = sum(1 for f in findings if f.ident in ignored)
        if not self.show_ignored.isChecked():
            findings = [f for f in findings if f.ident not in ignored]
        self.findings = findings
        tokens = current_tokens()
        self.table.blockSignals(True)
        clear_items(self.table, len(findings))
        for row, finding in enumerate(findings):
            muted = finding.ident in ignored
            severity = tr("Ignoré") if muted else severity_label(finding.severity)
            values = (severity, finding.title(), finding.target, finding.fix_label() or "—")
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(finding.detail())
                if column == 0:
                    item.setForeground(
                        QBrush(QColor(status_colors(TONE_OF_SEVERITY[finding.severity], tokens)[0]))
                    )
                if column == 3 and finding.fix and not muted:
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    # Cochées d'office : ce qui ne peut rien casser. Protéger un nom d'hôte le ferme à tous (un site
                    # public voulu le serait aussi) ; supprimer un token ou une politique se décide au cas par cas.
                    checked = finding.fix in ("catch_all_404", "delete_dns")
                    item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
                self.table.setItem(row, column, item)
        self.table.blockSignals(False)
        active = [f for f in findings if f.ident not in ignored]
        counts = {s: sum(1 for f in active if f.severity == s) for s in ("high", "medium", "low")}
        if active:
            text = tr("{high} élevé(s), {medium} moyen(s), {low} faible(s).").format(**counts)
        else:
            text = tr("Aucun constat : rien à signaler sur ce compte.")
        if hidden:
            text += " " + plural(hidden, tr("{n} constat ignoré."), tr("{n} constats ignorés."))
        self.summary.setText(text)
        if findings:
            self.table.selectRow(0)
        self._busy(False)

    def checked(self) -> list[Finding]:
        chosen: list[Finding] = []
        for row, finding in enumerate(self.findings):
            item = self.table.item(row, 3)
            if finding.fix and item is not None and item.checkState() == Qt.CheckState.Checked:
                chosen.append(finding)
        return chosen

    def _update_actions(self) -> None:
        self.fix_button.setEnabled(bool(self.checked()) and self.rerun_button.isEnabled())

    def selected(self) -> Finding | None:
        row = self.table.currentRow()
        return self.findings[row] if 0 <= row < len(self.findings) else None

    def _show_detail(self) -> None:
        finding = self.selected()
        self.detail.setText(finding.detail() if finding is not None else "")
        muted = finding is not None and finding.ident in self.ignored()
        self.ignore_button.setEnabled(finding is not None)
        self.ignore_button.setText(tr("Ne plus ignorer") if muted else tr("Ignorer ce constat"))

    def toggle_ignored(self) -> None:
        finding = self.selected()
        if finding is None:
            return
        ident = finding.ident

        def apply(config: Config) -> None:
            current = config.settings.ignored_findings
            config.settings.ignored_findings = (
                [i for i in current if i != ident] if ident in current else [*current, ident]
            )

        self.ctx.update_config(apply)
        self.show_findings(self.all_findings)

    def fix_selected(self) -> None:
        chosen = self.checked()
        if not chosen:
            return
        lines = [f"• {f.fix_label()} : {f.target}" for f in chosen]
        heading = plural(len(chosen), tr("Appliquer {n} correction ?"), tr("Appliquer {n} corrections ?"))
        if not confirm(self, heading, "\n".join(lines), tr("Corriger")):
            return
        self._busy(True, tr("Corrections en cours…"))

        def done(results: list[tuple[Finding, str | None]]) -> None:
            failures = [(f, error) for f, error in results if error]
            fixed = len(results) - len(failures)
            text = plural(fixed, tr("{n} correction faite."), tr("{n} corrections faites."))
            if failures:
                text += " " + tr("Échecs : {list}").format(
                    list="; ".join(f"{f.target} — {error}" for f, error in failures)
                )
            self.ctx.notify("warning" if failures else "success", text)
            if self.on_change is not None:
                self.on_change()
            self.run_review()

        self.ctx.run(self.admin.fix_findings(chosen), done, self._failed)


def show_security_review(
    parent: QWidget, ctx: GuiContext, admin: CloudflareAdmin, on_change: Callable[[], None] | None = None
) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    SecurityReviewDialog(parent, ctx, admin, on_change).exec()
