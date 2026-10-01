"""Boîte « Diagnostiquer » : contrôles explicites d'un accès Cloudflare, avec un rapport copiable."""

from __future__ import annotations

from PySide6.QtWidgets import QDialog, QDialogButtonBox, QGridLayout, QVBoxLayout, QWidget

from cma.core.diagnose import Check, diagnose_cloudflare_profile, format_report
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.icons import app_icon
from cma.ui.widgets import copy_to_clipboard, label, title

SYMBOLS = {
    "ok": ("✓", "success"),
    "warning": ("!", "warning"),
    "error": ("×", "error"),
    "skipped": ("–", "muted"),
}


class DiagnoseDialog(QDialog):
    def __init__(self, parent: QWidget | None, ctx: GuiContext, profile_id: str) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.profile_id = profile_id
        profile = ctx.config().cloudflare_profile(profile_id)
        self.profile_name = profile.name if profile else "?"
        heading = tr("Diagnostiquer « {name} »").format(name=self.profile_name)
        self.setWindowTitle(heading)
        self.setWindowIcon(app_icon())
        self.checks: list[Check] = []
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(heading, "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Contrôles lancés à votre demande, chacun limité à quelques secondes. Un service token est testé "
                    "en ouvrant brièvement cloudflared sur un port libre."
                ),
                "muted",
                wrap=True,
            )
        )
        self.status = label("", "meta")
        layout.addWidget(self.status)
        self.grid_host = QWidget()
        self.grid = QGridLayout(self.grid_host)
        self.grid.setContentsMargins(0, 0, 0, 0)
        self.grid.setHorizontalSpacing(12)
        self.grid.setVerticalSpacing(8)
        self.grid.setColumnStretch(2, 1)
        layout.addWidget(self.grid_host)
        layout.addStretch()
        buttons = QDialogButtonBox()
        self.rerun = buttons.addButton(tr("Relancer"), QDialogButtonBox.ButtonRole.ActionRole)
        self.rerun.clicked.connect(self.run)
        self.copy = buttons.addButton(tr("Copier le rapport"), QDialogButtonBox.ButtonRole.ActionRole)
        self.copy.clicked.connect(lambda: copy_to_clipboard(format_report(self.profile_name, self.checks)))
        close = buttons.addButton(tr("Fermer"), QDialogButtonBox.ButtonRole.RejectRole)
        close.clicked.connect(self.reject)
        layout.addWidget(buttons)
        self.resize(720, 460)
        self.run()

    def run(self) -> None:
        self.rerun.setEnabled(False)
        self.copy.setEnabled(False)
        self.status.setText(tr("Diagnostic en cours…"))
        self.ctx.run(
            diagnose_cloudflare_profile(self.ctx.manager, self.profile_id), self.show_checks, self._failed
        )

    def _failed(self, error: BaseException) -> None:
        self.rerun.setEnabled(True)
        self.status.setText(tr("Le diagnostic n'a pas pu aboutir : {error}").format(error=error))

    def show_checks(self, checks: list[Check]) -> None:
        self.checks = checks
        while self.grid.count():
            item = self.grid.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.deleteLater()
        for row, check in enumerate(checks):
            symbol, role = SYMBOLS[check.status]
            self.grid.addWidget(label(symbol, role), row, 0)
            self.grid.addWidget(label(check.name), row, 1)
            self.grid.addWidget(label(check.detail, "muted", wrap=True, selectable=True), row, 2)
        problems = sum(1 for c in checks if c.status == "error")
        self.status.setText(
            tr("Aucun problème détecté.")
            if problems == 0
            else tr("{n} contrôle(s) en échec.").format(n=problems)
        )
        self.rerun.setEnabled(True)
        self.copy.setEnabled(True)


def open_diagnosis(parent: QWidget | None, ctx: GuiContext, profile_id: str) -> None:
    DiagnoseDialog(parent, ctx, profile_id).exec()
