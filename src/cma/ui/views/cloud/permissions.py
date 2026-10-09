"""Permissions du jeton d'API : chaque fonction de CMA, la permission qu'elle demande, et si elle fonctionne."""

from __future__ import annotations

from PySide6.QtCore import QUrl
from PySide6.QtGui import QBrush, QColor, QDesktopServices
from PySide6.QtWidgets import QDialog, QHBoxLayout, QTableWidgetItem, QVBoxLayout, QWidget

from cma.core.cfadmin import CloudflareAdmin
from cma.core.cfapi import TOKENS_PAGE
from cma.core.permissions import PermissionCheck
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.icons import app_icon
from cma.ui.states import plural
from cma.ui.theme import current_tokens, status_colors
from cma.ui.views.cloud.helpers import data_table, describe_api_error
from cma.ui.widgets import button, clear_items, label, primary_button, title


def check_label(check: PermissionCheck) -> tuple[str, str]:
    """(texte, teinte) de l'état d'une vérification."""
    if check.state == "ok":
        return tr("Fonctionne"), "success"
    if check.state == "denied":
        return (tr("Manquante (facultative)"), "neutral") if check.optional else (tr("Manquante"), "danger")
    if check.state == "skipped":
        return tr("Non vérifiée"), "neutral"
    return tr("Erreur"), "warning"


class PermissionsDialog(QDialog):
    def __init__(self, parent: QWidget | None, ctx: GuiContext, admin: CloudflareAdmin) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.admin = admin
        self.checks: list[PermissionCheck] = []
        self.setWindowTitle(tr("Permissions du jeton"))
        self.setWindowIcon(app_icon())
        self.resize(900, 480)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(title(tr("Permissions du jeton d'API"), "SectionTitle"))
        layout.addWidget(
            label(
                tr(
                    "Chaque fonction est vérifiée par une lecture : rien n'est modifié sur le compte. Une permission "
                    "« Edit » n'est donc vérifiée qu'en lecture ; un refus d'écriture se verra au moment de modifier."
                ),
                "muted",
                wrap=True,
            )
        )
        self.table = data_table(
            [tr("Fonction"), tr("Permission"), tr("État"), tr("Détail")], tr("Permissions du jeton")
        )
        for column, width in enumerate((220, 240, 200)):
            self.table.horizontalHeader().resizeSection(column, width)
        layout.addWidget(self.table, 1)
        self.summary = label("", "meta", wrap=True)
        layout.addWidget(self.summary)
        footer = QHBoxLayout()
        self.check_button = primary_button(tr("Vérifier de nouveau"), "refresh")
        self.check_button.clicked.connect(self.run_checks)
        footer.addWidget(self.check_button)
        edit = button(tr("Modifier le jeton dans Cloudflare"), "external-link")
        edit.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(TOKENS_PAGE)))
        footer.addWidget(edit)
        footer.addStretch()
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)
        self.run_checks()

    def run_checks(self) -> None:
        self.check_button.setEnabled(False)
        self.summary.setText(tr("Vérification des permissions…"))

        def failed(error: BaseException) -> None:
            self.check_button.setEnabled(True)
            self.summary.setText(describe_api_error(error))

        self.ctx.run(self.admin.permissions(), self.show_checks, failed)

    def show_checks(self, checks: list[PermissionCheck]) -> None:
        self.checks = checks
        tokens = current_tokens()
        clear_items(self.table, len(checks))
        for row, check in enumerate(checks):
            text, tone = check_label(check)
            for column, value in enumerate((check.feature, check.permission, text, check.detail)):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 2:
                    item.setForeground(QBrush(QColor(status_colors(tone, tokens)[0])))
                self.table.setItem(row, column, item)
        missing = [c for c in checks if c.state == "denied" and not c.optional]
        if missing:
            self.summary.setText(
                plural(len(missing), tr("{n} permission manque"), tr("{n} permissions manquent"))
                + " : "
                + ", ".join(sorted({c.permission for c in missing}))
            )
        else:
            self.summary.setText(tr("Toutes les permissions nécessaires sont présentes."))
        self.check_button.setEnabled(True)


def show_permissions(parent: QWidget, ctx: GuiContext, admin: CloudflareAdmin) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    PermissionsDialog(parent, ctx, admin).exec()
