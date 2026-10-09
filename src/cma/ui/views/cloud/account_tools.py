"""Menu « Outils » de l'en-tête du compte : journal d'audit, instantanés de la configuration, permissions du jeton."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QMenu, QPushButton

from cma.core.cfapi import Account
from cma.i18n import tr
from cma.ui.widgets import button

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from cma.core.audit import AuditEntry
    from cma.core.cfadmin import CloudflareAdmin
    from cma.ui.context import GuiContext
    from cma.ui.views.cloud.view import CloudView


# Chaque boîte n'est importée qu'à son ouverture : ces modules ne pèsent pas sur le démarrage. Les tests remplacent
# ces fonctions de module.
def show_audit_log(parent: CloudView, entries: list[AuditEntry]) -> None:
    from cma.ui.views.cloud.audit_log import show_audit_log as show

    show(parent, entries)


def show_availability(parent: CloudView, path: Path) -> None:
    from cma.ui.views.cloud.availability import show_availability as show

    show(parent, path)


def show_permissions(parent: CloudView, ctx: GuiContext, admin: CloudflareAdmin) -> None:
    from cma.ui.views.cloud.permissions import show_permissions as show

    show(parent, ctx, admin)


def show_security_review(
    parent: CloudView, ctx: GuiContext, admin: CloudflareAdmin, refresh: Callable[[], None]
) -> None:
    from cma.ui.views.cloud.security_review import show_security_review as show

    show(parent, ctx, admin, refresh)


def show_snapshots(parent: CloudView, ctx: GuiContext, admin: CloudflareAdmin, account: Account) -> None:
    from cma.ui.views.cloud.snapshots import show_snapshots as show

    show(parent, ctx, admin, account)


class AccountTools:
    def __init__(self, view: CloudView) -> None:
        self.view = view
        self.button: QPushButton = button(
            tr("Outils"), "settings", tooltip=tr("Journal d'audit, instantanés, permissions")
        )
        self.menu = QMenu(self.button)
        self.menu.addAction(tr("Bilan de sécurité…"), self.open_security_review)
        self.menu.addAction(tr("Disponibilité…"), self.open_availability)
        self.menu.addAction(tr("Journal d'audit du compte…"), self.open_audit_log)
        self.menu.addAction(tr("Instantanés de la configuration…"), self.open_snapshots)
        self.menu.addAction(tr("Permissions du jeton…"), self.open_permissions)
        self.menu.addSeparator()
        self.menu.addAction(tr("Ajouter un jeton d'API…"), view.start_add_token)
        self.button.setMenu(self.menu)

    def account(self) -> Account | None:
        data = self.view.account.currentData()
        return data if isinstance(data, Account) else None

    def open_audit_log(self) -> None:
        view = self.view
        view.status.setText(tr("Lecture du journal d'audit…"))

        def done(entries: list[AuditEntry]) -> None:
            view._show_summary()
            show_audit_log(view, entries)

        view.ctx.run(view.admin.audit_log(days=30), done, view._error)

    def open_snapshots(self) -> None:
        account = self.account()
        if account is not None:
            show_snapshots(self.view, self.view.ctx, self.view.admin, account)

    def open_security_review(self) -> None:
        show_security_review(self.view, self.view.ctx, self.view.admin, self.view.refresh)

    def open_availability(self) -> None:
        show_availability(self.view, self.view.ctx.paths.data_dir / "availability.json")

    def open_permissions(self) -> None:
        show_permissions(self.view, self.view.ctx, self.view.admin)
