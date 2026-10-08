"""Onglet « Applications Access » de la vue Cloudflare : applications en cartes, protection d'un nom d'hôte,
autorisation d'un token, politiques, réglages, journal des accès et suppression. Ce qui appartient à la vue (compte
choisi, barre d'état, relecture, erreurs, dernière lecture du compte) se lit par `self.view`."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QStackedWidget, QTableWidgetItem, QVBoxLayout, QWidget

from cma.core.cfadmin import Overview
from cma.core.cfapi import AccessApp, AccessRequest, AppSettings
from cma.core.policies import AccessGroup, AccessPolicy
from cma.i18n import tr
from cma.ui.views.cloud.access_log import show_access_log
from cma.ui.views.cloud.cards import CARD_ROLE, TUNNEL_ROLE, CardTable, app_card
from cma.ui.views.cloud.dialogs import ask_allow, ask_app_settings, ask_protect
from cma.ui.views.cloud.helpers import app_type_label, describe_api_error
from cma.ui.views.cloud.policies import AccountPoliciesDialog, PoliciesDialog, show_policies
from cma.ui.views.cloud.summary import protected_hosts
from cma.ui.views.common import confirm
from cma.ui.widgets import EmptyState, button, label, primary_button

if TYPE_CHECKING:
    from cma.ui.views.cloud.view import CloudView


class AppsTab(QWidget):
    def __init__(self, view: CloudView) -> None:
        super().__init__()
        self.view = view
        self.ctx = view.ctx
        self._build()

    def _build(self) -> None:
        box = QVBoxLayout(self)
        box.setContentsMargins(0, 12, 0, 0)
        box.setSpacing(8)
        row = QHBoxLayout()
        protect = primary_button(tr("Protéger un nom d'hôte…"), "shield-check")
        protect.clicked.connect(self.protect_hostname)
        self.allow_button = button(tr("Autoriser un service token…"), "key")
        self.allow_button.clicked.connect(self.allow_token)
        self.policies_button = button(tr("Politiques…"), "user")
        self.policies_button.setToolTip(tr("Qui peut atteindre l'application"))
        self.policies_button.clicked.connect(self.manage_policies)
        self.app_settings_button = button(tr("Réglages…"), "settings")
        self.app_settings_button.setToolTip(tr("Nom, durée de session, lanceur d'applications"))
        self.app_settings_button.clicked.connect(self.edit_app_settings)
        self.delete_app_button = button(tr("Supprimer…"), "trash", danger=True)
        self.delete_app_button.clicked.connect(self.delete_selected_app)
        account_policies = button(tr("Politiques du compte…"), "list-details")
        account_policies.clicked.connect(self.manage_account_policies)
        self.access_log_button = button(tr("Journal des accès…"), "history")
        self.access_log_button.setToolTip(tr("Qui s'est connecté, quand, autorisé ou refusé"))
        self.access_log_button.clicked.connect(self.open_access_log)
        row.addWidget(protect)
        row.addWidget(self.allow_button)
        row.addWidget(self.policies_button)
        row.addWidget(self.app_settings_button)
        row.addWidget(self.delete_app_button)
        row.addStretch()
        row.addWidget(self.access_log_button)
        row.addWidget(account_policies)
        box.addLayout(row)
        self.apps_hint = label(
            tr("Sélectionnez une application pour voir qui y a accès ou y autoriser un service token."),
            "muted",
        )
        box.addWidget(self.apps_hint)
        self.table = CardTable([tr("Nom"), tr("Domaine"), tr("Type")], tr("Applications Access"))
        self.table.itemSelectionChanged.connect(self.update_actions)
        protect_empty = primary_button(tr("Protéger un nom d'hôte…"), "shield-check")
        protect_empty.clicked.connect(self.protect_hostname)
        self.apps_empty = EmptyState(
            "shield-check",
            tr("Aucune application Access."),
            tr("Une application Access protège un nom d'hôte publié."),
            [protect_empty],
        )
        self.apps_stack = QStackedWidget()
        self.apps_stack.addWidget(self.table)
        self.apps_stack.addWidget(self.apps_empty)
        box.addWidget(self.apps_stack, 1)

    def fill(self, overview: Overview) -> None:
        for app in sorted(overview.apps, key=lambda a: a.name.lower()):
            row = self.table.rowCount()
            self.table.insertRow(row)
            card = app_card(app)
            for column, value in enumerate((app.name, app.domain, app_type_label(app.type))):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                item.setData(TUNNEL_ROLE, app)
                if column == 0:
                    item.setData(CARD_ROLE, card)
                    item.setData(
                        Qt.ItemDataRole.AccessibleTextRole,
                        ", ".join([app.name, app.domain, *(badge[0] for badge in card.badges)]),
                    )
                self.table.setItem(row, column, item)
        self.apps_stack.setCurrentWidget(self.table if overview.apps else self.apps_empty)

    # --- Sélection et politiques ------------------------------------------------------------------------------

    def selected_app(self) -> AccessApp | None:
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 and self.table.selectedItems() else None
        app = item.data(TUNNEL_ROLE) if item is not None else None
        return app if isinstance(app, AccessApp) else None

    def update_actions(self) -> None:
        app = self.selected_app()
        has_app = app is not None
        self.allow_button.setEnabled(has_app)
        self.policies_button.setEnabled(has_app)
        self.delete_app_button.setEnabled(has_app)
        self.app_settings_button.setEnabled(app is not None and app.type == "self_hosted")
        self.apps_hint.setVisible(not has_app and bool(self.view.overview and self.view.overview.apps))

    def _policy_tokens(self) -> dict[str, str]:
        """Service tokens du compte par nom, pour la saisie « token : Nom »."""
        return {t.name: t.id for t in (self.view.overview.tokens if self.view.overview else [])}

    def manage_policies(self) -> None:
        """Politiques Access de l'application sélectionnée : lecture, puis modification dans une boîte de dialogue."""
        app = self.selected_app()
        if app is None:
            return
        self.view.status.setText(tr("Lecture des politiques…"))

        async def load() -> tuple[list[AccessPolicy], list[AccessGroup], list[AccessPolicy]]:
            policies, groups = await self.view.admin.policies(app)
            return policies, groups, await self.view.admin.account_policies()

        async def after(action: Awaitable[object]) -> list[AccessPolicy]:
            await action
            return (await self.view.admin.policies(app))[0]

        def loaded(result: tuple[list[AccessPolicy], list[AccessGroup], list[AccessPolicy]]) -> None:
            self.view._show_summary()
            policies, groups, account = result
            dialog: PoliciesDialog | None = None

            def failed(error: BaseException) -> None:
                if dialog is not None:
                    dialog.failed()
                self.view._error(error)

            def save(policy: AccessPolicy, done: Callable[[list[AccessPolicy]], None]) -> None:
                self.ctx.run(after(self.view.admin.save_policy(app, policy)), done, failed)

            def remove(policy: AccessPolicy, done: Callable[[list[AccessPolicy]], None]) -> None:
                self.ctx.run(after(self.view.admin.remove_policy(app, policy)), done, failed)

            def attach(policy: AccessPolicy, done: Callable[[list[AccessPolicy]], None]) -> None:
                self.ctx.run(after(self.view.admin.attach_policy(app, policy)), done, failed)

            dialog = PoliciesDialog(
                self,
                app,
                policies,
                groups,
                self._policy_tokens(),
                account,
                save=save,
                remove=remove,
                attach=attach,
            )
            show_policies(dialog)

        self.ctx.run(load(), loaded, self.view._error)

    def manage_account_policies(self) -> None:
        """Toutes les politiques réutilisables du compte : modifier, supprimer celles qui ne servent plus."""
        self.view.status.setText(tr("Lecture des politiques…"))

        async def load() -> tuple[list[AccessPolicy], list[AccessGroup]]:
            return await self.view.admin.account_policies(), await self.view.admin.groups()

        async def after(action: Awaitable[object]) -> list[AccessPolicy]:
            await action
            return await self.view.admin.account_policies()

        def loaded(result: tuple[list[AccessPolicy], list[AccessGroup]]) -> None:
            self.view._show_summary()
            policies, groups = result
            dialog: AccountPoliciesDialog | None = None

            def failed(error: BaseException) -> None:
                if dialog is not None:
                    dialog.failed()
                self.view._error(error)

            def save(policy: AccessPolicy, done: Callable[[list[AccessPolicy]], None]) -> None:
                self.ctx.run(after(self.view.admin.save_policy(None, policy)), done, failed)

            def delete(policy: AccessPolicy, done: Callable[[list[AccessPolicy]], None]) -> None:
                self.ctx.run(after(self.view.admin.delete_account_policy(policy)), done, failed)

            dialog = AccountPoliciesDialog(
                self, policies, groups, self._policy_tokens(), save=save, delete=delete
            )
            show_policies(dialog)

        self.ctx.run(load(), loaded, self.view._error)

    def open_access_log(self) -> None:
        """Dernières connexions du compte ; filtrées d'emblée sur l'application choisie, s'il y en a une."""
        selected = self.selected_app()
        apps = list(self.view.overview.apps) if self.view.overview is not None else []
        # Cloudflare journalise un service token par son Client ID : on le nomme d'après les tokens du compte.
        names = (
            {t.client_id: t.name for t in self.view.overview.tokens} if self.view.overview is not None else {}
        )
        self.view.status.setText(tr("Lecture du journal des accès…"))

        def done(requests: list[AccessRequest]) -> None:
            self.view._show_summary()
            show_access_log(self, requests, apps, selected, names)

        self.ctx.run(self.view.admin.access_requests(), done, self.view._error)

    def edit_app_settings(self) -> None:
        """Réglages de l'application choisie : relus, présentés, puis renvoyés par un PUT complet."""
        app = self.selected_app()
        if app is None:
            return
        self.view.status.setText(tr("Lecture des réglages…"))

        def loaded(settings: AppSettings) -> None:
            self.view._show_summary()
            answer = ask_app_settings(self, app, settings)
            if answer is None or answer == settings:
                return

            def saved(_settings: AppSettings) -> None:
                self.ctx.notify("success", tr("Réglages de {name} enregistrés.").format(name=answer.name))
                self.view.refresh()

            self.ctx.run(self.view.admin.save_app_settings(app, answer), saved, self.view._error)

        self.ctx.run(self.view.admin.app_settings(app), loaded, self.view._error)

    def delete_selected_app(self) -> None:
        app = self.selected_app()
        if app is None or not confirm(
            self,
            tr("Supprimer l'application Access « {name} » ?").format(name=app.name),
            tr(
                "{domain} ne sera plus protégé par Cloudflare Access : s'il est publié par un tunnel, il devient "
                "joignable sans authentification. Les politiques réutilisables restent dans le compte."
            ).format(domain=app.domain),
            tr("Supprimer"),
        ):
            return
        self.view.status.setText(tr("Suppression de l'application…"))

        def done(_result: object) -> None:
            self.ctx.notify("success", tr("Application « {name} » supprimée.").format(name=app.name))
            self.view.refresh()

        self.ctx.run(self.view.admin.delete_app(app), done, self.view._error)

    def protect_hostname(self) -> None:
        hostnames = []
        if self.view.overview is not None:
            protected = protected_hosts(self.view.overview.apps)
            hostnames = [
                r.hostname
                for v in self.view.overview.tunnels
                for r in v.hostnames
                if r.hostname.lower() not in protected
            ]
        hostname = ask_protect(self, hostnames)
        hostname = (hostname or "").strip().lower()
        if not hostname:
            return
        self.view.status.setText(tr("Création de l'application Access…"))

        def done(_app: AccessApp) -> None:
            self.ctx.notify("success", tr("Application Access créée."))
            self.view.refresh()

        def failed(error: BaseException) -> None:
            self.view._error(
                RuntimeError(
                    tr("Impossible de créer la protection Access.") + " " + describe_api_error(error)
                )
            )

        self.ctx.run(self.view.admin.protect_hostname(hostname), done, failed)

    def allow_token(self) -> None:
        app = self.selected_app()
        if app is None:
            self.ctx.notify("info", tr("Sélectionnez d'abord une application Access."))
            return
        remote = {t.client_id for t in self.view.overview.tokens} if self.view.overview else set()
        tokens = [t for t in self.ctx.config().tokens if t.client_id in remote]
        token = ask_allow(self, app, tokens)
        if token is None:
            return
        self.view.status.setText(tr("Ajout de l'autorisation…"))

        def done(_policy: object) -> None:
            self.view._show_summary()
            self.ctx.notify(
                "success",
                tr("Service token autorisé : {token} sur {app}.").format(token=token.name, app=app.domain),
            )

        def failed(error: BaseException) -> None:
            self.view._error(
                RuntimeError(
                    tr("L'autorisation n'a pas pu être enregistrée.") + " " + describe_api_error(error)
                )
            )

        self.ctx.run(self.view.admin.allow_token(app, token.id), done, failed)
