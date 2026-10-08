"""Onglet « Service tokens » de la vue Cloudflare : tokens du compte en cartes, création, échéance, secret et
suppression. Ce qui appartient à la vue (compte choisi, barre d'état, relecture, erreurs) se lit par `self.view`."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QStackedWidget, QTableWidgetItem, QVBoxLayout, QWidget

from cma.core.cfadmin import Overview
from cma.core.cfapi import CloudflareApiError, RemoteServiceToken
from cma.core.models import ServiceToken
from cma.i18n import tr
from cma.ui.views.cloud.cards import CARD_ROLE, TOKEN_ROLE, CardTable, token_card
from cma.ui.views.cloud.dialogs import ask_create_token
from cma.ui.views.cloud.helpers import expiry_label
from cma.ui.views.common import confirm
from cma.ui.widgets import EmptyState, button, label, primary_button

if TYPE_CHECKING:
    from cma.ui.views.cloud.view import CloudView


class TokensTab(QWidget):
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
        create = primary_button(tr("Créer un service token…"), "plus")
        create.clicked.connect(self.create_token)
        row.addWidget(create)
        self.extend_button = button(
            tr("Prolonger"), "hourglass", tooltip=tr("Repousser l'échéance, sans changer le secret")
        )
        self.extend_button.clicked.connect(self.extend_selected_token)
        row.addWidget(self.extend_button)
        self.rotate_button = button(tr("Changer le secret…"), "rotate-clockwise")
        self.rotate_button.clicked.connect(self.rotate_selected_token)
        row.addWidget(self.rotate_button)
        self.delete_button = button(tr("Supprimer…"), "trash", danger=True)
        self.delete_button.clicked.connect(self.delete_selected_token)
        row.addWidget(self.delete_button)
        row.addStretch()
        box.addLayout(row)
        box.addWidget(
            label(
                tr(
                    "Service tokens du compte Cloudflare. « Dans CMA » indique si le token est aussi "
                    "enregistré sur ce poste, avec son secret. Seul un token enregistré dans CMA peut changer "
                    "de secret : le nouveau part directement dans le coffre."
                ),
                "muted",
                wrap=True,
            )
        )
        self.table = CardTable(
            [tr("Nom"), tr("ID client"), tr("Expiration"), tr("Dans CMA")], tr("Service tokens du compte")
        )
        self.table.itemSelectionChanged.connect(self.update_actions)
        create_empty = primary_button(tr("Créer un service token…"), "plus")
        create_empty.clicked.connect(self.create_token)
        self.tokens_empty = EmptyState(
            "key",
            tr("Aucun service token dans ce compte."),
            tr("Le secret d'un token créé ici part directement dans le coffre de CMA."),
            [create_empty],
        )
        self.tokens_stack = QStackedWidget()
        self.tokens_stack.addWidget(self.table)
        self.tokens_stack.addWidget(self.tokens_empty)
        box.addWidget(self.tokens_stack, 1)

    def fill(self, overview: Overview) -> None:
        local = {t.client_id: t for t in self.ctx.config().tokens}
        for token in sorted(overview.tokens, key=lambda t: t.name.lower()):
            row = self.table.rowCount()
            self.table.insertRow(row)
            mine = local.get(token.client_id)
            if mine is None:
                in_cma, in_tone = tr("Non"), "neutral"
            elif self.ctx.core.secrets.get(mine.secret_key):
                in_cma, in_tone = tr("Oui"), "success"
            else:
                in_cma, in_tone = tr("Secret indisponible"), "warning"
            card = token_card(token, None if mine is None else (in_cma, in_tone))
            values = (token.name, token.client_id, expiry_label(token.expires_at), in_cma)
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == 0:
                    item.setData(TOKEN_ROLE, token)
                    item.setData(CARD_ROLE, card)
                    item.setData(
                        Qt.ItemDataRole.AccessibleTextRole,
                        ", ".join([token.name, token.client_id, *(badge[0] for badge in card.badges)]),
                    )
                self.table.setItem(row, column, item)
        self.tokens_stack.setCurrentWidget(self.table if overview.tokens else self.tokens_empty)

    def create_token(self) -> None:
        account = self.view.account.currentText() or "—"
        answer = ask_create_token(self, account, self.ctx.core.secrets.persistent)
        name, duration = answer if answer is not None else ("", "")
        name = name.strip()
        if not name:
            return
        self.view.status.setText(tr("Création du service token…"))

        def done(_token: ServiceToken) -> None:
            self.ctx.notify("success", tr("Service token créé et enregistré dans CMA."))
            self.view.refresh()

        def failed(error: BaseException) -> None:
            if isinstance(error, CloudflareApiError):
                self.view._error(error)
                return
            self.view._error(
                RuntimeError(
                    tr("Le token a été créé dans Cloudflare, mais son secret n'a pas pu être enregistré.")
                    + f" ({error})"
                )
            )
            self.view.refresh()

        self.ctx.run(self.view.admin.create_service_token(name, duration=duration), done, failed)

    def delete_selected_token(self) -> None:
        remote = self.selected_remote_token()
        if remote is None:
            return
        local = self._local_token(remote)
        text = tr(
            "Cloudflare révoque le token aussitôt : les accès qui l'utilisent sont refusés. Les politiques "
            "inutilisées qui ne servaient qu'à lui sont supprimées avec lui."
        )
        if local is not None:
            text += " " + tr("Sa copie dans CMA reste dans la vue Service tokens, à supprimer à part.")
        if not confirm(
            self,
            tr("Supprimer le service token « {name} » ?").format(name=remote.name),
            text,
            tr("Supprimer"),
        ):
            return
        self.view.status.setText(tr("Suppression du service token…"))

        def done(policies: list[str]) -> None:
            text = tr("Service token « {name} » supprimé.").format(name=remote.name)
            if policies:
                text += " " + tr("Politique(s) supprimée(s) avec lui : {names}.").format(
                    names=", ".join(policies)
                )
            self.ctx.notify("success", text)
            self.view.refresh()

        self.ctx.run(self.view.admin.delete_remote_token(remote), done, self.view._error)

    # --- Échéance et secret --------------------------------------------------------------

    def selected_remote_token(self) -> RemoteServiceToken | None:
        rows = self.table.selectionModel().selectedRows()
        item = self.table.item(rows[0].row(), 0) if rows else None
        token = item.data(TOKEN_ROLE) if item is not None else None
        return token if isinstance(token, RemoteServiceToken) else None

    def _local_token(self, remote: RemoteServiceToken | None) -> ServiceToken | None:
        if remote is None:
            return None
        return next((t for t in self.ctx.config().tokens if t.client_id == remote.client_id), None)

    def update_actions(self) -> None:
        remote = self.selected_remote_token()
        self.extend_button.setEnabled(remote is not None)
        self.rotate_button.setEnabled(self._local_token(remote) is not None)
        self.delete_button.setEnabled(remote is not None)

    def extend_selected_token(self) -> None:
        remote = self.selected_remote_token()
        if remote is None:
            return
        self.view.status.setText(tr("Prolongation du service token…"))

        def done(expires_at: str) -> None:
            self.ctx.notify(
                "success",
                tr("« {name} » expire désormais le {date}.").format(
                    name=remote.name, date=expiry_label(expires_at)
                ),
            )
            self.view.refresh()

        self.ctx.run(self.view.admin.extend_token(remote), done, self.view._error)

    def rotate_selected_token(self) -> None:
        local = self._local_token(self.selected_remote_token())
        if local is None:
            return
        users = [p.name for p in self.ctx.config().profiles_using_token(local.id)]
        text = tr(
            "Cloudflare crée un nouveau secret et révoque aussitôt l'ancien. Le nouveau secret est rangé dans le "
            "coffre de CMA ; l'ID client ne change pas."
        )
        if users:
            text += "\n\n" + tr("Les accès en cours qui l'utilisent sont à relancer : {names}.").format(
                names=", ".join(users)
            )
        if not confirm(
            self,
            tr("Changer le secret de « {name} » ?").format(name=local.name),
            text,
            tr("Changer le secret"),
        ):
            return
        self.view.status.setText(tr("Changement du secret…"))

        def done(token: ServiceToken) -> None:
            self.ctx.notify(
                "success", tr("Nouveau secret de « {name} » enregistré dans CMA.").format(name=token.name)
            )
            self.view.refresh()

        self.ctx.run(self.view.admin.rotate_token(local.id), done, self.view._error)
