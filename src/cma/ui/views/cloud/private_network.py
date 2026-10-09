"""Réseaux privés d'un tunnel (WARP) : routes vers des plages d'adresses privées, et routage WARP du tunnel."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QSignalBlocker
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLineEdit,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.cfadmin import CloudflareAdmin, PrivateNetwork
from cma.core.cfapi import Tunnel
from cma.core.privnet import PrivateRoute, is_private, normalize_network
from cma.i18n import tr
from cma.ui.context import GuiContext
from cma.ui.icons import app_icon
from cma.ui.views.cloud.helpers import data_table, describe_api_error
from cma.ui.views.common import confirm
from cma.ui.widgets import button, clear_items, label, primary_button, title


class PrivateNetworkDialog(QDialog):
    def __init__(
        self,
        parent: QWidget | None,
        ctx: GuiContext,
        admin: CloudflareAdmin,
        tunnel: Tunnel,
        on_change: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.admin = admin
        self.tunnel = tunnel
        self.on_change = on_change
        self.routes: list[PrivateRoute] = []
        self.setWindowTitle(tr("Réseaux privés"))
        self.setWindowIcon(app_icon())
        self.resize(820, 480)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addWidget(
            title(tr("Réseaux privés du tunnel « {name} »").format(name=tunnel.name), "SectionTitle")
        )
        layout.addWidget(
            label(
                tr(
                    "Les appareils munis du client WARP de votre organisation atteignent ces plages d'adresses à "
                    "travers le tunnel, sans nom d'hôte publié. Il faut une route par plage et le routage WARP "
                    "activé sur le tunnel."
                ),
                "muted",
                wrap=True,
            )
        )
        self.warp = QCheckBox(tr("Routage WARP activé sur ce tunnel"))
        self.warp.setEnabled(False)
        self.warp.toggled.connect(self.set_warp_routing)
        layout.addWidget(self.warp)
        self.table = data_table(
            [tr("Plage d'adresses"), tr("Réseau virtuel"), tr("Commentaire")], tr("Routes du tunnel")
        )
        for column, width in enumerate((200, 180)):
            self.table.horizontalHeader().resizeSection(column, width)
        self.table.itemSelectionChanged.connect(self._update_actions)
        layout.addWidget(self.table, 1)
        form = QHBoxLayout()
        self.network = QLineEdit()
        self.network.setPlaceholderText("10.0.0.0/24")
        self.network.setAccessibleName(tr("Plage d'adresses"))
        self.network.returnPressed.connect(self.add_route)
        form.addWidget(self.network, 2)
        self.vnet = QComboBox()
        self.vnet.setAccessibleName(tr("Réseau virtuel"))
        form.addWidget(self.vnet, 1)
        self.comment = QLineEdit()
        self.comment.setPlaceholderText(tr("Commentaire (facultatif)"))
        self.comment.setAccessibleName(tr("Commentaire"))
        self.comment.setMaxLength(100)
        form.addWidget(self.comment, 2)
        self.add_button = primary_button(tr("Ajouter la route"), "plus")
        self.add_button.clicked.connect(self.add_route)
        form.addWidget(self.add_button)
        layout.addLayout(form)
        self.status = label("", "meta", wrap=True)
        layout.addWidget(self.status)
        footer = QHBoxLayout()
        self.remove_button = button(tr("Retirer la route…"), "trash", danger=True)
        self.remove_button.clicked.connect(self.remove_route)
        footer.addWidget(self.remove_button)
        footer.addStretch()
        close = button(tr("Fermer"))
        close.clicked.connect(self.accept)
        footer.addWidget(close)
        layout.addLayout(footer)
        self._busy(True)
        self.load()

    def _busy(self, busy: bool) -> None:
        self.add_button.setEnabled(not busy)
        self.warp.setEnabled(not busy)
        self._update_actions(busy)

    def _update_actions(self, busy: bool = False) -> None:
        self.remove_button.setEnabled(not busy and self.selected() is not None)

    def selected(self) -> PrivateRoute | None:
        row = self.table.currentRow()
        return self.routes[row] if 0 <= row < len(self.routes) and self.table.selectedItems() else None

    def _failed(self, error: BaseException) -> None:
        self._busy(False)
        self.status.setText(describe_api_error(error))

    def load(self) -> None:
        self.status.setText(tr("Lecture des routes…"))
        self.ctx.run(self.admin.private_network(self.tunnel), self.show_network, self._failed)

    def show_network(self, network: PrivateNetwork) -> None:
        self.routes = network.routes
        names = {n.id: n.name for n in network.virtual_networks}
        clear_items(self.table, len(self.routes))
        for row, route in enumerate(self.routes):
            vnet = route.virtual_network_name or names.get(route.virtual_network_id, route.virtual_network_id)
            for column, value in enumerate((route.network, vnet or "—", route.comment)):
                self.table.setItem(row, column, QTableWidgetItem(value))
        current = self.vnet.currentData()
        self.vnet.clear()
        for vnet in network.virtual_networks:
            text = tr("{name} (par défaut)").format(name=vnet.name) if vnet.is_default else vnet.name
            self.vnet.addItem(text, vnet.id)
        if current is not None and (index := self.vnet.findData(current)) >= 0:
            self.vnet.setCurrentIndex(index)
        with QSignalBlocker(self.warp):
            self.warp.setChecked(network.warp_routing)
        if self.routes and not network.warp_routing:
            self.status.setText(
                tr("Le routage WARP est coupé : ces routes ne servent pas tant qu'il ne l'est pas.")
            )
        else:
            self.status.setText(
                tr("Aucune route : ce tunnel ne donne accès à aucun réseau privé.") if not self.routes else ""
            )
        self._busy(False)

    def _changed(self) -> None:
        if self.on_change is not None:
            self.on_change()
        self.load()

    def add_route(self) -> None:
        try:
            network = normalize_network(self.network.text())
        except ValueError as exc:
            self.status.setText(str(exc))
            return
        if not is_private(network) and not confirm(
            self,
            tr("Router une plage publique ?"),
            tr(
                "{network} n'est pas une plage d'adresses privées : les appareils WARP passeront par ce tunnel pour "
                "l'atteindre, au lieu d'Internet."
            ).format(network=network),
            tr("Ajouter"),
        ):
            return
        self._busy(True)

        def done(route: PrivateRoute) -> None:
            self.network.clear()
            self.comment.clear()
            self.ctx.notify(
                "success",
                tr("{network} est routé par le tunnel « {name} ».").format(
                    network=route.network, name=self.tunnel.name
                ),
            )
            self._changed()

        vnet = self.vnet.currentData()
        self.ctx.run(
            self.admin.add_route(
                self.tunnel,
                network,
                comment=self.comment.text().strip(),
                virtual_network_id=str(vnet) if vnet else None,
            ),
            done,
            self._failed,
        )

    def remove_route(self) -> None:
        route = self.selected()
        if route is None or not confirm(
            self,
            tr("Retirer la route {network} ?").format(network=route.network),
            tr("Les appareils WARP n'atteindront plus {network} par ce tunnel.").format(
                network=route.network
            ),
            tr("Retirer"),
        ):
            return
        self._busy(True)
        self.ctx.run(self.admin.remove_route(route), lambda _r: self._changed(), self._failed)

    def set_warp_routing(self, enabled: bool) -> None:
        if (
            not enabled
            and self.routes
            and not confirm(
                self,
                tr("Couper le routage WARP ?"),
                tr("Les routes de ce tunnel cesseront de fonctionner jusqu'à sa réactivation."),
                tr("Couper"),
            )
        ):
            with QSignalBlocker(self.warp):
                self.warp.setChecked(True)
            return
        self._busy(True)
        self.ctx.run(
            self.admin.set_warp_routing(self.tunnel, enabled), lambda _r: self._changed(), self._failed
        )


def show_private_network(
    parent: QWidget,
    ctx: GuiContext,
    admin: CloudflareAdmin,
    tunnel: Tunnel,
    on_change: Callable[[], None] | None = None,
) -> None:
    """Fonction de module : les tests la remplacent pour ne pas ouvrir de boîte modale."""
    PrivateNetworkDialog(parent, ctx, admin, tunnel, on_change).exec()
