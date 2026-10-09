"""Objets du compte Cloudflare dans la palette Ctrl+K : tunnels, noms d'hôte, applications Access, service tokens.

Seul le compte déjà lu (dernière lecture de la vue Cloudflare) est proposé : la palette ne lance aucun appel. Choisir
un objet ouvre la vue Cloudflare sur le bon onglet, l'objet sélectionné et visible.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PySide6.QtWidgets import QTableWidget

from cma.core.cfapi import AccessApp, IngressRule, RemoteServiceToken, Tunnel
from cma.i18n import tr
from cma.ui.dialogs.palette import PaletteEntry
from cma.ui.views.cloud.cards import RULE_ROLE, TOKEN_ROLE, TUNNEL_ROLE

if TYPE_CHECKING:
    from cma.ui.views.cloud.view import CloudView

TUNNELS_TAB, APPS_TAB, TOKENS_TAB = 0, 1, 2


def reveal_tunnel(view: CloudView, tunnel_id: str, rule: IngressRule | None = None) -> bool:
    """Sélectionne le tunnel (ou l'une de ses règles) dans l'onglet Tunnels ; False s'il n'y est plus."""
    view.tabs.setCurrentIndex(TUNNELS_TAB)
    for row in range(view.tree.topLevelItemCount()):
        parent = view.tree.topLevelItem(row)
        tunnel = parent.data(0, TUNNEL_ROLE) if parent is not None else None
        if parent is None or not isinstance(tunnel, Tunnel) or tunnel.id != tunnel_id:
            continue
        target = parent
        if rule is not None:
            for index in range(parent.childCount()):
                child = parent.child(index)
                if child is not None and child.data(0, RULE_ROLE) == rule:
                    target = child
        parent.setExpanded(True)
        view.tree.setCurrentItem(target)
        view.tree.scrollToItem(target)
        return True
    return False


def _reveal_row(
    view: CloudView, tab: int, table: QTableWidget, role: int, match: Callable[[object], bool]
) -> bool:
    view.tabs.setCurrentIndex(tab)
    for row in range(table.rowCount()):
        item = table.item(row, 0)
        if item is not None and match(item.data(role)):
            table.selectRow(row)
            table.scrollToItem(item)
            return True
    return False


def reveal_app(view: CloudView, app_id: str) -> bool:
    return _reveal_row(
        view,
        APPS_TAB,
        view.apps_tab.table,
        TUNNEL_ROLE,
        lambda data: isinstance(data, AccessApp) and data.id == app_id,
    )


def reveal_token(view: CloudView, token_id: str) -> bool:
    return _reveal_row(
        view,
        TOKENS_TAB,
        view.tokens_tab.table,
        TOKEN_ROLE,
        lambda data: isinstance(data, RemoteServiceToken) and data.id == token_id,
    )


def palette_entries(view: CloudView, show: Callable[[], None]) -> list[PaletteEntry]:
    """Entrées de la palette pour le compte lu ; `show` affiche la vue Cloudflare avant de sélectionner."""
    overview = view.overview
    if overview is None:
        return []
    section = tr("Compte Cloudflare")
    entries: list[PaletteEntry] = []

    def run(action: Callable[[], object]) -> Callable[[], None]:
        def go() -> None:
            show()
            action()

        return go

    for tunnel_view in overview.tunnels:
        tunnel = tunnel_view.tunnel
        entries.append(
            PaletteEntry(
                section,
                tr("Tunnel « {name} »").format(name=tunnel.name),
                run(lambda t=tunnel: reveal_tunnel(view, t.id)),
                tunnel.id,
                "cloud",
                "tunnel",
            )
        )
        for rule in tunnel_view.hostnames:
            entries.append(
                PaletteEntry(
                    section,
                    rule.hostname + rule.path,
                    run(lambda t=tunnel, r=rule: reveal_tunnel(view, t.id, r)),
                    f"{rule.service} · {tunnel.name}",
                    "world-www",
                    tr("nom d'hôte"),
                )
            )
    for app in overview.apps:
        entries.append(
            PaletteEntry(
                section,
                tr("Application Access « {name} »").format(name=app.name),
                run(lambda a=app: reveal_app(view, a.id)),
                app.domain,
                "shield-check",
                "access",
            )
        )
    for token in overview.tokens:
        entries.append(
            PaletteEntry(
                section,
                tr("Service token « {name} »").format(name=token.name),
                run(lambda t=token: reveal_token(view, t.id)),
                token.client_id,
                "key",
                "token",
            )
        )
    return entries
