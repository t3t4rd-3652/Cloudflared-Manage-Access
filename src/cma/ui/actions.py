"""Actions rapides d'une session selon son type de service : navigateur, terminal SSH, RDP, URI de base de données."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices

from cma.core.models import ServiceType
from cma.core.sessions import SessionInfo, connect_host
from cma.i18n import tr
from cma.platform.launchers import (
    LaunchError,
    find_mongodb_compass,
    open_mongodb_compass,
    open_rdp,
    open_ssh_terminal,
    rdp_available,
)
from cma.ui.widgets import copy_to_clipboard


@dataclass(frozen=True)
class QuickAction:
    label: str
    icon: str
    run: Callable[[], str | None]  # renvoie un message de confirmation éventuel


def _copy(text: str, what: str) -> Callable[[], str | None]:
    def run() -> str | None:
        copy_to_clipboard(text)
        return tr("{what} copiée : {text}").format(what=what, text=text)

    return run


def quick_actions(info: SessionInfo) -> list[QuickAction]:
    host = connect_host(info.local_host)
    port = info.local_port
    address = info.local_address
    actions: list[QuickAction] = []
    url = info.url
    if url:
        actions.append(
            QuickAction(
                tr("Ouvrir dans le navigateur"),
                "external-link",
                lambda: (QDesktopServices.openUrl(QUrl(url)), None)[1],
            )
        )
    service = info.service_type
    if service == ServiceType.SSH:

        def ssh() -> str | None:
            open_ssh_terminal(host, port, info.service_user, info.name)
            return None

        actions.append(QuickAction(tr("Ouvrir un terminal SSH"), "terminal-2", ssh))
        command = f"ssh -p {port} {info.service_user + '@' if info.service_user else ''}{host}"
        actions.append(QuickAction(tr("Copier la commande SSH"), "copy", _copy(command, tr("Commande"))))
    elif service == ServiceType.RDP and rdp_available():

        def rdp() -> str | None:
            open_rdp(host, port)
            return None

        actions.append(QuickAction(tr("Bureau à distance"), "device-desktop", rdp))
    elif service == ServiceType.MONGODB:
        uri = f"mongodb://{address}/?directConnection=true"
        if find_mongodb_compass() is not None:

            def compass() -> str | None:
                open_mongodb_compass(uri)
                return None

            actions.append(QuickAction(tr("Ouvrir dans MongoDB Compass"), "database", compass))
        actions.append(QuickAction(tr("Copier l'URI MongoDB"), "copy", _copy(uri, tr("URI"))))
    elif service in (ServiceType.POSTGRESQL, ServiceType.MYSQL, ServiceType.REDIS):
        scheme = {
            ServiceType.POSTGRESQL: "postgresql",
            ServiceType.MYSQL: "mysql",
            ServiceType.REDIS: "redis",
        }[service]
        uri = f"{scheme}://{address}/"
        actions.append(QuickAction(tr("Copier l'URI de connexion"), "copy", _copy(uri, tr("URI"))))
    actions.append(QuickAction(tr("Copier l'adresse locale"), "copy", _copy(address, tr("Adresse"))))
    return actions


def run_action(action: QuickAction, notify: Callable[..., None]) -> None:
    try:
        message = action.run()
    except LaunchError as exc:
        notify("error", str(exc))
        return
    if message:
        notify("success", message)
