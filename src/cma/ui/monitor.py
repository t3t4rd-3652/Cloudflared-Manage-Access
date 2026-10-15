"""Surveillance du compte Cloudflare côté interface (ADR 0001) : relevés des tunnels toutes les 5 minutes et des
services publiés toutes les 15, journal de disponibilité, alertes vers l'extérieur, sourdine.

Un `QObject` sans widget : la fenêtre principale le crée et relaie ses signaux (bandeaux, navigation, zone de
notification, carte « Santé du compte »). La logique partagée avec la tâche planifiée est dans
`cma.core.monitoring` ; ici, seulement les minuteurs, l'état entre deux relevés et les signaux.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from datetime import UTC, datetime

from PySide6.QtCore import QObject, QTimer, Signal

from cma.core.alertlog import AlertLog, log_path
from cma.core.alertstate import AlertState, state_path
from cma.core.availability import AvailabilityLog
from cma.core.cfapi import Tunnel
from cma.core.hostprobe import HostProbe
from cma.core.monitoring import (
    Event,
    close_unwatched_kinds,
    deliver_follow_up,
    is_muted,
    prepare_follow_up,
    record_services,
    record_tunnels,
    send_events,
    service_key,
    tunnel_key,
)
from cma.core.servicewatch import ServiceChange, ServiceResult, ServiceTarget
from cma.core.tunnelwatch import TunnelChange, TunnelWatch
from cma.i18n import tr
from cma.ui.context import GuiContext

log = logging.getLogger(__name__)

TUNNEL_WATCH_MS = 5 * 60 * 1000  # relevé de l'état des tunnels du compte
SERVICE_WATCH_MS = 15 * 60 * 1000  # test des services publiés depuis Internet

Action = tuple[str, Callable[[], None]] | None


class Monitor(QObject):
    # Pannes à signaler (sans ce qui est en sourdine) : tunnels, puis services.
    troubled = Signal(list, list)
    # Message pour l'utilisateur : niveau, texte, action éventuelle (libellé, fonction).
    notice = Signal(str, str, object)
    # Un relevé des services vient d'aboutir (les cartes de la vue Cloudflare se mettent à jour).
    services_checked = Signal()

    def __init__(
        self,
        ctx: GuiContext,
        parent: QObject | None = None,
        *,
        open_tunnel: Callable[[Tunnel | None, bool], None] | None = None,
        start: bool = True,
    ) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.open_tunnel = open_tunnel or (lambda _tunnel, _diagnose: None)
        self.tunnel_watch = TunnelWatch()
        self.availability = AvailabilityLog(ctx.paths.data_dir / "availability.json")
        # Journal des envois : noté depuis le fil qui envoie (un envoi de relevé ou de suite à la fois, plus le test
        # des Paramètres) ; le verrou de `AlertLog` sérialise les écritures.
        self.alert_log = AlertLog(log_path(ctx.paths.data_dir))
        self.tunnel_check_running = False
        self.service_check_running = False
        self._follow_up_running = False
        self._tunnel_account: str | None = None
        self._service_account: str | None = None
        self._tunnel_timer = QTimer(self)
        self._tunnel_timer.setInterval(TUNNEL_WATCH_MS)
        self._tunnel_timer.timeout.connect(self.check_tunnels)
        self._service_timer = QTimer(self)
        self._service_timer.setInterval(SERVICE_WATCH_MS)
        self._service_timer.timeout.connect(self.check_services)
        if start:
            self._tunnel_timer.start()
            self._service_timer.start()
            # Premiers relevés peu après l'affichage : le démarrage passe d'abord.
            QTimer.singleShot(20_000, self.check_tunnels)
            QTimer.singleShot(60_000, self.check_services)

    # --- Relevés ----------------------------------------------------------------------------------------

    def check_tunnels(self) -> bool:
        """Relève l'état des tunnels (une requête) ; renvoie False quand la surveillance n'a rien à faire."""
        settings = self.ctx.config().settings
        admin = self.ctx.manager.cloudflare
        account = settings.cloudflare_account_id
        if not settings.watch_tunnels:
            self._close_unwatched()
        if self.tunnel_check_running or not settings.watch_tunnels or not account or not admin.has_token():
            if self.tunnel_watch.troubled and not self.tunnel_check_running:
                # Surveillance coupée ou jeton oublié : un ancien relevé ne doit pas rester affiché.
                self.tunnel_watch.forget()
                self.refresh()
            return False
        if account != self._tunnel_account:
            self.tunnel_watch.forget()
            self._tunnel_account = account
        self.tunnel_check_running = True

        def done(tunnels: list[Tunnel]) -> None:
            self.tunnel_check_running = False
            if self.ctx.config().settings.cloudflare_account_id == account:
                self.report_tunnel_changes(self.tunnel_watch.update(tunnels))
                self._record(record_tunnels(self.availability, self.ctx.config(), tunnels))
                self._follow_up(digest=True)
                self.refresh()

        def failed(error: BaseException) -> None:
            # Réseau coupé, jeton révoqué… : pas d'alerte toutes les 5 minutes, la vue Cloudflare le dira.
            self.tunnel_check_running = False
            log.info("Surveillance des tunnels : relevé impossible (%s)", error)

        self.ctx.run(admin.tunnel_states(), done, failed)
        return True

    def check_services(self) -> bool:
        """Teste depuis Internet les noms d'hôte HTTP des tunnels en service ; False quand il n'y a rien à faire."""
        settings = self.ctx.config().settings
        admin = self.ctx.manager.cloudflare
        account = settings.cloudflare_account_id
        watch = self.ctx.services
        if not settings.watch_services:
            self._close_unwatched()
        if self.service_check_running or not settings.watch_services or not account or not admin.has_token():
            if watch.troubled and not self.service_check_running:
                watch.forget()
                self.refresh()
            return False
        if account != self._service_account:
            watch.forget()
            self._service_account = account
        self.service_check_running = True

        def done(results: list[tuple[ServiceTarget, HostProbe]]) -> None:
            self.service_check_running = False
            if self.ctx.config().settings.cloudflare_account_id != account:
                return
            self.report_service_changes(watch.update(results))
            # Relevé réussi : un service qui n’y figure plus voit son incident clos (plus de rappel sans fin).
            self._record(record_services(self.availability, self.ctx.config(), results, complete=True))
            self._follow_up(digest=False)
            self.refresh()
            self.services_checked.emit()

        def failed(error: BaseException) -> None:
            self.service_check_running = False
            log.info("Surveillance des services : relevé impossible (%s)", error)

        self.ctx.run(admin.check_services(), done, failed)
        return True

    # --- Suites d'un relevé -----------------------------------------------------------------------------------

    def _close_unwatched(self) -> None:
        """Surveillance coupée : les incidents ouverts de ce type sont clos, sans événement ni notification."""
        if close_unwatched_kinds(self.availability, self.ctx.config()):
            try:
                self.availability.save()
            except OSError as exc:
                log.warning("Journal de disponibilité non enregistré : %s", exc)

    def _record(self, events: list[Event]) -> None:
        """Journal enregistré ; les nouveaux incidents et les retours partent vers les canaux d'alerte."""
        try:
            self.availability.save()
        except OSError as exc:
            log.warning("Journal de disponibilité non enregistré : %s", exc)
        config = self.ctx.config()
        if not events or not config.settings.alert_channels:
            return

        async def send() -> list[str]:
            return await asyncio.to_thread(
                send_events, events, config, self.ctx.core.secrets, None, self.alert_log
            )

        def done(errors: list[str]) -> None:
            for error in errors:
                log.warning("Alerte non envoyée : %s", error)
            if errors:
                self.notice.emit("warning", tr("Alerte non envoyée : {error}").format(error=errors[0]), None)

        self.ctx.run(send(), done)

    def _follow_up(self, *, digest: bool) -> None:
        """Après un relevé : rappel des pannes qui durent (toutes les N heures) et, après celui des tunnels, résumé du
        lundi s'il est dû. Le plan se prépare ici (rapide, sans réseau), l'envoi et la note dans `alert_state.json`
        se font sur un autre fil ; un seul à la fois, pour qu'un seul écrive le fichier."""
        config = self.ctx.config()
        settings = config.settings
        if self._follow_up_running or not settings.alert_channels:
            return
        if settings.alert_repeat_hours <= 0 and not (digest and settings.weekly_digest):
            return
        tunnel_of = {service_key(r.target): r.target.tunnel_id for r in self.ctx.services.results}
        plan = prepare_follow_up(
            self.availability,
            config,
            AlertState(state_path(self.ctx.paths.data_dir)),
            check_digest=digest,
            tunnel_of=tunnel_of,
        )
        if plan.empty:
            with contextlib.suppress(OSError):
                plan.state.save()  # rappels d'incidents clos oubliés
            return
        self._follow_up_running = True

        async def send() -> list[str]:
            return await asyncio.to_thread(
                deliver_follow_up,
                plan,
                config,
                self.ctx.core.secrets,
                datetime.now(UTC),
                None,
                self.alert_log,
            )

        def done(errors: list[str]) -> None:
            self._follow_up_running = False
            for error in errors:
                log.warning("Rappel ou résumé non envoyé : %s", error)
            if errors:
                self.notice.emit("warning", tr("Alerte non envoyée : {error}").format(error=errors[0]), None)

        def failed(error: BaseException) -> None:
            self._follow_up_running = False
            log.warning("Rappel ou résumé non envoyé : %s", error)

        self.ctx.run(send(), done, failed)

    def known_objects(self) -> list[tuple[str, str]]:
        """(clé de sourdine, libellé) des tunnels et des noms d'hôte du dernier relevé, pour viser une maintenance."""
        found = [(tunnel_key(t.id), t.name) for t in self.tunnel_watch.tunnels]
        found += [(service_key(r.target), r.target.label) for r in self.ctx.services.results]
        return sorted(found, key=lambda item: item[1].lower())

    def report_tunnel_changes(self, changes: list[TunnelChange]) -> None:
        config = self.ctx.config()
        for change in changes:
            if is_muted(config, tunnel_key(change.tunnel.id)):
                continue
            action: Action = (
                None
                if change.recovered
                else (tr("Diagnostiquer…"), lambda t=change.tunnel: self.open_tunnel(t, True))
            )
            self.notice.emit(change.level, change.message(), action)

    def report_service_changes(self, changes: list[ServiceChange]) -> None:
        config = self.ctx.config()
        for change in changes:
            if is_muted(config, service_key(change.target), change.target.tunnel_id):
                continue
            action: Action = (
                None if change.recovered else (tr("Voir…"), lambda: self.open_tunnel(None, False))
            )
            self.notice.emit(change.level, change.message(), action)

    def current_troubles(self) -> tuple[list[Tunnel], list[ServiceResult]]:
        """Tunnels et services en panne au dernier relevé, sans ce qui est en sourdine (maintenance)."""
        config = self.ctx.config()
        tunnels = [t for t in self.tunnel_watch.troubled if not is_muted(config, tunnel_key(t.id))]
        services = [
            r
            for r in self.ctx.services.troubled
            if not is_muted(config, service_key(r.target), r.target.tunnel_id)
        ]
        return tunnels, services

    def refresh(self) -> None:
        """Annonce les pannes en cours (après un relevé, une sourdine posée ou levée, un changement de réglage)."""
        tunnels, services = self.current_troubles()
        self.troubled.emit(tunnels, services)
