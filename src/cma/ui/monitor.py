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
from cma.core.cfadmin import ServiceSweep, TunnelSweep, token_secret_key
from cma.core.cfapi import Tunnel
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
from cma.core.slo import has_targets
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
        open_service: Callable[[ServiceTarget], None] | None = None,
        start: bool = True,
    ) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.open_tunnel = open_tunnel or (lambda _tunnel, _diagnose: None)
        # « Voir… » sur un service d'un autre compte : la vue Cloudflare de ce compte, sur ce nom d'hôte.
        self.open_service = open_service
        self.tunnel_watch = TunnelWatch()
        self.availability = AvailabilityLog(ctx.paths.data_dir / "availability.json")
        # Journal des envois : noté depuis le fil qui envoie (un envoi de relevé ou de suite à la fois, plus le test
        # des Paramètres) ; le verrou de `AlertLog` sérialise les écritures.
        self.alert_log = AlertLog(log_path(ctx.paths.data_dir))
        self.tunnel_check_running = False
        self.service_check_running = False
        self._follow_up_running = False
        # Portée du dernier relevé : le compte choisi, ou chaque jeton et son compte (« Surveiller tous les comptes »).
        self._tunnel_account: str | None = None
        self._service_account: str | None = None
        # Tous les comptes (ADR 0003) : compte de chaque tunnel du dernier relevé (identifiant du tunnel → du compte).
        self._tunnel_accounts: dict[str, str] = {}
        # Jeton qui a relevé chaque compte au dernier relevé des tunnels (compte → jeton) : celui qui l'ouvre.
        self._account_tokens: dict[str, str] = {}
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

    def _scope(self) -> str | None:
        """Ce qu'il y a à relever : le compte choisi avec un jeton (un seul compte), ou chaque jeton du coffre et son
        compte (« Surveiller tous les comptes ») ; None s'il n'y a rien."""
        settings = self.ctx.config().settings
        admin = self.ctx.manager.cloudflare
        if settings.watch_all_accounts:
            return admin.watch_scope() or None
        account = settings.cloudflare_account_id
        return account if account and admin.has_token() else None

    def _same_scope(self, scope: str) -> bool:
        """Le relevé qui se termine vaut-il encore ? Pas si l'utilisateur a changé de compte (ou de jetons) entre-temps."""
        settings = self.ctx.config().settings
        if settings.watch_all_accounts:
            return self.ctx.manager.cloudflare.watch_scope() == scope
        return settings.cloudflare_account_id == scope

    def _new_scope(self, previous: str | None, scope: str, forget: Callable[[], None]) -> None:
        """Un seul compte : changer de compte fait oublier le relevé précédent. Tous les comptes : il reste valable (les
        identifiants de tunnels et les noms publics ne se répètent pas d'un compte à l'autre) et le relevé suivant le
        remplace ; une panne déjà connue n'est pas annoncée une seconde fois parce qu'un jeton a été ajouté."""
        if scope != previous and not self.ctx.config().settings.watch_all_accounts:
            forget()

    def check_tunnels(self) -> bool:
        """Relève l'état des tunnels (une requête par compte) ; renvoie False quand la surveillance n'a rien à faire."""
        settings = self.ctx.config().settings
        admin = self.ctx.manager.cloudflare
        if not settings.watch_tunnels:
            self._close_unwatched()
        scope = self._scope() if settings.watch_tunnels and not self.tunnel_check_running else None
        if scope is None:
            if self.tunnel_watch.troubled and not self.tunnel_check_running:
                # Surveillance coupée ou jeton oublié : un ancien relevé ne doit pas rester affiché.
                self.tunnel_watch.forget()
                self.refresh()
            return False
        self._new_scope(self._tunnel_account, scope, self.tunnel_watch.forget)
        self._tunnel_account = scope
        self.tunnel_check_running = True

        def done(sweep: TunnelSweep) -> None:
            self.tunnel_check_running = False
            if self._same_scope(scope):
                # Un compte illisible cette fois garde ses tunnels tels qu'au relevé précédent : pas de nouvelle alerte
                # pour une panne déjà connue quand il revient.
                failed = {f.account_id for f in sweep.failures if f.account_id}
                kept = [
                    t
                    for t in self.tunnel_watch.tunnels
                    if self._tunnel_accounts.get(t.id) in failed and t.id not in sweep.accounts
                ]
                self._tunnel_accounts = {
                    **{t.id: self._tunnel_accounts[t.id] for t in kept},
                    **{tid: watched.account_id for tid, watched in sweep.accounts.items()},
                }
                self._account_tokens.update(
                    {watched.account_id: watched.token_id for watched in sweep.accounts.values()}
                )
                self.report_tunnel_changes(self.tunnel_watch.update(sweep.tunnels + kept))
                self._record(
                    record_tunnels(
                        self.availability, self.ctx.config(), sweep.tunnels, complete=sweep.complete
                    )
                )
                self._follow_up(digest=True)
                self.refresh()

        def failed(error: BaseException) -> None:
            # Réseau coupé, jeton révoqué… : pas d'alerte toutes les 5 minutes, la vue Cloudflare le dira.
            self.tunnel_check_running = False
            log.info("Surveillance des tunnels : relevé impossible (%s)", error)

        self.ctx.run(admin.watch_tunnels(), done, failed)
        return True

    def check_services(self) -> bool:
        """Teste depuis Internet les noms d'hôte HTTP des tunnels en service ; False quand il n'y a rien à faire."""
        settings = self.ctx.config().settings
        admin = self.ctx.manager.cloudflare
        watch = self.ctx.services
        if not settings.watch_services:
            self._close_unwatched()
        scope = self._scope() if settings.watch_services and not self.service_check_running else None
        if scope is None:
            if watch.troubled and not self.service_check_running:
                watch.forget()
                self.refresh()
            return False
        self._new_scope(self._service_account, scope, watch.forget)
        self._service_account = scope
        self.service_check_running = True

        def done(sweep: ServiceSweep) -> None:
            self.service_check_running = False
            if not self._same_scope(scope):
                return
            # Les noms d'un compte illisible cette fois restent tels qu'au relevé précédent.
            failed = {f.account_id for f in sweep.failures if f.account_id}
            self.report_service_changes(
                watch.update(sweep.results, keep=lambda target: target.account_id in failed)
            )
            # Relevé réussi : un service qui n’y figure plus voit son incident clos (plus de rappel sans fin) ; un
            # relevé dont un compte a échoué ne clôt rien.
            self._record(
                record_services(self.availability, self.ctx.config(), sweep.results, complete=sweep.complete)
            )
            self._follow_up(digest=False)
            self.refresh()
            self.services_checked.emit()

        def failed(error: BaseException) -> None:
            self.service_check_running = False
            log.info("Surveillance des services : relevé impossible (%s)", error)

        self.ctx.run(admin.watch_services(), done, failed)
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
        # Rien à rappeler, pas de résumé dû et aucun objectif de disponibilité : rien à préparer.
        if (
            settings.alert_repeat_hours <= 0
            and not (digest and settings.weekly_digest)
            and not has_targets(config)
        ):
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

    def other_account(self, account_id: str | None) -> bool:
        """Objet d'un autre compte que celui de la vue Cloudflare (tous les comptes) : la vue ne le montre pas, aucune
        action « Diagnostiquer… » ou « Voir… » ne lui est proposée si aucun jeton ne la donne (`can_open`)."""
        return bool(account_id) and account_id != self.ctx.config().settings.cloudflare_account_id

    def tunnel_account(self, tunnel_id: str) -> str | None:
        """Compte d'un tunnel du dernier relevé (tous les comptes) ; None avec un seul compte surveillé."""
        return self._tunnel_accounts.get(tunnel_id)

    def token_for_account(self, account_id: str) -> str | None:
        """Jeton d'API avec lequel la vue Cloudflare peut ouvrir ce compte : celui qui l'a relevé au dernier relevé des
        tunnels, sinon un jeton dont le dernier compte choisi est celui-là ; dans tous les cas un jeton encore dans le
        coffre. None quand aucun ne le donne (jeton oublié ou retiré du coffre depuis le relevé)."""
        admin = self.ctx.manager.cloudflare
        tokens = admin.tokens()
        ranked = [self._account_tokens.get(account_id)] + [t.id for t in tokens if t.account_id == account_id]
        known = {t.id for t in tokens}
        for token_id in ranked:
            if token_id in known and admin.secrets.get(token_secret_key(token_id)):
                return token_id
        return None

    def can_open(self, account_id: str | None) -> bool:
        """L'objet d'un autre compte peut-il être ouvert (un jeton enregistré donne ce compte) ? Toujours vrai pour le
        compte de la vue Cloudflare. Ouvrir ne fait que lire : « Diagnostiquer… » et « Voir… » lisent le compte
        (connecteurs, noms d'hôte) sans rien modifier."""
        return not self.other_account(account_id) or (
            account_id is not None and self.token_for_account(account_id) is not None
        )

    def report_tunnel_changes(self, changes: list[TunnelChange]) -> None:
        config = self.ctx.config()
        for change in changes:
            if is_muted(config, tunnel_key(change.tunnel.id)):
                continue
            action: Action = (
                None
                if change.recovered or not self.can_open(self.tunnel_account(change.tunnel.id))
                else (tr("Diagnostiquer…"), lambda t=change.tunnel: self.open_tunnel(t, True))
            )
            self.notice.emit(change.level, change.message(), action)

    def report_service_changes(self, changes: list[ServiceChange]) -> None:
        config = self.ctx.config()
        for change in changes:
            if is_muted(config, service_key(change.target), change.target.tunnel_id):
                continue
            action: Action = (
                None
                if change.recovered or not self.can_open(change.target.account_id)
                else (tr("Voir…"), lambda t=change.target: self._view_service(t))
            )
            self.notice.emit(change.level, change.message(), action)

    def _view_service(self, target: ServiceTarget) -> None:
        """« Voir… » : la vue Cloudflare ; pour un service d'un autre compte, ce compte et ce nom d'hôte."""
        if self.open_service is not None and self.other_account(target.account_id):
            self.open_service(target)
        else:
            self.open_tunnel(None, False)

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
