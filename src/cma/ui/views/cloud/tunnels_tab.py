"""Onglet « Tunnels » de la vue Cloudflare : tunnels et noms d'hôte publiés en cartes, publication, règles
d'ingress, DNS, test depuis Internet, connecteurs, réseaux privés, création et ménage. Ce qui appartient à la vue
(compte choisi, barre d'état, relecture, erreurs, dernière lecture du compte) se lit par `self.view`."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PySide6.QtCore import QPoint, QSignalBlocker, Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QMenu,
    QStackedWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from cma.core.cfadmin import CloudflareAdmin, NewTunnel, Overview, PublishRequest, PublishResult
from cma.core.cfapi import Connector, IngressRule, Tunnel
from cma.core.dnscheck import DnsCheck
from cma.core.hostprobe import HostProbe, probe_hostname_async
from cma.core.models import CloudflareProfile
from cma.core.servicewatch import ServiceResult, ServiceTarget, probe_token, targets_of
from cma.core.traffic import HostTraffic
from cma.i18n import tr
from cma.ui.icons import token_icon
from cma.ui.theme import mono_font
from cma.ui.views.cloud.cards import (
    DNS_ROLE,
    PROFILE_ROLE,
    PROTECTED_ROLE,
    RULE_ROLE,
    SERVICE_ROLE,
    TRAFFIC_ROLE,
    TUNNEL_ROLE,
    TunnelTree,
    service_icon,
)
from cma.ui.views.cloud.connectors import show_connectors
from cma.ui.views.cloud.dialogs import (
    PublishDialog,
    ask_catch_all,
    ask_path_rule,
    ask_service,
    publish_summary,
)
from cma.ui.views.cloud.helpers import describe_api_error, plural, tunnel_state
from cma.ui.views.cloud.private_network import show_private_network
from cma.ui.views.cloud.services import service_tooltip, show_service_tests
from cma.ui.views.cloud.summary import protected_hosts
from cma.ui.views.cloud.tunnel_create import ask_tunnel_name, show_new_tunnel
from cma.ui.views.common import confirm
from cma.ui.widgets import EmptyState, button, clear_items, copy_to_clipboard, label, primary_button

if TYPE_CHECKING:
    from cma.ui.views.cloud.view import CloudView


class TunnelsTab(QWidget):
    def __init__(self, view: CloudView) -> None:
        super().__init__()
        self.view = view
        self.ctx = view.ctx
        self._preferred_tunnel: Tunnel | None = None
        self._build()

    @property
    def admin(self) -> CloudflareAdmin:
        return self.view.admin

    def _build(self) -> None:
        box = QVBoxLayout(self)
        box.setContentsMargins(0, 12, 0, 0)
        box.setSpacing(8)
        row = QHBoxLayout()
        self.publish_button = primary_button(tr("Publier un service…"), "world-www")
        self.publish_button.clicked.connect(self.publish)
        self.import_button = button(tr("Importer comme profils"), "file-import")
        self.import_button.clicked.connect(self.import_selected)
        self.unpublish_button = button(tr("Retirer…"), "trash", danger=True)
        self.unpublish_button.clicked.connect(self.unpublish_selected)
        for widget in (self.publish_button, self.import_button, self.unpublish_button):
            row.addWidget(widget)
        row.addStretch()
        self.test_all_button = button(
            tr("Tester tous les noms d'hôte"),
            "world",
            tooltip=tr("Demander chaque nom d'hôte publié depuis Internet, comme un visiteur"),
        )
        self.test_all_button.clicked.connect(self.test_all_hostnames)
        row.addWidget(self.test_all_button)
        create = button(tr("Créer un tunnel…"), "plus")
        create.clicked.connect(self.create_tunnel)
        row.addWidget(create)
        box.addLayout(row)
        self.tunnel_hint = label("", "meta", wrap=True)
        box.addWidget(self.tunnel_hint)
        self.tree = TunnelTree()
        self.tree.setAccessibleName(tr("Tunnels et noms d'hôte publiés"))
        self.tree.setHeaderLabels([tr("Tunnel ou nom d'hôte"), tr("Service"), tr("État")])
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.itemSelectionChanged.connect(self.update_actions)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_menu)
        refresh = button(tr("Actualiser"), "refresh")
        refresh.clicked.connect(self.view.refresh)
        create_empty = primary_button(tr("Créer un tunnel…"), "plus")
        create_empty.clicked.connect(self.create_tunnel)
        self.tunnels_empty = EmptyState(
            "cloud",
            tr("Aucun tunnel disponible dans ce compte."),
            tr("Créez un tunnel, puis installez son connecteur sur un serveur de votre réseau."),
            [create_empty, refresh],
        )
        self.tunnels_stack = QStackedWidget()
        self.tunnels_stack.addWidget(self.tree)
        self.tunnels_stack.addWidget(self.tunnels_empty)
        box.addWidget(self.tunnels_stack, 1)

    def clear(self) -> None:
        # Vider d'abord la sélection (ses éléments existent encore), puis reconstruire sans signaux : un
        # `itemSelectionChanged` émis pendant le vidage ferait relire un élément en cours de destruction
        # (abandon de Qt sous Linux).
        self.tree.clearSelection()
        with QSignalBlocker(self.tree):
            clear_items(self.tree)

    def fill(self, overview: Overview) -> None:
        """Une carte par tunnel, une ligne par règle d'ingress (l'arbre a été vidé par `clear`)."""
        mono = mono_font(9.5)
        protected = protected_hosts(overview.apps)
        imported = {p.hostname.lower() for p in self.ctx.config().cloudflare_profiles if p.hostname}
        for tunnel_view in sorted(overview.tunnels, key=lambda v: v.tunnel.name.lower()):
            text, _tone, symbol = tunnel_state(tunnel_view.tunnel.status)
            count = plural(len(tunnel_view.hostnames), tr("{n} nom d'hôte"), tr("{n} noms d'hôte"))
            guarded = sum(1 for r in tunnel_view.hostnames if r.hostname.lower() in protected)
            summary = count
            if tunnel_view.hostnames:
                summary += " · " + tr("{n}/{total} protégés par Access").format(
                    n=guarded, total=len(tunnel_view.hostnames)
                )
            routes = sum(1 for r in overview.routes if r.tunnel_id == tunnel_view.tunnel.id)
            if routes:
                summary += " · " + plural(routes, tr("{n} réseau privé"), tr("{n} réseaux privés"))
            parent = QTreeWidgetItem([tunnel_view.tunnel.name, summary, f"{symbol} {text}"])
            parent.setToolTip(
                0,
                tr("Tunnel {name} ({id})").format(name=tunnel_view.tunnel.name, id=tunnel_view.tunnel.id)
                + "\n"
                + tr("Règle finale : {service}").format(service=tunnel_view.catch_all),
            )
            parent.setData(0, TUNNEL_ROLE, tunnel_view.tunnel)
            parent.setData(
                0, Qt.ItemDataRole.AccessibleTextRole, f"{tunnel_view.tunnel.name}, {text}, {summary}"
            )
            for rule in tunnel_view.hostnames:
                child = QTreeWidgetItem([rule.hostname + rule.path, rule.service, "—"])
                child.setIcon(0, token_icon(service_icon(rule.service), "muted"))
                child.setFont(1, mono)
                is_protected = rule.hostname.lower() in protected
                in_cma = rule.hostname.lower() in imported
                notes = [tr("protégé par Access") if is_protected else tr("non protégé")]
                if in_cma:
                    notes.append(tr("profil présent dans CMA"))
                child.setToolTip(1, rule.service)
                child.setData(0, TUNNEL_ROLE, tunnel_view.tunnel)
                child.setData(0, RULE_ROLE, rule)
                child.setData(0, PROTECTED_ROLE, is_protected)
                child.setData(0, PROFILE_ROLE, in_cma)
                dns = overview.dns.get(rule.hostname.lower())
                child.setData(0, DNS_ROLE, dns)
                child.setData(0, TRAFFIC_ROLE, overview.traffic.get(rule.hostname.lower()))
                self._set_service_result(child, self.ctx.services.result(rule.hostname, rule.path))
                if dns is not None and not dns.ok:
                    notes.append(dns.label())
                child.setData(
                    0,
                    Qt.ItemDataRole.AccessibleTextRole,
                    ", ".join([rule.hostname, rule.service, *notes]),
                )
                parent.addChild(child)
            self.tree.addTopLevelItem(parent)
            parent.setExpanded(True)
        self.tunnels_stack.setCurrentWidget(self.tree if overview.tunnels else self.tunnels_empty)

    # --- Sélection et actions -----------------------------------------------------------------------------------------

    def _selected_item(self) -> QTreeWidgetItem | None:
        items = self.tree.selectedItems()
        return items[0] if items else None

    def update_actions(self) -> None:
        item = self._selected_item()
        rule = item.data(0, RULE_ROLE) if item is not None else None
        tunnel = item.data(0, TUNNEL_ROLE) if item is not None else None
        usable = (
            self.view.overview is not None
            and bool(self.view.overview.tunnels)
            and bool(self.view.overview.zones)
        )
        self.publish_button.setEnabled(usable)
        self.test_all_button.setEnabled(
            self.view.overview is not None and any(v.hostnames for v in self.view.overview.tunnels)
        )
        self.unpublish_button.setEnabled(isinstance(rule, IngressRule))
        if isinstance(rule, IngressRule):
            scope = tr("Importer {host} comme profil").format(host=rule.hostname)
        elif isinstance(tunnel, Tunnel):
            scope = tr("Importer les noms d'hôte du tunnel {name}").format(name=tunnel.name)
        else:
            scope = tr("Importer tous les noms d'hôte du compte")
        self.import_button.setToolTip(scope)
        self.import_button.setAccessibleDescription(scope)
        if self.view.overview is not None and not usable:
            hint = tr("Aucun tunnel ou domaine utilisable dans ce compte.")
        elif not isinstance(rule, IngressRule):
            hint = tr(
                "Sélectionnez un nom d'hôte pour le retirer ; sans sélection, l'import couvre tout le compte."
            )
        else:
            hint = ""
        self.tunnel_hint.setText(hint)
        self.tunnel_hint.setVisible(bool(hint))

    def selected_rules(self) -> list[tuple[Tunnel, IngressRule]]:
        """Noms d'hôte sélectionnés ; un tunnel sélectionné vaut tous ses noms ; rien de sélectionné vaut tout."""
        items = self.tree.selectedItems() or [
            self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount())
        ]
        chosen: list[tuple[Tunnel, IngressRule]] = []
        for item in items:
            if item is None:
                continue
            rule = item.data(0, RULE_ROLE)
            tunnel = item.data(0, TUNNEL_ROLE)
            if isinstance(rule, IngressRule):
                chosen.append((tunnel, rule))
            else:
                for index in range(item.childCount()):
                    child = item.child(index)
                    if child is not None:
                        chosen.append((tunnel, child.data(0, RULE_ROLE)))
        unique: dict[str, tuple[Tunnel, IngressRule]] = {}
        for tunnel, rule in chosen:
            unique.setdefault(rule.hostname, (tunnel, rule))
        return list(unique.values())

    def import_selected(self) -> None:
        rules = self.selected_rules()
        if not rules:
            self.ctx.notify("info", tr("Aucun nom d'hôte publié à importer."))
            return
        created: list[CloudflareProfile] = self.admin.import_profiles(rules)
        if len(created) == 1:
            profile = created[0]
            self.ctx.notify(
                "success",
                tr("Profil créé : {name}.").format(name=profile.name),
                action=self._open_action(profile),
            )
        elif created:
            self.ctx.notify("success", tr("{n} profils importés.").format(n=len(created)))
        else:
            self.ctx.notify("info", tr("Ces noms d'hôte ont déjà un profil dans CMA."))

    def _open_action(self, profile: CloudflareProfile | None) -> tuple[str, Callable[[], None]] | None:
        opener = self.view.open_profile
        if profile is None or opener is None:
            return None
        return (tr("Ouvrir le profil"), lambda: opener(profile.id))

    def _tree_menu(self, pos: QPoint) -> None:
        item = self.tree.itemAt(pos)
        if item is None:
            return
        self.tree.setCurrentItem(item)
        menu = self.tree_menu(item)
        menu.exec(self.tree.viewport().mapToGlobal(pos))
        menu.deleteLater()

    def tree_menu(self, item: QTreeWidgetItem) -> QMenu:
        """Menu d'un tunnel ou d'une règle (construit à part de son `exec`, pour les tests)."""
        rule = item.data(0, RULE_ROLE)
        tunnel = item.data(0, TUNNEL_ROLE)
        menu = QMenu(self)
        if isinstance(rule, IngressRule):
            menu.addAction(tr("Importer comme profil"), self.import_selected)
            menu.addAction(tr("Copier le nom d'hôte"), lambda: copy_to_clipboard(rule.hostname))
            menu.addAction(tr("Tester depuis Internet"), lambda: self.test_from_internet(rule))
            if rule.service.lower().startswith(("http://", "https://")):
                menu.addAction(
                    tr("Ouvrir dans le navigateur"),
                    lambda: QDesktopServices.openUrl(QUrl(f"https://{rule.hostname}{rule.path}")),
                )
            parent = item.parent()
            owner = parent.data(0, TUNNEL_ROLE) if parent is not None else None
            if isinstance(owner, Tunnel) and parent is not None:
                menu.addAction(tr("Modifier le service…"), lambda: self.edit_service(owner, rule))
                menu.addAction(tr("Ajouter une règle avec chemin…"), lambda: self.add_path_rule(owner, rule))
                dns = item.data(0, DNS_ROLE)
                if isinstance(dns, DnsCheck) and dns.fixable:
                    menu.addAction(tr("Corriger le DNS…"), lambda: self.fix_dns(owner, rule, dns))
                menu.addSeparator()
                position, count = parent.indexOfChild(item), parent.childCount()
                up = menu.addAction(tr("Monter"), lambda: self.move_rule(owner, rule, -1))
                up.setEnabled(position > 0)
                down = menu.addAction(tr("Descendre"), lambda: self.move_rule(owner, rule, 1))
                down.setEnabled(position < count - 1)
            menu.addSeparator()
            menu.addAction(
                tr("Retirer cette règle…") if rule.path else tr("Retirer ce nom d'hôte…"),
                self.unpublish_selected,
            )
        elif isinstance(tunnel, Tunnel):
            menu.addAction(tr("Importer ses noms d'hôte"), self.import_selected)
            publish = menu.addAction(tr("Publier un service sur ce tunnel…"), lambda: self.publish(tunnel))
            publish.setEnabled(self.publish_button.isEnabled())
            menu.addAction(tr("Règle finale…"), lambda: self.edit_catch_all(tunnel))
            menu.addAction(tr("État des connecteurs…"), lambda: self.check_connectors(tunnel))
            menu.addAction(
                tr("Réseaux privés…"),
                lambda: show_private_network(self, self.ctx, self.admin, tunnel, self.view.refresh),
            )
            menu.addSeparator()
            menu.addAction(tr("Renommer…"), lambda: self.rename_tunnel(tunnel))
            menu.addAction(tr("Supprimer le tunnel…"), lambda: self.delete_tunnel(tunnel))
        return menu

    def add_path_rule(self, tunnel: Tunnel, rule: IngressRule) -> None:
        """Nouvelle règle avec chemin sur le nom d'hôte de `rule` (même DNS, même protection Access)."""
        answer = ask_path_rule(self, tunnel, rule.hostname)
        if not answer:
            return
        path, service = answer

        def done(added: IngressRule) -> None:
            self.ctx.notify(
                "success",
                tr("{host} pointe désormais vers {service}.").format(
                    host=added.hostname + added.path, service=added.service
                ),
            )
            self.view.refresh()

        self.ctx.run(self.admin.add_path_rule(tunnel, rule.hostname, path, service), done, self.view._error)

    def fix_dns(self, tunnel: Tunnel, rule: IngressRule, check: DnsCheck) -> None:
        """CNAME du nom d'hôte vers ce tunnel, proxifié ; la confirmation dit ce qui est faux et ce qui change."""
        host = rule.hostname
        text = (
            check.explanation(host)
            + "\n\n"
            + tr("Le CNAME de {host} visera ce tunnel ({tunnel}), proxifié par Cloudflare.").format(
                host=host, tunnel=tunnel.name
            )
        )
        if not confirm(self, tr("Corriger le DNS de {host} ?").format(host=host), text, tr("Corriger")):
            return

        def done(_result: object) -> None:
            self.ctx.notify("success", tr("DNS de {host} corrigé.").format(host=host))
            self.view.refresh()

        self.ctx.run(self.admin.fix_dns(tunnel, host), done, self.view._error)

    def _probe_token(self, hostname: str) -> tuple[str, str] | None:
        return probe_token(self.ctx.config(), self.ctx.core.secrets, hostname)

    def _set_service_result(self, item: QTreeWidgetItem, result: ServiceResult | None) -> None:
        """Dernier test du nom d'hôte, et info-bulle : règle, trafic des 24 dernières heures, test."""
        item.setData(0, SERVICE_ROLE, result)
        rule = item.data(0, RULE_ROLE)
        if not isinstance(rule, IngressRule):
            return
        parts = [f"{rule.hostname}{rule.path}  →  {rule.service}"]
        traffic = item.data(0, TRAFFIC_ROLE)
        if isinstance(traffic, HostTraffic):
            parts.append(
                tr("Dernières 24 h : {requests} requêtes, {errors} erreurs 5xx.").format(
                    requests=traffic.requests, errors=traffic.errors
                )
            )
        if result is not None:
            parts.append(service_tooltip(result))
        item.setToolTip(0, "\n\n".join(parts))

    def show_service_results(self) -> None:
        """Reporte les derniers tests (surveillance ou test manuel) sur les cartes, sans relire le compte."""
        for row in range(self.tree.topLevelItemCount()):
            parent = self.tree.topLevelItem(row)
            for index in range(parent.childCount() if parent is not None else 0):
                child = parent.child(index) if parent is not None else None
                rule = child.data(0, RULE_ROLE) if child is not None else None
                if child is not None and isinstance(rule, IngressRule):
                    self._set_service_result(child, self.ctx.services.result(rule.hostname, rule.path))
        self.tree.viewport().update()

    def _target(self, rule: IngressRule) -> ServiceTarget:
        owner = next(
            (
                v.tunnel
                for v in (self.view.overview.tunnels if self.view.overview else [])
                if rule in v.hostnames
            ),
            None,
        )
        return ServiceTarget(
            rule.hostname, rule.path, rule.service, owner.id if owner else "", owner.name if owner else ""
        )

    def test_all_hostnames(self) -> None:
        """Tous les noms d'hôte publiés, testés depuis Internet ; le tableau des résultats s'ouvre ensuite."""
        if self.view.overview is None:
            return
        targets = targets_of(
            ((v.tunnel, v.hostnames) for v in self.view.overview.tunnels), web_only=False, active_only=False
        )
        if not targets:
            return
        self.test_all_button.setEnabled(False)
        self.view.status.setText(
            plural(
                len(targets),
                tr("Test de {n} nom d'hôte depuis Internet…"),
                tr("Test de {n} noms d'hôte depuis Internet…"),
            )
        )

        def done(results: list[tuple[ServiceTarget, HostProbe]]) -> None:
            self.view._show_summary()
            self.update_actions()
            self.ctx.services.record(results)
            self.show_service_results()
            show_service_tests(self, results)

        def failed(error: BaseException) -> None:
            self.update_actions()
            self.view._error(error)

        self.ctx.run(self.admin.probe_services(targets), done, failed)

    def test_from_internet(self, rule: IngressRule) -> None:
        """Ce qu'obtient un visiteur : DNS public, Access, tunnel, service. Un service non HTTP (SSH, RDP, TCP)
        ne se teste ainsi que jusqu'à Access ; la connexion complète se teste avec une session."""
        target = self._target(rule)
        web = target.web
        token = self._probe_token(rule.hostname) if web else None
        self.view.status.setText(tr("Test de {host} depuis Internet…").format(host=rule.hostname + rule.path))

        def done(result: HostProbe) -> None:
            self.view._show_summary()
            self.ctx.services.record([(target, result)])
            self.show_service_results()
            text = result.summary(rule.hostname + rule.path)
            if not web:
                text += " " + tr(
                    "Service non HTTP : seuls le DNS et Access sont testés ; la connexion complète se teste avec "
                    "une session (« Tester le service »)."
                )
            elif token is not None:
                text += " " + tr("Test fait avec le service token du profil CMA.")
            self.ctx.notify(result.tone, text)

        self.ctx.run(
            probe_hostname_async(rule.hostname, token=token, path=target.probe_path), done, self.view._error
        )

    def move_rule(self, tunnel: Tunnel, rule: IngressRule, offset: int) -> None:
        self.ctx.run(
            self.admin.move_rule(tunnel, rule, offset), lambda _p: self.view.refresh(), self.view._error
        )

    def edit_catch_all(self, tunnel: Tunnel) -> None:
        current = next(
            (
                v.catch_all
                for v in (self.view.overview.tunnels if self.view.overview else [])
                if v.tunnel.id == tunnel.id
            ),
            "http_status:404",
        )
        service = ask_catch_all(self, tunnel, current)
        if not service or service == current:
            return

        def done(_result: object) -> None:
            self.ctx.notify(
                "success",
                tr("Règle finale du tunnel {name} : {service}.").format(name=tunnel.name, service=service),
            )
            self.view.refresh()

        self.ctx.run(self.admin.set_catch_all(tunnel, service), done, self.view._error)

    def edit_service(self, tunnel: Tunnel, rule: IngressRule) -> None:
        """Change la cible d'un nom d'hôte publié (même nom, même DNS, même protection Access)."""
        answer = ask_service(self, tunnel, rule)
        if not answer:
            return
        service, origin = answer
        self.view.status.setText(tr("Modification du service…"))

        def done(updated: IngressRule) -> None:
            self.ctx.notify(
                "success",
                tr("{host} pointe désormais vers {service}.").format(
                    host=updated.hostname, service=updated.service
                ),
            )
            self.view.refresh()

        self.ctx.run(
            self.admin.edit_hostname(tunnel, rule.hostname, service, origin, rule.path),
            done,
            self.view._error,
        )

    def create_tunnel(self) -> None:
        """Crée un tunnel géré depuis Cloudflare, puis donne la commande d'installation de son connecteur."""
        existing = [v.tunnel.name for v in self.view.overview.tunnels] if self.view.overview else []
        name = ask_tunnel_name(self, existing)
        if not name:
            return
        self.view.status.setText(tr("Création du tunnel…"))

        def done(created: NewTunnel) -> None:
            self.view.refresh()
            show_new_tunnel(self, created)

        self.ctx.run(self.admin.create_tunnel(name), done, self.view._error)

    def check_connectors(self, tunnel: Tunnel) -> None:
        """Lit les connecteurs du tunnel puis affiche le diagnostic et les connexions vers Cloudflare."""
        self.view.status.setText(tr("Lecture des connecteurs…"))

        def done(connectors: list[Connector]) -> None:
            self.view._show_summary()
            show_connectors(self, tunnel, connectors)

        self.ctx.run(self.admin.connectors(tunnel), done, self.view._error)

    def ask_publish(self) -> PublishRequest | None:
        if self.view.overview is None:
            return None
        remote = {t.client_id for t in self.view.overview.tokens}
        tokens = [t for t in self.ctx.config().tokens if t.client_id in remote]
        dialog = PublishDialog(self, self.view.overview, tokens, self._preferred_tunnel)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        return dialog.request()

    def publish(self, tunnel: Tunnel | None = None) -> None:
        self._preferred_tunnel = tunnel if isinstance(tunnel, Tunnel) else None
        request = self.ask_publish()
        self._preferred_tunnel = None
        if request is None:
            return
        self.view.status.setText(tr("Publication de {host}…").format(host=request.hostname))

        def done(result: PublishResult) -> None:
            if result.complete:
                parts = [tr("Service publié : {host}.").format(host=result.rule.hostname)]
                if result.app is not None:
                    parts.append(tr("Protégé par Access."))
                if result.profile is not None:
                    parts.append(tr("Profil CMA créé."))
                self.ctx.notify("success", " ".join(parts), action=self._open_action(result.profile))
            else:
                self.ctx.notify("warning", publish_summary(result), action=self._open_action(result.profile))
            self.view.refresh()

        def failed(error: BaseException) -> None:
            self.view._error(
                RuntimeError(
                    tr("La publication n'a pas abouti. Contrôlez l'état dans Cloudflare avant de réessayer.")
                    + " "
                    + describe_api_error(error)
                )
            )
            self.view.refresh()

        self.ctx.run(self.admin.publish(request, self.view.publish_progress.emit), done, failed)

    def unpublish_selected(self) -> None:
        item = self._selected_item()
        rule = item.data(0, RULE_ROLE) if item is not None else None
        tunnel = item.data(0, TUNNEL_ROLE) if item is not None else None
        if not isinstance(rule, IngressRule) or not isinstance(tunnel, Tunnel):
            self.ctx.notify("info", tr("Sélectionnez un nom d'hôte à retirer."))
            return
        shared = self.view.overview is not None and any(
            r.hostname == rule.hostname and r.path != rule.path
            for v in self.view.overview.tunnels
            if v.tunnel.id == tunnel.id
            for r in v.hostnames
        )
        if not confirm(
            self,
            tr("Retirer {host} ?").format(host=rule.hostname + rule.path),
            (
                tr(
                    "La règle est retirée du tunnel {tunnel}. Le nom d'hôte reste publié par ses autres règles : "
                    "son enregistrement DNS est gardé."
                )
                if shared
                else tr(
                    "La règle est retirée du tunnel {tunnel} et l'enregistrement DNS est supprimé. "
                    "Le tunnel, l'application Access et les profils CMA sont conservés."
                )
            ).format(tunnel=tunnel.name),
            tr("Retirer"),
        ):
            return

        def done(_result: object) -> None:
            self.ctx.notify("success", tr("{host} retiré.").format(host=rule.hostname + rule.path))
            self.view.refresh()

        self.ctx.run(self.admin.unpublish(tunnel, rule.hostname, rule.path), done, self.view._error)

    # --- Ménage -----------------------------------------------------------------------------------------------

    def rename_tunnel(self, tunnel: Tunnel) -> None:
        existing = [v.tunnel.name for v in self.view.overview.tunnels] if self.view.overview else []
        name = ask_tunnel_name(self, existing, tunnel.name)
        if not name:
            return
        self.view.status.setText(tr("Renommage du tunnel…"))

        def done(renamed: Tunnel) -> None:
            self.ctx.notify("success", tr("Tunnel renommé : {name}.").format(name=renamed.name))
            self.view.refresh()

        self.ctx.run(self.admin.rename_tunnel(tunnel, name), done, self.view._error)

    def delete_tunnel(self, tunnel: Tunnel) -> None:
        view = (
            next((v for v in self.view.overview.tunnels if v.tunnel.id == tunnel.id), None)
            if self.view.overview
            else None
        )
        hostnames = [r.hostname for r in view.hostnames] if view else []
        text = tr(
            "Le tunnel doit être arrêté sur son serveur (aucun connecteur actif). Ses {n} nom(s) d'hôte publié(s) "
            "cessent de répondre et leurs enregistrements DNS qui le visent sont supprimés. Les applications Access "
            "et les profils CMA ne sont pas touchés."
        ).format(n=len(hostnames))
        if not confirm(
            self, tr("Supprimer le tunnel « {name} » ?").format(name=tunnel.name), text, tr("Supprimer")
        ):
            return
        self.view.status.setText(tr("Suppression du tunnel…"))

        def done(removed: int) -> None:
            self.ctx.notify(
                "success",
                tr("Tunnel « {name} » supprimé, {n} enregistrement(s) DNS retiré(s).").format(
                    name=tunnel.name, n=removed
                ),
            )
            self.view.refresh()

        self.ctx.run(self.admin.delete_tunnel(tunnel, hostnames), done, self.view._error)
