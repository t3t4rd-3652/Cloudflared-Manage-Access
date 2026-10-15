"""Captures d'écran de l'interface avec des données de démonstration fictives (pour la documentation).

    uv run python scripts/capture_screenshots.py [dossier_de_sortie]

Aucune donnée réelle n'est lue : un dossier de données temporaire et un coffre en mémoire sont utilisés.
Les sessions affichées sont simulées : aucun processus n'est lancé.
"""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from cma.context import create_context
from cma.core.engine import Engine
from cma.core.events import LogLine
from cma.core.models import (
    AuthMode,
    CloudflareProfile,
    SavedForward,
    ServiceToken,
    ServiceType,
    SshAuthMode,
    SshProfile,
    Theme,
)
from cma.core.prompts import NonInteractivePrompter
from cma.core.secrets import MemorySecretStore
from cma.core.sessions import SessionInfo, SessionKind, SessionState
from cma.core.ssh.discovery import DiscoveryResult, RemotePort
from cma.i18n import set_language
from cma.paths import AppPaths
from cma.ui.bridge import EngineBridge, TaskRunner
from cma.ui.context import GuiContext
from cma.ui.theme import ThemeManager


class DemoStore(MemorySecretStore):
    persistent = True


def demo_config(ctx: GuiContext) -> None:
    prod = ServiceToken(name="Production", client_id="8f3c2a1b.access")
    lab = ServiceToken(name="Laboratoire", client_id="51d0e9aa.access")
    mongo = CloudflareProfile(
        name="MongoDB production",
        group="Production",
        favorite=True,
        hostname="mongodb.exemple.fr",
        local_port=27017,
        auth=AuthMode.SERVICE_TOKEN,
        token_id=prod.id,
        service_type=ServiceType.MONGODB,
    )
    ssh_cf = CloudflareProfile(
        name="SSH bastion",
        group="Production",
        favorite=True,
        hostname="ssh.exemple.fr",
        local_port=2222,
        auth=AuthMode.SERVICE_TOKEN,
        token_id=prod.id,
        service_type=ServiceType.SSH,
        service_user="admin",
    )
    rdp = CloudflareProfile(
        name="Bureau labo",
        group="Laboratoire",
        hostname="rdp.lab.exemple.fr",
        local_port=3390,
        auth=AuthMode.SERVICE_TOKEN,
        token_id=lab.id,
        service_type=ServiceType.RDP,
        proxy="proxy.exemple.fr:3128",
    )
    web = CloudflareProfile(
        name="Intranet", hostname="intranet.exemple.fr", local_port=8443, service_type=ServiceType.HTTPS
    )
    nas = SshProfile(
        name="NAS",
        favorite=True,
        host="nas.exemple.lan",
        user="admin",
        auth=SshAuthMode.KEY,
        key_path="id_ed25519_nas",
        saved_forwards=[
            SavedForward(remote_port=3000, local_port=3000, scheme="https", label="grafana"),
            SavedForward(
                remote_host="172.17.0.1", remote_port=8080, local_port=8081, scheme="http", label="portainer"
            ),
        ],
    )
    backup = SshProfile(name="Serveur de sauvegarde", group="Production", host="10.0.0.20", user="backup")

    def fill(config: object) -> None:
        config.tokens.extend([prod, lab])  # type: ignore[attr-defined]
        config.cloudflare_profiles.extend([mongo, ssh_cf, rdp, web])  # type: ignore[attr-defined]
        config.ssh_profiles.extend([nas, backup])  # type: ignore[attr-defined]
        config.settings.onboarding_done = True  # type: ignore[attr-defined]

    ctx.store.update(fill)
    ctx.core.secrets.set(prod.secret_key, "d3m0-s3cr3t-pr0d")
    ctx.core.secrets.set(lab.secret_key, "d3m0-s3cr3t-l4b")


def demo_sessions(ctx: GuiContext) -> list[SessionInfo]:
    config = ctx.config()
    now = datetime.now()
    by_name = {p.name: p for p in config.cloudflare_profiles}
    nas = next(p for p in config.ssh_profiles if p.name == "NAS")

    def cf(name: str, state: SessionState, message: str = "", minutes: int = 0) -> SessionInfo:
        profile = by_name[name]
        return SessionInfo(
            id=f"demo-{profile.id[:6]}",
            kind=SessionKind.CLOUDFLARE,
            profile_id=profile.id,
            forward_id=None,
            name=profile.name,
            subtitle=profile.hostname,
            local_host="127.0.0.1",
            local_port=profile.local_port or 0,
            state=state,
            message=message,
            started_at=now - timedelta(minutes=minutes + 1),
            listening_since=now - timedelta(minutes=minutes)
            if state in (SessionState.LISTENING, SessionState.DEGRADED)
            else None,
            service_type=profile.service_type,
            scheme=None,
            service_user=profile.service_user,
            connections=0,
            bytes_up=0,
            bytes_down=0,
            reconnect_in=4.0 if state == SessionState.RECONNECTING else None,
            attempts=2,
        )

    forward = nas.saved_forwards[0]
    ssh = SessionInfo(
        id="demo-forward",
        kind=SessionKind.SSH_FORWARD,
        profile_id=nas.id,
        forward_id=forward.id,
        name="NAS · grafana",
        subtitle="NAS → 127.0.0.1:3000 (vu du serveur)",
        local_host="127.0.0.1",
        local_port=3000,
        state=SessionState.LISTENING,
        message="",
        started_at=now - timedelta(minutes=13),
        listening_since=now - timedelta(minutes=12, seconds=40),
        service_type=ServiceType.HTTPS,
        scheme="https",
        service_user="",
        connections=3,
        bytes_up=184_320,
        bytes_down=12_845_056,
        reconnect_in=None,
        attempts=0,
    )
    return [
        cf("MongoDB production", SessionState.LISTENING, minutes=134),
        ssh,
        cf(
            "Bureau labo",
            SessionState.DEGRADED,
            "Cloudflare Access a refusé la connexion : token invalide ou non autorisé, "
            "ou application qui n'est pas protégée par Access.",
            minutes=6,
        ),
        cf("SSH bastion", SessionState.RECONNECTING, "cloudflared s'est arrêté (code 1).", minutes=0),
    ]


def show_demo_cloud(view) -> None:
    """Compte Cloudflare fictif : deux tunnels, leurs noms d'hôte, applications Access et tokens."""
    from cma.core.cfadmin import Overview, TunnelView
    from cma.core.cfapi import AccessApp, Account, IngressRule, RemoteServiceToken, Tunnel, Zone

    account = Account("acc", "Exemple SAS")
    overview = Overview(
        account=account,
        tunnels=[
            TunnelView(
                Tunnel("t1", "bureau", "healthy"),
                [
                    IngressRule("mongodb.exemple.fr", "tcp://localhost:27017"),
                    IngressRule("ssh.exemple.fr", "ssh://localhost:22"),
                    IngressRule("rdp.exemple.fr", "rdp://10.0.0.12:3389"),
                    IngressRule("wiki.exemple.fr", "http://localhost:8080"),
                ],
            ),
            TunnelView(
                Tunnel("t2", "labo", "degraded"),
                [IngressRule("grafana.lab.exemple.fr", "http://localhost:3000")],
            ),
        ],
        apps=[
            AccessApp("a1", "MongoDB production", "mongodb.exemple.fr", "self_hosted"),
            AccessApp("a2", "SSH", "ssh.exemple.fr", "self_hosted"),
        ],
        tokens=[RemoteServiceToken("r1", "Production", "8f3c2a1b.access", "2027-09-29T00:00:00Z")],
        zones=[Zone("z1", "exemple.fr"), Zone("z2", "lab.exemple.fr")],
    )
    # Dernier relevé de la surveillance des services : un service en panne derrière un tunnel en ligne.
    from cma.core.hostprobe import HostProbe
    from cma.core.servicewatch import ServiceTarget

    view.ctx.services.record(
        [
            (
                ServiceTarget("wiki.exemple.fr", "", "http://localhost:8080", "t1", "bureau"),
                HostProbe("origin_down", 502),
            ),
            (
                ServiceTarget("grafana.lab.exemple.fr", "", "http://localhost:3000", "t2", "labo"),
                HostProbe("ok", 200),
            ),
        ]
    )
    view.stack.setCurrentIndex(1)
    view.account.clear()
    view.account.addItem(account.name, account)
    view._fill(overview)


def show_demo_health(window) -> None:
    """Carte « Santé du compte » de la page Sessions : un tunnel dégradé, un service en panne, un token à renouveler."""
    from cma.core.cfapi import Tunnel
    from cma.core.expiry import TokenExpiry
    from cma.core.hostprobe import HostProbe
    from cma.core.servicewatch import ServiceResult, ServiceTarget

    token = next(t for t in window.ctx.config().tokens if t.name == "Laboratoire")
    tunnels = [Tunnel("t2", "labo", "degraded")]
    services = [
        ServiceResult(
            ServiceTarget("wiki.exemple.fr", "", "http://localhost:8080", "t1", "bureau"),
            HostProbe("origin_down", 502),
            datetime.now(),
        )
    ]
    # Comme un relevé de la surveillance : badge « Cloudflare · 2 ! » de la navigation, puis la carte, avec un
    # token à renouveler (les tokens de démonstration n'expirent pas).
    window._on_troubled(tunnels, services)
    window.dashboard.health.update_state(tunnels, services, [TokenExpiry(token, 12)])


def demo_availability(path: Path) -> None:
    """Journal de disponibilité fictif sur 30 jours : un relevé par heure, quelques pannes."""
    from datetime import UTC

    from cma.core.availability import AvailabilityLog

    log = AvailabilityLog(path)
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    objects = (
        (
            "service:wiki.exemple.fr",
            "wiki.exemple.fr",
            "service",
            160,
            {(12, 9), (12, 10), (12, 11), (3, 14)},
        ),
        ("service:grafana.lab.exemple.fr", "grafana.lab.exemple.fr", "service", 90, {(20, 3), (20, 4)}),
        ("tunnel:t1", "bureau", "tunnel", 0, set()),
        ("tunnel:t2", "labo", "tunnel", 0, {(20, 2), (20, 3), (20, 4), (20, 5)}),
    )
    for key, name, kind, base_ms, outages in objects:
        down_since = None
        for hours in range(30 * 24, -1, -1):
            at = now - timedelta(hours=hours)
            day, hour = divmod(hours, 24)
            ok = (day, hour) not in outages
            ms = float(base_ms + (hours * 37) % 90 + (180 if day == 12 else 0)) if base_ms and ok else None
            log.record_check(key, name, ok, ms, at)
            if not ok and down_since is None:
                down_since = at
                log.start(kind, key, name, "origin_down" if kind == "service" else "down", at)
            elif ok and down_since is not None:
                down_since = None
                log.end(kind, key, at)
    log.save()


def capture_guide(window, output: Path) -> None:
    """Boîtes illustrant docs/GUIDE.md (thème clair) : test des noms d'hôte, réseaux privés, instantanés, partage,
    bilan de sécurité, disponibilité, publication d'un port découvert. Données fictives, aucun appel réseau :
    l'administration Cloudflare est remplacée par une façade inerte."""
    from types import SimpleNamespace

    from PySide6.QtWidgets import QDialog

    from cma.core.cfadmin import PrivateNetwork
    from cma.core.cfapi import Account, Tunnel
    from cma.core.hostprobe import HostProbe
    from cma.core.privnet import PrivateRoute, VirtualNetwork
    from cma.core.servicewatch import ServiceTarget
    from cma.core.snapshot import SnapshotChange
    from cma.ui.dialogs.links import ShareDialog
    from cma.ui.views.cloud.private_network import PrivateNetworkDialog
    from cma.ui.views.cloud.services import ServiceTestsDialog
    from cma.ui.views.cloud.snapshots import SnapshotsDialog

    ctx = window.ctx
    inert = SimpleNamespace(
        private_network=lambda _t: None,
        snapshot=lambda _a: None,
        permissions=lambda: None,
        security_review=lambda: None,
    )
    quiet = SimpleNamespace(
        run=lambda *_a, **_k: None, notify=lambda *_a, **_k: None, paths=ctx.paths, config=ctx.config
    )

    def save(dialog: QDialog, name: str) -> None:
        dialog.show()
        for _ in range(5):
            QApplication.processEvents()
        dialog.grab().save(str(output / name))
        dialog.close()
        dialog.deleteLater()

    bureau = ("t1", "bureau")
    tests = [
        (
            ServiceTarget("wiki.exemple.fr", "", "http://localhost:8080", *bureau),
            HostProbe("origin_down", 502),
        ),
        (ServiceTarget("mongodb.exemple.fr", "", "tcp://localhost:27017", *bureau), HostProbe("access", 302)),
        (ServiceTarget("ssh.exemple.fr", "", "ssh://localhost:22", *bureau), HostProbe("access", 302)),
        (
            ServiceTarget("grafana.lab.exemple.fr", "", "http://localhost:3000", "t2", "labo"),
            HostProbe("ok", 200),
        ),
        (
            ServiceTarget("status.exemple.fr", "", "http://localhost:3001", *bureau),
            HostProbe("challenge", 403),
        ),
    ]
    save(ServiceTestsDialog(window, tests), "guide-test-noms.png")
    network = PrivateNetworkDialog(window, quiet, inert, Tunnel("t1", "bureau", "healthy"))  # type: ignore[arg-type]
    network.show_network(
        PrivateNetwork(
            [
                PrivateRoute("r1", "10.0.0.0/24", "t1", "vn1", "default", "LAN bureau"),
                PrivateRoute("r2", "192.168.10.0/24", "t1", "vn1", "default", "NAS"),
            ],
            [VirtualNetwork("vn1", "default", True)],
            True,
        )
    )
    save(network, "guide-reseaux-prives.png")
    from cma.core.snapshot import save_snapshot
    from cma.ui.views.cloud.snapshots import snapshot_dir

    for day, policies in ((8, 3), (9, 2)):
        save_snapshot(
            snapshot_dir(ctx.paths),
            {
                "version": 1,
                "taken_at": f"2026-10-0{day}T08:00:00Z",
                "account": {"id": "acc", "name": "Exemple SAS"},
                "tunnels": {"t1": {}, "t2": {}},
                "apps": {"a1": {}, "a2": {}},
                "policies": {f"p{i}": {} for i in range(policies)},
                "service_tokens": {"s1": {}},
            },
        )
    snapshots = SnapshotsDialog(window, quiet, inert, Account("acc", "Exemple SAS"))  # type: ignore[arg-type]
    snapshots.fill_changes(
        [
            SnapshotChange(
                "tunnels",
                "t1",
                "bureau",
                "changed",
                ("config.ingress[3].service : http://localhost:8080 → http://10.0.0.20:8080",),
            ),
            SnapshotChange("policies", "p2", "Prestataires", "removed"),
            SnapshotChange("routes", "r2", "192.168.10.0/24", "added"),
        ]
    )
    snapshots.status.setText("3 changements depuis le 08/10/2026 10:00.")
    save(snapshots, "guide-instantanes.png")
    profile = next(p for p in ctx.config().cloudflare_profiles if p.name == "MongoDB production")
    save(ShareDialog(window, ctx, profile), "guide-partager.png")

    from cma.core.security import Finding
    from cma.ui.views.cloud.availability import AvailabilityDialog
    from cma.ui.views.cloud.dialogs import PublishDialog
    from cma.ui.views.cloud.security_review import SecurityReviewDialog

    review = SecurityReviewDialog(window, quiet, inert)  # type: ignore[arg-type]
    review.show_findings(
        [
            Finding("unprotected", "high", "wiki.exemple.fr", "wiki.exemple.fr", "protect", ("t1", "")),
            Finding("dangling_dns", "medium", "ancien.exemple.fr", "d1", "delete_dns", ("z1",)),
            Finding("exposed_catch_all", "medium", "labo", "t2", "catch_all_404"),
            Finding("token_unused", "medium", "Prestataire 2025", "s9", "delete_token"),
            Finding(
                "access_not_required",
                "low",
                "mongodb.exemple.fr",
                "mongodb.exemple.fr",
                "require_access",
                ("t1", "", "aud"),
            ),
            Finding("inactive_tunnel", "low", "ancien-nas", "t9"),
        ]
    )
    review.table.selectRow(0)
    save(review, "guide-bilan.png")

    demo_availability(ctx.paths.data_dir / "availability.json")
    availability = AvailabilityDialog(window, ctx.paths.data_dir / "availability.json")
    availability.table.selectRow(availability.keys.index("service:wiki.exemple.fr"))
    save(availability, "guide-disponibilite.png")

    overview = window.cloud.overview
    remote = {t.client_id for t in overview.tokens}
    publish = PublishDialog(
        window,
        overview,
        [t for t in ctx.config().tokens if t.client_id in remote],
        hostname="grafana",
        service="https://localhost:3000",
        note="Le service est joint depuis le connecteur du tunnel : choisissez le tunnel dont cloudflared tourne "
        "sur « NAS » (sinon, remplacez localhost par l'adresse du serveur).",
    )
    save(publish, "guide-publier-port.png")
    capture_guide_alerts(window, output)
    capture_guide_health_menu(window, output)
    capture_guide_sends(window, output)
    capture_guide_maintenance_card(window, output)


def capture_guide_alerts(window, output: Path) -> None:
    """`guide-maintenance.png` : section « Maintenance et rappels » des Paramètres, avec trois fenêtres de
    maintenance et un canal d'alerte d'exemple. La configuration de démonstration est rétablie ensuite : les
    captures suivantes (thème sombre) ne doivent pas les montrer."""
    from cma.core.models import AlertChannel, MaintenanceWindow
    from cma.ui.views.common import FormCard
    from cma.ui.views.settings import SettingsView

    ctx = window.ctx
    before = ctx.config().settings
    saved = (
        list(before.alert_channels),
        list(before.maintenance_windows),
        before.alert_repeat_hours,
        before.weekly_digest,
    )

    def demo(config) -> None:
        config.settings.alert_channels = [AlertChannel(name="Téléphone", kind="ntfy")]
        config.settings.maintenance_windows = [
            MaintenanceWindow(weekday=6, start="02:00", end="04:00", label="Mises à jour des serveurs"),
            MaintenanceWindow(weekday=5, start="23:00", end="01:30", target="tunnel:t1", label="Sauvegarde"),
            MaintenanceWindow(weekday=2, start="12:00", end="12:30", target="service:wiki.exemple.fr"),
        ]
        config.settings.alert_repeat_hours = 6
        config.settings.weekly_digest = True

    def restore(config) -> None:
        config.settings.alert_channels, config.settings.maintenance_windows = saved[0], saved[1]
        config.settings.alert_repeat_hours, config.settings.weekly_digest = saved[2], saved[3]

    ctx.update_config(demo)
    try:
        view = SettingsView(ctx)
        view.known_objects = lambda: [("tunnel:t1", "bureau"), ("service:wiki.exemple.fr", "wiki.exemple.fr")]
        view.load()
        view.resize(980, 900)
        card = view.alerts.digest.parentWidget()
        while card is not None and not isinstance(card, FormCard):
            card = card.parentWidget()
        if card is None:
            raise RuntimeError("section Maintenance et rappels introuvable")
        view.show()
        for _ in range(8):
            QApplication.processEvents()
        card.resize(900, card.sizeHint().height())
        for _ in range(4):
            QApplication.processEvents()
        card.grab().save(str(output / "guide-maintenance.png"))
        view.hide()
        view.deleteLater()
    finally:
        ctx.update_config(restore)


def capture_guide_health_menu(window, output: Path) -> None:
    """`guide-menu-pannes.png` : sous-menu « Pannes » de l'icône, avec le tunnel « labo » hors ligne et le service
    `wiki.exemple.fr` injoignable (état injecté, aucun relevé réel)."""
    from PySide6.QtCore import QPoint

    from cma.core.cfapi import Tunnel
    from cma.core.hostprobe import HostProbe
    from cma.core.servicewatch import ServiceResult, ServiceTarget
    from cma.ui.tray import Tray

    tray = Tray(window.ctx, window)
    target = ServiceTarget("wiki.exemple.fr", "", "http://localhost:8080", "t1", "bureau")
    tray._on_services([ServiceResult(target, HostProbe("origin_down", 502), datetime.now())])
    tray._on_tunnels([Tunnel("t2", "labo", "down")])
    menu = tray._health_menu
    if menu is None:
        raise RuntimeError("sous-menu Pannes absent")
    menu.popup(QPoint(300, 300))
    for _ in range(10):
        QApplication.processEvents()
    menu.grab().save(str(output / "guide-menu-pannes.png"))
    menu.hide()
    tray.deleteLater()
    QApplication.processEvents()


def capture_guide_sends(window, output: Path) -> None:
    """`guide-envois.png` : boîte « Envois récents » avec un journal d'exemple (réussis et échecs). Le journal est un
    fichier temporaire : ni le journal du poste ni une vraie adresse de canal n'interviennent."""
    from datetime import UTC

    from cma.core.alertlog import AlertLog
    from cma.ui.dialogs.sends import SendsDialog

    now = datetime.now(UTC).replace(microsecond=0)
    rows = [
        ("Téléphone", "ntfy", "alert", "mongodb.exemple.fr", "", 190),
        ("Équipe infra", "slack", "alert", "mongodb.exemple.fr", "Le canal a refusé l'alerte (403).", 189),
        ("Téléphone", "ntfy", "reminder", "tunnel bureau", "", 120),
        ("Équipe infra", "slack", "reminder", "tunnel bureau", "Canal injoignable : timed out", 119),
        ("Téléphone", "ntfy", "recovery", "mongodb.exemple.fr", "", 60),
        ("Téléphone", "ntfy", "digest", "", "", 30),
        ("Équipe infra", "slack", "test", "", "", 5),
    ]
    with tempfile.TemporaryDirectory(prefix="cma-demo-log-") as folder:
        journal = AlertLog(Path(folder) / "alert_log.json")
        for channel, kind, nature, subject, error, minutes in rows:
            journal.note(
                channel=channel,
                kind=kind,
                nature=nature,
                subject=subject,
                error=error or None,
                at=now - timedelta(minutes=minutes),
            )
        dialog = SendsDialog(window, journal)
        dialog.show()
        for _ in range(8):
            QApplication.processEvents()
        dialog.grab().save(str(output / "guide-envois.png"))
        dialog.close()
        dialog.deleteLater()
        QApplication.processEvents()


def capture_guide_maintenance_card(window, output: Path) -> None:
    """`guide-carte-maintenance.png` : la vue Cloudflare de démonstration avec le tunnel « bureau » en maintenance
    (une fenêtre commencée il y a une heure, finie dans trois). La configuration est rétablie ensuite."""
    from cma.core.models import MaintenanceWindow

    ctx = window.ctx
    saved = list(ctx.config().settings.maintenance_windows)
    start = datetime.now().astimezone() - timedelta(hours=1)
    end = start + timedelta(hours=3)

    def demo(config) -> None:
        config.settings.maintenance_windows = [
            MaintenanceWindow(
                weekday=start.weekday(),
                start=start.strftime("%H:%M"),
                end=end.strftime("%H:%M"),
                target="tunnel:t1",
                label="Mises à jour du serveur",
            )
        ]

    def restore(config) -> None:
        config.settings.maintenance_windows = saved

    ctx.update_config(demo)
    try:
        window.show_view("cloud")
        window.cloud.show_maintenance()
        for _ in range(8):
            QApplication.processEvents()
        shot = window.cloud.grab()
        # Coupée sous la carte du tunnel « bureau » : la suivante, rognée, n'apporterait rien.
        shot.copy(0, 0, shot.width(), int(680 * shot.devicePixelRatio())).save(
            str(output / "guide-carte-maintenance.png")
        )
    finally:
        ctx.update_config(restore)
        window.cloud.show_maintenance()
        QApplication.processEvents()


def main() -> int:
    output = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/captures")
    output.mkdir(parents=True, exist_ok=True)
    app = QApplication(sys.argv)
    temp = tempfile.TemporaryDirectory(prefix="cma-demo-")
    paths = AppPaths(Path(temp.name))
    theme = ThemeManager(app)
    core = create_context(paths, NonInteractivePrompter(), secrets=DemoStore())
    # CMA_CAPTURE_LANGUAGE=de (ou en, es) : captures dans une autre langue, pour vérifier la mise en page.
    set_language(os.environ.get("CMA_CAPTURE_LANGUAGE", "fr"))
    engine = Engine()
    engine.start()
    bridge = EngineBridge(core.bus)
    core.store.add_listener(bridge.config_changed.emit)
    ctx = GuiContext(
        core=core, engine=engine, runner=TaskRunner(engine), bridge=bridge, theme=theme, prompter=None
    )  # type: ignore[arg-type]
    demo_config(ctx)

    from cma.ui.main_window import MainWindow
    from cma.ui.views import settings as settings_view

    async def demo_version(_binary: object) -> str:
        return "2026.9.3"

    # Aucune information du poste dans les captures : binaire et dossier de données fictifs.
    settings_view.read_version = demo_version  # type: ignore[assignment]
    core.manager.cloudflared_path = lambda: Path(r"C:\Outils\cloudflared\cloudflared.exe")  # type: ignore[method-assign]

    for theme_name in (Theme.LIGHT, Theme.DARK):
        theme.set_theme(theme_name)
        window = MainWindow(ctx)
        window.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
        width, height = (int(v) for v in os.environ.get("CMA_CAPTURE_SIZE", "1240x780").split("x"))
        window.resize(width, height)
        window.show()
        for info in demo_sessions(ctx):
            window.dashboard._on_session(info)
            window.profiles._on_session(info)
            window.ssh._on_session(info)
            window._on_session(info)
        for level, source, text in (
            (
                "INFO",
                "MongoDB production",
                "Commande : cloudflared access tcp --hostname mongodb.exemple.fr --url 127.0.0.1:27017 --loglevel info",
            ),
            (
                "INFO",
                "MongoDB production",
                "2026-09-29T09:12:03Z INF Start Websocket listener host=127.0.0.1:27017",
            ),
            ("INFO", "MongoDB production", "À l'écoute sur 127.0.0.1:27017."),
            (
                "ERROR",
                "Bureau labo",
                '2026-09-29T09:20:41Z ERR failed to connect to origin error="websocket: bad handshake"',
            ),
            ("WARNING", "SSH bastion", "cloudflared s'est arrêté (code 1). Nouvelle tentative dans 4 s."),
            ("INFO", "NAS · grafana", "À l'écoute sur 127.0.0.1:3000, vers 127.0.0.1:3000 depuis NAS."),
        ):
            window.logs.model.add(LogLine(source_id=None, source_label=source, level=level, message=text))  # type: ignore[arg-type]
        window.logs.model.flush()
        window.set_cloudflared_status("cloudflared 2026.9.3")
        window.settings.data_dir.setText(r"C:\Users\<utilisateur>\AppData\Roaming\CloudflaredManager")
        suffix = "sombre" if theme_name == Theme.DARK else "clair"
        show_demo_health(window)
        for key in ("dashboard", "profiles", "tokens", "ssh", "cloud", "logs", "settings"):
            window.show_view(key)
            if key == "profiles":
                window.profiles.select_profile(
                    next(p.id for p in ctx.config().cloudflare_profiles if p.name == "MongoDB production")
                )
            if key == "tokens":
                window.tokens.list.select(ctx.config().tokens[0].id)
            if key == "ssh":
                nas = next(p for p in ctx.config().ssh_profiles if p.name == "NAS")
                window.ssh.discoveries[nas.id] = (
                    DiscoveryResult(
                        ports=[
                            RemotePort(22, ("0.0.0.0", "::"), service="ssh"),
                            RemotePort(
                                3000, ("127.0.0.1",), container="grafana", scheme="https", http_code=302
                            ),
                            RemotePort(5432, ("127.0.0.1",), service="postgresql"),
                            RemotePort(
                                8080,
                                ("172.17.0.1",),
                                service="http-alt",
                                container="portainer",
                                scheme="http",
                                http_code=200,
                            ),
                            RemotePort(
                                9100, ("0.0.0.0",), container="node-exporter", scheme="http", http_code=200
                            ),
                        ],
                        script_version="2.0.0",
                        docker="helper",
                    ),
                    datetime.now() - timedelta(minutes=2),
                )
                window.ssh.select_profile(nas.id)
            if key == "cloud":
                show_demo_cloud(window.cloud)
            for _ in range(5):
                app.processEvents()
            window.grab().save(str(output / f"{key}-{suffix}.png"))
            if key == "cloud":
                # Page de connexion (sans jeton), puis retour au compte de démonstration.
                window.cloud.stack.setCurrentIndex(0)
                for _ in range(5):
                    app.processEvents()
                window.grab().save(str(output / f"cloud-connexion-{suffix}.png"))
                window.cloud.stack.setCurrentIndex(1)
        if theme_name == Theme.LIGHT:
            capture_guide(window, output)
        window.quitting = True
        window.close()
        window.deleteLater()
        app.processEvents()
    engine.stop()
    temp.cleanup()
    print(f"Captures enregistrées dans {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
