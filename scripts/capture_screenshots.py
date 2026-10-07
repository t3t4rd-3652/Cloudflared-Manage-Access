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
    view.stack.setCurrentIndex(1)
    view.account.clear()
    view.account.addItem(account.name, account)
    view._fill(overview)


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
