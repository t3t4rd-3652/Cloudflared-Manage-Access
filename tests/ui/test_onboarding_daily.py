"""Prise en main et usage quotidien (P15) : import de ~/.ssh/config, carte « Santé du compte », espaces de travail
au démarrage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import cma.ui.dialogs.workspaces as workspaces_module
from cma.core.cfapi import Tunnel
from cma.core.hostprobe import HostProbe
from cma.core.models import LaunchItem, ServiceToken, Workspace
from cma.core.servicewatch import ServiceTarget
from cma.ui.dialogs.workspaces import WorkspacesDialog
from cma.ui.views.ssh.import_config import SshConfigImportDialog

CONFIG = """
Host bastion
    HostName bastion.exemple.fr
    User alice
Host nas
    HostName 192.168.50.23
    ProxyJump bastion
Host deja
    HostName deja.exemple.fr
"""


def test_import_ssh_config_dialog(qtbot, gui, tmp_path):
    ctx, window = gui
    from cma.core.models import SshProfile

    ctx.update_config(lambda c: c.ssh_profiles.append(SshProfile(name="deja", host="deja.exemple.fr")))
    path = tmp_path / "config"
    path.write_text(CONFIG, encoding="utf-8")
    dialog = SshConfigImportDialog(window, ctx, path)
    qtbot.addWidget(dialog)
    assert [dialog.table.item(r, 6).text() for r in range(3)] == ["Nouveau", "Nouveau", "Déjà dans CMA"]
    assert [e.alias for e in dialog.checked()] == ["bastion", "nas"]
    assert dialog.summary.text() == "2 serveurs choisis"
    dialog.import_selected()
    profiles = {p.name: p for p in ctx.config().ssh_profiles}
    assert profiles["nas"].jump_profile == profiles["bastion"].id and dialog.imported == 2
    assert dialog.table.item(0, 6).text() == "Déjà dans CMA"  # relu après l'import
    assert not dialog.import_button.isEnabled()
    empty = SshConfigImportDialog(window, ctx, tmp_path / "absent")
    qtbot.addWidget(empty)
    assert empty.table.isHidden() and not empty.empty.isHidden()
    assert "Importer ~/.ssh/config…" in [a.text() for a in window.ssh.list.actions_menu.actions()]


def test_health_card_on_the_sessions_page(qtbot, gui, monkeypatch):
    ctx, window = gui
    window.show()
    health = window.dashboard.health
    window._show_troubled_tunnels()
    assert health.isHidden()
    # Un token qui expire bientôt : la carte le dit, et « Voir » ouvre l'onglet des tokens.
    token = ServiceToken(
        name="Robot", client_id="robot.access", expires_at=datetime.now(UTC) + timedelta(days=3)
    )
    ctx.update_config(lambda c: c.tokens.append(token))
    assert health.isVisible() and "1 service token à renouveler" in health.detail.text()
    opened: list[str] = []
    monkeypatch.setattr(window, "open_cloud_tokens", lambda: opened.append("tokens"))
    health.open_tokens = window.open_cloud_tokens
    health.action.click()
    assert opened == ["tokens"]
    # Un tunnel hors ligne et un service en panne : « Voir » ouvre la vue Cloudflare.
    window.tunnel_watch.update([Tunnel("t1", "bureau", "down")])
    target = ServiceTarget("wiki.exemple.fr", "", "http://x:1", "t1", "bureau")
    ctx.services.update([(target, HostProbe("origin_down", 502))])
    window._show_troubled_tunnels()
    text = health.detail.text()
    assert "Tunnel « bureau » hors ligne" in text and "wiki.exemple.fr ne répond plus" in text
    health.open_cloud = lambda: opened.append("cloud")
    health.action.click()
    assert opened == ["tokens", "cloud"]


def test_workspace_startup_settings_and_launch(qtbot, gui, monkeypatch):
    ctx, window = gui
    item = LaunchItem(kind="cloudflare", profile_id="p1")
    workspace = Workspace(name="Matin", items=[item])
    ctx.update_config(lambda c: c.workspaces.append(workspace))
    dialog = WorkspacesDialog(window, ctx)
    qtbot.addWidget(dialog)
    assert not dialog.on_startup.isChecked() and not dialog.unless_network.isEnabled()
    dialog.on_startup.setChecked(True)
    monkeypatch.setattr(workspaces_module, "current_wifi", lambda: "Maison 5G")
    dialog._use_current_network()
    saved = ctx.config().workspace(workspace.id)
    assert saved is not None and saved.on_startup and saved.unless_network == "Maison 5G"

    from cma.ui import app as app_module

    launched: list[str] = []
    monkeypatch.setattr(workspaces_module, "launch_workspace", lambda _ctx, w: launched.append(w.name))
    monkeypatch.setattr("cma.platform.network.current_wifi", lambda: "Maison 5G")
    app_module.open_startup_workspaces(ctx)
    qtbot.wait(300)
    assert launched == []  # à la maison : pas ouvert
    monkeypatch.setattr("cma.platform.network.current_wifi", lambda: "Café")
    app_module.open_startup_workspaces(ctx)
    qtbot.waitUntil(lambda: launched == ["Matin"], timeout=5000)
