"""Outils du compte dans la vue Cloudflare (P10) contre le faux serveur : réseaux privés, journal d'audit,
instantanés, permissions du jeton, trafic sur les cartes."""

from __future__ import annotations

import pytest

import cma.ui.views.cloud.account_tools as tools_module
import cma.ui.views.cloud.audit_log as audit_module
import cma.ui.views.cloud.private_network as privnet_module
import cma.ui.views.cloud.snapshots as snapshots_module
import cma.ui.views.cloud.tunnels_tab as tunnels_module
from cma.core.audit import AuditEntry
from cma.core.cfapi import Tunnel
from cma.core.traffic import HostTraffic
from cma.ui.views.cloud.audit_log import AuditLogDialog, actor_label
from cma.ui.views.cloud.cards import TRAFFIC_ROLE
from cma.ui.views.cloud.permissions import PermissionsDialog
from cma.ui.views.cloud.private_network import PrivateNetworkDialog
from cma.ui.views.cloud.snapshots import SnapshotsDialog
from tests.fakes.fake_cfapi import TOKEN, FakeCloudflare, FakeCloudflareServer

BUREAU = Tunnel("t1", "bureau", "healthy")


@pytest.fixture
def cf():
    with FakeCloudflareServer(FakeCloudflare()) as server:
        yield server


@pytest.fixture
def view(qtbot, gui, cf):
    ctx, window = gui
    ctx.core.manager.cloudflare.base_url = cf.base_url
    window.show_view("cloud")
    cloud = window.cloud
    cloud.token_field.set_text(TOKEN)
    cloud.connect_account()
    qtbot.waitUntil(lambda: cloud.tree.topLevelItemCount() == 2, timeout=10000)
    return cloud


def test_private_network_dialog(qtbot, view, cf, monkeypatch):
    changed: list[bool] = []
    dialog = PrivateNetworkDialog(view, view.ctx, view.admin, BUREAU, lambda: changed.append(True))
    qtbot.addWidget(dialog)
    qtbot.waitUntil(lambda: dialog.add_button.isEnabled(), timeout=5000)
    assert dialog.table.rowCount() == 0 and not dialog.warp.isChecked()
    assert dialog.vnet.currentText() == "default (par défaut)"
    # Saisie invalide : expliquée, rien n'est envoyé.
    dialog.network.setText("bureau")
    dialog.add_route()
    assert "ni une adresse IP" in dialog.status.text() and cf.state.routes == []
    # Plage publique : confirmation demandée (ici refusée).
    asked: list[str] = []
    monkeypatch.setattr(privnet_module, "confirm", lambda _p, heading, *_a: asked.append(heading) or False)
    dialog.network.setText("8.8.8.0/24")
    dialog.add_route()
    assert asked == ["Router une plage publique ?"] and cf.state.routes == []
    # Plage privée : ajoutée, et le routage WARP est activé avec elle.
    dialog.network.setText("10.0.0.9/24")
    dialog.comment.setText("LAN")
    dialog.add_route()
    qtbot.waitUntil(lambda: dialog.table.rowCount() == 1 and dialog.add_button.isEnabled(), timeout=5000)
    assert dialog.table.item(0, 0).text() == "10.0.0.0/24" and dialog.warp.isChecked()
    assert cf.state.configs["t1"]["warp-routing"] == {"enabled": True} and changed
    # Couper le routage avec des routes : confirmation (refusée : la case revient).
    dialog.warp.setChecked(False)
    assert dialog.warp.isChecked() and cf.state.configs["t1"]["warp-routing"]["enabled"]
    # Retirer la route (confirmée).
    monkeypatch.setattr(privnet_module, "confirm", lambda *_a: True)
    dialog.table.selectRow(0)
    dialog.remove_route()
    qtbot.waitUntil(lambda: dialog.table.rowCount() == 0 and dialog.add_button.isEnabled(), timeout=5000)
    assert cf.state.routes == []


def test_tunnel_menu_routes_and_traffic_on_cards(qtbot, view, cf, monkeypatch):
    opened: list[str] = []
    monkeypatch.setattr(
        tunnels_module, "show_private_network", lambda _p, _c, _a, tunnel, _r: opened.append(tunnel.name)
    )
    bureau = view.tree.topLevelItem(0)
    action = next(a for a in view.tree_menu(bureau).actions() if a.text() == "Réseaux privés…")
    action.trigger()
    assert opened == ["bureau"]
    grafana = next(bureau.child(i) for i in range(3) if bureau.child(i).text(0) == "grafana.exemple.fr")
    assert grafana.data(0, TRAFFIC_ROLE) == HostTraffic(126, 6)
    assert "126 requêtes, 6 erreurs 5xx" in grafana.toolTip(0)
    # Une route sur « bureau » apparaît dans le résumé de sa carte après relecture.
    cf.state.routes.append(
        {"id": "r1", "network": "10.0.0.0/24", "tunnel_id": "t1", "virtual_network_id": "vn1"}
    )
    view.refresh()
    qtbot.waitUntil(
        lambda: (
            "1 réseau privé" in (view.tree.topLevelItem(0).text(1) if view.tree.topLevelItemCount() else "")
        ),
        timeout=10000,
    )


def test_audit_log_dialog_filters_and_exports(qtbot, tmp_path, monkeypatch):
    from datetime import UTC, datetime, timedelta

    def ago(**delta: float) -> str:
        return (datetime.now(UTC) - timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")

    entries = [
        AuditEntry(
            ago(hours=2),
            "Update a Cloudflare Tunnel configuration",
            "update",
            "success",
            "cfd_tunnel",
            "configurations",
            "t1",
            "alice@exemple.fr",
            "user",
            "dash",
        ),
        AuditEntry(
            ago(days=3),
            "Delete an Access application",
            "delete",
            "failure",
            "access",
            "apps",
            "app9",
            "",
            "user",
            "api_token",
        ),
        AuditEntry(
            ago(days=20),
            "Renew certificate",
            "update",
            "success",
            "certificates",
            "certificate_pack",
            "c1",
            "",
            "system",
            "",
        ),
    ]
    dialog = AuditLogDialog(None, entries)
    qtbot.addWidget(dialog)
    assert dialog.table.rowCount() == 2 and dialog.summary.text() == "2 modifications · 1 en échec"
    assert [dialog.table.item(r, 2).text() for r in range(2)] == ["Tunnels", "Access"]
    assert (
        dialog.table.item(1, 4).text() == "Jeton d'API"
        and dialog.table.item(0, 5).text() == "Tableau de bord"
    )
    dialog.period.setCurrentIndex(2)
    assert dialog.table.rowCount() == 3 and actor_label(entries[2]) == "Cloudflare (automatique)"
    dialog.search.setText("tunnel alice")
    assert dialog.table.rowCount() == 1
    target = tmp_path / "audit.csv"
    monkeypatch.setattr(audit_module, "ask_audit_csv_path", lambda _p: target)
    dialog.export_csv()
    text = target.read_text(encoding="utf-8-sig")
    assert text.splitlines()[0].startswith("Date;Action;Produit") and "alice@exemple.fr" in text
    assert dialog.export_note.text() == "1 modification exportée : audit.csv"


def test_tools_menu_opens_the_audit_log(qtbot, view, monkeypatch):
    shown: list[int] = []
    monkeypatch.setattr(tools_module, "show_audit_log", lambda _p, entries: shown.append(len(entries)))
    assert [a.text() for a in view.tools.menu.actions()] == [
        "Journal d'audit du compte…",
        "Instantanés de la configuration…",
        "Permissions du jeton…",
        "",
        "Ajouter un jeton d'API…",
    ]
    view.tools.open_audit_log()
    qtbot.waitUntil(lambda: shown == [3], timeout=5000)


def test_snapshots_dialog(qtbot, view, cf, monkeypatch, tmp_path):
    account = view.tools.account()
    assert account is not None
    dialog = SnapshotsDialog(view, view.ctx, view.admin, account)
    qtbot.addWidget(dialog)
    assert dialog.table.rowCount() == 0 and not dialog.now_button.isEnabled()
    dialog.take()
    qtbot.waitUntil(lambda: dialog.table.rowCount() == 1, timeout=10000)
    assert "Instantané enregistré" in dialog.status.text() and "2 tunnels" in dialog.table.item(0, 1).text()
    # Une modification faite ailleurs : « Comparer à l'état actuel » la montre.
    cf.state.configs["t1"]["ingress"][2]["service"] = "http://localhost:3001"
    dialog.compare_with_now()
    qtbot.waitUntil(lambda: dialog.changes.topLevelItemCount() == 1, timeout=10000)
    top = dialog.changes.topLevelItem(0)
    assert top.text(0) == "Tunnels · bureau — modifié"
    assert top.child(0).text(0).endswith("http://localhost:3000 → http://localhost:3001")
    assert dialog.status.text().startswith("1 changement depuis le ")
    # Second instantané (les deux secondes d'écart évitent deux fichiers du même nom) : comparé au précédent.
    import time

    time.sleep(1.1)
    dialog.take()
    qtbot.waitUntil(lambda: dialog.table.rowCount() == 2, timeout=10000)
    dialog.table.selectRow(0)
    dialog.compare_with_previous()
    assert dialog.changes.topLevelItemCount() == 1
    dialog.table.selectRow(1)
    assert not dialog.previous_button.isEnabled()  # le plus ancien n'a pas de précédent
    target = tmp_path / "export.json"
    monkeypatch.setattr(snapshots_module, "ask_export_path", lambda _p, _n: target)
    dialog.export()
    assert target.exists() and "Instantané exporté" in dialog.status.text()


def test_permissions_dialog(qtbot, view, cf):
    cf.state.analytics_allowed = False
    cf.state.audit_allowed = False
    dialog = PermissionsDialog(view, view.ctx, view.admin)
    qtbot.addWidget(dialog)
    qtbot.waitUntil(lambda: dialog.table.rowCount() == 10, timeout=10000)
    states = {dialog.table.item(r, 0).text(): dialog.table.item(r, 2).text() for r in range(10)}
    assert states["Tunnels et noms d'hôte"] == "Fonctionne"
    assert states["Journal des accès"] == "Manquante"
    assert states["Trafic par nom d'hôte"] == "Manquante (facultative)"
    assert dialog.summary.text() == "1 permission manque : Access: Audit Logs : Read"
    cf.state.audit_allowed = True
    dialog.run_checks()
    qtbot.waitUntil(
        lambda: dialog.summary.text() == "Toutes les permissions nécessaires sont présentes.", timeout=10000
    )
