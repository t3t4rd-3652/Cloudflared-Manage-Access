"""Du serveur SSH à Cloudflare (P20) : un port découvert se publie sur un tunnel, boîte préremplie."""

from __future__ import annotations

from datetime import datetime

import pytest
from PySide6.QtWidgets import QDialog

import cma.ui.views.cloud.tunnels_tab as tunnels_module
from cma.core.models import SshProfile
from cma.core.ssh.discovery import DiscoveryResult, RemotePort
from cma.ui.views.cloud.dialogs import PublishDialog
from tests.fakes.fake_cfapi import TOKEN, FakeCloudflare, FakeCloudflareServer


@pytest.fixture
def cf():
    with FakeCloudflareServer(FakeCloudflare()) as server:
        yield server


def test_port_suggestions():
    grafana = RemotePort(3000, ("127.0.0.1",), container="Grafana_1", scheme="http", http_code=302)
    assert (grafana.publish_service(), grafana.suggested_hostname()) == ("http://localhost:3000", "grafana-1")
    assert RemotePort(22, ("0.0.0.0", "::"), service="ssh").publish_service() == "ssh://localhost:22"
    assert RemotePort(3389, ("10.0.0.5",)).publish_service() == "rdp://10.0.0.5:3389"
    assert RemotePort(5432, ("::1",), service="postgresql").publish_service() == "tcp://localhost:5432"
    assert RemotePort(8443, ("fd00::5",), scheme="https").publish_service() == "https://[fd00::5]:8443"
    assert RemotePort(9999, ()).suggested_hostname() == "port-9999"


def test_publish_a_discovered_port(qtbot, gui, cf, monkeypatch):
    ctx, window = gui
    notes: list[str] = []
    window.banners.show_message = lambda _level, text, **_k: notes.append(text)  # type: ignore[method-assign]
    nas = SshProfile(name="NAS", host="192.168.50.23", user="admin")
    ctx.update_config(lambda c: c.ssh_profiles.append(nas))
    port = RemotePort(3000, ("127.0.0.1",), container="grafana", scheme="http", http_code=200)
    window.ssh.discoveries[nas.id] = (DiscoveryResult(ports=[port]), datetime.now())
    window.show_view("ssh")
    window.ssh.select_profile(nas.id)
    tab = window.ssh.panel.ports_tab
    tab.table.selectRow(0)

    # Sans jeton d'API : la vue Cloudflare s'ouvre, avec une explication.
    tab.publish_selected()
    assert window.stack.currentWidget() is window.cloud and "Connectez d'abord" in notes[-1]

    ctx.core.manager.cloudflare.base_url = cf.base_url
    view = window.cloud
    view.token_field.set_text(TOKEN)
    view.connect_account()
    qtbot.waitUntil(lambda: view.tree.topLevelItemCount() == 2, timeout=10000)

    seen: list[tuple[str, str]] = []

    class AutoPublish(PublishDialog):
        def exec(self) -> int:
            seen.append((self.hostname.text(), self.service.text()))
            return QDialog.DialogCode.Accepted

    monkeypatch.setattr(tunnels_module, "PublishDialog", AutoPublish)
    window.show_view("ssh")
    tab.table.selectRow(0)  # le retour sur la vue relit les ports ; le clic droit resélectionne la ligne
    assert tab.publish_button.isEnabled()
    tab.publish_button.click()
    assert seen == [("grafana", "http://localhost:3000")], notes
    qtbot.waitUntil(
        lambda: any(
            r.get("hostname") == "grafana.exemple.fr" and r.get("service") == "http://localhost:3000"
            for r in cf.state.configs["t1"]["ingress"]
        ),
        timeout=10000,
    )
    assert window.stack.currentWidget() is window.cloud
