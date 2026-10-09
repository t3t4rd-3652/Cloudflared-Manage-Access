"""Import de ~/.ssh/config, nom du réseau Wi-Fi, espaces de travail au démarrage."""

from __future__ import annotations

from cma.core.models import (
    CloudflareProfile,
    Config,
    LaunchItem,
    SshAuthMode,
    SshProfile,
    Workspace,
    startup_workspaces,
)
from cma.core.sshconfig import already_known, parse_ssh_config, profiles_from_entries
from cma.platform.network import parse_netsh, parse_nmcli

CONFIG = """
# Serveurs du labo
Host bastion
    HostName bastion.exemple.fr
    User alice
    Port 2222
    IdentityFile ~/.ssh/id_bastion

Host nas nas-alias
    HostName 192.168.50.23
    User admin
    ProxyJump alice@bastion:2222
    ForwardAgent yes

Host prod-ssh
    HostName prod.exemple.fr
    ProxyCommand cloudflared access ssh --hostname ssh.exemple.fr
    User = deploy
    User ignoré

Host *.lab !secret
    User lab

Match host truc
    User personne

Include conf.d/*.conf
"""

INCLUDED = """
Host invalide
    HostName %h.exemple.fr
Host routeur
    HostName 192.168.1.1
"""


def write_config(tmp_path):
    (tmp_path / "conf.d").mkdir()
    (tmp_path / "conf.d" / "lab.conf").write_text(INCLUDED, encoding="utf-8")
    path = tmp_path / "config"
    path.write_text(CONFIG, encoding="utf-8")
    return path


def test_parse_ssh_config(tmp_path):
    entries = parse_ssh_config(write_config(tmp_path))
    assert [e.alias for e in entries] == ["bastion", "nas", "nas-alias", "prod-ssh", "invalide", "routeur"]
    bastion, nas, _alias, prod, _invalide, routeur = entries
    assert (bastion.target, bastion.user, bastion.port) == ("bastion.exemple.fr", "alice", 2222)
    assert bastion.identity.endswith("id_bastion") and "~" not in bastion.identity
    assert (nas.target, nas.proxy_jump, nas.ignored) == ("192.168.50.23", "bastion", ["forwardagent"])
    assert (prod.user, prod.cloudflare_hostname) == (
        "deploy",
        "ssh.exemple.fr",
    )  # le premier « User » l'emporte
    assert routeur.target == "192.168.1.1" and routeur.user == ""
    assert parse_ssh_config(tmp_path / "absent") == []


def test_profiles_from_entries(tmp_path):
    entries = parse_ssh_config(write_config(tmp_path))
    cloudflare = CloudflareProfile(name="SSH prod", hostname="ssh.exemple.fr")
    existing = SshProfile(name="routeur", host="192.168.1.1")
    config = Config(cloudflare_profiles=[cloudflare], ssh_profiles=[existing])
    known = [e.alias for e in entries if already_known(e, config)]
    assert known == ["routeur"]
    chosen = [e for e in entries if e.alias in ("bastion", "nas", "prod-ssh", "invalide")]
    profiles = {p.name: p for p in profiles_from_entries(chosen, config)}
    assert set(profiles) == {"bastion", "nas", "prod-ssh"}  # « %h » : hôte illisible, ignoré
    assert profiles["bastion"].auth == SshAuthMode.KEY and profiles["bastion"].port == 2222
    assert (
        profiles["nas"].auth == SshAuthMode.AGENT and profiles["nas"].jump_profile == profiles["bastion"].id
    )
    assert profiles["prod-ssh"].via_cloudflare_profile == cloudflare.id
    # Rebond vers un serveur déjà dans CMA ; nom déjà pris : rendu unique.
    config = Config(ssh_profiles=[SshProfile(name="bastion", host="10.0.0.1")])
    [nas] = profiles_from_entries([e for e in entries if e.alias == "nas"], config)
    assert nas.jump_profile == config.ssh_profiles[0].id
    [again] = profiles_from_entries([e for e in entries if e.alias == "bastion"], config)
    assert again.name == "bastion (2)"


def test_wifi_name_parsing():
    netsh = """
Il existe 1 interface sur le système :

    Nom                    : Wi-Fi
    État                   : connecté
    SSID                   : Maison 5G
    BSSID                  : aa:bb:cc:dd:ee:ff
"""
    assert parse_netsh(netsh) == "Maison 5G"
    assert parse_netsh("    État : déconnecté") is None
    assert parse_nmcli("no:Voisin\nyes:Bureau\n") == "Bureau"
    assert parse_nmcli("non:Voisin\n") is None


def test_startup_workspaces():
    item = LaunchItem(kind="cloudflare", profile_id="p1")
    always = Workspace(name="Toujours", items=[item], on_startup=True)
    away = Workspace(name="Hors maison", items=[item], on_startup=True, unless_network="Maison 5G")
    manual = Workspace(name="À la main", items=[item])
    empty = Workspace(name="Vide", on_startup=True)
    config = Config(workspaces=[always, away, manual, empty])
    assert [w.name for w in startup_workspaces(config, "maison 5g")] == ["Toujours"]
    assert [w.name for w in startup_workspaces(config, "Café")] == ["Toujours", "Hors maison"]
    assert [w.name for w in startup_workspaces(config, None)] == ["Toujours", "Hors maison"]
