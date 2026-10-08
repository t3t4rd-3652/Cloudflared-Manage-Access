"""DNS des noms d'hôte publiés : chaque cas de panne reconnu, sans réseau."""

from __future__ import annotations

from cma.core.cfapi import Tunnel, Zone
from cma.core.dnscheck import DnsCheck, check_all, check_hostname, zone_of

TUNNEL = Tunnel("t1", "bureau", "healthy")
NAMES = {"t1": "bureau", "t2": "labo"}


def cname(name: str, target: str, proxied: bool = True) -> dict[str, object]:
    return {"type": "CNAME", "name": name, "content": target, "proxied": proxied}


def state(records, host: str = "app.exemple.fr") -> DnsCheck:
    return check_hostname(host, TUNNEL, records, NAMES)


def test_each_case():
    assert state([cname("app.exemple.fr", "t1.cfargotunnel.com")]) == DnsCheck("ok")
    assert state([cname("APP.exemple.fr.", "T1.cfargotunnel.com.")]).ok  # casse et point final ignorés
    assert state([]) == DnsCheck("missing")
    assert state([{"type": "TXT", "name": "app.exemple.fr", "content": "v=spf1"}]) == DnsCheck("missing")
    assert state([cname("app.exemple.fr", "t1.cfargotunnel.com", proxied=False)]) == DnsCheck("not_proxied")
    assert state([cname("app.exemple.fr", "t2.cfargotunnel.com")]) == DnsCheck("other_tunnel", "labo")
    # Tunnel inconnu du compte : le début de son identifiant.
    assert state([cname("app.exemple.fr", "abcdef0123456789.cfargotunnel.com")]).detail == "abcdef01"
    assert state([{"type": "A", "name": "app.exemple.fr", "content": "1.2.3.4"}]) == DnsCheck(
        "other_record", "A"
    )
    assert state([cname("app.exemple.fr", "ailleurs.net")]) == DnsCheck(
        "other_record", "CNAME → ailleurs.net"
    )
    assert state(None) == DnsCheck("unknown") and state(None).ok


def test_labels_and_fixable():
    assert DnsCheck("missing").fixable and DnsCheck("other_tunnel", "labo").fixable
    assert not DnsCheck("other_record", "A").fixable and not DnsCheck("ok").fixable
    assert DnsCheck("other_tunnel", "labo").label() == "DNS vers labo"
    assert DnsCheck("ok").label() == "" and DnsCheck("unknown").label() == ""
    assert "vise le tunnel labo" in DnsCheck("other_tunnel", "labo").explanation("app.exemple.fr")
    assert "enregistrement A" in DnsCheck("other_record", "A").explanation("app.exemple.fr")
    assert DnsCheck("no_zone").explanation("x.org") == "Aucune zone du compte ne contient x.org."


def test_zone_and_whole_account():
    zones = [Zone("z1", "exemple.fr"), Zone("z2", "lab.exemple.fr")]
    assert zone_of("app.lab.exemple.fr", zones) == zones[1]
    assert zone_of("exemple.fr", zones) == zones[0] and zone_of("autre.org", zones) is None
    rules = [
        (TUNNEL, "app.exemple.fr"),
        (TUNNEL, "App.exemple.fr"),  # même nom, autre règle (chemin) : vérifié une fois
        (TUNNEL, "pg.lab.exemple.fr"),
        (TUNNEL, "x.autre.org"),
    ]
    records = {"z1": [cname("app.exemple.fr", "t1.cfargotunnel.com")], "z2": None}
    result = check_all(rules, zones, records, NAMES)
    assert result == {
        "app.exemple.fr": DnsCheck("ok"),
        "pg.lab.exemple.fr": DnsCheck("unknown"),
        "x.autre.org": DnsCheck("no_zone"),
    }
