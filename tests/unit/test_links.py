"""Liens cma:// et profils partagés : lecture, partage sans secret, recréation, enregistrement auprès du système."""

from __future__ import annotations

import json
import sys
import types

import pytest

from cma.__main__ import split_link
from cma.core.links import (
    LinkError,
    connect_link,
    is_link,
    parse_link,
    profile_from_share,
    read_share,
    share_file_text,
    share_link,
    share_payload,
)
from cma.core.models import AuthMode, CloudflareProfile, Config, ServiceToken, ServiceType
from cma.platform import links as platform_links

TOKEN = ServiceToken(name="Robot", client_id="robot.access")


def config_with_profile() -> tuple[Config, CloudflareProfile]:
    profile = CloudflareProfile(
        name="NAS équipe",
        hostname="nas.exemple.fr",
        local_port=24445,
        auth=AuthMode.SERVICE_TOKEN,
        token_id=TOKEN.id,
        service_type=ServiceType.SMB,
        group="Bureau",
        proxy="http://alice:motdepasse@proxy:3128",
        headers=["X-Secret: valeur"],
    )
    return Config(tokens=[TOKEN], cloudflare_profiles=[profile]), profile


def test_connect_links():
    link = connect_link("NAS équipe")
    assert link == "cma://connect/NAS%20%C3%A9quipe" and is_link(link)
    parsed = parse_link(link)
    assert (parsed.action, parsed.profile) == ("connect", "NAS équipe")
    for bad, message in (
        ("https://exemple.fr", "pas un lien CMA"),
        ("cma://connect/", "aucun profil"),
        ("cma://supprimer/tout", "Action inconnue"),
        ("cma://import?p=%%%", "abîmé"),
        ("cma://connect/" + "x" * 5000, "trop long"),
    ):
        with pytest.raises(LinkError, match=message):
            parse_link(bad)


def test_share_contains_no_secret_and_round_trips():
    config, profile = config_with_profile()
    payload = share_payload(profile, config)
    assert payload == {
        "cma_share": 1,
        "name": "NAS équipe",
        "hostname": "nas.exemple.fr",
        "local_port": 24445,
        "auth": "service_token",
        "service_type": "smb",
        "group": "Bureau",
        "token_client_id": "robot.access",
        "token_name": "Robot",
    }
    text = share_file_text(profile, config)
    assert "motdepasse" not in text and "X-Secret" not in text
    assert read_share(text) == payload
    assert parse_link(share_link(profile, config)).share == payload
    with pytest.raises(LinkError):
        read_share(json.dumps({"name": "x"}))
    with pytest.raises(LinkError):
        read_share("pas du json")


def test_profile_from_share_finds_the_token_or_names_the_missing_one():
    config, profile = config_with_profile()
    payload = share_payload(profile, config)
    # Chez soi : nom rendu unique, token retrouvé par son Client ID.
    mine = profile_from_share(payload, config)
    assert (
        mine.profile.name == "NAS équipe (2)"
        and mine.profile.token_id == TOKEN.id
        and mine.missing_token is None
    )
    # Chez un collègue sans le token : profil créé, token à ajouter.
    theirs = profile_from_share(payload, Config())
    assert theirs.profile.name == "NAS équipe" and theirs.profile.token_id is None
    assert theirs.missing_token == ("Robot", "robot.access")
    assert theirs.profile.proxy is None and theirs.profile.headers == []
    with pytest.raises(LinkError, match="invalide"):
        profile_from_share({**payload, "auth": "magie"}, Config())
    with pytest.raises(LinkError, match="invalide"):
        profile_from_share({**payload, "hostname": "pas un nom"}, Config())


def test_entry_point_extracts_links_and_files():
    assert split_link(["--debug", "cma://connect/NAS"]) == (["--debug"], "cma://connect/NAS")
    assert split_link([r"C:\Users\x\NAS.cma"]) == ([], r"C:\Users\x\NAS.cma")
    assert split_link(["list", "--json"]) == (["list", "--json"], None)


def test_register_on_windows(monkeypatch):
    values: dict[tuple[str, str], str] = {}

    class Key:
        def __init__(self, path: str) -> None:
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

    def query(key: Key, name: str) -> tuple[str, int]:
        if (key.path, name) not in values:
            raise OSError
        return values[(key.path, name)], 1

    fake = types.SimpleNamespace(
        HKEY_CURRENT_USER=1,
        REG_SZ=1,
        CreateKey=lambda _root, path: Key(path),
        OpenKey=lambda _root, path: (
            Key(path) if any(p == path for p, _n in values) else (_ for _ in ()).throw(OSError())
        ),
        SetValueEx=lambda key, name, _r, _t, value: values.__setitem__((key.path, name), value),
        QueryValueEx=query,
    )
    monkeypatch.setitem(sys.modules, "winreg", fake)
    monkeypatch.setattr(platform_links.sys, "platform", "win32")
    monkeypatch.setattr(platform_links.sys, "frozen", True, raising=False)
    monkeypatch.setattr(platform_links.sys, "executable", r"C:\Programmes\CMA\CloudflaredManageAccess.exe")
    assert platform_links.supported() and not platform_links.is_registered()
    platform_links.register()
    assert platform_links.is_registered()
    command = values[(r"Software\Classes\cma\shell\open\command", "")]
    assert command == r'"C:\Programmes\CMA\CloudflaredManageAccess.exe" "%1"'
    assert values[(r"Software\Classes\cma", "URL Protocol")] == ""
    assert values[(r"Software\Classes\.cma", "")] == platform_links.PROG_ID


def test_register_on_linux(monkeypatch, tmp_path):
    desktop = tmp_path / "applications" / "cma-links.desktop"
    calls: list[list[str]] = []
    monkeypatch.setattr(platform_links, "_DESKTOP_FILE", desktop)
    monkeypatch.setattr(platform_links.sys, "platform", "linux")
    monkeypatch.setattr(platform_links.subprocess, "run", lambda args, **_k: calls.append(args))
    assert not platform_links.is_registered()
    platform_links.register()
    text = desktop.read_text(encoding="utf-8")
    assert "x-scheme-handler/cma" in text and text.splitlines()[4].endswith("%u")
    assert calls[0] == ["xdg-mime", "default", desktop.name, "x-scheme-handler/cma"]
    assert platform_links.is_registered()
