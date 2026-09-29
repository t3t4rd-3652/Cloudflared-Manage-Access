import pytest
from pydantic import ValidationError

from cma.core.models import (
    AuthMode,
    CloudflareProfile,
    Config,
    ServiceToken,
    ServiceType,
    Settings,
    SshAuthMode,
    SshProfile,
    guess_service_type,
    is_valid_host,
    normalize_hostname,
    unique_name,
)


def test_hostname_is_normalized():
    profile = CloudflareProfile(name="p", hostname="  HTTPS://Mongo.Exemple.fr/chemin?x=1 ")
    assert profile.hostname == "mongo.exemple.fr"
    assert normalize_hostname("ssh.exemple.fr.") == "ssh.exemple.fr"


@pytest.mark.parametrize("bad", ["avec espace.fr", "quote'.fr", "a;b", "$(calc).fr"])
def test_hostname_rejects_shell_characters(bad):
    with pytest.raises(ValidationError):
        CloudflareProfile(name="p", hostname=bad)


def test_empty_hostname_is_a_draft_not_an_error():
    profile = CloudflareProfile(name="brouillon")
    assert profile.hostname == ""
    assert "le hostname n'est pas renseigné" in profile.readiness_problems({})


def test_local_host_accepts_ipv6_and_rejects_garbage():
    assert CloudflareProfile(name="p", local_host="[::1]").local_host == "::1"
    with pytest.raises(ValidationError):
        CloudflareProfile(name="p", local_host="pas une adresse")


@pytest.mark.parametrize(
    "proxy",
    ["proxy.corp:3128", "http://proxy.corp:3128", "http://user:pw@10.0.0.1:8080/", "socks5://127.0.0.1:1080"],
)
def test_valid_proxies(proxy):
    assert CloudflareProfile(name="p", proxy=proxy).proxy == proxy


@pytest.mark.parametrize("proxy", ["proxy.corp", "http://proxy:99999", "proxy corp:80"])
def test_invalid_proxies(proxy):
    with pytest.raises(ValidationError):
        CloudflareProfile(name="p", proxy=proxy)


def test_blank_proxy_becomes_none():
    assert CloudflareProfile(name="p", proxy="   ").proxy is None


def test_headers_format():
    profile = CloudflareProfile(name="p", headers=["X-Test: 1", "  ", "Autre:valeur"])
    assert profile.headers == ["X-Test: 1", "Autre:valeur"]
    with pytest.raises(ValidationError):
        CloudflareProfile(name="p", headers=["pas d'en-tête"])


def test_browser_auth_clears_token_reference():
    profile = CloudflareProfile(name="p", auth=AuthMode.SERVICE_TOKEN, token_id="abc")
    profile.auth = AuthMode.BROWSER
    assert profile.token_id is None


def test_readiness_problems():
    token = ServiceToken(name="t", client_id="id.access")
    profile = CloudflareProfile(
        name="p", hostname="app.ex.fr", local_port=2222, auth=AuthMode.SERVICE_TOKEN, token_id="absent"
    )
    assert profile.readiness_problems({token.id: token}) == ["aucun service token valide n'est choisi"]
    profile.token_id = token.id
    assert profile.readiness_problems({token.id: token}) == []


def test_ssh_profile_validation():
    assert SshProfile(name="nas", host="nas.exemple.lan", user="admin").port == 22
    with pytest.raises(ValidationError):
        SshProfile(name="x", user="a b")
    profile = SshProfile(name="x", host="h", user="u", auth=SshAuthMode.KEY)
    assert profile.readiness_problems({}) == ["aucune clé n'est choisie"]


def test_settings_port_range_must_be_ordered():
    with pytest.raises(ValidationError):
        Settings(auto_port_min=30000, auto_port_max=20000)


def test_unique_name_ignores_case():
    assert unique_name("Prod", ["prod", "Prod (2)"]) == "Prod (3)"
    assert unique_name("Nouveau", []) == "Nouveau"


@pytest.mark.parametrize(
    ("name", "hostname", "port", "expected"),
    [
        ("MongoDB prod", "", 27017, ServiceType.MONGODB),
        ("", "ssh.exemple.fr", 2222, ServiceType.SSH),
        ("Bureau", "", 3389, ServiceType.RDP),
        ("Web", "", 8080, ServiceType.HTTP),
        ("Divers", "", 12345, ServiceType.GENERIC),
    ],
)
def test_guess_service_type(name, hostname, port, expected):
    assert guess_service_type(name, hostname, port) == expected


def test_is_valid_host():
    assert is_valid_host("127.0.0.1")
    assert is_valid_host("::1")
    assert is_valid_host("serveur-01.exemple.fr")
    assert not is_valid_host("")
    assert not is_valid_host("a b")


def test_config_lookups():
    token = ServiceToken(name="t", client_id="id")
    profile = CloudflareProfile(
        name="Mongo", hostname="m.ex.fr", auth=AuthMode.SERVICE_TOKEN, token_id=token.id
    )
    ssh = SshProfile(name="NAS", host="nas", user="u", via_cloudflare_profile=profile.id)
    config = Config(tokens=[token], cloudflare_profiles=[profile], ssh_profiles=[ssh])
    assert config.profiles_using_token(token.id) == [profile]
    assert config.ssh_profiles_via(profile.id) == [ssh]
    assert config.find_profile_by_name("mongo") is profile
    assert config.find_profile_by_name(ssh.id) is ssh
    assert config.find_profile_by_name("absent") is None
