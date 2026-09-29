import pytest

from cma.core.cloudflared.command import (
    CommandError,
    build_access_login,
    build_access_tcp,
    normalize_proxy_url,
    proxy_host_port,
)
from cma.core.models import AuthMode, CloudflareProfile

SECRET = "s3cr'et$(calc);`rm -rf /`"


def profile(**overrides):
    values = {"name": "p", "hostname": "app.exemple.fr", "local_port": 2222}
    values.update(overrides)
    return CloudflareProfile(**values)


def test_arguments_are_a_list_without_shell():
    spec = build_access_tcp("C:/cf/cloudflared.exe", profile(), base_env={})
    assert spec.args == (
        "C:/cf/cloudflared.exe",
        "access",
        "tcp",
        "--hostname",
        "app.exemple.fr",
        "--url",
        "127.0.0.1:2222",
        "--loglevel",
        "info",
    )


def test_service_token_goes_through_environment_only():
    spec = build_access_tcp(
        "cloudflared",
        profile(auth=AuthMode.SERVICE_TOKEN, token_id="t"),
        client_id="abc.access",
        client_secret=SECRET,
        base_env={},
    )
    assert SECRET not in " ".join(spec.args)
    assert "abc.access" not in " ".join(spec.args)
    assert spec.env["TUNNEL_SERVICE_TOKEN_ID"] == "abc.access"
    assert spec.env["TUNNEL_SERVICE_TOKEN_SECRET"] == SECRET
    assert SECRET not in spec.display()


def test_missing_token_secret_is_an_error():
    with pytest.raises(CommandError):
        build_access_tcp(
            "cloudflared", profile(auth=AuthMode.SERVICE_TOKEN, token_id="t"), client_id="x", base_env={}
        )


def test_inherited_tunnel_variables_are_removed():
    env = {"TUNNEL_SERVICE_TOKEN_SECRET": "ancien", "TUNNEL_SERVICE_URL": "0.0.0.0:1", "PATH": "x"}
    spec = build_access_tcp("cloudflared", profile(), base_env=env)
    assert "TUNNEL_SERVICE_TOKEN_SECRET" not in spec.env
    assert "TUNNEL_SERVICE_URL" not in spec.env
    assert spec.env["PATH"] == "x"


def test_proxy_sets_all_proxy_variables():
    spec = build_access_tcp("cloudflared", profile(proxy="proxy.corp:3128"), base_env={})
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        assert spec.env[name] == "http://proxy.corp:3128"


def test_proxy_helpers():
    assert normalize_proxy_url("h:1") == "http://h:1"
    assert normalize_proxy_url("socks5://h:1") == "socks5://h:1"
    assert proxy_host_port("http://user:pw@proxy.corp:3128/") == "proxy.corp:3128"
    assert proxy_host_port(None) is None


def test_ipv6_listen_address_and_headers():
    spec = build_access_tcp(
        "cloudflared", profile(local_host="::1", headers=["X-A: 1", "X-B: 2"]), base_env={}
    )
    assert "[::1]:2222" in spec.args
    assert spec.args[-4:] == ("--header", "X-A: 1", "--header", "X-B: 2")


def test_incomplete_profile_is_refused():
    with pytest.raises(CommandError):
        build_access_tcp("cloudflared", profile(hostname=""), base_env={})
    with pytest.raises(CommandError):
        build_access_tcp("cloudflared", profile(local_port=None), base_env={})


def test_login_command():
    assert build_access_login("cf", "app.exemple.fr", base_env={}).args == (
        "cf",
        "access",
        "login",
        "https://app.exemple.fr",
    )


def test_access_commands_use_the_profile_proxy():
    from cma.core.cloudflared.command import build_access_token, build_ssh_config

    system = {"HTTPS_PROXY": "http://systeme:8080", "TUNNEL_SERVICE_TOKEN_SECRET": "fuite"}
    login = build_access_login("cf", "app.exemple.fr", proxy="proxy.corp:3128", base_env=system)
    assert login.env["HTTPS_PROXY"] == "http://proxy.corp:3128"
    assert login.env["https_proxy"] == "http://proxy.corp:3128"
    assert "TUNNEL_SERVICE_TOKEN_SECRET" not in login.env
    token = build_access_token("cf", "app.exemple.fr", proxy="socks5://p:1080", base_env=system)
    assert token.env["ALL_PROXY"] == "socks5://p:1080"
    without = build_access_token("cf", "app.exemple.fr", base_env=system)
    assert without.env["HTTPS_PROXY"] == "http://systeme:8080"
    assert build_ssh_config("cf", "h", proxy="p:1").env["HTTP_PROXY"] == "http://p:1"
