import socket

import pytest

from cma.core import netutil
from cma.core.cloudflared.binary import _release_from_json, asset_name, is_newer, parse_version, version_tuple
from cma.core.netutil import PortStatus, check_local_port, find_free_port, format_host_port
from cma.core.ssh.discovery import RemotePort, parse_ndjson, parse_ss


def test_format_host_port():
    assert format_host_port("127.0.0.1", 80) == "127.0.0.1:80"
    assert format_host_port("::1", 80) == "[::1]:80"
    assert format_host_port("[::1]", 80) == "[::1]:80"


def test_check_local_port_free_and_in_use():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        assert check_local_port("127.0.0.1", port).status == PortStatus.IN_USE
        assert netutil.is_port_listening("127.0.0.1", port)
    assert check_local_port("127.0.0.1", port).free
    assert check_local_port("127.0.0.1", 0).status == PortStatus.INVALID


def test_find_free_port_prefers_requested_port():
    port = find_free_port(port_range=(20000, 29999))
    assert port is not None and 20000 <= port <= 29999
    assert find_free_port(preferred=port, port_range=(20000, 20010)) == port


def test_excluded_ranges_are_parsed(monkeypatch):
    output = "Port de début    Port de fin\n-------------    -----------\n      5357        5357\n     50000       50059     *\n"

    class Result:
        stdout = output.encode()

    netutil.excluded_port_ranges.cache_clear()
    monkeypatch.setattr(netutil.sys, "platform", "win32")
    monkeypatch.setattr(netutil.subprocess, "run", lambda *a, **k: Result())
    try:
        assert netutil.excluded_port_ranges() == ((5357, 5357), (50000, 50059))
        assert netutil.is_excluded(50010)
        assert "50000-50059" in netutil.reserved_port_message(50010)
    finally:
        netutil.excluded_port_ranges.cache_clear()


NDJSON = """{"v":2,"meta":{"version":"2.0.0","docker":"denied","web_probe":true}}
{"v":2,"proto":"tcp","port":22,"bind":["0.0.0.0","::"],"service":"ssh","container":null,"scheme":null,"http_code":null,"final_url":null}
{"v":2,"proto":"tcp","port":3000,"bind":["127.0.0.1"],"service":null,"container":"grafana","scheme":"https","http_code":302,"final_url":"https://127.0.0.1:3000/login"}
ligne parasite
{"v":2,"proto":"tcp","port":8080,"bind":["172.17.0.1"],"service":"http-alt","container":null,"scheme":"http","http_code":200,"final_url":"http://172.17.0.1:8080/"}
"""


def test_parse_ndjson():
    result = parse_ndjson(NDJSON)
    assert [p.port for p in result.ports] == [22, 3000, 8080]
    assert result.script_version == "2.0.0"
    assert result.warnings  # docker refusé : conseil d'installer le helper
    grafana = result.ports[1]
    assert grafana.display_name == "grafana"
    assert grafana.web_label == "HTTPS 302"
    assert grafana.local_only
    assert result.ports[2].forward_host == "172.17.0.1"
    assert result.ports[0].forward_host == "127.0.0.1"


@pytest.mark.parametrize(
    ("bind", "expected"),
    [(("::",), "::1"), (("::1",), "::1"), (("10.0.0.5", "fe80::1"), "10.0.0.5"), ((), "127.0.0.1")],
)
def test_forward_host(bind, expected):
    assert RemotePort(port=1, bind=bind).forward_host == expected


def test_parse_ss_fallback():
    output = """State  Recv-Q Send-Q Local Address:Port  Peer Address:Port
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*
LISTEN 0      128             [::]:22            [::]:*
LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*
LISTEN 0      511                *:80               *:*
"""
    ports = parse_ss(output)
    assert [(p.port, p.bind) for p in ports] == [
        (22, ("0.0.0.0", "::")),
        (53, ("127.0.0.53",)),
        (80, ("0.0.0.0",)),
    ]


def test_versions():
    assert parse_version("cloudflared version 2026.7.2 (built 2026-07-15T04:01 UTC)") == "2026.7.2"
    assert version_tuple("2026.10.1") > version_tuple("2026.9.3")
    assert is_newer("2026.9.3", "2026.7.2")
    assert not is_newer("2026.7.2", "2026.7.2")
    assert not is_newer(None, "2026.7.2")


@pytest.mark.parametrize(
    ("system", "machine", "name"),
    [
        ("Windows", "AMD64", "cloudflared-windows-amd64.exe"),
        ("Windows", "ARM64", "cloudflared-windows-amd64.exe"),
        ("Windows", "x86", "cloudflared-windows-386.exe"),
        ("Linux", "x86_64", "cloudflared-linux-amd64"),
        ("Linux", "aarch64", "cloudflared-linux-arm64"),
        ("Linux", "armv7l", "cloudflared-linux-armhf"),
        ("Darwin", "arm64", "cloudflared-darwin-arm64.tgz"),
        ("Darwin", "x86_64", "cloudflared-darwin-amd64.tgz"),
    ],
)
def test_asset_names(system, machine, name):
    assert asset_name(system, machine) == name


def test_release_parsing_keeps_digests():
    release = _release_from_json(
        {
            "tag_name": "2026.9.3",
            "html_url": "https://github.com/cloudflare/cloudflared/releases/tag/2026.9.3",
            "assets": [
                {
                    "name": "cloudflared-windows-amd64.exe",
                    "browser_download_url": "https://x/a",
                    "size": 10,
                    "digest": "sha256:ABC",
                },
                {"name": "sans-digest", "browser_download_url": "https://x/b", "size": 1},
            ],
        }
    )
    assert release.version == "2026.9.3"
    assert release.asset("cloudflared-windows-amd64.exe").sha256 == "abc"
    assert release.asset("sans-digest").sha256 is None
