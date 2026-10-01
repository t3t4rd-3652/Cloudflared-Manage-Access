"""Poignée de main SOCKS (cas refusés) et contrôles du diagnostic guidé, sans réseau."""

from __future__ import annotations

import asyncio
import ssl
import urllib.error
from types import SimpleNamespace

import pytest

import cma.core.diagnose as diagnose
from cma.core.models import AuthMode, CloudflareProfile, Config, ServiceToken
from cma.core.ssh import socks


class Writer:
    def __init__(self) -> None:
        self.data = b""

    def write(self, data: bytes) -> None:
        self.data += data

    async def drain(self) -> None:
        return None


def reader_with(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


async def test_socks5_domain_and_ipv6():
    writer = Writer()
    request = b"\x05\x01\x00" + b"\x05\x01\x00\x03\x09localhost\x00\x50"
    assert await socks.negotiate(reader_with(request), writer) == ("localhost", 80, 5)  # type: ignore[arg-type]
    ipv6 = b"\x05\x01\x00" + b"\x05\x01\x00\x04" + bytes(15) + b"\x01" + b"\x01\xbb"
    assert await socks.negotiate(reader_with(ipv6), Writer()) == ("::1", 443, 5)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("request_bytes", "reply"),
    [
        (b"\x05\x01\x02", b"\x05\xff"),  # aucune méthode sans authentification
        (b"\x05\x01\x00\x05\x02\x00\x01", b"\x05\x00" + socks.socks5_failure(0x07)),  # BIND refusé
        (b"\x05\x01\x00\x05\x01\x00\x09", b"\x05\x00" + socks.socks5_failure(0x08)),  # type d'adresse inconnu
        (b"\x04\x02\x00\x50\x7f\x00\x00\x01\x00", socks.SOCKS4_FAILURE),  # SOCKS4 BIND refusé
        (b"\x06", b""),  # version inconnue
    ],
)
async def test_socks_refusals(request_bytes, reply):
    writer = Writer()
    with pytest.raises(socks.SocksError):
        await socks.negotiate(reader_with(request_bytes), writer)  # type: ignore[arg-type]
    assert writer.data == reply


async def test_socks4_ip_and_replies():
    request = b"\x04\x01\x00\x16\x0a\x00\x00\x05user\x00"
    assert await socks.negotiate(reader_with(request), Writer()) == ("10.0.0.5", 22, 4)  # type: ignore[arg-type]
    assert socks.success_reply(4) == socks.SOCKS4_SUCCESS and socks.failure_reply(4) == socks.SOCKS4_FAILURE
    assert socks.success_reply(5) == socks.SOCKS5_SUCCESS and socks.failure_reply(5)[1] == 0x05


# --- Diagnostic --------------------------------------------------------------------------------------


class FakeManager:
    def __init__(self, config: Config, binary=None, secrets=None, active=False, token_ok=True, cached=False):
        self.store = SimpleNamespace(snapshot=lambda: config)
        self._binary = binary
        self.secrets = SimpleNamespace(get=lambda key: (secrets or {}).get(key))
        self._active = active
        self._token_ok = token_ok
        self._cached = cached

    def cloudflared_path(self):
        return self._binary

    def active_session_for(self, _profile_id):
        return object() if self._active else None

    async def test_cloudflare_profile(self, profile_id):
        return self._token_ok, "message du test"

    async def access_token_valid(self, _profile_id):
        return self._cached


def profile(**overrides) -> CloudflareProfile:
    values = {"name": "P", "hostname": "p.exemple.fr", "local_port": 31555}
    values.update(overrides)
    return CloudflareProfile(**values)


async def test_diagnosis_without_cloudflared_or_hostname():
    config = Config(cloudflare_profiles=[profile(hostname="")])
    checks = await diagnose.diagnose_cloudflare_profile(FakeManager(config), config.cloudflare_profiles[0].id)
    assert [c.status for c in checks] == ["error", "ok", "error"]


async def test_diagnosis_local_port_cases():
    config = Config()
    assert diagnose._local_port(FakeManager(config), profile(local_port=None)).status == "error"
    assert diagnose._local_port(FakeManager(config, active=True), profile()).status == "ok"


async def test_diagnosis_dns_and_proxy(monkeypatch):
    assert (await diagnose._dns("nom.invalide.")).status == "error"
    assert (await diagnose._proxy("pas un proxy")).status == "error"
    server = await asyncio.start_server(lambda _r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    assert (await diagnose._proxy(f"http://127.0.0.1:{port}")).status == "ok"
    server.close()


@pytest.mark.parametrize(
    ("outcome", "status"),
    [
        ((403, ""), "ok"),
        (ssl.SSLError(1, "certificat inconnu"), "error"),
        (urllib.error.URLError("refus"), "error"),
    ],
)
async def test_diagnosis_https_outcomes(monkeypatch, outcome, status):
    def fake(*_args):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(diagnose, "_https_head", fake)
    assert (await diagnose._access(profile(proxy="127.0.0.1:3128"))).status == status


async def test_diagnosis_https_skipped_through_socks():
    assert (await diagnose._access(profile(proxy="socks5://127.0.0.1:1080"))).status == "skipped"


async def test_diagnosis_authentication():
    token = ServiceToken(name="T", client_id="t.access")
    with_token = profile(auth=AuthMode.SERVICE_TOKEN, token_id=token.id)
    config = Config(tokens=[token], cloudflare_profiles=[with_token])
    assert (await diagnose._authentication(FakeManager(Config()), with_token)).status == "error"
    assert (await diagnose._authentication(FakeManager(config), with_token)).status == "error"
    filled = FakeManager(config, secrets={token.secret_key: "valeur-du-secret"}, token_ok=False)
    assert (await diagnose._authentication(filled, with_token)).status == "error"
    browser = profile()
    assert (await diagnose._authentication(FakeManager(config, cached=True), browser)).status == "ok"
    assert (await diagnose._authentication(FakeManager(config), browser)).status == "warning"
