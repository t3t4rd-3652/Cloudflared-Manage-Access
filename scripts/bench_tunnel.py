"""Banc d'essai : débit d'une redirection SSH locale, relais v1 (paramiko, blocs de 1 Kio) contre v2 (asyncssh).

    uv run --group bench python scripts/bench_tunnel.py [taille_en_Mio]

Tout est local : un serveur SSH asyncssh et un puits TCP tournent dans ce processus.
Le chiffre mesure donc le coût des relais eux-mêmes, pas celui d'un réseau.
"""

from __future__ import annotations

import asyncio
import select
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import asyncssh
import paramiko

from cma.core.config_store import ConfigStore
from cma.core.events import EventBus
from cma.core.manager import SessionManager
from cma.core.models import SavedForward, SshAuthMode, SshProfile
from cma.core.netutil import find_free_port
from cma.core.prompts import PasswordAnswer
from cma.core.secrets import MemorySecretStore
from cma.core.sessions import SessionState
from cma.paths import AppPaths

PASSWORD = "banc-d-essai"
EXPECTED = [0]


class Server(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return password == PASSWORD

    def connection_requested(self, *args: object) -> bool:
        return True


class Store(MemorySecretStore):
    persistent = True


class Prompter:
    async def confirm_host_key(self, prompt: object) -> bool:
        return True

    async def ask_password(self, request: object) -> PasswordAnswer:
        return PasswordAnswer(PASSWORD)

    async def ask_passphrase(self, request: object) -> None:
        return None


def start_background_loop() -> asyncio.AbstractEventLoop:
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True).start()
    return loop


async def start_servers() -> tuple[int, int]:
    async def sink(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Répond dès le volume attendu reçu : le relais v1 ne sait pas transmettre une demi-fermeture.
        received = 0
        while received < EXPECTED[0]:
            data = await reader.read(1 << 20)
            if not data:
                break
            received += len(data)
        writer.write(b"OK")
        await writer.drain()
        writer.close()

    sink_server = await asyncio.start_server(sink, "127.0.0.1", 0)
    ssh_server = await asyncssh.create_server(
        Server, "127.0.0.1", 0, server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")]
    )
    return ssh_server.sockets[0].getsockname()[1], sink_server.sockets[0].getsockname()[1]


def push(local_port: int, size: int) -> float:
    """Envoie `size` octets à travers la redirection et attend l'accusé du puits. Renvoie des Mio/s."""
    chunk = b"\x5a" * (1 << 20)
    started = time.perf_counter()
    with socket.create_connection(("127.0.0.1", local_port)) as sock:
        sent = 0
        while sent < size:
            sock.sendall(chunk)
            sent += len(chunk)
        assert sock.recv(2) == b"OK"
    return size / (1 << 20) / (time.perf_counter() - started)


def v1_relay(ssh_port: int, sink_port: int, local_port: int) -> paramiko.SSHClient:
    """Copie fidèle du relais de la v1.4 (CloudflaredManageAccess.py, create_ssh_tunnel)."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "127.0.0.1",
        port=ssh_port,
        username="bench",
        password=PASSWORD,
        look_for_keys=False,
        allow_agent=False,
    )
    transport = client.get_transport()
    assert transport is not None

    def handler(chan: paramiko.Channel, sock: socket.socket) -> None:
        try:
            while True:
                r, _w, _x = select.select([sock, chan], [], [])
                if sock in r:
                    data = sock.recv(1024)
                    if not data:
                        break
                    chan.send(data)
                if chan in r:
                    data = chan.recv(1024)
                    if not data:
                        break
                    sock.send(data)
        except Exception:
            pass
        chan.close()
        sock.close()

    def forward() -> None:
        server = socket.socket()
        server.bind(("127.0.0.1", local_port))
        server.listen(100)
        while True:
            client_sock, _addr = server.accept()
            chan = transport.open_channel("direct-tcpip", ("127.0.0.1", sink_port), ("127.0.0.1", 0))
            threading.Thread(target=handler, args=(chan, client_sock), daemon=True).start()

    threading.Thread(target=forward, daemon=True).start()
    time.sleep(0.3)
    return client


def main() -> int:
    size = int(sys.argv[1] if len(sys.argv) > 1 else 64) << 20
    EXPECTED[0] = size
    server_loop = start_background_loop()
    ssh_port, sink_port = asyncio.run_coroutine_threadsafe(start_servers(), server_loop).result()

    v1_port = find_free_port(port_range=(28000, 28999))
    assert v1_port is not None
    v1_relay(ssh_port, sink_port, v1_port)
    v1 = push(v1_port, size)

    with tempfile.TemporaryDirectory() as temp:
        paths = AppPaths(Path(temp))
        paths.ensure()
        store = ConfigStore(paths)
        store.load()
        profile = SshProfile(
            name="banc", host="127.0.0.1", port=ssh_port, user="bench", auth=SshAuthMode.PASSWORD
        )
        store.update(lambda c: c.ssh_profiles.append(profile))
        engine_loop = start_background_loop()
        manager = SessionManager(
            paths=paths, store=store, secrets=Store(), bus=EventBus(), prompter=Prompter()
        )  # type: ignore[arg-type]
        v2_port = find_free_port(port_range=(29000, 29999))
        assert v2_port is not None
        forward = SavedForward(remote_port=sink_port, local_port=v2_port)
        info = asyncio.run_coroutine_threadsafe(
            manager.start_forward(profile.id, forward), engine_loop
        ).result()
        session = manager.session(info.id)
        assert session is not None
        while session.state != SessionState.LISTENING:
            time.sleep(0.05)
        v2 = push(v2_port, size)
        asyncio.run_coroutine_threadsafe(manager.shutdown(), engine_loop).result()

    print(f"Volume transféré : {size >> 20} Mio par relais")
    print(f"v1.4 (paramiko, blocs de 1 Kio) : {v1:8.1f} Mio/s")
    print(f"v2.0 (asyncssh, blocs de 64 Kio) : {v2:8.1f} Mio/s")
    print(f"Rapport v2 / v1 : x{v2 / v1:.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
