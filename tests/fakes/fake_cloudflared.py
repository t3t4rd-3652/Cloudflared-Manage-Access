"""Faux `cloudflared access tcp` pour les tests. Il reproduit les messages réels de la version 2026.7.2.

Mode choisi par la variable FAKE_CF_MODE :
  ok          écoute sur --url jusqu'à l'arrêt
  port_in_use annonce l'écoute, puis échoue comme cloudflared quand le port est pris (code 1)
  usage       « Incorrect Usage » et code 0, comme cloudflared
  crash       écoute FAKE_CF_CRASH_AFTER secondes puis s'arrête (code 1)
  auth_error  écoute, et chaque connexion cliente produit « websocket: bad handshake »
  proxy       écoute et relaie chaque connexion vers FAKE_CF_TARGET (hôte:port), comme un vrai tunnel
Sous-commandes « access login » et « access ssh-config » : sortie factice et code 0.
« access token » : affiche FAKE_CF_ACCESS_TOKEN s'il est défini, sinon échoue (code 1) comme cloudflared.
Le fichier FAKE_CF_ENV_DUMP, s'il est donné, reçoit les variables TUNNEL_SERVICE_TOKEN_* reçues.
"""

import contextlib
import json
import os
import socket
import sys
import threading
import time


def log(level: str, message: str) -> None:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(f"{stamp} {level} {message}", flush=True)


def main() -> int:
    args = sys.argv[1:]
    mode = os.environ.get("FAKE_CF_MODE", "ok")
    if args[:2] == ["access", "login"]:
        print("Successfully fetched your token", flush=True)
        return 0
    if args[:2] == ["access", "token"]:
        token = os.environ.get("FAKE_CF_ACCESS_TOKEN")
        if not token:
            print("Unable to find token for provided application.", file=sys.stderr, flush=True)
            return 1
        print(token, flush=True)
        return 0
    if args[:2] == ["access", "ssh-config"]:
        print("Host app.exemple.fr", flush=True)
        print("  ProxyCommand cloudflared access ssh --hostname %h", flush=True)
        return 0
    dump = os.environ.get("FAKE_CF_ENV_DUMP")
    if dump:
        with open(dump, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    k: v
                    for k, v in os.environ.items()
                    if k.startswith(("TUNNEL_", "HTTP_PROXY", "HTTPS_PROXY"))
                },
                handle,
            )
    if mode == "usage":
        print("Incorrect Usage: flag provided but not defined: -nope", flush=True)
        return 0
    url = args[args.index("--url") + 1]
    host, _, port = url.rpartition(":")
    host = host.strip("[]")
    log("INF", f"Start Websocket listener host={url}")
    if mode == "port_in_use":
        message = f"failed to start forwarding server: listen tcp {url}: bind: address already in use"
        log("ERR", f'Error on Websocket listener error="{message}"')
        print(message, flush=True)
        return 1
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    server = socket.socket(family, socket.SOCK_STREAM)
    server.bind((host, int(port)))
    server.listen()

    def pipe(source: socket.socket, target: socket.socket) -> None:
        try:
            while data := source.recv(65536):
                target.sendall(data)
        except OSError:
            pass
        finally:
            for sock in (source, target):
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)

    def relay(client: socket.socket) -> None:
        target_host, _, target_port = os.environ["FAKE_CF_TARGET"].rpartition(":")
        upstream = socket.create_connection((target_host, int(target_port)))
        threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
        pipe(upstream, client)

    def serve() -> None:
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            if mode == "proxy":
                threading.Thread(target=relay, args=(conn,), daemon=True).start()
                continue
            if mode == "auth_error":
                log(
                    "ERR",
                    'failed to connect to origin error="websocket: bad handshake" originURL=https://app.example',
                )
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    if mode == "crash":
        time.sleep(float(os.environ.get("FAKE_CF_CRASH_AFTER", "1")))
        return 1
    while True:
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
