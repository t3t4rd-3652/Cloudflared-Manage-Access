"""Faux serveur de l'API Cloudflare v4, en mémoire, pour tester cfapi et cfadmin sans compte réel.

Il reproduit l'enveloppe des réponses ({success, errors, result, result_info}), la pagination,
l'authentification par jeton Bearer et les routes utilisées par CMA.
"""

from __future__ import annotations

import http.server
import json
import re
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

TOKEN = "jeton-api-de-test"


@dataclass
class FakeCloudflare:
    token: str = TOKEN
    accounts: list[dict[str, Any]] = field(default_factory=lambda: [{"id": "acc1", "name": "Mon compte"}])
    zones: list[dict[str, Any]] = field(
        default_factory=lambda: [
            {"id": "z1", "name": "exemple.fr", "account": {"id": "acc1"}},
            {"id": "z2", "name": "lab.exemple.fr", "account": {"id": "acc1"}},
        ]
    )
    tunnels: list[dict[str, Any]] = field(
        default_factory=lambda: [
            {"id": "t1", "name": "bureau", "status": "healthy"},
            {"id": "t2", "name": "labo", "status": "down"},
        ]
    )
    configs: dict[str, dict[str, Any]] = field(
        default_factory=lambda: {
            "t1": {
                "ingress": [
                    {"hostname": "ssh.exemple.fr", "service": "ssh://localhost:22"},
                    {"hostname": "rdp.exemple.fr", "service": "rdp://10.0.0.5:3389"},
                    {"hostname": "grafana.exemple.fr", "service": "http://localhost:3000"},
                    {"service": "http_status:404"},
                ]
            },
            "t2": {"ingress": [{"service": "http_status:404"}]},
        }
    )
    dns: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: {"z1": [], "z2": []})
    apps: list[dict[str, Any]] = field(
        default_factory=lambda: [
            {"id": "app1", "name": "SSH", "domain": "ssh.exemple.fr", "type": "self_hosted"}
        ]
    )
    policies: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    service_tokens: list[dict[str, Any]] = field(default_factory=list)
    requests: list[tuple[str, str]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


def _page(items: list[dict[str, Any]], query: dict[str, list[str]]) -> dict[str, Any]:
    per_page = int(query.get("per_page", ["50"])[0])
    page = int(query.get("page", ["1"])[0])
    total_pages = max(1, -(-len(items) // per_page))
    chunk = items[(page - 1) * per_page : page * per_page]
    return {
        "success": True,
        "errors": [],
        "result": chunk,
        "result_info": {"page": page, "per_page": per_page, "total_pages": total_pages, "count": len(chunk)},
    }


def _ok(result: Any) -> dict[str, Any]:
    return {"success": True, "errors": [], "messages": [], "result": result}


class Handler(http.server.BaseHTTPRequestHandler):
    state: FakeCloudflare

    def log_message(self, *_args: Any) -> None:
        pass

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _error(self, status: int, code: int, message: str) -> None:
        self._send(status, {"success": False, "errors": [{"code": code, "message": message}], "result": None})

    def _body(self) -> Any:
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"null")

    def _handle(self, method: str) -> None:
        state = self.state
        parts = urlsplit(self.path)
        path = parts.path.removeprefix("/client/v4")
        query = parse_qs(parts.query)
        with state.lock:
            state.requests.append((method, path))
        if self.headers.get("Authorization") != f"Bearer {state.token}":
            self._error(401, 10000, "Authentication error")
            return
        body = self._body() if method in ("POST", "PUT") else None
        with state.lock:
            self._route(method, path, query, body)

    def _route(self, method: str, path: str, query: dict[str, list[str]], body: Any) -> None:
        state = self.state
        if method == "GET" and path == "/accounts":
            return self._send(200, _page(state.accounts, query))
        if method == "GET" and path == "/zones":
            account = query.get("account.id", [""])[0]
            return self._send(200, _page([z for z in state.zones if z["account"]["id"] == account], query))
        if m := re.fullmatch(r"/accounts/(\w+)/cfd_tunnel", path):
            return self._send(200, _page(state.tunnels, query))
        if m := re.fullmatch(r"/accounts/(\w+)/cfd_tunnel/(\w+)/configurations", path):
            tunnel = m.group(2)
            if method == "PUT":
                state.configs[tunnel] = body["config"]
            return self._send(200, _ok({"tunnel_id": tunnel, "config": state.configs.get(tunnel, {})}))
        if m := re.fullmatch(r"/zones/(\w+)/dns_records", path):
            records = state.dns.setdefault(m.group(1), [])
            if method == "POST":
                record = {**body, "id": uuid.uuid4().hex}
                records.append(record)
                return self._send(200, _ok(record))
            name = query.get("name", [None])[0]
            kind = query.get("type", [None])[0]
            found = [
                r
                for r in records
                if (name is None or r["name"] == name) and (kind is None or r["type"] == kind)
            ]
            return self._send(200, _page(found, query))
        if m := re.fullmatch(r"/zones/(\w+)/dns_records/(\w+)", path):
            records = state.dns.setdefault(m.group(1), [])
            record = next((r for r in records if r["id"] == m.group(2)), None)
            if record is None:
                return self._error(404, 81044, "Record does not exist.")
            if method == "DELETE":
                records.remove(record)
                return self._send(200, _ok({"id": record["id"]}))
            record.update(body)
            return self._send(200, _ok(record))
        if m := re.fullmatch(r"/accounts/(\w+)/access/apps", path):
            if method == "POST":
                if any(a["domain"] == body["domain"] for a in state.apps):
                    return self._error(400, 12130, "access.api.error.conflict: application already exists")
                app = {**body, "id": uuid.uuid4().hex}
                state.apps.append(app)
                return self._send(200, _ok(app))
            return self._send(200, _page(state.apps, query))
        if m := re.fullmatch(r"/accounts/(\w+)/access/apps/(\w+)/policies", path):
            policy = {**body, "id": uuid.uuid4().hex}
            state.policies.setdefault(m.group(2), []).append(policy)
            return self._send(200, _ok(policy))
        if m := re.fullmatch(r"/accounts/(\w+)/access/service_tokens", path):
            if method == "POST":
                token = {
                    "id": uuid.uuid4().hex,
                    "name": body["name"],
                    "client_id": f"{uuid.uuid4().hex}.access",
                    "expires_at": "2027-09-29T00:00:00Z",
                }
                state.service_tokens.append(token)
                return self._send(200, _ok({**token, "client_secret": "secret-" + uuid.uuid4().hex}))
            return self._send(200, _page(state.service_tokens, query))
        return self._error(404, 7003, f"No route for that URI: {method} {path}")

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def do_DELETE(self) -> None:
        self._handle("DELETE")


class FakeCloudflareServer:
    def __init__(self, state: FakeCloudflare | None = None) -> None:
        self.state = state or FakeCloudflare()
        handler = type("BoundHandler", (Handler,), {"state": self.state})
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/client/v4"

    def __enter__(self) -> FakeCloudflareServer:
        self.thread.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.server.shutdown()
        self.server.server_close()
