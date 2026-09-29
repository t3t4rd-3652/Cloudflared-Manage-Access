"""Services factices pour les tests de ports-report : un serveur HTTP et un service à bannière (non HTTP)."""

import http.server
import socket
import threading

HTTP_PORT = 18080
BANNER_PORT = 18022


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()


def serve_banner(sock):
    while True:
        conn, _ = sock.accept()
        try:
            conn.sendall(b"SSH-2.0-fake\r\n")
        finally:
            conn.close()


httpd = http.server.ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), Handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()

banner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
banner.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
banner.bind(("0.0.0.0", BANNER_PORT))
banner.listen()
threading.Thread(target=serve_banner, args=(banner,), daemon=True).start()

threading.Event().wait()
