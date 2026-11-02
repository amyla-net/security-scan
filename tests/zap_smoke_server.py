"""Intentionally simple, authenticated loopback application for ZAP CI smoke tests."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


REDIRECTS = {"visited": 0, "credential_leaked": False}
TARGET_PORT = int(os.environ.get("ZAP_SMOKE_PORT", "8818"))
SINK_PORT = TARGET_PORT + 1
BIND_HOST = os.environ.get("ZAP_SMOKE_BIND", "127.0.0.1")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer fixture-zap-auth":
            self.send_response(403)
            self.end_headers()
            return
        path = urlsplit(self.path).path
        if path == "/redirect-outside":
            REDIRECTS["visited"] += 1
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{SINK_PORT}/")
            self.end_headers()
            return
        if path == "/probe":
            body = json.dumps(REDIRECTS).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        query = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
        body = ('<html><head><title>ZAP fixture</title></head><body><a href="/">Home</a>'
                '<a href="/redirect-outside">Redirect</a>'
                '<form method="get" action="/"><input name="q"><button>Search</button></form>'
                '<p>' + query + '</p></body></html>').encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class RedirectSink(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Authorization") or self.headers.get("X-Access-Key"):
            REDIRECTS["credential_leaked"] = True
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    sink = ThreadingHTTPServer((BIND_HOST, SINK_PORT), RedirectSink)
    threading.Thread(target=sink.serve_forever, daemon=True).start()
    ThreadingHTTPServer((BIND_HOST, TARGET_PORT), Handler).serve_forever()
