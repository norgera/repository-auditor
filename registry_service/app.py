"""Service registry. Run one process per registry: python -m registry_service.app

Environment: REGISTRY_NAME, REGISTRY_TOKEN (required), PORT, HOST, LEASE_TTL, SWEEP_INTERVAL.
"""
import hmac
import json
import os
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from contracts import validate

MAX_BODY = 64 * 1024


class Inventory:
    """In-memory lease store. Expired records are hidden at once and deleted by the sweeper."""

    def __init__(self, ttl, clock=time.monotonic):
        self.ttl, self.clock = ttl, clock
        self.lock = threading.Lock()
        self.records = {}

    def register(self, meta):
        with self.lock:
            self.records[meta["id"]] = {"meta": meta, "expires": self.clock() + self.ttl}

    def renew(self, sid):
        with self.lock:
            rec = self.records.get(sid)
            if rec is None or rec["expires"] <= self.clock():
                self.records.pop(sid, None)
                return False
            rec["expires"] = self.clock() + self.ttl
            return True

    def remove(self, sid):
        with self.lock:
            return self.records.pop(sid, None) is not None

    def _live(self):
        now = self.clock()
        return [r["meta"] for r in self.records.values() if r["expires"] > now]

    def search(self, query=""):
        q = query.strip().lower()
        with self.lock:
            live = self._live()
        if q:
            live = [m for m in live if q in " ".join([m["id"], m["name"], m["description"], *m["capabilities"]]).lower()]
        return sorted(live, key=lambda m: m["id"])

    def get(self, sid):
        with self.lock:
            return next((m for m in self._live() if m["id"] == sid), None)

    def sweep(self):
        now = self.clock()
        with self.lock:
            dead = [k for k, r in self.records.items() if r["expires"] <= now]
            for k in dead:
                del self.records[k]
        return dead


def make_handler(name, token, inv):
    class Handler(BaseHTTPRequestHandler):
        server_version = "RepositoryAuditorRegistry"
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def _send(self, code, body=None):
            data = json.dumps(body if body is not None else {}).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self):
            given = self.headers.get("X-Registration-Token", "")
            if hmac.compare_digest(given.encode(), token.encode()):
                return True
            self._send(401, {"error": "invalid registration token"})
            return False

        def _service_id(self, path):
            parts = [p for p in path.split("/") if p]
            if len(parts) >= 3 and parts[:2] == ["v1", "services"]:
                return unquote(parts[2]), parts[3:]
            return None, []

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/health":
                return self._send(200, {"status": "ok", "registry": name})
            if url.path == "/v1/services":
                q = parse_qs(url.query).get("q", [""])[0]
                return self._send(200, {"registry": name, "services": inv.search(q)})
            sid, rest = self._service_id(url.path)
            if sid and not rest:
                meta = inv.get(sid)
                return self._send(200, meta) if meta else self._send(404, {"error": "unknown service"})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if urlparse(self.path).path != "/v1/services":
                return self._send(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                self.close_connection = True
                return self._send(413, {"error": "registration too large"})
            raw = self.rfile.read(length)
            if not self._authorized():
                return
            try:
                meta = json.loads(raw)
            except ValueError:
                return self._send(400, {"error": "invalid JSON"})
            errors = validate(meta, "service_metadata")
            if errors:
                return self._send(400, {"error": "contract violation", "details": errors})
            inv.register(meta)
            self._send(201, {"id": meta["id"], "leaseSeconds": inv.ttl})

        def do_PUT(self):
            sid, rest = self._service_id(urlparse(self.path).path)
            if not sid or rest != ["lease"]:
                return self._send(404, {"error": "not found"})
            if not self._authorized():
                return
            if inv.renew(sid):
                return self._send(200, {"id": sid, "leaseSeconds": inv.ttl})
            self._send(404, {"error": "unknown lease"})

        def do_DELETE(self):
            sid, rest = self._service_id(urlparse(self.path).path)
            if not sid or rest:
                return self._send(404, {"error": "not found"})
            if not self._authorized():
                return
            self._send(200 if inv.remove(sid) else 404, {"id": sid})

    return Handler


def build(name, token, host, port, ttl, sweep_interval):
    inv = Inventory(ttl)
    server = ThreadingHTTPServer((host, port), make_handler(name, token, inv))
    server.daemon_threads = True
    stop = threading.Event()

    def sweeper():
        while not stop.wait(sweep_interval):
            inv.sweep()

    threading.Thread(target=sweeper, daemon=True).start()
    return server, inv, stop


def main():
    token = os.environ.get("REGISTRY_TOKEN")
    if not token:
        sys.exit("REGISTRY_TOKEN must be set")
    name = os.environ.get("REGISTRY_NAME", "A")
    server, _, stop = build(name, token, os.environ.get("HOST", "127.0.0.1"), int(os.environ.get("PORT", "8701")),
                            float(os.environ.get("LEASE_TTL", "15")), float(os.environ.get("SWEEP_INTERVAL", "2")))

    def shutdown(*_):
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    print(f"registry {name} listening on {server.server_address}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
