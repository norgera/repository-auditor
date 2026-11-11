"""HTTP server shared by all scanners: input guard, sandbox, sanitizing and clean-up."""
import base64
import binascii
import json
import os
import signal
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import PurePosixPath

from contracts import validate
from .adapter import Adapter, Context, Result, ToolFailed, ToolMissing, ToolTimeout
from .agent import RegistrationAgent

DRAIN_LIMIT = 32 * 1024 * 1024


class Rejected(Exception):
    def __init__(self, status, message, skipped=()):
        super().__init__(message)
        self.status, self.message, self.skipped = status, message, list(skipped)


def metadata(adapter: Adapter, url):
    return {"id": adapter.id, "name": adapter.name, "description": adapter.description, "capabilities": adapter.capabilities,
            "url": url, "version": "0.1.0", "tool": adapter.tool, "accepts": adapter.accepts_patterns,
            "inputMode": adapter.input_mode, "maxBytes": adapter.max_bytes}


def safe_path(rel):
    if not isinstance(rel, str) or not rel or "\\" in rel or "\0" in rel:
        return False
    p = PurePosixPath(rel)
    return not p.is_absolute() and ".." not in p.parts


def guard(adapter, request):
    """Server-side input checks. Returns accepted (path, bytes) pairs and skipped names."""
    if not isinstance(request, dict) or not isinstance(request.get("files"), list):
        raise Rejected("error", "request must contain a files list")
    if len(request["files"]) > adapter.max_files:
        raise Rejected("too_large", f"at most {adapter.max_files} files are accepted")
    accepted, skipped, total = [], [], 0
    for item in request["files"]:
        rel = item.get("path") if isinstance(item, dict) else None
        if not safe_path(rel):
            raise Rejected("error", "invalid file path")
        try:
            data = base64.b64decode(item.get("content", ""), validate=True)
        except (binascii.Error, ValueError, TypeError):
            raise Rejected("error", f"file is not valid base64: {rel}")
        total += len(data)
        if total > adapter.max_bytes:
            raise Rejected("too_large", f"input exceeds the limit of {adapter.max_bytes} bytes")
        if adapter.accepts(rel):
            accepted.append((rel, data))
        else:
            skipped.append(rel)
    if not accepted:
        raise Rejected("unsupported", "no supported scan target was provided", skipped)
    return accepted, skipped


def _scrub(value, secrets):
    for s in secrets:
        if s:
            value = value.replace(s, "[REDACTED]")
    return value


def envelope(adapter, version, status, message, findings=(), skipped=()):
    return {"service": adapter.id, "tool": adapter.tool, "toolVersion": version, "status": status,
            "message": message, "findings": list(findings), "skipped": list(skipped)}


def process(adapter, body, version, time_limit):
    """Runs one scan. Every path leaves through the workspace's clean-up."""
    skipped = []
    try:
        try:
            request = json.loads(body)
        except ValueError:
            raise Rejected("error", "request is not valid JSON")
        accepted, skipped = guard(adapter, request)
        options = request.get("options") if isinstance(request.get("options"), dict) else {}
        with tempfile.TemporaryDirectory(prefix="repo-auditor-", dir=os.environ.get("SCAN_TMP")) as ws:
            for rel, data in accepted:
                target = os.path.join(ws, rel)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as f:
                    f.write(data)
            result = adapter.scan(Context(ws, [r for r, _ in accepted], options, time_limit))
        findings = [{k: _scrub(v, result.secrets) if isinstance(v, str) else v for k, v in vars(f).items()} for f in result.findings]
        out = envelope(adapter, version, result.status, _scrub(result.message, result.secrets), findings, skipped)
    except Rejected as e:
        out = envelope(adapter, version, e.status, e.message, skipped=e.skipped or skipped)
    except ToolTimeout:
        out = envelope(adapter, version, "timeout", f"scan stopped at the {time_limit:g} second limit", skipped=skipped)
    except ToolMissing as e:
        out = envelope(adapter, version, "error", f"required tool is not installed: {e}", skipped=skipped)
    except ToolFailed as e:
        out = envelope(adapter, version, "error", str(e), skipped=skipped)
    except Exception as e:  # never echo exception text, which could hold file content
        print(f"{adapter.id}: internal error {type(e).__name__}", file=sys.stderr, flush=True)
        out = envelope(adapter, version, "error", "internal scanner error", skipped=skipped)
    if validate(out, "findings"):
        out = envelope(adapter, version, "error", "scanner produced an invalid response", skipped=skipped)
    return out


def make_handler(adapter, meta, version, time_limit):
    max_body = int(adapter.max_bytes * 4 / 3) + 1024 * 1024

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def _send(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/health":
                return self._send(200, {"status": "ok", "service": adapter.id, "toolAvailable": adapter.tool is None or version is not None})
            if self.path == "/metadata":
                return self._send(200, meta)
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/scan":
                return self._send(404, {"error": "not found"})
            length = int(self.headers.get("Content-Length") or 0)
            if length > max_body:
                remaining = min(length, DRAIN_LIMIT)
                while remaining > 0:
                    chunk = self.rfile.read(min(65536, remaining))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                self.close_connection = True
                return self._send(200, envelope(adapter, version, "too_large", f"input exceeds the limit of {adapter.max_bytes} bytes"))
            self._send(200, process(adapter, self.rfile.read(length), version, time_limit))

    return Handler


def serve(adapter: Adapter):
    """Process entry point: start HTTP, register with all registries, deregister on SIGTERM."""
    token = os.environ.get("REGISTRY_TOKEN")
    if not token:
        sys.exit("REGISTRY_TOKEN must be set")
    host, port = os.environ.get("HOST", "127.0.0.1"), int(os.environ["PORT"])
    url = os.environ.get("PUBLIC_URL", f"http://127.0.0.1:{port}")
    meta = metadata(adapter, url)
    server = ThreadingHTTPServer((host, port), make_handler(adapter, meta, adapter.tool_version(), float(os.environ.get("SCAN_TIME_LIMIT", "20"))))
    server.daemon_threads = True
    registries = [u.strip().rstrip("/") for u in os.environ.get("REGISTRY_URLS", "http://127.0.0.1:8701,http://127.0.0.1:8702").split(",") if u.strip()]
    agent = RegistrationAgent(meta, registries, token, float(os.environ.get("RENEW_INTERVAL", "5")), float(os.environ.get("RETRY_INTERVAL", "3")))

    def shutdown(*_):
        def work():
            agent.stop()
            server.shutdown()
        threading.Thread(target=work, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    agent.start()
    print(f"{adapter.id} listening on {url}", flush=True)
    server.serve_forever()
