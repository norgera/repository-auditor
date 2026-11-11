"""Registers a scanner with every registry and keeps each lease alive independently."""
import json
import threading
import urllib.error
import urllib.request
from urllib.parse import quote


class RegistrationAgent:
    def __init__(self, metadata, registries, token, renew_interval=5.0, retry_interval=3.0, timeout=2.0):
        self.meta, self.registries, self.token = metadata, registries, token
        self.renew_interval, self.retry_interval, self.timeout = renew_interval, retry_interval, timeout
        self.stopping = threading.Event()
        self.threads = []

    def _call(self, method, url, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={"X-Registration-Token": self.token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status
        except urllib.error.HTTPError as e:
            e.close()
            return e.code
        except (urllib.error.URLError, OSError):
            return None

    def _service_url(self, base):
        return f"{base}/v1/services/{quote(self.meta['id'], safe='')}"

    def _loop(self, base):
        registered = False
        while not self.stopping.is_set():
            if not registered:
                registered = self._call("POST", f"{base}/v1/services", self.meta) == 201
                wait = self.renew_interval if registered else self.retry_interval
            else:
                code = self._call("PUT", self._service_url(base) + "/lease")
                if code == 404:  # the registry restarted or the lease lapsed: re-register at once (P FR2.1)
                    registered = self._call("POST", f"{base}/v1/services", self.meta) == 201
                wait = self.renew_interval if registered else self.retry_interval
            if self.stopping.wait(wait):
                return

    def start(self):
        for base in self.registries:
            t = threading.Thread(target=self._loop, args=(base,), daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self):
        """Stop renewing and deregister from every registry, on a graceful shutdown."""
        self.stopping.set()
        for base in self.registries:
            self._call("DELETE", self._service_url(base))
