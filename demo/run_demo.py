"""Runs preliminary demo scenarios D1 to D6 against real local processes and records timings.

From the project root: python3 demo/run_demo.py
"""
import json
import base64
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A, B = "http://127.0.0.1:8701", "http://127.0.0.1:8702"
FIVE = ["s1", "s2", "s3", "s4", "s5"]
ENV = dict(os.environ, REGISTRY_TOKEN=secrets.token_hex(16), PYTHONPATH=ROOT, PYTHONDONTWRITEBYTECODE="1")
procs, results = {}, []


def spawn(key, args, **extra):
    procs[key] = subprocess.Popen([sys.executable, "-m", *args], cwd=ROOT, env=dict(ENV, **extra), stdout=subprocess.DEVNULL)


def registry(name):
    spawn("reg" + name, ["registry_service.app"], REGISTRY_NAME=name, PORT="8701" if name == "A" else "8702")


def scanner(sid):
    spawn(sid, ["scanners.run", sid])


def get(url, timeout):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def search(q=""):
    """Same policy as the extension: 3 s on the primary, then 2 s on the backup."""
    try:
        return get(f"{A}/v1/services?q={q}", 3), "A"
    except (urllib.error.URLError, OSError):
        return get(f"{B}/v1/services?q={q}", 2), "B"


def ids(base=A, q=""):
    return {s["id"] for s in get(f"{base}/v1/services?q={q}", 2)["services"]}


def wait(cond, limit):
    start = time.monotonic()
    while time.monotonic() - start < limit:
        try:
            if cond():
                return time.monotonic() - start
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.05)
    return None


def record(sid, name, ok, detail):
    results.append({"id": sid, "scenario": name, "passed": bool(ok), "detail": detail})
    print(f"{sid}  {'PASS' if ok else 'FAIL'}  {name}: {detail}", flush=True)


def scan(url):
    body = json.dumps({"files": [{"path": "sample.txt", "content": base64.b64encode(b"synthetic").decode()}]}).encode()
    with urllib.request.urlopen(urllib.request.Request(url + "/scan", data=body, method="POST"), timeout=25) as r:
        return json.load(r)


def main():
    try:
        registry("A"); registry("B")
        wait(lambda: get(A + "/health", 1) and get(B + "/health", 1), 5)

        for s in FIVE:
            scanner(s)
        t = wait(lambda: set(FIVE) <= ids() and set(FIVE) <= ids(B), 15)
        record("D1", "Registration at start", t is not None, f"all five on both registries in {t:.2f} s (target 15 s)" if t is not None else "timed out")

        by_name = search("secret")[0]["services"]
        by_cap = search("github-actions")[0]["services"]
        detail = get(f"{A}/v1/services/s3", 2)
        record("D2", "Search and details", [s["id"] for s in by_name] == ["s2"] and [s["id"] for s in by_cap] == ["s4"] and detail["name"] == "Container Security Auditor",
               f"'secret' -> {by_name[0]['id']}, 'github-actions' -> {by_cap[0]['id']}, details for {detail['id']} opened")

        pids = {k: procs[k].pid for k in FIVE}
        scanner("s6")
        t = wait(lambda: "s6" in ids(), 15)
        same = all(procs[k].poll() is None and procs[k].pid == pids[k] for k in FIVE)
        record("D3", "Add a service while running", t is not None and same, f"S6 listed after {t:.2f} s with no restart of other services" if t is not None else "timed out")

        procs["s6"].send_signal(signal.SIGTERM)
        t = wait(lambda: "s6" not in ids() and "s6" not in ids(B), 5)
        record("D4", "Graceful removal", t is not None, f"S6 left both registries {t:.2f} s after a normal stop" if t is not None else "timed out")

        procs["s6"].wait(timeout=5)  # its port must be free before the restart
        scanner("s6")
        wait(lambda: "s6" in ids(), 15)
        procs["s4"].kill()
        killed_at = time.monotonic()
        out = scan("http://127.0.0.1:8716")
        t = wait(lambda: "s4" not in ids(), 25)
        others = ids()
        record("D5", "Crash removal and isolation", t is not None and t <= 20 and out["status"] == "complete" and {"s1", "s2", "s3", "s5", "s6"} <= others,
               f"killed S4 expired after {time.monotonic() - killed_at:.2f} s (target 20 s); S6 scan returned {out['status']}; other services stayed listed")

        procs["regA"].send_signal(signal.SIGSTOP)  # a hung primary is the slow case: it accepts but never answers
        start = time.monotonic()
        res, source = search("drift")
        hung = time.monotonic() - start
        procs["regA"].send_signal(signal.SIGCONT)
        procs["regA"].kill(); procs["regA"].wait()
        start = time.monotonic()
        res2, source2 = search("drift")
        dead = time.monotonic() - start
        record("D6", "Registry failover", source == "B" and source2 == "B" and hung <= 5 and [s["id"] for s in res["services"]] == ["s1"],
               f"hung primary: answered by backup in {hung:.2f} s; killed primary: {dead:.3f} s (target 5 s)")

        registry("A")
        t = wait(lambda: {"s1", "s2", "s3", "s5", "s6"} <= ids(), 15)
        record("D6b", "Primary recovery", t is not None, f"restarted empty registry repopulated in {t:.2f} s through re-registration" if t is not None else "timed out")
    finally:
        for p in procs.values():
            if p.poll() is None:
                p.kill()
            p.wait()
    with open(os.path.join(ROOT, "demo", "results.json"), "w") as f:
        json.dump({"ranAt": datetime.now().isoformat(timespec="seconds"), "environment": "local processes, HTTP on localhost", "results": results}, f, indent=2)
    print(f"\n{sum(r['passed'] for r in results)} of {len(results)} scenarios passed")
    sys.exit(0 if all(r["passed"] for r in results) else 1)


if __name__ == "__main__":
    main()
