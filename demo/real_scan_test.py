"""Runs each scanner service with its real tool on synthetic fixtures. Run: python3 demo/real_scan_test.py

S5 sends package names and versions to osv.dev. Everything else stays on this machine.
"""
import base64
import json
import os
import secrets
import stat
import string
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = {"s1": 8711, "s2": 8712, "s3": 8713, "s4": 8714, "s5": 8715}
ALPHABET = string.ascii_letters + string.digits
FAKE_TOKEN = "ghp_" + "".join(secrets.choice(ALPHABET) for _ in range(36))
SENTINEL = "s3nt1nel-Value-" + secrets.token_hex(6)

BASE = b"apiVersion: apps/v1\nmetadata:\n  name: web\nspec:\n  replicas: 2\n  image: web:1.0\n  removed: true\n"
TARGET = f"apiVersion: apps/v1\nmetadata:\n  name: web\nspec:\n  replicas: 5\n  image: web:{SENTINEL}\n  added: yes\n".encode()
DOCKER = b"FROM ubuntu:latest\nRUN apt-get update\nADD . /app\n"
WF1 = b"""name: one
on:
  issues:
    types: [opened]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.issue.title }}"
"""
WF2 = b"""name: two
on: pull_request_target
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
REQS = b"django==1.11.0\n"

failures = []


def check(cond, what):
    print(f"    {'ok  ' if cond else 'FAIL'} {what}", flush=True)
    if not cond:
        failures.append(what)


def scan(sid, files, options=None):
    body = json.dumps({"files": [{"path": p, "content": base64.b64encode(c).decode()} for p, c in files], "options": options or {}}).encode()
    start = time.monotonic()
    with urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{PORT[sid]}/scan", data=body, method="POST"), timeout=120) as r:
        out = json.load(r)
    print(f"\n{sid} ({out['toolVersion']}): status={out['status']} findings={len(out['findings'])} {time.monotonic() - start:.2f}s {out['message']}", flush=True)
    for f in out["findings"][:6]:
        print(f"    [{f['severity']}] {f['rule']} | {f['file']} | {f['location']} | {f['message'][:70]}", flush=True)
    return out


def main():
    tmp = tempfile.mkdtemp(prefix="ra-real-")
    scan_tmp = os.path.join(tmp, "scan")
    os.makedirs(scan_tmp)
    env = dict(os.environ, REGISTRY_TOKEN=secrets.token_hex(16), PYTHONPATH=ROOT, PYTHONDONTWRITEBYTECODE="1", SCAN_TMP=scan_tmp, SCAN_TIME_LIMIT=os.environ.get("SCAN_TIME_LIMIT", "20"))
    run = lambda sid, e=env: subprocess.Popen([sys.executable, "-m", "scanners.run", sid], cwd=ROOT, env=e, stdout=subprocess.DEVNULL)
    procs = {s: run(s) for s in PORT}
    try:
        time.sleep(4)  # tool version checks run at start-up
        o = scan("s1", [("base.yaml", BASE), ("target.yaml", TARGET)], {"baseline": "base.yaml", "target": "target.yaml", "requiredKeys": ["spec.replicas"]})
        locs = {f["location"] for f in o["findings"]}
        check(o["status"] == "complete" and "spec.replicas" in locs, "S1 FR1: changed key reported")
        check(any(f["rule"] == "required-key-drift" and f["location"] == "spec.replicas" for f in o["findings"]), "S1 FR2: required key flagged")
        check(SENTINEL not in json.dumps(o), "S1 QR2: value absent from response")
        check(next(f for f in o["findings"] if f["location"] == "spec")["severity"] == "info", "S1 FR2: sibling change does not flag a required key")
        o = scan("s1", [("base.yaml", BASE), ("target.yaml", TARGET)], {"baseline": "base.yaml", "target": "target.yaml", "requiredKeys": ["spec.removed"]})
        check(next(f for f in o["findings"] if f["location"] == "spec")["rule"] == "required-key-drift", "S1 FR2: removed required key flagged")

        o = scan("s2", [("config/.env", f"GITHUB_TOKEN={FAKE_TOKEN}\n".encode()), ("clean.txt", b"nothing\n")])
        check(o["status"] == "complete" and len(o["findings"]) >= 1, "S2 FR1: synthetic token detected")
        check(bool(o["findings"]) and o["findings"][0]["file"] == "config/.env" and o["findings"][0]["location"] == "line 1", "S2 FR2: file and line reported")
        check(FAKE_TOKEN not in json.dumps(o) and FAKE_TOKEN[8:] not in json.dumps(o), "S2 FR2: secret absent from response")
        o = scan("s2", [("clean.txt", b"nothing to see\n")])
        check(o["status"] == "complete" and o["findings"] == [], "S2: clean file has no findings")

        o = scan("s3", [("Dockerfile", DOCKER)])
        check(o["status"] == "complete" and len(o["findings"]) >= 1, "S3 FR1: misconfiguration found")
        check(bool(o["findings"]) and all(f["rule"] and f["severity"] != "unknown" for f in o["findings"]), "S3 FR2: rule and severity mapped")
        o = scan("s3", [("notes.txt", b"hello")])
        check(o["status"] == "unsupported", "S3 FR3/QR2: unsupported input is not complete")

        o = scan("s4", [(".github/workflows/one.yml", WF1), (".github/workflows/two.yml", WF2)])
        check(o["status"] == "complete" and len(o["findings"]) >= 1, "S4 FR1: workflow issue found")
        check({f["file"] for f in o["findings"]} == {".github/workflows/one.yml", ".github/workflows/two.yml"}, "S4 FR3: both workflows reported with paths")
        check(all(f["location"].startswith("line ") and f["severity"] != "unknown" for f in o["findings"]), "S4 FR2: location and severity mapped")

        o = scan("s5", [("requirements.txt", REQS)])
        check(o["status"] == "complete" and len(o["findings"]) >= 1, "S5 FR1: known vulnerable package found")
        check(bool(o["findings"]) and o["findings"][0]["file"] == "requirements.txt" and o["findings"][0]["location"] == "django@1.11.0", "S5 FR2/FR3: package, version and manifest reported")
        check(all(f["severity"] != "unknown" for f in o["findings"]), "S5 FR2: normalized severity present")
        check(len({f["rule"] for f in o["findings"]}) == len(o["findings"]), "S5: aliases of one flaw are merged")

        # S5 again with the feed unreachable: a wrapper points the real tool at a dead proxy.
        wrap = os.path.join(tmp, "bin")
        os.makedirs(wrap)
        real = subprocess.check_output(["which", "osv-scanner"], text=True).strip()
        path = os.path.join(wrap, "osv-scanner")
        with open(path, "w") as f:
            f.write(f'#!/bin/sh\nHTTPS_PROXY=http://127.0.0.1:1 HTTP_PROXY=http://127.0.0.1:1 exec "{real}" "$@"\n')
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        procs["s5"].kill(); procs["s5"].wait()
        procs["s5"] = run("s5", dict(env, PATH=wrap + os.pathsep + env["PATH"]))
        time.sleep(3)
        o = scan("s5", [("requirements.txt", REQS)])
        check(o["status"] in ("partial", "error") and o["status"] != "complete", "S5 QR1: feed outage is not reported as clean")
        check(o["status"] == "partial", "S5 QR1: feed outage reported as partial")

        check(os.listdir(scan_tmp) == [], "S2 QR1: no temporary files left after any scan")
    finally:
        for p in procs.values():
            if p.poll() is None:
                p.kill()
            p.wait()
        subprocess.run(["rm", "-rf", tmp])
    print(f"\n{'ALL CHECKS PASSED' if not failures else str(len(failures)) + ' CHECK(S) FAILED'}")
    for f in failures:
        print("  -", f)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
