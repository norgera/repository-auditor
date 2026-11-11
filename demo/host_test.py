"""Loads the extension in the installed VS Code and exercises the live sidebar. Run: python3 demo/host_test.py"""
import json
import os
import secrets
import string
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXT = os.path.join(ROOT, "extension")
HT = os.path.join(EXT, "hosttest")
CTX, RESULT = os.path.join(HT, ".ctx.json"), os.path.join(HT, ".result.json")
TOKEN = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
ENV = dict(os.environ, REGISTRY_TOKEN=secrets.token_hex(16), PYTHONPATH=ROOT, PYTHONDONTWRITEBYTECODE="1")


def start(args, **extra):
    return subprocess.Popen([sys.executable, "-m", *args], cwd=ROOT, env=dict(ENV, **extra), stdout=subprocess.DEVNULL)


procs = {"regA": start(["registry_service.app"], REGISTRY_NAME="A", PORT="8701"), "regB": start(["registry_service.app"], REGISTRY_NAME="B", PORT="8702"),
         "s1": start(["scanners.run", "s1"]), "s2": start(["scanners.run", "s2"]), "s6": start(["scanners.run", "s6"])}
code = 1
try:
    time.sleep(1.5)
    urllib.request.urlopen("http://127.0.0.1:8701/health", timeout=2).close()
    with open(CTX, "w") as f:
        json.dump({**{k: p.pid for k, p in procs.items()}, "token": TOKEN}, f)
    if os.path.exists(RESULT):
        os.remove(RESULT)
    with tempfile.TemporaryDirectory(prefix="ra-vscode-", dir=os.environ.get("TMPDIR")) as data:
        ws = os.path.join(data, "workspace")
        os.makedirs(os.path.join(ws, "config"))
        fixtures = {"config/.env": f"GITHUB_TOKEN={TOKEN}\n", "base.yaml": "a: 1\n", "target.yaml": "a: 2\n", "notes.txt": "hello\n"}
        for name, text in fixtures.items():
            with open(os.path.join(ws, name), "w") as f:
                f.write(text)
        vs = subprocess.Popen(["code", "--new-window", "--disable-extensions", "--skip-welcome", "--user-data-dir", os.path.join(data, "u"), "--extensions-dir", os.path.join(data, "e"),
                               "--extensionDevelopmentPath=" + EXT, "--extensionTestsPath=" + os.path.join(HT, "suite.js"), ws])
        end = time.monotonic() + 120
        while time.monotonic() < end and not os.path.exists(RESULT):
            time.sleep(0.5)
        vs.wait(timeout=30)
        time.sleep(2)
    if os.path.exists(RESULT):
        print(open(RESULT).read())
        code = 0 if json.load(open(RESULT))["passed"] else 1
    else:
        print("no result: the extension host did not finish within 120 s")
finally:
    for p in procs.values():
        if p.poll() is None:
            p.kill()
        p.wait()
    for f in (CTX, RESULT):
        if os.path.exists(f):
            os.remove(f)
sys.exit(code)
