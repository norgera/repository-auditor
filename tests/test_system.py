"""Backend tests. Run from the project root: python3 -m unittest discover -s tests -v

Tool output in these tests comes from stubs written from each tool's documented format. They check the
adapters' parsing and safety rules. They do not prove compatibility with a specific installed tool version.
"""
import base64
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from contracts import validate  # noqa: E402
from registry_service.app import Inventory, build  # noqa: E402
from scanner_kit import Adapter, Finding, Result  # noqa: E402
from scanner_kit.agent import RegistrationAgent  # noqa: E402
from scanner_kit.server import metadata, process  # noqa: E402
from scanners import ADAPTERS  # noqa: E402

SECRET = "AKIAIOSFODNN7SYNTHETIC"


def req(files, options=None):
    return json.dumps({"files": [{"path": p, "content": base64.b64encode(c).decode()} for p, c in files], "options": options or {}}).encode()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scan_tmp = os.path.join(self.tmp.name, "scan")
        self.bin = os.path.join(self.tmp.name, "bin")
        os.makedirs(self.scan_tmp)
        os.makedirs(self.bin)
        self._env = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(self._env)))
        os.environ["SCAN_TMP"] = self.scan_tmp
        os.environ["PATH"] = self.bin + os.pathsep + "/usr/bin:/bin"

    def stub(self, name, script):
        path = os.path.join(self.bin, name)
        with open(path, "w") as f:
            f.write("#!/bin/sh\n" + script)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)

    def run_scan(self, adapter, body, limit=5):
        out = process(adapter, body, "stub", limit)
        self.assertEqual(validate(out, "findings"), [])
        self.assertEqual(os.listdir(self.scan_tmp), [], "workspace must be deleted on every path")
        return out


class Echo(Adapter):
    id, name, description, capabilities = "x", "X", "X", []
    accepts_patterns = ["*.txt"]
    max_bytes = 100

    def scan(self, ctx):
        return Result("complete", [Finding("r", "low", ctx.files[0], "f", "contains " + SECRET)], secrets=[SECRET])


class Crash(Echo):
    def scan(self, ctx):
        raise RuntimeError("file content " + SECRET)


class Slow(Echo):
    tool = "sleep"

    def scan(self, ctx):
        ctx.run(["sleep", "30"])
        return Result()


class GuardAndStatus(Base):
    def test_complete_is_redacted(self):
        out = self.run_scan(Echo(), req([("a.txt", b"x")]))
        self.assertEqual(out["status"], "complete")
        self.assertNotIn(SECRET, json.dumps(out))

    def test_too_large(self):
        self.assertEqual(self.run_scan(Echo(), req([("a.txt", b"x" * 101)]))["status"], "too_large")

    def test_unsupported_is_not_complete(self):
        out = self.run_scan(Echo(), req([("a.bin", b"x")]))
        self.assertEqual(out["status"], "unsupported")
        self.assertEqual(out["skipped"], ["a.bin"])

    def test_path_traversal_rejected(self):
        for bad in ("../evil.txt", "/etc/evil.txt", "a/../../evil.txt", "a\\b.txt"):
            self.assertEqual(self.run_scan(Echo(), req([(bad, b"x")]))["status"], "error", bad)

    def test_bad_json_and_base64(self):
        self.assertEqual(self.run_scan(Echo(), b"{not json")["status"], "error")
        body = json.dumps({"files": [{"path": "a.txt", "content": "***"}]}).encode()
        self.assertEqual(self.run_scan(Echo(), body)["status"], "error")

    def test_crash_does_not_leak(self):
        out = self.run_scan(Crash(), req([("a.txt", b"x")]))
        self.assertEqual(out["status"], "error")
        self.assertNotIn(SECRET, json.dumps(out))

    def test_timeout(self):
        start = time.monotonic()
        out = self.run_scan(Slow(), req([("a.txt", b"x")]), limit=0.5)
        self.assertEqual(out["status"], "timeout")
        self.assertLess(time.monotonic() - start, 5)


class Adapters(Base):
    def test_missing_tool_is_error_never_clean(self):
        cases = {"s1": [("a.yaml", b"a: 1"), ("b.yaml", b"a: 2")], "s2": [("a.txt", b"x")], "s3": [("Dockerfile", b"FROM x")],
                 "s4": [(".github/workflows/a.yml", b"on: push")], "s5": [("requirements.txt", b"x==1")]}
        os.environ["PATH"] = self.bin
        for sid, files in cases.items():
            out = self.run_scan(ADAPTERS[sid](), req(files))
            self.assertEqual(out["status"], "error", sid)
            self.assertIn("not installed", out["message"], sid)

    def test_s1_reports_paths_never_values_and_flags_required(self):
        self.stub("dyff", "cat <<'E'\nspec.replicas\n  ± value change\n    - hunter2\n    + 3\n\nmetadata.name\n  ± value change\n    - a\n    + b\nE\n")
        out = self.run_scan(ADAPTERS["s1"](), req([("a.yaml", b"a: 1"), ("b.yaml", b"a: 2")], {"baseline": "a.yaml", "target": "b.yaml", "requiredKeys": ["spec.replicas"]}))
        self.assertEqual(out["status"], "complete")
        self.assertEqual([(f["location"], f["severity"]) for f in out["findings"]], [("spec.replicas", "high"), ("metadata.name", "info")])
        self.assertNotIn("hunter2", json.dumps(out))

    def test_s1_parses_captured_dyff_output(self):
        # Output captured from dyff 1.12.0 with --no-table-style.
        self.stub("dyff", """cat <<'E'

(root level)
- one map entry removed:
  keep:
    x: topsecret
  

+ one map entry added:
  extra: "e"
  


a
  ± value change
    - 1
    + 2
  

spec
  - two map entries removed:
    gone: topsecret
    nested:
      deep: 1
    
  
  + one map entry added:
    fresh: new
    
  

E
""")
        run = lambda keys: self.run_scan(ADAPTERS["s1"](), req([("a.yaml", b"a: 1"), ("b.yaml", b"a: 2")], {"baseline": "a.yaml", "target": "b.yaml", "requiredKeys": keys}))
        out = run(["spec.replicas"])
        self.assertEqual([f["location"] for f in out["findings"]], ["(root level)", "a", "spec"])
        self.assertTrue(all(f["severity"] == "info" for f in out["findings"]), "a sibling change must not flag a required key")
        self.assertNotIn("topsecret", json.dumps(out))
        by = lambda keys: {f["location"]: f["severity"] for f in run(keys)["findings"]}
        self.assertEqual(by(["spec.gone"])["spec"], "high")
        self.assertEqual(by(["spec.nested.deep"])["spec"], "high")
        self.assertEqual(by(["keep"])["(root level)"], "high")
        self.assertEqual(by(["a"])["a"], "high")

    def test_s1_needs_two_files(self):
        self.stub("dyff", "exit 0\n")
        self.assertEqual(self.run_scan(ADAPTERS["s1"](), req([("a.yaml", b"a: 1")]))["status"], "unsupported")

    def test_s2_never_returns_secret(self):
        report = json.dumps([{"RuleID": "aws", "File": "conf/a.env", "StartLine": 3, "Description": "AWS key " + SECRET, "Secret": SECRET, "Match": "key=" + SECRET}])
        self.stub("gitleaks", f"""
while [ $# -gt 0 ]; do [ "$1" = "--report-path" ] && R="$2"; shift; done
cat > "$R" <<'E'
{report}
E
""")
        out = self.run_scan(ADAPTERS["s2"](), req([("conf/a.env", SECRET.encode())]))
        self.assertEqual(out["status"], "complete")
        self.assertEqual((out["findings"][0]["file"], out["findings"][0]["location"]), ("conf/a.env", "line 3"))
        self.assertNotIn(SECRET, json.dumps(out))

    def test_s3_findings_and_unrecognized_target(self):
        doc = json.dumps({"Results": [{"Target": "Dockerfile", "Misconfigurations": [{"ID": "DS002", "Title": "Root user", "Severity": "HIGH", "Status": "FAIL", "PrimaryURL": "http://x", "CauseMetadata": {"StartLine": 2}}]}]})
        self.stub("trivy", f"cat <<'E'\n{doc}\nE\n")
        out = self.run_scan(ADAPTERS["s3"](), req([("Dockerfile", b"FROM x")]))
        self.assertEqual((out["status"], out["findings"][0]["rule"], out["findings"][0]["severity"]), ("complete", "DS002", "high"))
        self.stub("trivy", "echo '{}'\n")
        self.assertEqual(self.run_scan(ADAPTERS["s3"](), req([("Dockerfile", b"FROM x")]))["status"], "unsupported")
        self.assertEqual(self.run_scan(ADAPTERS["s3"](), req([("notes.txt", b"hello")]))["status"], "unsupported")

    def test_s4_exit_codes(self):
        doc = json.dumps([{"ident": "template-injection", "desc": "bad", "url": "http://x", "determinations": {"severity": "High"},
                           "locations": [{"symbolic": {"kind": "Primary", "key": {"Local": {"verbatim_path": ".github/workflows/a.yml"}}}, "concrete": {"location": {"start_point": {"row": 4}}}}]}])
        self.stub("zizmor", f"cat <<'E'\n{doc}\nE\nexit 14\n")
        out = self.run_scan(ADAPTERS["s4"](), req([(".github/workflows/a.yml", b"on: push")]))
        self.assertEqual((out["status"], out["findings"][0]["location"], out["findings"][0]["severity"]), ("complete", "line 5", "high"))
        self.stub("zizmor", "exit 1\n")
        self.assertEqual(self.run_scan(ADAPTERS["s4"](), req([(".github/workflows/a.yml", b"on: push")]))["status"], "error")

    def test_s5_vulnerable_and_feed_down(self):
        doc = json.dumps({"results": [{"source": {"path": "requirements.txt"}, "packages": [{"package": {"name": "django", "version": "1.0"}, "groups": [{"ids": ["PYSEC-1", "GHSA-1"], "max_severity": "6.1"}], "vulnerabilities": [{"id": "PYSEC-1", "details": "first line\\nsecond"}, {"id": "GHSA-1", "summary": "bad"}]}]}]})
        self.stub("osv-scanner", f"cat <<'E'\n{doc}\nE\nexit 1\n")
        out = self.run_scan(ADAPTERS["s5"](), req([("requirements.txt", b"django==1.0")]))
        self.assertEqual((out["status"], out["findings"][0]["location"], out["findings"][0]["severity"]), ("complete", "django@1.0", "medium"))
        self.assertEqual((len(out["findings"]), out["findings"][0]["rule"], out["findings"][0]["message"]), (1, "GHSA-1", "bad"))
        self.stub("osv-scanner", "echo 'dial tcp: connection refused' >&2\nexit 128\n")
        out = self.run_scan(ADAPTERS["s5"](), req([("requirements.txt", b"django==1.0")]))
        self.assertEqual((out["status"], out["findings"]), ("partial", []))
        self.stub("osv-scanner", "sleep 30\n")
        out = self.run_scan(ADAPTERS["s5"](), req([("requirements.txt", b"django==1.0")]), limit=0.5)
        self.assertEqual((out["status"], out["findings"]), ("partial", []))


class FakeClock:
    now = 0.0

    def __call__(self):
        return self.now


META = {"id": "s9", "name": "Nine", "description": "d", "capabilities": ["cap"], "url": "http://127.0.0.1:1", "version": "1", "tool": None, "accepts": ["*"], "inputMode": "files", "maxBytes": 10}


class Leases(unittest.TestCase):
    def test_lifecycle(self):
        c = FakeClock()
        inv = Inventory(15, c)
        inv.register(META)
        self.assertEqual([m["id"] for m in inv.search("CAP")], ["s9"])
        self.assertEqual(inv.search("zzz"), [])
        c.now = 14
        self.assertTrue(inv.renew("s9"))
        c.now = 28
        self.assertTrue(inv.get("s9"))
        c.now = 29
        self.assertEqual(inv.search(), [], "expired leases are hidden before the sweep")
        self.assertEqual(inv.sweep(), ["s9"])
        self.assertFalse(inv.renew("s9"))


class RegistryHttp(unittest.TestCase):
    def setUp(self):
        self.server, self.inv, self.stop = build("T", "tok", "127.0.0.1", 0, 1.0, 0.1)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.addCleanup(self._close)

    def _close(self):
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()

    def call(self, method, path, body=None, token="tok"):
        r = urllib.request.Request(self.url + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers={"X-Registration-Token": token})
        try:
            with urllib.request.urlopen(r, timeout=3) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            e.close()
            return e.code, None

    def test_token_required(self):
        self.assertEqual(self.call("POST", "/v1/services", META, token="wrong")[0], 401)
        self.assertEqual(self.call("GET", "/v1/services")[1]["services"], [])

    def test_contract_enforced(self):
        self.assertEqual(self.call("POST", "/v1/services", {"id": "x"})[0], 400)

    def test_register_search_delete(self):
        self.assertEqual(self.call("POST", "/v1/services", META)[0], 201)
        self.assertEqual(len(self.call("GET", "/v1/services?q=nine")[1]["services"]), 1)
        self.assertEqual(self.call("GET", "/v1/services/s9")[1]["id"], "s9")
        self.assertEqual(self.call("DELETE", "/v1/services/s9")[0], 200)
        self.assertEqual(self.call("GET", "/v1/services")[1]["services"], [])

    def test_renew_unknown_is_404(self):
        self.assertEqual(self.call("PUT", "/v1/services/none/lease")[0], 404)

    def test_agent_recovers_a_restarted_registry(self):
        agent = RegistrationAgent(META, [self.url], "tok", renew_interval=0.1, retry_interval=0.1, timeout=1)
        agent.start()
        self.addCleanup(agent.stop)
        self._wait(lambda: self.inv.get("s9"))
        self.inv.remove("s9")  # same state as a restart: the registry has forgotten the service
        self._wait(lambda: self.inv.get("s9"))

    def _wait(self, cond, limit=3):
        end = time.monotonic() + limit
        while time.monotonic() < end:
            if cond():
                return
            time.sleep(0.02)
        self.fail("condition not reached")


if __name__ == "__main__":
    unittest.main()
