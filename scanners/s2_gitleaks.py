"""S2: hard-coded credential detection, using Gitleaks."""
import json
import os
import tempfile

from scanner_kit import Adapter, Finding, Result, ToolFailed


class GitleaksAdapter(Adapter):
    id = "s2"
    name = "Secret Exposure Scanner"
    description = "Scans selected files for hard-coded credentials and never returns the matched value."
    capabilities = ["secrets", "credentials"]
    tool = "gitleaks"
    version_args = ["version"]

    def scan(self, ctx):
        # The report sits outside the scanned tree so that it cannot be scanned itself.
        with tempfile.TemporaryDirectory(prefix="repo-auditor-report-", dir=os.environ.get("SCAN_TMP")) as d:
            report = os.path.join(d, "report.json")
            done = ctx.run(["gitleaks", "dir", ".", "--no-banner", "--redact", "--exit-code", "0",
                            "--report-format", "json", "--report-path", report])
            if done.code != 0 or not os.path.exists(report):
                raise ToolFailed("gitleaks did not complete")
            with open(report) as f:
                try:
                    raw = json.load(f)
                except ValueError:
                    raise ToolFailed("gitleaks produced an unreadable report")
        secrets = [v for r in raw for v in (r.get("Secret"), r.get("Match")) if v and "REDACTED" not in v]
        findings = [Finding(str(r.get("RuleID", "unknown")), "high", ctx.rel(r.get("File", "")), f"line {r.get('StartLine', '?')}",
                            str(r.get("Description") or "Possible hard-coded secret"), "Remove the value and rotate the credential.") for r in raw]
        return Result("complete", findings, secrets=secrets)
