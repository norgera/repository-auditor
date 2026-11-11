"""S5: known dependency vulnerabilities, using OSV-Scanner."""
import json
import re

from scanner_kit import Adapter, Finding, Result, ToolFailed
from scanner_kit.adapter import ToolTimeout

_NETWORK = re.compile(r"(dial|timeout|timed out|connection|no such host|temporary failure|unavailable|tls|EOF|proxy)", re.I)
SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def from_cvss(score):
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    return "critical" if value >= 9 else "high" if value >= 7 else "medium" if value >= 4 else "low"


def _describe(vulns):
    for v in vulns:
        if v.get("summary"):
            return str(v["summary"])
    for v in vulns:
        if v.get("details"):
            return str(v["details"]).split("\n")[0][:160]
    return "Known vulnerability"


class OsvAdapter(Adapter):
    id = "s5"
    name = "Dependency Risk Scanner"
    description = "Checks dependency lockfiles for known vulnerable packages."
    capabilities = ["dependencies", "vulnerabilities", "sca"]
    tool = "osv-scanner"
    accepts_patterns = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock", "Pipfile.lock",
                        "go.mod", "Cargo.lock", "Gemfile.lock", "composer.lock", "pom.xml"]

    def scan(self, ctx):
        cmd = ["osv-scanner", "scan", "source", "--format", "json"]
        for f in ctx.files:
            cmd += ["-L", f]
        try:
            done = ctx.run(cmd)
        except ToolTimeout:  # osv-scanner spends its time on the feed, and retries for a long while when it is down
            return Result("partial", message="the vulnerability feed did not answer in time, so results are incomplete")
        if done.code not in (0, 1):
            if _NETWORK.search(done.stderr):
                return Result("partial", message="the vulnerability feed was unavailable, so results are incomplete")
            raise ToolFailed("osv-scanner did not complete")
        try:
            raw = json.loads(done.stdout)
        except ValueError:
            raise ToolFailed("osv-scanner produced an unreadable report")
        findings = []
        for res in raw.get("results") or []:
            path = ctx.rel((res.get("source") or {}).get("path", ""))
            for pkg in res.get("packages") or []:
                info = pkg.get("package") or {}
                by_id = {v.get("id"): v for v in pkg.get("vulnerabilities") or []}
                groups = list(pkg.get("groups") or [])
                grouped = {i for g in groups for i in g.get("ids", [])}
                groups += [{"ids": [i]} for i in by_id if i not in grouped]
                for g in groups:  # one finding per issue: aliases of the same flaw share a group
                    ids = g.get("ids") or ["unknown"]
                    main = next((i for i in ids if str(i).startswith("GHSA-")), ids[0])
                    vulns = [by_id[i] for i in ids if i in by_id]
                    named = next((SEVERITY[s] for s in (str((v.get("database_specific") or {}).get("severity", "")).upper() for v in vulns) if s in SEVERITY), None)
                    findings.append(Finding(str(main), from_cvss(g.get("max_severity")) or named or "unknown", path,
                                            f"{info.get('name')}@{info.get('version')}", _describe(vulns), f"https://osv.dev/{main}"))
        return Result("complete", findings)
