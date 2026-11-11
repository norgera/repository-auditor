"""S3: Dockerfile misconfiguration checks, using Trivy."""
import json

from scanner_kit import Adapter, Finding, Result, ToolFailed

SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


class TrivyAdapter(Adapter):
    id = "s3"
    name = "Container Security Auditor"
    description = "Checks Dockerfiles for security misconfigurations."
    capabilities = ["container", "docker", "misconfiguration"]
    tool = "trivy"
    version_args = ["--version"]
    accepts_patterns = ["Dockerfile", "Dockerfile.*", "*.dockerfile", "Containerfile"]

    def scan(self, ctx):
        done = ctx.run(["trivy", "config", "--format", "json", "--quiet", "."])
        if done.code != 0:
            raise ToolFailed("trivy did not complete")
        try:
            raw = json.loads(done.stdout)
        except ValueError:
            raise ToolFailed("trivy produced an unreadable report")
        results = raw.get("Results") or []
        checked = {ctx.rel(r.get("Target", "")) for r in results}
        if not checked.intersection(ctx.files):
            return Result("unsupported", message="trivy did not recognize any submitted file as a scan target")
        findings = []
        for res in results:
            for m in res.get("Misconfigurations") or []:
                if m.get("Status", "FAIL") != "FAIL":
                    continue
                start = (m.get("CauseMetadata") or {}).get("StartLine")
                findings.append(Finding(str(m.get("ID", "unknown")), SEVERITY.get(m.get("Severity"), "unknown"), ctx.rel(res.get("Target", "")),
                                        f"line {start}" if start else "file", str(m.get("Title") or m.get("Message") or "Misconfiguration"),
                                        m.get("PrimaryURL") or m.get("Resolution")))
        return Result("complete", findings)
