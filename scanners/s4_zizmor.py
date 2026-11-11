"""S4: static audit of GitHub Actions workflows, using zizmor. Workflows are never executed."""
import json

from scanner_kit import Adapter, Finding, Result, ToolFailed

SEVERITY = {"Unknown": "unknown", "Informational": "info", "Low": "low", "Medium": "medium", "High": "high"}
# zizmor exits 0 when clean and with 10 to 14 when findings exist, by highest severity.
OK_CODES = {0, 10, 11, 12, 13, 14}


def _where(item):
    for loc in item.get("locations") or []:
        if (loc.get("symbolic") or {}).get("kind") == "Primary" or len(item["locations"]) == 1:
            key = ((loc.get("symbolic") or {}).get("key") or {}).get("Local") or {}
            row = ((loc.get("concrete") or {}).get("location") or {}).get("start_point", {}).get("row")
            return key.get("verbatim_path") or key.get("given_path") or "", (f"line {row + 1}" if isinstance(row, int) else "file")
    return "", "file"


class ZizmorAdapter(Adapter):
    id = "s4"
    name = "CI/CD Pipeline Auditor"
    description = "Audits GitHub Actions workflow files for unsafe patterns without running them."
    capabilities = ["ci", "cd", "github-actions", "workflow"]
    tool = "zizmor"
    accepts_patterns = [".github/workflows/*.yml", ".github/workflows/*.yaml"]

    def scan(self, ctx):
        done = ctx.run(["zizmor", "--offline", "--format=json", *ctx.files])
        if done.code not in OK_CODES:
            raise ToolFailed("zizmor did not complete")
        try:
            raw = json.loads(done.stdout)
        except ValueError:
            raise ToolFailed("zizmor produced an unreadable report")
        findings = []
        for item in raw:
            path, where = _where(item)
            sev = (item.get("determinations") or {}).get("severity")
            findings.append(Finding(str(item.get("ident", "unknown")), SEVERITY.get(sev, "unknown"), ctx.rel(path), where,
                                    str(item.get("desc") or "Workflow issue"), item.get("url")))
        return Result("complete", findings)
