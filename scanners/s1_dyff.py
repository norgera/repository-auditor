"""S1: structural drift between a baseline and a target file, using dyff."""
import re
from dataclasses import dataclass, field
from typing import List

from scanner_kit import Adapter, Finding, Result, ToolFailed

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_HEADER = re.compile(r"^(\s*)[±+\-⇆#]\s+(?:(\w+ (?:map|list) entr(?:y|ies) (?:added|removed))|(value change|type change|order changed|whitespace only change))")
_KEY = re.compile(r"^([^\s:#\-\"'][^:]*):(?:\s|$)")
ROOT = "(root level)"


@dataclass
class Change:
    path: str
    kinds: List[str] = field(default_factory=list)
    removed_keys: List[str] = field(default_factory=list)


def parse_changes(text):
    """Read dyff's one-column output. Only paths, change kinds and removed key names are kept, never values (S1 QR2)."""
    changes, current, removing_at = [], None, None
    for line in _ANSI.sub("", text).splitlines():
        if not line.strip():
            continue
        header = _HEADER.match(line)
        depth = len(line) - len(line.lstrip())
        if header and current is not None and depth == (0 if current.path == ROOT else 2):
            kind = header.group(2) or header.group(3)
            current.kinds.append(kind)
            removing_at = depth + 2 if kind.endswith("removed") else None
        elif depth == 0:
            current, removing_at = Change(line.strip()), None
            changes.append(current)
        elif removing_at is not None and depth == removing_at:
            key = _KEY.match(line.strip())
            if key:
                current.removed_keys.append(key.group(1))
    return changes


def _is_required(change, required):
    path = "" if change.path == ROOT else change.path
    if any(path and (path == k or path.startswith(k + ".")) for k in required):
        return True
    gone = [f"{path}.{r}" if path else r for r in change.removed_keys]
    return any(k == g or k.startswith(g + ".") for k in required for g in gone)


class DyffAdapter(Adapter):
    id = "s1"
    name = "Deployment Drift Analyzer"
    description = "Finds structural differences between a baseline and a target YAML or JSON configuration."
    capabilities = ["drift", "configuration", "yaml", "json"]
    tool = "dyff"
    version_args = ["version"]
    accepts_patterns = ["*.yaml", "*.yml", "*.json"]
    input_mode = "baseline-target"
    max_bytes = 2 * 1024 * 1024

    def scan(self, ctx):
        baseline = ctx.options.get("baseline") or ctx.files[0]
        target = ctx.options.get("target") or (ctx.files[1] if len(ctx.files) > 1 else None)
        if target is None or baseline not in ctx.files or target not in ctx.files:
            return Result("unsupported", message="a baseline file and a target file are both required")
        done = ctx.run(["dyff", "--color=off", "between", "--omit-header", "--no-table-style", "--output=human", baseline, target])
        if done.code != 0:
            raise ToolFailed("dyff could not compare the files")
        required = [k for k in ctx.options.get("requiredKeys", []) if isinstance(k, str)]
        findings = []
        for c in parse_changes(done.stdout):
            hit = _is_required(c, required)
            summary = ", ".join(c.kinds) or "changed"
            findings.append(Finding("required-key-drift" if hit else "drift", "high" if hit else "info", target, c.path,
                                    f"{'Required key affected' if hit else 'Changed'}: {summary}"))
        return Result("complete", findings)
