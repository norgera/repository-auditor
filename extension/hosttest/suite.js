// Runs inside a real VS Code extension host. Started by demo/host_test.py.
const fs = require("fs");
const path = require("path");
const vscode = require("vscode");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, limitMs, what) {
  const end = Date.now() + limitMs;
  while (Date.now() < end) {
    if (cond()) return;
    await sleep(100);
  }
  throw new Error("timed out waiting for: " + what);
}

exports.run = async () => {
  const dir = __dirname;
  const out = { steps: [] };
  try {
    const ctx = JSON.parse(fs.readFileSync(path.join(dir, ".ctx.json"), "utf8"));
    const ext = vscode.extensions.getExtension("cs4471-group4.repository-auditor");
    const api = await ext.activate();
    const ids = () => api.catalog().services.map((s) => s.id);
    const note = (s) => out.steps.push(s);
    note("extension activated");
    const cmds = await vscode.commands.getCommands(true);
    for (const c of ["search", "clearSearch", "selectProfile", "open"]) {
      if (!cmds.includes("repositoryAuditor." + c)) throw new Error("missing command " + c);
    }
    note("commands registered");
    await until(() => ids().includes("s1") && ids().includes("s6"), 20000, "services in sidebar");
    note("sidebar lists running services: " + ids().join(", "));
    await vscode.commands.executeCommand("repositoryAuditor.search", "credentials");
    if (ids().join() !== "s2") throw new Error("search returned: " + ids().join());
    await vscode.commands.executeCommand("repositoryAuditor.clearSearch");
    note("search filtered the catalog by capability");
    await vscode.commands.executeCommand("repositoryAuditor.open", api.catalog().services[0]);
    note("service detail panel opened");
    const service = (id) => api.catalog().services.find((s) => s.id === id);
    await until(() => service("s2"), 15000, "S2 in sidebar");
    const root = vscode.workspace.workspaceFolders[0].uri;
    const scan = await api.scanWith(service("s2"), [vscode.Uri.joinPath(root, "config", ".env")]);
    if (!scan || scan.response.status !== "complete" || scan.response.findings.length !== 1) throw new Error("S2 scan: " + JSON.stringify(scan && scan.response.status));
    if (JSON.stringify(scan).includes(ctx.token)) throw new Error("secret returned to the extension");
    if (scan.verdict.verdict !== "blocked" || !scan.canCleanup) throw new Error("verdict: " + JSON.stringify(scan.verdict));
    note("real Gitleaks scan of a workspace file: 1 finding, secret absent, staging profile blocked, cleanup offered");
    const drift = await api.scanWith(service("s1"), [vscode.Uri.joinPath(root, "base.yaml"), vscode.Uri.joinPath(root, "target.yaml")]);
    if (!drift || drift.response.status !== "complete" || drift.response.findings.length !== 1) throw new Error("S1 scan: " + JSON.stringify(drift && drift.response));
    note("real dyff scan from baseline and target workspace files");
    const refused = await api.scanWith(service("s1"), [vscode.Uri.joinPath(root, "notes.txt"), vscode.Uri.joinPath(root, "notes.txt")]);
    if (refused !== undefined) throw new Error("unsupported files were sent");
    note("unsupported files were stopped before sending");
    process.kill(ctx.s6, "SIGTERM");
    await until(() => !ids().includes("s6"), 8000, "S6 removal");
    note("stopped service left the sidebar with no reload");
    process.kill(ctx.regA, "SIGKILL");
    await until(() => api.catalog().source === "backup" && ids().includes("s1"), 10000, "backup in use");
    note("sidebar switched to the backup registry after the primary was killed");
    out.passed = true;
  } catch (e) {
    out.passed = false;
    out.error = String(e && e.message);
  }
  fs.writeFileSync(path.join(dir, ".result.json"), JSON.stringify(out, null, 2));
};
