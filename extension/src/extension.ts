import * as path from "path";
import * as vscode from "vscode";
import { BUILT_IN, evaluate, Profile, RANK } from "./profiles";
import { Catalog, RegistryClient, ServiceMeta } from "./registryClient";
import { runScan, ScanFile, ScanResponse } from "./scanClient";

const REFRESH_MS = 3000;
const PROFILE_KEY = "repositoryAuditor.profile";
const PROFILES = [...Object.keys(BUILT_IN), "custom"];

function nonce(): string {
  return [...Array(32)].map(() => Math.floor(Math.random() * 16).toString(16)).join("");
}

function esc(value: unknown): string {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

function sidebarHtml(n: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${n}'; script-src 'nonce-${n}';">
<style nonce="${n}">
body{padding:8px 12px;color:var(--vscode-foreground);font-family:var(--vscode-font-family);font-size:var(--vscode-font-size)}
label{display:block;margin:10px 0 4px;color:var(--vscode-descriptionForeground)}
input,select{width:100%;box-sizing:border-box;padding:4px 6px;color:var(--vscode-input-foreground);background:var(--vscode-input-background);border:1px solid var(--vscode-input-border,var(--vscode-panel-border))}
input:focus,select:focus,button:focus-visible{outline:1px solid var(--vscode-focusBorder);outline-offset:-1px}
#notice{margin-top:10px;padding:6px 8px;background:var(--vscode-inputValidation-warningBackground);border:1px solid var(--vscode-inputValidation-warningBorder)}
#notice[hidden]{display:none}
ul{list-style:none;margin:10px 0 0;padding:0}
button{display:block;width:100%;padding:6px;text-align:left;color:inherit;background:none;border:0;cursor:pointer}
button:hover{background:var(--vscode-list-hoverBackground)}
.name{font-weight:600}
.tool{display:block;color:var(--vscode-descriptionForeground)}
#empty{margin-top:12px;color:var(--vscode-descriptionForeground)}
</style></head><body>
<label for="q">Search by name or capability</label><input id="q" type="search" placeholder="for example: secrets" autocomplete="off">
<label for="p">Release profile</label><select id="p"></select>
<div id="notice" role="status" hidden></div><ul id="list"></ul><div id="empty" hidden></div>
<script nonce="${n}">
const v=acquireVsCodeApi(),q=document.getElementById('q'),p=document.getElementById('p'),list=document.getElementById('list'),notice=document.getElementById('notice'),empty=document.getElementById('empty');
let t;q.addEventListener('input',()=>{clearTimeout(t);t=setTimeout(()=>v.postMessage({type:'search',q:q.value}),150);});
p.addEventListener('change',()=>v.postMessage({type:'profile',name:p.value}));
window.addEventListener('message',e=>{const s=e.data;
 if(document.activeElement!==q)q.value=s.query;
 p.replaceChildren(...s.profiles.map(n=>{const o=document.createElement('option');o.value=n;o.textContent=n;return o;}));p.value=s.profile;
 notice.hidden=s.source==='primary';notice.textContent=s.source==='backup'?'Primary registry is down. Using the backup.':s.source==='stale'?'No registry is reachable. This list may be out of date.':'';
 list.replaceChildren(...s.services.map(x=>{const li=document.createElement('li'),b=document.createElement('button'),a=document.createElement('span'),c=document.createElement('span');
  a.className='name';a.textContent=x.name;c.className='tool';c.textContent=x.tool||'test service';b.title=x.description;b.append(a,c);b.addEventListener('click',()=>v.postMessage({type:'open',id:x.id}));li.append(b);return li;}));
 empty.hidden=s.services.length>0;empty.textContent=s.query?'No scanners match this search.':'No scanners are registered.';
});
v.postMessage({type:'ready'});
</script></body></html>`;
}

class CatalogProvider implements vscode.WebviewViewProvider {
  private catalog: Catalog = { services: [], source: "primary" };
  private view?: vscode.WebviewView;
  private sent = "";
  query = "";

  constructor(private readonly client: () => RegistryClient, private readonly profile: () => string,
    private readonly onOpen: (s: ServiceMeta) => void, private readonly onProfile: (name: string) => void) {}

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    view.webview.options = { enableScripts: true };
    view.webview.html = sidebarHtml(nonce());
    view.onDidDispose(() => { this.view = undefined; });
    view.webview.onDidReceiveMessage((m) => {
      if (m.type === "ready") {
        this.sent = "";
        this.post();
      } else if (m.type === "search") {
        this.setQuery(String(m.q ?? ""));
      } else if (m.type === "profile" && PROFILES.includes(m.name)) {
        this.onProfile(m.name);
      } else if (m.type === "open") {
        const service = this.catalog.services.find((s) => s.id === m.id);
        if (service) {
          this.onOpen(service);
        }
      }
    });
  }

  post(): void {
    const state = { ...this.catalog, query: this.query, profile: this.profile(), profiles: PROFILES };
    const text = JSON.stringify(state);
    if (this.view && text !== this.sent) {
      this.sent = text;
      this.view.webview.postMessage(state);
    }
  }

  async refresh(): Promise<void> {
    const query = this.query;
    const catalog = await this.client().search(query);
    if (query === this.query) { // a slower, older search must not overwrite a newer one
      this.catalog = catalog;
      this.post();
    }
  }

  async setQuery(query: string): Promise<void> {
    this.query = query;
    await this.refresh();
  }

  snapshot(): Catalog {
    return this.catalog;
  }
}

function matches(service: ServiceMeta, rel: string): boolean {
  const toRegex = (p: string) => new RegExp("^" + p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$");
  return service.accepts.some((p) => toRegex(p).test(path.posix.basename(rel)) || toRegex(p).test(rel));
}

async function pick(label: string, many: boolean): Promise<vscode.Uri[] | undefined> {
  return vscode.window.showOpenDialog({ canSelectMany: many, canSelectFiles: true, canSelectFolders: false, openLabel: label, defaultUri: vscode.workspace.workspaceFolders?.[0]?.uri });
}

/** Reads only the files the user chose, and applies the allowlist and size limit before anything is sent. */
async function collect(service: ServiceMeta, choose: typeof pick): Promise<{ files: ScanFile[]; options: Record<string, unknown> } | undefined> {
  let uris: vscode.Uri[];
  const options: Record<string, unknown> = {};
  if (service.inputMode === "baseline-target") {
    const baseline = await choose("Select baseline", false);
    const target = baseline && (await choose("Select target", false));
    if (!baseline || !target) {
      return undefined;
    }
    uris = [baseline[0], target[0]];
  } else {
    const chosen = await choose("Scan selected files", true);
    if (!chosen) {
      return undefined;
    }
    uris = chosen;
  }
  const files: ScanFile[] = [];
  let total = 0;
  for (const uri of uris) {
    const rel = vscode.workspace.asRelativePath(uri, false).split(path.sep).join("/");
    if (!matches(service, rel)) {
      vscode.window.showWarningMessage(`${service.name} does not accept ${rel}. It was left out.`);
      continue;
    }
    total += (await vscode.workspace.fs.stat(uri)).size;
    if (total > service.maxBytes) {
      vscode.window.showErrorMessage(`The selection exceeds the ${service.maxBytes} byte limit. Nothing was sent.`);
      return undefined;
    }
    files.push({ path: rel, content: await vscode.workspace.fs.readFile(uri) });
  }
  if (files.length === 0) {
    vscode.window.showErrorMessage("No supported files were selected. Nothing was sent.");
    return undefined;
  }
  if (service.inputMode === "baseline-target") {
    if (files.length < 2) {
      vscode.window.showErrorMessage("Both a baseline and a target file are required.");
      return undefined;
    }
    options.baseline = files[0].path;
    options.target = files[1].path;
  }
  return { files, options };
}

const STATUS_TEXT: Record<string, string> = {
  complete: "Scan complete",
  partial: "Some data sources were unavailable",
  unsupported: "Not scanned: unsupported target",
  too_large: "Rejected: input too large",
  timeout: "Did not finish",
  error: "Scanner error",
};

const VERDICT_TEXT: Record<string, [string, string]> = {
  ready: ["✓", "Ready for release"],
  blocked: ["✕", "Release blocked"],
  incomplete: ["!", "Incomplete: do not treat as clean"],
};

function page(service: ServiceMeta, profileName: string, profile: Profile, response?: ScanResponse, canCleanup = false): string {
  const n = nonce();
  const rank = (s: string) => RANK[s] ?? RANK.unknown;
  let results = "";
  if (response) {
    const verdict = evaluate(response, profile);
    const [icon, title] = VERDICT_TEXT[verdict.verdict];
    const findings = [...response.findings].sort((a, b) => rank(b.severity) - rank(a.severity));
    const rows = findings.map((f) => `<tr><td><span class="pill ${esc(f.severity)}">${esc(f.severity)}</span></td><td>${esc(f.rule)}</td><td>${esc(f.file)}</td><td>${esc(f.location)}</td><td>${esc(f.message)}</td></tr>`).join("");
    results = `<section class="verdict ${esc(verdict.verdict)}" role="status"><span class="icon">${icon}</span><div><strong>${title}</strong><div>${esc(verdict.reason)}</div></div></section>
    <h2>${esc(STATUS_TEXT[response.status])}</h2>${response.message ? `<p>${esc(response.message)}</p>` : ""}
    ${response.status === "complete" && findings.length === 0 ? "<p>No findings.</p>" : ""}
    ${rows ? `<table><thead><tr><th>Severity</th><th>Rule</th><th>File</th><th>Location</th><th>Message</th></tr></thead><tbody>${rows}</tbody></table>` : ""}
    ${response.skipped.length ? `<p>Skipped: ${esc(response.skipped.join(", "))}</p>` : ""}
    ${canCleanup ? `<p><button id="cleanup" class="secondary">Preview adding env files to .gitignore</button></p>` : ""}`;
  }
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${n}'; script-src 'nonce-${n}';">
<style nonce="${n}">
body{font-family:var(--vscode-font-family);color:var(--vscode-foreground);padding:16px 24px;max-width:1000px}
h1{margin-bottom:4px}h2{font-size:1.1em;margin-top:20px}
.meta{color:var(--vscode-descriptionForeground)}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--vscode-panel-border);padding:6px 8px;text-align:left;vertical-align:top}
button{background:var(--vscode-button-background);color:var(--vscode-button-foreground);border:0;padding:6px 14px;cursor:pointer}
button.secondary{background:var(--vscode-button-secondaryBackground);color:var(--vscode-button-secondaryForeground);border:1px solid var(--vscode-button-border,var(--vscode-panel-border))}
.verdict{display:flex;gap:12px;align-items:center;margin-top:20px;padding:12px 16px;border:1px solid;border-radius:4px;font-size:1.1em}
.verdict .icon{font-size:1.6em;font-weight:700;width:1.2em;text-align:center}
.ready{border-color:var(--vscode-testing-iconPassed)}.ready .icon{color:var(--vscode-testing-iconPassed)}
.blocked{border-color:var(--vscode-errorForeground);background:var(--vscode-inputValidation-errorBackground)}.blocked .icon{color:var(--vscode-errorForeground)}
.incomplete{border-color:var(--vscode-editorWarning-foreground);background:var(--vscode-inputValidation-warningBackground)}.incomplete .icon{color:var(--vscode-editorWarning-foreground)}
.pill{display:inline-block;min-width:4.5em;padding:1px 6px;text-align:center;border-radius:3px;border:1px solid var(--vscode-panel-border)}
.critical,.high{color:var(--vscode-errorForeground);border-color:var(--vscode-errorForeground);font-weight:700}.medium{color:var(--vscode-editorWarning-foreground);border-color:var(--vscode-editorWarning-foreground)}
</style></head><body><h1>${esc(service.name)}</h1><p>${esc(service.description)}</p>
<p class="meta">Tool: ${esc(service.tool ?? "none")} &nbsp;|&nbsp; Capabilities: ${esc(service.capabilities.join(", "))}</p>
<p class="meta">Release profile: <strong>${esc(profileName)}</strong> (blocks at ${esc(profile.failAt)} and above). Change it in the sidebar.</p>
<p><button id="scan">Select files and scan</button></p>${results}
<script nonce="${n}">const v=acquireVsCodeApi();document.getElementById('scan').onclick=()=>v.postMessage('scan');const c=document.getElementById('cleanup');if(c)c.onclick=()=>v.postMessage('cleanup');</script></body></html>`;
}

/** The only write path. VS Code shows the edit in its Refactor Preview and applies it after approval. */
async function previewGitignore(): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    return;
  }
  const uri = vscode.Uri.joinPath(folder.uri, ".gitignore");
  const meta: vscode.WorkspaceEditEntryMetadata = { label: "Ignore local environment files", needsConfirmation: true };
  const edit = new vscode.WorkspaceEdit();
  try {
    const doc = await vscode.workspace.openTextDocument(uri);
    if (doc.getText().split(/\r?\n/).includes(".env*")) {
      vscode.window.showInformationMessage(".gitignore already covers env files.");
      return;
    }
    edit.insert(uri, doc.lineAt(doc.lineCount - 1).range.end, (doc.getText().endsWith("\n") || doc.getText() === "" ? "" : "\n") + ".env*\n", meta);
  } catch {
    edit.createFile(uri, { ignoreIfExists: true, overwrite: false, contents: new TextEncoder().encode(".env*\n") }, meta);
  }
  await vscode.workspace.applyEdit(edit);
}

interface OpenPanel {
  panel: vscode.WebviewPanel;
  service: ServiceMeta;
  response?: ScanResponse;
  canCleanup: boolean;
}

interface ScanOutcome {
  response: ScanResponse;
  verdict: { verdict: string; reason: string };
  canCleanup: boolean;
}

export interface Api {
  catalog: () => Catalog;
  /** The panel's scan path with the file dialog replaced, used by the VS Code host test. */
  scanWith: (service: ServiceMeta, uris: vscode.Uri[]) => Promise<ScanOutcome | undefined>;
}

export function activate(context: vscode.ExtensionContext): Api {
  const makeClient = () => new RegistryClient({ urls: vscode.workspace.getConfiguration("repositoryAuditor").get<string[]>("registries", []) });
  let client = makeClient();
  const profileName = () => context.globalState.get<string>(PROFILE_KEY, "staging");
  const profile = (): Profile => profileName() === "custom"
    ? { failAt: "high", requiredKeys: [], ...vscode.workspace.getConfiguration("repositoryAuditor").get<Partial<Profile>>("customProfile", {}) }
    : BUILT_IN[profileName()] ?? BUILT_IN.staging;

  const panels = new Map<string, OpenPanel>();
  const render = (p: OpenPanel) => { p.panel.webview.html = page(p.service, profileName(), profile(), p.response, p.canCleanup); };

  const performScan = async (service: ServiceMeta, choose: typeof pick): Promise<ScanOutcome | undefined> => {
    const input = await collect(service, choose);
    if (!input) {
      return undefined;
    }
    const response = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: `Running ${service.name}` },
      () => runScan(service, input.files, { ...input.options, requiredKeys: profile().requiredKeys }));
    const canCleanup = service.id === "s2" && response.findings.some((f) => path.posix.basename(f.file).startsWith(".env"));
    provider.refresh();
    const open = panels.get(service.id);
    if (open) {
      open.response = response;
      open.canCleanup = canCleanup;
      render(open);
    }
    return { response, verdict: evaluate(response, profile()), canCleanup };
  };

  const open = (service: ServiceMeta) => {
    const existing = panels.get(service.id);
    if (existing) {
      existing.panel.reveal();
      return;
    }
    const panel = vscode.window.createWebviewPanel("repositoryAuditor.detail", service.name, vscode.ViewColumn.Active, { enableScripts: true });
    const entry: OpenPanel = { panel, service, canCleanup: false };
    panels.set(service.id, entry);
    panel.onDidDispose(() => panels.delete(service.id));
    render(entry);
    panel.webview.onDidReceiveMessage((message) => (message === "cleanup" ? previewGitignore() : performScan(service, pick)), undefined, context.subscriptions);
  };

  const setProfile = async (name: string) => {
    await context.globalState.update(PROFILE_KEY, name);
    provider.post();
    panels.forEach(render);
  };

  const provider: CatalogProvider = new CatalogProvider(() => client, profileName, open, setProfile);
  const timer = setInterval(() => provider.refresh(), REFRESH_MS);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider("repositoryAuditor.catalog", provider, { webviewOptions: { retainContextWhenHidden: true } }),
    { dispose: () => clearInterval(timer) },
    vscode.commands.registerCommand("repositoryAuditor.open", open),
    vscode.commands.registerCommand("repositoryAuditor.search", async (given?: string) => {
      const q = typeof given === "string" ? given : await vscode.window.showInputBox({ prompt: "Search by scanner name or capability", value: provider.query });
      if (q !== undefined) {
        await provider.setQuery(q);
      }
    }),
    vscode.commands.registerCommand("repositoryAuditor.clearSearch", () => provider.setQuery("")),
    vscode.commands.registerCommand("repositoryAuditor.selectProfile", async (given?: string) => {
      const choice = typeof given === "string" ? given : await vscode.window.showQuickPick(PROFILES, { placeHolder: `Current profile: ${profileName()}` });
      if (choice && PROFILES.includes(choice)) {
        await setProfile(choice);
      }
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("repositoryAuditor.registries")) {
        client = makeClient();
        provider.refresh();
      }
    }));
  provider.refresh();
  return { catalog: () => provider.snapshot(), scanWith: (service, uris) => {
    let next = 0;
    return performScan(service, async (_label, many) => (many ? uris : [uris[next++]]));
  } };
}

export function deactivate(): void {}
