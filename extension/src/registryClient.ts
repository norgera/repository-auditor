// Registry discovery with automatic failover. This file does not import vscode, so tests can run it directly.

export interface ServiceMeta {
  id: string;
  name: string;
  description: string;
  capabilities: string[];
  url: string;
  version: string;
  tool: string | null;
  accepts: string[];
  inputMode: "files" | "baseline-target";
  maxBytes: number;
}

export type Source = "primary" | "backup" | "stale";

export interface Catalog {
  services: ServiceMeta[];
  source: Source;
}

export interface Options {
  urls: string[];
  primaryTimeoutMs?: number;
  backupTimeoutMs?: number;
  probeIntervalMs?: number;
}

export class RegistryClient {
  private readonly urls: string[];
  private readonly primaryTimeoutMs: number;
  private readonly backupTimeoutMs: number;
  private readonly probeIntervalMs: number;
  private onBackup = false;
  private lastProbe = 0;
  private probing = false;
  private lastGood: ServiceMeta[] = [];

  constructor(options: Options) {
    this.urls = options.urls.map((u) => u.replace(/\/+$/, ""));
    if (this.urls.length === 0) {
      throw new Error("at least one registry URL is required");
    }
    this.primaryTimeoutMs = options.primaryTimeoutMs ?? 3000;
    this.backupTimeoutMs = options.backupTimeoutMs ?? 2000;
    this.probeIntervalMs = options.probeIntervalMs ?? 30000;
  }

  private async fetchJson(base: string, path: string, timeoutMs: number): Promise<any> {
    const response = await fetch(base + path, { signal: AbortSignal.timeout(timeoutMs) });
    if (!response.ok) {
      throw new Error(`registry returned ${response.status}`);
    }
    return response.json();
  }

  private probePrimary(): void {
    const now = Date.now();
    if (!this.onBackup || this.probing || now - this.lastProbe < this.probeIntervalMs) {
      return;
    }
    this.lastProbe = now;
    this.probing = true;
    this.fetchJson(this.urls[0], "/health", this.backupTimeoutMs)
      .then(() => { this.onBackup = false; })
      .catch(() => undefined)
      .finally(() => { this.probing = false; });
  }

  /** Searches the active registry, then every other one. Falls back to the last catalog, marked stale. */
  async search(query = ""): Promise<Catalog> {
    this.probePrimary();
    const path = `/v1/services?q=${encodeURIComponent(query)}`;
    const order = this.urls.map((_, i) => i);
    if (this.onBackup) {
      order.reverse();
    }
    for (let attempt = 0; attempt < order.length; attempt++) {
      const index = order[attempt];
      try {
        const body = await this.fetchJson(this.urls[index], path, attempt === 0 ? this.primaryTimeoutMs : this.backupTimeoutMs);
        // Change state only on evidence from this call, so a late backup answer cannot undo a successful probe.
        if (index === 0) {
          this.onBackup = false;
        } else if (attempt > 0) {
          this.onBackup = true;
          this.lastProbe = Date.now();
        }
        if (query === "") {
          this.lastGood = body.services;
        }
        return { services: body.services, source: index === 0 ? "primary" : "backup" };
      } catch {
        // try the next registry
      }
    }
    const q = query.toLowerCase();
    const services = this.lastGood.filter((s) => [s.id, s.name, s.description, ...s.capabilities].join(" ").toLowerCase().includes(q));
    return { services, source: "stale" };
  }
}
