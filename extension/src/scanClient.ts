// Calls one scanner directly. A reply that breaks the contract is reported as an error, never as results.

export const STATUSES = ["complete", "partial", "unsupported", "too_large", "timeout", "error"] as const;
export type Status = (typeof STATUSES)[number];

export interface Finding {
  rule: string;
  severity: string;
  file: string;
  location: string;
  message: string;
  remediation?: string | null;
}

export interface ScanResponse {
  service: string;
  tool: string | null;
  toolVersion: string | null;
  status: Status;
  message: string;
  findings: Finding[];
  skipped: string[];
}

export interface ScanFile {
  path: string;
  content: Uint8Array;
}

function failure(service: string, message: string): ScanResponse {
  return { service, tool: null, toolVersion: null, status: "error", message, findings: [], skipped: [] };
}

function isValid(body: any): body is ScanResponse {
  return !!body && STATUSES.includes(body.status) && typeof body.message === "string" && Array.isArray(body.skipped)
    && Array.isArray(body.findings)
    && body.findings.every((f: any) => f && ["rule", "severity", "file", "location", "message"].every((k) => typeof f[k] === "string"));
}

export async function runScan(service: { id: string; url: string }, files: ScanFile[], options: object, timeoutMs = 25000): Promise<ScanResponse> {
  const payload = { files: files.map((f) => ({ path: f.path, content: Buffer.from(f.content).toString("base64") })), options };
  try {
    const response = await fetch(`${service.url}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const body = await response.json();
    return isValid(body) ? body : failure(service.id, "The scanner returned a response that violates the contract.");
  } catch (e: any) {
    if (e?.name === "TimeoutError") {
      return { ...failure(service.id, "The scanner did not answer in time."), status: "timeout" };
    }
    return failure(service.id, "The scanner is unavailable. The catalog will refresh.");
  }
}
