// Release profiles. Policy stays on the workstation, and scanners remain stateless.
import type { ScanResponse } from "./scanClient";

export interface Profile {
  failAt: string;
  requiredKeys: string[];
}

export const BUILT_IN: Record<string, Profile> = {
  development: { failAt: "critical", requiredKeys: [] },
  staging: { failAt: "high", requiredKeys: [] },
  production: { failAt: "medium", requiredKeys: [] },
};

export const RANK: Record<string, number> = { info: 0, low: 1, unknown: 2, medium: 2, high: 3, critical: 4 };

export type Verdict = "ready" | "blocked" | "incomplete";

/** Only a complete scan can be ready. Any other status means something went unchecked. */
export function evaluate(response: ScanResponse, profile: Profile): { verdict: Verdict; reason: string } {
  if (response.status !== "complete") {
    return { verdict: "incomplete", reason: `Scan status is ${response.status}: ${response.message}` };
  }
  const threshold = RANK[profile.failAt] ?? RANK.high;
  const blocking = response.findings.filter((f) => (RANK[f.severity] ?? RANK.unknown) >= threshold);
  if (blocking.length > 0) {
    return { verdict: "blocked", reason: `${blocking.length} finding(s) at or above ${profile.failAt}` };
  }
  return { verdict: "ready", reason: response.findings.length ? `No findings at or above ${profile.failAt}` : "No findings" };
}
