/**
 * DevSift correlation adapter (M4, SPEC-0.4.0 D3: read files only).
 *
 * Reads a DevSift report file (`urn:devsift:report:1`, schema_version "1") that the user hands over and lists
 * which of its source-code cases may relate to which NavSentry runtime findings, by a fixed rule table.
 * It never runs DevSift, installs nothing and contacts no service. Any other report version is refused.
 * A correlation is a lead for a person to check, never proof: it confirms nothing and changes no finding.
 * Report content is untrusted data: only IDs, enums, the file path and line are read, never code or prompts.
 */
import type { RunResult } from "./types.js";

export const DEVSIFT_REPORT_VERSION = "1";
export const MAX_DEVSIFT_BYTES = 16 * 1024 * 1024;

/**
 * DevSift rule → NavSentry cases whose runtime symptom the code pattern can cause. Rules with no runtime
 * symptom NavSentry observes (e.g. SEC002 disabled TLS validation in a client, LOG002 swallowed exceptions)
 * are absent on purpose.
 */
export const DEVSIFT_RULE_MAP: Readonly<Record<string, readonly string[]>> = {
  SEC001: ["NSC-INFO-006"], // logging secrets/PII → secrets in the browser console
  SEC003: ["NSC-INJ-001"], // dynamic SQL with untrusted input → SQL injection
  CFG003: ["NSC-AUTH-001", "NSC-INFO-007", "NSC-CRYPT-005"], // secret in committed config
  HC002: ["NSC-AUTH-001", "NSC-INFO-007", "NSC-CRYPT-005"], // credential/API key/token literal
  LOG001: ["NSC-CONF-005", "NSC-INFO-006"], // debug printing in runtime paths
  HC001: ["NSC-INFO-003"], // literal URL/IP/hostname → internal address disclosure
};

export interface DevsiftCase { caseId: string; ruleId: string; severity: string; confidence: string; path?: string; line?: number }
export interface Correlation { navsentry: { ruleId: string; fingerprint: string; target: string }; devsift: DevsiftCase }
export interface CorrelationResult {
  kind: "navsentry-devsift-correlation";
  schemaVersion: "1";
  runId: string;
  devsift: { complete: boolean; status: string; cases: number; unmappedRules: string[] };
  correlations: Correlation[];
  limitations: string[];
}

export const CORRELATION_LIMITATIONS = [
  "A correlation is a lead, not proof: it pairs a code pattern with a runtime finding of a related case by a fixed rule table",
  "It does not check that the code path serves the URL in the finding; a person must confirm each pair",
  "Only DevSift report schema version 1 is read; DevSift is never run",
];

export class DevsiftError extends Error {}

const str = (v: unknown, max = 4096): string | undefined => (typeof v === "string" && v.length <= max ? v : undefined);

/** Structural check of the fields this adapter reads; everything else in the report is ignored. */
export function parseDevsiftReport(text: string): { complete: boolean; status: string; cases: DevsiftCase[] } {
  if (Buffer.byteLength(text) > MAX_DEVSIFT_BYTES) throw new DevsiftError(`DevSift report larger than ${MAX_DEVSIFT_BYTES} bytes`);
  let j: Record<string, unknown>;
  try { j = JSON.parse(text) as Record<string, unknown>; } catch { throw new DevsiftError("DevSift report is not valid JSON"); }
  if (j?.tool !== "devsift" || j.schema_version !== DEVSIFT_REPORT_VERSION) throw new DevsiftError(`not a DevSift report v${DEVSIFT_REPORT_VERSION} (unsupported versions are refused, never guessed)`);
  if (typeof j.complete !== "boolean" || !["clean", "enforced", "incomplete"].includes(j.status as string) || !Array.isArray(j.cases) || j.cases.length > 1000) throw new DevsiftError("DevSift report v1 is malformed");
  const cases: DevsiftCase[] = [];
  for (const c of j.cases as Record<string, unknown>[]) {
    const caseId = str(c?.case_id, 128), ruleId = str(c?.rule_id, 8);
    if (!caseId || !ruleId || !/^[A-Z]{2,3}[0-9]{3}$/.test(ruleId)) throw new DevsiftError("DevSift case without a valid case_id or rule_id");
    const loc = (c.source as { location?: { path?: unknown; region?: { start_line?: unknown } } } | undefined)?.location;
    const path = str(loc?.path);
    const line = typeof loc?.region?.start_line === "number" ? loc.region.start_line : undefined;
    cases.push({ caseId, ruleId, severity: str(c.severity, 20) ?? "unknown", confidence: str(c.confidence, 20) ?? "unknown", ...(path ? { path } : {}), ...(line !== undefined ? { line } : {}) });
  }
  return { complete: j.complete, status: j.status as string, cases };
}

export function correlate(run: RunResult, report: ReturnType<typeof parseDevsiftReport>): CorrelationResult {
  const out: Correlation[] = [];
  const unmapped = new Set<string>();
  for (const c of report.cases) {
    const cases = DEVSIFT_RULE_MAP[c.ruleId];
    if (!cases) { unmapped.add(c.ruleId); continue; }
    for (const f of run.findings) if (cases.includes(f.ruleId)) out.push({ navsentry: { ruleId: f.ruleId, fingerprint: f.fingerprint, target: f.target }, devsift: c });
  }
  return {
    kind: "navsentry-devsift-correlation", schemaVersion: "1", runId: run.runId,
    devsift: { complete: report.complete, status: report.status, cases: report.cases.length, unmappedRules: [...unmapped].sort() },
    correlations: out,
    limitations: [...CORRELATION_LIMITATIONS, ...(report.complete ? [] : ["The DevSift report says it is incomplete; missing cases cannot be correlated"])],
  };
}

export function renderCorrelation(r: CorrelationResult): string {
  const lines = [`# DevSift correlation for run ${r.runId}`, "", `DevSift report: status ${r.devsift.status}, ${r.devsift.cases} case(s), complete=${r.devsift.complete}.`, ""];
  if (!r.correlations.length) lines.push("No correlations: no DevSift case maps to a case NavSentry found.");
  else {
    lines.push("| NavSentry finding | Target | DevSift case | Rule | Location | Severity |", "|---|---|---|---|---|---|");
    const cell = (s: string) => s.replace(/[|\r\n`]/g, " ");
    for (const c of r.correlations) lines.push(`| ${c.navsentry.ruleId} | ${cell(c.navsentry.target)} | ${cell(c.devsift.caseId)} | ${c.devsift.ruleId} | ${c.devsift.path ? cell(c.devsift.path) + (c.devsift.line ? `:${c.devsift.line}` : "") : "—"} | ${cell(c.devsift.severity)} |`);
  }
  if (r.devsift.unmappedRules.length) lines.push("", `DevSift rules with no runtime counterpart in NavSentry: ${r.devsift.unmappedRules.join(", ")}.`);
  lines.push("", "Limitations:", ...r.limitations.map((l) => `- ${l}`));
  return lines.join("\n");
}
