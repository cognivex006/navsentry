/** Renders one validated RunResult into JSON, Markdown and SARIF 2.1.0. */
import { CASE_BY_ID } from "../catalog.js";
import type { RunResult } from "../types.js";
export { renderMarkdown, securityResult, groupFindings, ACTION_MARK } from "./markdown.js";

const SARIF_LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" } as const;

export function renderSarif(r: RunResult): object {
  const ruleIds = [...new Set(r.findings.map((f) => f.ruleId))];
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "NavSentry",
            version: r.tool.version,
            informationUri: "https://github.com/cognivex006/navsentry",
            rules: ruleIds.map((id) => {
              const c = CASE_BY_ID.get(id)!;
              return { id, name: c.titleEn.replace(/[^A-Za-z0-9]+/g, ""), shortDescription: { text: c.titleEn }, fullDescription: { text: c.fact }, help: { text: c.fix }, properties: { tags: [...c.cwe, ...c.owasp2025], category: c.category, priority: c.priority } };
            }),
          },
        },
        automationDetails: { id: `navsentry/${r.project}/${r.runId}` },
        invocations: [{ executionSuccessful: r.executionStatus !== "FAILED", startTimeUtc: r.startedAt, endTimeUtc: r.finishedAt }],
        results: r.findings.map((f) => ({
          ruleId: f.ruleId,
          ruleIndex: ruleIds.indexOf(f.ruleId),
          level: SARIF_LEVEL[f.severity],
          message: { text: `${f.title}: ${f.actual[0] ?? ""}` },
          locations: [{ physicalLocation: { artifactLocation: { uri: f.target.replace(/^[A-Z]+ /, "") } } }],
          partialFingerprints: { navsentryFingerprint: f.fingerprint },
          properties: { lifecycle: f.lifecycle, confidence: f.confidence, severity: f.severity },
        })),
      },
    ],
  };
}

export function renderJson(r: RunResult): string {
  return JSON.stringify(r, null, 2) + "\n";
}

/** Structural validation for imported run files (report/compare inputs are untrusted). */
export function validateRunResult(x: unknown): RunResult {
  const o = x as RunResult;
  const ok = !!o && o.schemaVersion === "1" && typeof o.runId === "string" && Array.isArray(o.findings) && Array.isArray(o.coverage) && Array.isArray(o.requests) && Array.isArray(o.checks) && typeof o.executionStatus === "string";
  if (!ok) throw new Error("input is not a NavSentry run result (schemaVersion 1)");
  // 0.1.3 additive fields; 0.1.2 reports without them stay readable (absent coverage is unknown, never PASS).
  if (o.scanMode !== undefined && !["page", "spider", "flow"].includes(o.scanMode)) throw new Error("invalid scanMode");
  if (!["observe", "safe-validate", "active-approved"].includes(o.mode)) throw new Error("invalid safety mode");
  if (o.workspace !== undefined && !["PASS", "FAIL", "NOT_TESTED"].includes(o.workspace.status)) throw new Error("invalid workspace status");
  for (const c of o.coverage) if (!["PASS", "FAIL", "INCONCLUSIVE", "NOT_TESTED", "ERROR"].includes(c.status)) throw new Error("invalid coverage status");
  return o;
}
