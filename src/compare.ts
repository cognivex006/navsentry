/**
 * Before/after comparison. Answers two questions for a remediation:
 *  1. Did the security result improve? (per-case status transitions)
 *  2. Did legitimate callers keep the same response contract? (status, content type,
 *     non-security header set, JSON shape) — the "do not break real users" guarantee.
 */
import type { CheckStatus, FlowRunResult, ResponseContract, RunResult } from "./types.js";

export interface ContractDrift {
  key: string;
  field: keyof ResponseContract;
  before: string;
  after: string;
}

export interface CompareResult {
  fixed: string[];
  regressed: string[];
  unchanged: string[];
  stillFailing: string[];
  contractDrift: ContractDrift[];
  missingInAfter: string[];
  /** Origins differ between the runs; requests are still matched by method, path and actor. */
  originChange?: { before: string[]; after: string[] };
  /** Present when both runs carry flows.json. */
  flows?: FunctionalCompare;
  verdict: "IMPROVED_NO_DRIFT" | "IMPROVED_WITH_DRIFT" | "NO_CHANGE" | "REGRESSED" | "DRIFT_ONLY" | "FUNCTIONAL_REGRESSION";
}

export interface FunctionalCompare {
  regressions: string[];
  fixed: string[];
  notComparable: string[];
  flowSetChanged: boolean;
}

/** Story-level transitions keyed by <flowId>/<stepId>; only steps with identical content are compared. */
export function compareFlows(before: FlowRunResult, after: FlowRunResult): FunctionalCompare {
  const idx = (r: FlowRunResult) => new Map(r.flows.flatMap((f) => f.steps).map((s) => [s.key, s]));
  const b = idx(before), a = idx(after);
  const regressions: string[] = [], fixed: string[] = [], notComparable: string[] = [];
  for (const [k, sb] of b) {
    const sa = a.get(k);
    if (!sa) { notComparable.push(`${k} (missing in after-run)`); continue; }
    if (sa.contentSha256 !== sb.contentSha256) { notComparable.push(`${k} (step changed)`); continue; }
    if (sb.status === "PASS" && (sa.status === "FAIL" || sa.status === "ERROR")) regressions.push(`${k}: PASS → ${sa.status}`);
    else if (sb.status === "FAIL" && sa.status === "PASS") fixed.push(k);
    else if (sb.status !== sa.status && [sb.status, sa.status].some((x) => x === "NOT_TESTED" || x === "INCONCLUSIVE")) notComparable.push(`${k} (${sb.status} → ${sa.status})`);
  }
  return { regressions, fixed, notComparable, flowSetChanged: before.flowSet.sha256 !== after.flowSet.sha256 };
}

/** Requests are matched by method, path + query and actor, so a changed origin (another port or host) is reported once instead of making every request "missing". */
const reqKey = (method: string, url: string, actor: string, transport: string) => {
  let path = url;
  try { const u = new URL(url); path = u.pathname + u.search; } catch { /* keep as is */ }
  return `${method} ${path} [${actor}/${transport}]`;
};

function contracts(r: RunResult): Map<string, ResponseContract> {
  const m = new Map<string, ResponseContract>();
  for (const q of r.requests) {
    // Probe requests carry an Origin header; only plain legitimate requests define the contract.
    // Access-denied probes from flows are expected to change when the fix lands.
    if (!q.contract || q.requestHeaders["origin"] || q.flow?.deniedProbe) continue;
    const k = reqKey(q.method, q.url, q.actor, q.transport);
    if (!m.has(k)) m.set(k, q.contract);
  }
  return m;
}

export function compareRuns(before: RunResult, after: RunResult, flows?: { before: FlowRunResult; after: FlowRunResult }): CompareResult {
  const b = new Map(before.coverage.map((c) => [c.ruleId, c.status]));
  const a = new Map(after.coverage.map((c) => [c.ruleId, c.status]));
  const fixed: string[] = [], regressed: string[] = [], unchanged: string[] = [], stillFailing: string[] = [];
  for (const [id, sb] of b) {
    const sa: CheckStatus = a.get(id) ?? "NOT_TESTED";
    if (sb === "FAIL" && sa === "PASS") fixed.push(id);
    else if (sb === "PASS" && sa === "FAIL") regressed.push(id);
    else if (sb === "FAIL" && sa === "FAIL") stillFailing.push(id);
    else if (sb === "FAIL" && sa !== "PASS") stillFailing.push(`${id} (now ${sa}: not proven fixed)`);
    else unchanged.push(id);
  }
  const cb = contracts(before), ca = contracts(after);
  const drift: ContractDrift[] = [];
  const missing: string[] = [];
  for (const [k, c] of cb) {
    const d = ca.get(k);
    if (!d) { missing.push(k); continue; }
    for (const f of ["status", "contentType", "jsonShapeHash"] as const) {
      if (String(c[f] ?? "") !== String(d[f] ?? "")) drift.push({ key: k, field: f, before: String(c[f] ?? "∅"), after: String(d[f] ?? "∅") });
    }
    const hb = c.headerNames.join(","), ha = d.headerNames.join(",");
    if (hb !== ha) drift.push({ key: k, field: "headerNames", before: hb, after: ha });
  }
  const fc = flows ? compareFlows(flows.before, flows.after) : undefined;
  const verdict: CompareResult["verdict"] = regressed.length ? "REGRESSED" : fc?.regressions.length ? "FUNCTIONAL_REGRESSION" : fixed.length ? (drift.length ? "IMPROVED_WITH_DRIFT" : "IMPROVED_NO_DRIFT") : drift.length ? "DRIFT_ONLY" : "NO_CHANGE";
  const ob = [...before.scope.origins].sort(), oa = [...after.scope.origins].sort();
  const originChange = ob.join(" ") !== oa.join(" ") ? { before: ob, after: oa } : undefined;
  return { fixed, regressed, unchanged, stillFailing, contractDrift: drift, missingInAfter: missing, ...(originChange ? { originChange } : {}), ...(fc ? { flows: fc } : {}), verdict };
}

export function renderCompareMarkdown(c: CompareResult): string {
  const list = (xs: string[]) => (xs.length ? xs.map((x) => `- ${x}`).join("\n") : "- none");
  return [
    `# NavSentry compare — verdict: **${c.verdict}**`, "",
    ...(c.originChange ? [`> Origin changed: ${c.originChange.before.join(", ")} → ${c.originChange.after.join(", ")}. Requests are matched by method, path and actor.`, ""] : []),
    "## Fixed (FAIL → PASS)", list(c.fixed), "",
    "## Regressed (PASS → FAIL)", list(c.regressed), "",
    "## Still failing / not proven fixed", list(c.stillFailing), "",
    "## Legitimate-response contract drift", c.contractDrift.length ? ["| Request | Field | Before | After |", "|---|---|---|---|", ...c.contractDrift.map((d) => `| ${d.key} | ${d.field} | ${d.before} | ${d.after} |`)].join("\n") : "- none (status, content type, non-security headers and JSON shape unchanged)", "",
    "## Requests missing in the after-run", list(c.missingInAfter), "",
    ...(c.flows
      ? ["## User stories (flows)", ...(c.flows.flowSetChanged ? ["> Flows changed between runs; only unchanged steps are compared.", ""] : []),
        "### Functional regressions (PASS → FAIL/ERROR)", list(c.flows.regressions), "", "### Fixed (FAIL → PASS)", list(c.flows.fixed), "", "### Not comparable", list(c.flows.notComparable), ""]
      : []),
  ].join("\n");
}
