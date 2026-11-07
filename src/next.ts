/**
 * `navsentry next` (SPEC-0.3.0 §3.2): what to do after a run, read from the run's own files.
 * Zero network. It lists the actions by level, the gaps, and the next commands with whether each
 * one sends traffic, so an agent can continue without a person copying results between tools.
 * Suggestions are commands only; they never approve flows, edit manifests or answer for the owner.
 */
import { CASE_BY_ID } from "./catalog.js";
import { groupFindings } from "./report/markdown.js";
import type { ActionLevel } from "./fixes.js";
import type { FlowRunResult, RunResult } from "./types.js";

export interface NextAction { level: ActionLevel; caseId: string; title: string; targets: number; fix: string }
export interface NextSuggestion { command: string; why: string; network: boolean; ownerOnly?: boolean }
export interface NextResult {
  kind: "navsentry-next";
  runId: string;
  executionStatus: RunResult["executionStatus"];
  securityResult: "FINDINGS" | "NO_FINDINGS_IN_TESTED_SCOPE" | "INCOMPLETE";
  counts: Record<ActionLevel, number>;
  actions: NextAction[];
  gaps: { notTested: number; inconclusive: number; incomplete: string[]; sampledOut: number; flowsIncomplete: string[] };
  reports: { markdown: string; html: string };
  suggestions: NextSuggestion[];
}

/** Paths inside commands are quoted only when needed, so they can be pasted into a shell. */
const q = (p: string) => (/^[\w./:\\-]+$/.test(p) ? p : `"${p.replace(/"/g, '\\"')}"`);

export function nextSteps(run: RunResult, flowRun: FlowRunResult | undefined, runDir: string, securityResult: NextResult["securityResult"]): NextResult {
  const groups = groupFindings(run);
  const counts: Record<ActionLevel, number> = { IMMEDIATE: 0, CAUTION: 0, PLANNED: 0, OPTIONAL: 0, INFO: 0 };
  for (const g of groups) counts[g.level]++;
  const actions = groups.map((g) => ({ level: g.level, caseId: g.id, title: g.items[0]!.title, targets: g.items.length, fix: g.items[0]!.recommendation }));
  const sep = runDir.includes("\\") ? "\\" : "/";
  const join = (...xs: string[]) => xs.join(sep);
  const flowsIncomplete = (flowRun?.flows ?? []).filter((f) => f.status === "INCOMPLETE" || f.status === "NOT_TESTED").map((f) => f.id);
  const s: NextSuggestion[] = [];
  const dev = run.profile === "development";
  if (groups.length) {
    s.push({ command: `navsentry compare --before ${q(runDir)} --after <new run dir>`, why: "After the fix is deployed, run the same scan again into a new folder, then compare. Only an after-run proves a fix.", network: false });
  }
  if (run.scanMode !== "spider" && !flowRun) s.push({ command: `navsentry scan --deep --out <new run dir>`, why: "Only the seed pages were scanned. --deep follows links, samples pages by template and builds page models.", network: true });
  if (run.spider && run.spider.groups.some((g) => g.sampledOut > 0)) s.push({ command: "navsentry scan --deep --out <new run dir>", why: "Some pages were sampled out and are NOT_TESTED. Raise safety.representatives_per_pattern in the manifest (owner decision) to cover more of each template.", network: true, ownerOnly: true });
  if (!flowRun) s.push({ command: `navsentry flow analyze --from-run ${q(join(runDir, "run.json"))} --out navsentry/flows/drafts`, why: "Draft story flows (test cases) from this run. Access-control checks need flows with declared expectations. Zero network.", network: false });
  if (flowRun?.flows.some((f) => f.review.status === "draft")) s.push({ command: "navsentry flow approve --flows <file> --by <owner>", why: "Some flows are drafts; their findings stay SUSPECTED. Only the owner approves a flow.", network: false, ownerOnly: true });
  if (flowsIncomplete.length && run.engine?.used !== "playwright") s.push({ command: "navsentry scan --mode flow --flows <flows dir> --engine playwright --out <new run dir>", why: `E2E flows with UI steps are INCOMPLETE on the http engine (${flowsIncomplete.join(", ")}). The playwright engine runs them (development profile, Chromium headless shell installed).`, network: true });
  if (dev) s.push({ command: `navsentry browse start --url ${run.scope.origins[0] ?? "<origin>"}/ --out <new run dir>`, why: "Explore pages and forms the crawl did not reach with the visual driver. Needs transports.visual_computer_use: true and the owner's consent to screenshots.", network: true });
  return {
    kind: "navsentry-next",
    runId: run.runId,
    executionStatus: run.executionStatus,
    securityResult,
    counts,
    actions,
    gaps: {
      notTested: run.coverage.filter((c) => c.status === "NOT_TESTED").length,
      inconclusive: run.coverage.filter((c) => c.status === "INCONCLUSIVE" || c.status === "ERROR").length,
      incomplete: run.incompleteReasons,
      sampledOut: run.spider?.groups.reduce((n, g) => n + g.sampledOut, 0) ?? 0,
      flowsIncomplete,
    },
    reports: { markdown: join(runDir, "REPORT.md"), html: join(runDir, "REPORT.html") },
    suggestions: s,
  };
}

export function renderNext(n: NextResult): string {
  const out = [`execution=${n.executionStatus} security=${n.securityResult} IMMEDIATE=${n.counts.IMMEDIATE} CAUTION=${n.counts.CAUTION} PLANNED=${n.counts.PLANNED} OPTIONAL=${n.counts.OPTIONAL} INFO=${n.counts.INFO}`, ""];
  if (n.actions.length) {
    out.push("Fix first:");
    for (const a of n.actions.filter((x) => x.level === "IMMEDIATE" || x.level === "CAUTION")) out.push(`  ${a.level.padEnd(9)} ${a.caseId} — ${a.title} (${a.targets} target${a.targets === 1 ? "" : "s"})`);
    out.push("");
  }
  out.push(`Gaps: ${n.gaps.notTested} NOT_TESTED, ${n.gaps.inconclusive} INCONCLUSIVE/ERROR${n.gaps.sampledOut ? `, ${n.gaps.sampledOut} sampled-out page(s)` : ""}${n.gaps.flowsIncomplete.length ? `, incomplete flows: ${n.gaps.flowsIncomplete.join(", ")}` : ""}`);
  for (const r of n.gaps.incomplete) out.push(`  - ${r}`);
  out.push("", "Next:");
  for (const x of n.suggestions) out.push(`  ${x.command}`, `      ${x.why}${x.network ? " [sends traffic]" : " [no network]"}${x.ownerOnly ? " [owner decision]" : ""}`);
  out.push("", `REPORT: ${n.reports.markdown}`, `HTML: ${n.reports.html}`);
  return out.join("\n");
}

/** Case title lookup for callers that only have an ID. */
export const caseTitle = (id: string) => CASE_BY_ID.get(id)?.titleEn ?? id;
