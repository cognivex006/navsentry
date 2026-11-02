/** Renders one validated RunResult into JSON, Markdown and SARIF 2.1.0. */
import { CASE_BY_ID } from "../catalog.js";
import type { CheckStatus, RunResult } from "../types.js";

const L = {
  en: { title: "NavSentry Report", summary: "Summary", exec: "Execution status", sec: "Security result", findings: "Findings", coverage: "Coverage matrix", transports: "Transports", incomplete: "Incomplete / limitations", denials: "Requests denied before execution", capture: "Capture", workspace: "Workspace", none: "None", note: "Zero findings does not mean the application is secure. NOT_TESTED, INCONCLUSIVE and ERROR rows are gaps, not passes.", priority: { IMMEDIATE: "Fix immediately", PLANNED: "Planned fix", CAUTION: "Fix with caution (may affect legitimate users)" } },
  th: { title: "รายงาน NavSentry", summary: "สรุป", exec: "สถานะการทำงาน", sec: "ผลด้านความปลอดภัย", findings: "รายการปัญหาที่พบ", coverage: "ตารางความครอบคลุม", transports: "ช่องทางที่ใช้ทดสอบ", incomplete: "ส่วนที่ไม่สมบูรณ์ / ข้อจำกัด", denials: "คำขอที่ถูกปฏิเสธก่อนส่ง", capture: "การเก็บข้อมูลตอบกลับ", workspace: "ความสะอาดของโฟลเดอร์โปรเจกต์", none: "ไม่มี", note: "การไม่พบปัญหาไม่ได้แปลว่าระบบปลอดภัย แถวที่เป็น NOT_TESTED, INCONCLUSIVE และ ERROR คือช่องว่างที่ยังไม่ได้ทดสอบ ไม่ใช่ผ่าน", priority: { IMMEDIATE: "ต้องแก้ทันที", PLANNED: "วางแผนแก้ได้", CAUTION: "แก้แล้วอาจกระทบผู้ใช้จริง ต้องระวัง" } },
} as const;

export function securityResult(r: RunResult): "FINDINGS" | "NO_FINDINGS_IN_TESTED_SCOPE" | "INCOMPLETE" {
  if (r.findings.length) return "FINDINGS";
  if (r.executionStatus !== "COMPLETE" || r.coverage.some((c) => c.status === "ERROR" || c.status === "INCONCLUSIVE")) return "INCOMPLETE";
  return "NO_FINDINGS_IN_TESTED_SCOPE";
}

const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");

export function renderMarkdown(r: RunResult, lang: "en" | "th" = "en"): string {
  const t = L[lang];
  const counts = (s: CheckStatus) => r.coverage.filter((c) => c.status === s).length;
  const out: string[] = [];
  out.push(`# ${t.title} — ${r.project} (${r.environment})`, "");
  out.push(`- Run ID: \`${r.runId}\``, `- Started: ${r.startedAt} · Finished: ${r.finishedAt}`, `- Tool: ${r.tool.name} ${r.tool.version} · Node ${r.tool.node} · ${r.tool.platform}`, `- Mode: \`${r.mode}\`${r.scanMode ? ` · Scan mode: \`${r.scanMode}\`` : ""}${r.profile ? ` · Profile: \`${r.profile}\`` : ""}${r.engine ? ` · Engine: \`${r.engine.used}\`${r.engine.analyze ? " + analyze" : ""}` : ""} · Origins: ${r.scope.origins.map((o) => `\`${o}\``).join(", ")}`,
    ...(r.authorizationReference ? [`- Authorization reference: \`${esc(r.authorizationReference)}\``] : []), `- ${t.exec}: **${r.executionStatus}** · ${t.sec}: **${securityResult(r)}**`, `- Requests: ${r.budget.requestsUsed}/${r.budget.requestsMax} · Denied before execution: ${r.budget.deniedBeforeExecution}`, "");
  out.push(`## ${t.summary}`, "", `| PASS | FAIL | INCONCLUSIVE | ERROR | NOT_TESTED | Findings |`, `|---|---|---|---|---|---|`, `| ${counts("PASS")} | ${counts("FAIL")} | ${counts("INCONCLUSIVE")} | ${counts("ERROR")} | ${counts("NOT_TESTED")} | ${r.findings.length} |`, "", `> ${t.note}`, "");
  out.push(`## ${t.findings}`, "");
  if (!r.findings.length) out.push(t.none, "");
  for (const f of r.findings) {
    out.push(`### ${f.ruleId} — ${f.title}`, "");
    out.push(`- Fingerprint: \`${f.fingerprint}\` · Severity: **${f.severity}** · Confidence: ${f.confidence} · Lifecycle: **${f.lifecycle}**`, `- Priority: **${f.priority}** — ${t.priority[f.priority]}`, `- Target: \`${esc(f.target)}\``, `- OWASP: ${[...f.mappings.owasp2025, ...f.mappings.owasp2021].join("; ") || "—"}`, `- CWE: ${f.mappings.cwe.join(", ") || "—"} · WSTG: ${f.mappings.wstg.join(", ") || "—"} · ASVS 5.0: ${f.mappings.asvs5Chapter.join(", ") || "—"}`, "");
    out.push("**Expected:** " + f.expected, "", "**Observed (redacted):**", ...f.actual.map((a) => `- ${a}`), "");
    out.push("**Reproduce:**", ...f.reproduction.map((a) => `- ${a}`), "", `**Recommendation:** ${f.recommendation}`, "", `**Regression guard:** ${f.regressionGuard}`, "");
    if (f.limitations.length) out.push("**Limitations:**", ...f.limitations.map((a) => `- ${a}`), "");
    out.push(`Agent prompt: see \`docs/cases/CASE-CATALOG.md#${f.ruleId.toLowerCase()}\``, "");
  }
  out.push(`## ${t.coverage}`, "", "| Case | Title | Status | Targets | Reason |", "|---|---|---|---|---|");
  for (const c of r.coverage) out.push(`| ${c.ruleId} | ${esc(CASE_BY_ID.get(c.ruleId)?.titleEn ?? "")} | ${c.status} | ${c.targets} | ${esc(c.reason ?? "")} |`);
  out.push("", `## ${t.transports}`, "", "| Transport | Available | Usable | Version | Reason |", "|---|---|---|---|---|");
  for (const tr of r.transports) out.push(`| ${tr.id} | ${tr.available} | ${tr.usable} | ${tr.version ?? "—"} | ${esc(tr.reason)} |`);
  out.push("", `## ${t.incomplete}`, "");
  out.push(...(r.incompleteReasons.length ? r.incompleteReasons.map((x) => `- ${x}`) : [t.none]), "");
  out.push(`## ${t.denials}`, "");
  out.push(...(r.denials.length ? r.denials.map((d) => `- ${d.method} \`${esc(d.url)}\` — ${d.reason}`) : [t.none]), "");
  if (r.spider) {
    const sp = r.spider;
    out.push("## Coverage by template", "", `Pages fetched: ${sp.pagesFetched} · Skipped: ${sp.skippedTotal}${sp.frontierOverflow ? " · frontier limit reached" : ""}`, "", "> Only fetched representatives are covered. Sampled-out pages are NOT_TESTED and never inherit a PASS; a shape hash is a grouping heuristic, never evidence.", "", "| Origin | Actor | Pattern | Query keys | Representatives | Shape hashes | Mixed shape | Spread | Sampled-out |", "|---|---|---|---|---|---|---|---|---|");
    for (const g of sp.groups) out.push(`| ${esc(g.origin)} | ${g.actor} | \`${esc(g.pattern)}\` | ${esc(g.queryKeys.join(", ")) || "—"} | ${g.representatives.length} | ${g.shapeHashes.map((h) => `\`${h}\``).join(" ") || "—"} | ${g.mixedShape ? "**mixed-shape**" : "no"} | ${g.spread} | ${g.sampledOut} |`);
    out.push("", "### robots.txt", "", "| Origin | Result | Detail | Enforced |", "|---|---|---|---|");
    for (const x of sp.robots) out.push(`| ${esc(x.origin)} | ${x.status} | ${esc(x.status === "policy" ? `group ${x.group}, ${x.rules} rule(s)` : x.reason ?? "")} | ${x.enforced ? "yes (production)" : "recorded only (development)"} |`);
    const reasons = new Map<string, number>();
    for (const k of sp.skipped) reasons.set(k.reason, (reasons.get(k.reason) ?? 0) + 1);
    out.push("", "### Skipped pages", "", ...(reasons.size ? [...reasons].map(([k, n]) => `- ${esc(k)}: ${n}`) : [t.none]));
    if (sp.skippedTotal > sp.skipped.length) out.push(`- (${sp.skippedTotal - sp.skipped.length} more not listed)`);
    out.push("");
  }
  if (r.redirectChains?.length) {
    out.push("## Redirect chains", "", "Every hop was checked by ScopeGate before it was requested.", "");
    for (const c of r.redirectChains) {
      out.push(`- \`${esc(c.start)}\` as ${c.actor}`);
      let prev: string[] | undefined;
      for (const h of c.hops) {
        const changed = prev ? [...h.securityHeaders.filter((x) => !prev!.includes(x)).map((x) => `+${x}`), ...prev.filter((x) => !h.securityHeaders.includes(x)).map((x) => `-${x}`)] : [];
        out.push(`  - ${h.status} \`${esc(h.url)}\`${h.location ? ` → \`${esc(h.location)}\`` : ""} · ${esc(h.decision)}${changed.length ? ` · security headers ${changed.join(" ")}` : ""}`);
        prev = h.securityHeaders;
      }
    }
    out.push("");
  }
  if (r.capture) {
    const c = r.capture;
    out.push(`## ${t.capture}`, "", "| Wire bytes | Decoded bytes | Truncated | Aborted | Partially inspected bodies |", "|---|---|---|---|---|", `| ${c.wireBytes} | ${c.decodedBytes} | ${c.truncated} | ${c.aborted} | ${c.partialBodies} |`, "");
  }
  if (r.workspace) {
    const w = r.workspace;
    out.push(`## ${t.workspace}`, "", `- Leftover check: **${w.status}**${w.reason ? ` — ${esc(w.reason)}` : ""} · Cleanup: **${w.cleanup}**${w.cleanupReason ? ` (${esc(w.cleanupReason)})` : ""} · Report files written: ${w.promoted}`);
    for (const [k, v] of [["Created", w.created], ["Modified", w.modified], ["Deleted", w.deleted]] as const) if (v.length) out.push(`- ${k}: ${v.map((x) => `\`${esc(x)}\``).join(", ")}`);
    out.push(...w.limitations.map((x) => `- Limitation: ${x}`), "");
  }
  return out.join("\n");
}

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
