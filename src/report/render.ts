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
  if (r.fixtures) {
    // safe-validate (SPEC-0.2.0 §7): fixtures, cleanup, leftovers with the exact manual action, and mutations.
    const fx = r.fixtures;
    out.push("## Fixtures and cleanup", "", `- Marker: \`${fx.marker}\` · Created: ${fx.created} · Cleaned: ${fx.cleaned} · Verified gone: ${fx.verifiedGone} · Non-observe requests: ${fx.mutationsUsed}/${fx.mutationsMax}`, "");
    if (fx.leftovers.length) {
      out.push("**Leftovers: remove these yourself. NavSentry never improvises a delete.**", "", "| Fixture | Id | Status | Reason | Manual action |", "|---|---|---|---|---|");
      for (const x of fx.leftovers) out.push(`| ${esc(x.fixture)} | \`${esc(x.displayId)}\` | ${x.status} | ${esc(x.reason)} | ${esc(x.manualAction)} |`);
      out.push("");
    } else out.push("No leftovers.", "");
    if (fx.pendingFromPreviousRuns?.length) {
      out.push("**Possible leftovers from an interrupted run (reported, nothing deleted):**", "");
      for (const p of fx.pendingFromPreviousRuns) out.push(`- ${esc(p.fixture)} ${p.id ? `\`${esc(p.id)}\`` : "(id unknown)"} · state ${p.state} · marker \`${p.marker}\``);
      out.push("");
    }
    out.push("## Mutations", "", "| Method | Path | Entry | Actor | Status | Body sha256 |", "|---|---|---|---|---|---|");
    for (const x of r.mutations ?? []) out.push(`| ${x.method} | \`${esc(x.path)}\` | ${esc(x.entry)} | ${esc(x.actor)} | ${x.status ?? esc(x.error ?? "—")} | ${x.bodySha256 ? `\`${x.bodySha256.slice(0, 16)}…\`` : "—"} |`);
    out.push("");
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
  if (r.assets) {
    const a = r.assets;
    out.push("## Client assets", "", `Engine: \`${a.engine}\` (detector version ${a.detectorVersion}). Only masked previews are kept; bundles and maps never leave the machine.`, "");
    out.push("| Asset | Actor | Kind | Status | Bytes | Complete | Cached | Facts |", "|---|---|---|---|---|---|---|---|");
    for (const x of [...a.assets, ...a.maps]) out.push(`| \`${esc(x.url)}\` | ${x.actor} | ${x.kind} | ${x.status || "—"} | ${x.bytes} | ${x.complete ? "yes" : `no${x.reason ? ` (${esc(x.reason)})` : ""}`} | ${x.cached ? "yes" : "no"} | ${x.facts} |`);
    if (!a.assets.length && !a.maps.length) out.push("| — | | | | | | | |");
    out.push("", "| Exposure probe | Origin | Result | Detail |", "|---|---|---|---|");
    for (const p of a.probes) out.push(`| \`${p.path}\` | ${esc(p.origin)} | ${p.result} | ${esc(p.detail)} |`);
    if (!a.probes.length) out.push("| — (disabled with checks.disabled NSC-CONF-009) | | | |");
    if (a.cost) out.push("", `Cost: ${a.cost.bytesScannedLocally} bytes scanned locally · ${a.cost.agentVisibleBytes} bytes agent-visible (client-findings.json) · cache hits ${a.cost.cacheHits}/${a.cost.cacheEligible}${a.cost.hitRatio === null ? " (ratio undefined)" : ""}`);
    out.push(`- Client findings: ${a.clientFindings.entries}${a.clientFindings.truncated ? ` (+${a.clientFindings.truncated} not listed)` : ""}`, `- Client libraries: ${a.libraryAdvisories}`);
    if (a.skipped.length) out.push(`- Skipped: ${a.skipped.length} (${[...new Set(a.skipped.map((x) => x.reason.split(":")[0]))].join(", ")})`);
    out.push("");
  }
  if (r.console) {
    const c = r.console;
    out.push("## Browser console", "", `Engine: \`${c.engine}\`. ${c.messages} message(s) inspected (${c.bytes} bytes)${c.dropped ? `, ${c.dropped} not inspected at the capture limit (incomplete)` : ""}. Message text is never kept; previews are masked and templates hash a value-free shape.`, "");
    out.push("| Case | Detector | Level | Source | Preview | Template | Flow step | Basis |", "|---|---|---|---|---|---|---|---|");
    for (const f of c.facts) out.push(`| ${f.caseId} | ${f.detector} | ${esc(f.level)} | \`${esc(f.source)}\` | \`${f.preview}\` | \`${f.template}\` | ${f.flow ? `${esc(f.flow)}/${esc(f.step ?? "")}` : "—"} | ${f.exact ? "exact known value" : "pattern"} |`);
    if (!c.facts.length) out.push("| — | | | | | | | |");
    if (c.observations) out.push("", `- Observations only (development profile): ${c.observations}`);
    out.push("");
  }
  if (r.analyzer) {
    const a = r.analyzer;
    out.push("## Analyzer", "", `- Engine \`${a.engine}\` · page models ${a.pages} (in \`page-models/\`) · incomplete ${a.incomplete} · withheld by the leak scan ${a.withheld}`, `- Free text: ${a.includeText ? "included (titles and headings, redacted, 120 characters; pattern redaction cannot prove free text free of personal data)" : "omitted (default)"}`);
    for (const e of a.extractors) out.push(`- Extractor \`${e.id}\` (${e.source}) sha256 \`${e.sha256.slice(0, 16)}\` — ${e.status}`);
    for (const x of a.refused) out.push(`- Refused \`${esc(x.file)}\`: ${esc(x.reason)}`);
    out.push("");
  }
  if (r.knowledge) {
    const k = r.knowledge;
    out.push("## Knowledge", "", `- Snapshot \`${k.snapshot.version}\` · sha256 \`${k.snapshot.sha256.slice(0, 16)}\` · ${k.snapshot.records} record(s), ${k.snapshot.reviewed} reviewed, ${k.snapshot.stale} stale${k.snapshot.verifiedAt ? ` · oldest verification ${k.snapshot.verifiedAt}` : ""}`, `- ${k.snapshot.note}`, "");
    out.push("### Known vulnerability applicability", "", "| Product (evidence) | Record | Identifiers | Applicability | Case | Caveats |", "|---|---|---|---|---|---|");
    for (const a of k.applicability) out.push(`| ${esc(a.product)} (${a.provenance}) | ${a.recordId ?? "—"} | ${esc((a.identifiers ?? []).join(", ")) || "—"} | **${a.applicability}** | ${a.case} | ${esc(a.caveats.join("; ")) || "—"} |`);
    if (!k.applicability.length) out.push("| — no product version evidence observed | | | | | |");
    out.push("", "### Knowledge gaps / proposed updates", "", "| Gap | Product | Detail |", "|---|---|---|");
    for (const g of k.gaps) out.push(`| ${g.kind} | ${esc(g.product ?? "—")} | ${esc(g.detail)} |`);
    if (!k.gaps.length) out.push("| — | | |");
    if (k.proposals.length) out.push("", `Proposals written to \`.navsentry/knowledge/proposals/\`: ${k.proposals.map((p) => `${p.id} (${p.status})`).join(", ")}`);
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
