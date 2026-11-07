/**
 * REPORT.md (SPEC-0.3.0 §4.1, §4.2). Every report has the same twelve sections in the same
 * order; a section without data says so. Findings are grouped into one card per case, with the
 * fix, before/after examples, recheck and acceptance criteria inline, so the report can be acted
 * on without NavSentry's own documentation.
 */
import { CASE_BY_ID } from "../catalog.js";
import { ACTION_ORDER, FIXES, STACK_LABEL, actionLevel, type ActionLevel } from "../fixes.js";
import { SNAPSHOT } from "../knowledge/advisories.js";
import type { CheckStatus, Finding, RunResult } from "../types.js";

const L = {
  en: {
    title: "NavSentry Report", summary: "Summary", exec: "Execution status", sec: "Security result", findings: "Findings",
    verification: "Fix verification", known: "Known vulnerabilities", coverage: "Coverage", limits: "Not tested and limitations",
    transports: "Transports and engine", denials: "Requests refused before sending", redirects: "Redirect chains", assets: "Client assets and browser",
    kgaps: "Knowledge gaps", details: "Run details", capture: "Capture", workspace: "Workspace", none: "None.",
    note: "Zero findings does not mean the application is secure. NOT_TESTED, INCONCLUSIVE and ERROR rows are gaps, not passes.",
    noFindings: "No findings in tested scope. This is not proof of security.", doFirst: "What to do first",
    noVerification: "No previous run compared. After a fix, run the same scan again and use `navsentry compare --before <dir> --after <dir>`.",
    noKnown: "No product versions observed.", notSpider: "Not a spider run: only the requested pages were scanned.", noAssets: "Not scanned in this mode.",
    noConsole: "Not captured (no browser engine in this run).", noAnalyzer: "Not run (add `--analyze`).", noFixtures: "Not used (observe mode).",
    level: "Action", severity: "Severity", targets: "Affected targets", why: "Why it matters", observed: "Observed (redacted)", expected: "Expected",
    reproduce: "How to reproduce", fix: "How to fix", examples: "Fix examples (reviewed examples; NavSentry does not execute them)",
    before: "Before", after: "After", recheck: "How to recheck", rerun: "Run the same NavSentry scan again and compare it with this run.",
    accepted: "Fixed when", guard: "Must not break", limitations: "Limitations", refs: "References", leftovers: "test object(s) were left behind. See Run details for the exact manual action.",
    notTested: "NOT_TESTED cases",
    action: { IMMEDIATE: "Fix now", CAUTION: "Fix carefully: may affect legitimate users", PLANNED: "Schedule the fix", OPTIONAL: "Hardening: may be skipped with a recorded reason", INFO: "Observation only: no action needed" },
  },
  th: {
    title: "รายงาน NavSentry", summary: "สรุป", exec: "สถานะการทำงาน", sec: "ผลด้านความปลอดภัย", findings: "ปัญหาที่พบ",
    verification: "การตรวจผลการแก้ไข", known: "ช่องโหว่ที่รู้จัก (CVE)", coverage: "ความครอบคลุม", limits: "สิ่งที่ยังไม่ได้ทดสอบและข้อจำกัด",
    transports: "ช่องทางและ engine ที่ใช้ทดสอบ", denials: "คำขอที่ถูกปฏิเสธก่อนส่ง", redirects: "Redirect chains", assets: "ไฟล์ฝั่ง client และเบราว์เซอร์",
    kgaps: "ช่องว่างของฐานความรู้", details: "รายละเอียดการรัน", capture: "การเก็บข้อมูลตอบกลับ", workspace: "ความสะอาดของโฟลเดอร์โปรเจกต์", none: "ไม่มี",
    note: "การไม่พบปัญหาไม่ได้แปลว่าระบบปลอดภัย แถวที่เป็น NOT_TESTED, INCONCLUSIVE และ ERROR คือช่องว่างที่ยังไม่ได้ทดสอบ ไม่ใช่ผ่าน",
    noFindings: "ไม่พบปัญหาในขอบเขตที่ทดสอบ ซึ่งไม่ได้พิสูจน์ว่าระบบปลอดภัย", doFirst: "ควรทำอะไรก่อน",
    noVerification: "ยังไม่ได้เทียบกับการรันครั้งก่อน หลังแก้ไขให้รันซ้ำแล้วใช้ `navsentry compare --before <dir> --after <dir>`",
    noKnown: "ไม่พบข้อมูลเวอร์ชันของผลิตภัณฑ์", notSpider: "ไม่ได้รันแบบ spider สแกนเฉพาะหน้าที่ระบุ", noAssets: "ไม่ได้สแกนในโหมดนี้",
    noConsole: "ไม่ได้เก็บ (การรันนี้ไม่มีเบราว์เซอร์)", noAnalyzer: "ไม่ได้รัน (เพิ่ม `--analyze`)", noFixtures: "ไม่ได้ใช้ (โหมด observe)",
    level: "ระดับ", severity: "ความรุนแรง", targets: "จุดที่พบ", why: "ทำไมจึงสำคัญ", observed: "สิ่งที่พบ (ปิดข้อมูลลับแล้ว)", expected: "สิ่งที่ควรเป็น",
    reproduce: "วิธีทำซ้ำ", fix: "วิธีแก้", examples: "ตัวอย่างการแก้ (ตัวอย่างที่ตรวจทานแล้ว NavSentry ไม่ได้รันโค้ดเหล่านี้)",
    before: "ก่อนแก้", after: "หลังแก้", recheck: "วิธีตรวจซ้ำ", rerun: "รัน NavSentry แบบเดิมซ้ำ แล้วเทียบกับการรันนี้",
    accepted: "ถือว่าแก้แล้วเมื่อ", guard: "สิ่งที่ต้องไม่พัง", limitations: "ข้อจำกัด", refs: "อ้างอิง", leftovers: "รายการทดสอบค้างอยู่ ดูวิธีลบเองในหัวข้อรายละเอียดการรัน",
    notTested: "เคสที่ยังไม่ได้ทดสอบ (NOT_TESTED)",
    action: { IMMEDIATE: "ต้องแก้ทันที", CAUTION: "แก้อย่างระวัง อาจกระทบผู้ใช้จริง", PLANNED: "วางแผนแก้", OPTIONAL: "การเสริมความแข็งแรง ข้ามได้ถ้าบันทึกเหตุผล", INFO: "ข้อสังเกต ไม่ต้องทำอะไร" },
  },
} as const;

/** Colour markers for Markdown viewers; the HTML report adds CSS colours. */
export const ACTION_MARK: Record<ActionLevel, string> = { IMMEDIATE: "🔴", CAUTION: "🟠", PLANNED: "🟡", OPTIONAL: "🔵", INFO: "⚪" };

export function securityResult(r: RunResult): "FINDINGS" | "NO_FINDINGS_IN_TESTED_SCOPE" | "INCOMPLETE" {
  if (r.findings.length) return "FINDINGS";
  if (r.executionStatus !== "COMPLETE" || r.coverage.some((c) => c.status === "ERROR" || c.status === "INCONCLUSIVE")) return "INCOMPLETE";
  return "NO_FINDINGS_IN_TESTED_SCOPE";
}

const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
const fence = (lang: string, code: string) => { const f = code.includes("```") ? "````" : "```"; return [f + lang, ...code.split("\n"), f]; };
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export interface FindingGroup { id: string; level: ActionLevel; items: Finding[] }

/** One card per case, since the same fix applies to every affected target. */
export function groupFindings(r: RunResult): FindingGroup[] {
  const by = new Map<string, Finding[]>();
  for (const f of r.findings) by.set(f.ruleId, [...(by.get(f.ruleId) ?? []), f]);
  return [...by].map(([id, items]) => ({ id, items, level: actionLevel(items[0]!.severity, items[0]!.priority) }))
    .sort((a, b) => ACTION_ORDER.indexOf(a.level) - ACTION_ORDER.indexOf(b.level) || (SEV_RANK[a.items[0]!.severity] ?? 9) - (SEV_RANK[b.items[0]!.severity] ?? 9) || a.id.localeCompare(b.id));
}

export function renderMarkdown(r: RunResult, lang: "en" | "th" = "en"): string {
  const t = L[lang];
  const counts = (s: CheckStatus) => r.coverage.filter((c) => c.status === s).length;
  const groups = groupFindings(r);
  const out: string[] = [];
  out.push(`# ${t.title} — ${r.project} (${r.environment})`, "");
  out.push(`- Run ID: \`${r.runId}\``, `- Started: ${r.startedAt} · Finished: ${r.finishedAt}`, `- Tool: ${r.tool.name} ${r.tool.version} · Node ${r.tool.node} · ${r.tool.platform}`, `- Mode: \`${r.mode}\`${r.scanMode ? ` · Scan mode: \`${r.scanMode}\`` : ""}${r.profile ? ` · Profile: \`${r.profile}\`` : ""}${r.engine ? ` · Engine: \`${r.engine.used}\`${r.engine.analyze ? " + analyze" : ""}` : ""} · Origins: ${r.scope.origins.map((o) => `\`${o}\``).join(", ")}`,
    ...(r.authorizationReference ? [`- Authorization reference: \`${esc(r.authorizationReference)}\``] : []), `- ${t.exec}: **${r.executionStatus}** · ${t.sec}: **${securityResult(r)}**`, `- Requests: ${r.budget.requestsUsed}/${r.budget.requestsMax} · Denied before execution: ${r.budget.deniedBeforeExecution}`, "");

  // 1. Summary
  out.push(`## ${t.summary}`, "");
  out.push(`| ${ACTION_ORDER.map((a) => `${ACTION_MARK[a]} ${a}`).join(" | ")} |`, `|${ACTION_ORDER.map(() => "---").join("|")}|`, `| ${ACTION_ORDER.map((a) => groups.filter((g) => g.level === a).length).join(" | ")} |`, "");
  out.push("| PASS | FAIL | INCONCLUSIVE | ERROR | NOT_TESTED | Findings |", "|---|---|---|---|---|---|", `| ${counts("PASS")} | ${counts("FAIL")} | ${counts("INCONCLUSIVE")} | ${counts("ERROR")} | ${counts("NOT_TESTED")} | ${r.findings.length} |`, "");
  if (r.fixtures?.leftovers.length) out.push(`> **${r.fixtures.leftovers.length} ${t.leftovers}**`, "");
  const first = groups.filter((g) => g.level === "IMMEDIATE" || g.level === "CAUTION");
  if (first.length) out.push(`**${t.doFirst}:**`, "", ...first.map((g) => `- ${ACTION_MARK[g.level]} ${g.level} · ${g.id} — ${g.items[0]!.title} (${g.items.length})`), "");
  out.push(`> ${t.note}`, "");

  // 2. Findings
  out.push(`## ${t.findings}`, "");
  if (!groups.length) out.push(t.noFindings, "");
  for (const level of ACTION_ORDER) {
    const gs = groups.filter((g) => g.level === level);
    if (!gs.length) continue;
    out.push(`### ${ACTION_MARK[level]} ${level} — ${t.action[level]}`, "");
    for (const g of gs) {
      const f = g.items[0]!;
      const c = CASE_BY_ID.get(g.id);
      out.push(`#### ${ACTION_MARK[level]} ${g.id} — ${f.title}`, "");
      out.push(`| ${t.level} | ${t.severity} | Category | ${t.targets} |`, "|---|---|---|---|", `| **${level}** | **${f.severity}** | ${esc(f.category)} | ${g.items.length} |`, "");
      if (c) out.push(`**${t.why}:** ${c.fact}`, "");
      out.push(`**${t.expected}:** ${f.expected}`, "", `**${t.observed}:**`, "", "| Target | Confidence | Lifecycle | Observed |", "|---|---|---|---|");
      for (const x of g.items) out.push(`| \`${esc(x.target)}\` | ${x.confidence} | ${x.lifecycle} | ${esc(x.actual.join("; "))} |`);
      out.push("", `**${t.reproduce}:**`, "", ...f.reproduction.map((a) => `- ${a}`), "");
      out.push(`**${t.fix}:** ${f.recommendation}`, "");
      const snippets = FIXES[g.id] ?? [];
      if (snippets.length) {
        out.push(`**${t.examples}:**`, "");
        for (const sn of snippets) {
          out.push(`- **${STACK_LABEL[sn.stack]}**${sn.verifiedAgainst ? ` (verified against ${sn.verifiedAgainst})` : ""}`, "", `  ${t.before}:`, "", ...fence(sn.lang, sn.before).map((l) => `  ${l}`), "", `  ${t.after}:`, "", ...fence(sn.lang, sn.after).map((l) => `  ${l}`), "");
          if (sn.note) out.push(`  ${sn.note}`, "");
        }
      }
      if (c?.webRecheck.length) out.push(`**${t.recheck}:**`, "", ...c.webRecheck.map((a) => `- ${a}`), `- ${t.rerun}`, "");
      if (c?.acceptance.length) out.push(`**${t.accepted}:**`, "", ...c.acceptance.map((a) => `- ${a}`), "");
      out.push(`**${t.guard}:** ${f.regressionGuard}`, "");
      const lim = [...new Set(g.items.flatMap((x) => x.limitations))];
      if (lim.length) out.push(`**${t.limitations}:**`, "", ...lim.map((a) => `- ${a}`), "");
      out.push(`${t.refs}: OWASP ${[...f.mappings.owasp2025, ...f.mappings.owasp2021].join("; ") || "—"} · CWE ${f.mappings.cwe.join(", ") || "—"} · WSTG ${f.mappings.wstg.join(", ") || "—"} · ASVS 5.0 ${f.mappings.asvs5Chapter.join(", ") || "—"}`, "", `Fingerprints: ${g.items.map((x) => `\`${x.fingerprint}\``).join(" ")}`, "");
    }
  }

  // 3. Fix verification
  out.push(`## ${t.verification}`, "", t.noVerification, "");

  // 4. Known vulnerabilities
  out.push(`## ${t.known}`, "");
  const k = r.knowledge;
  if (k) {
    out.push(`- Snapshot \`${k.snapshot.version}\` · sha256 \`${k.snapshot.sha256.slice(0, 16)}\` · ${k.snapshot.records} record(s), ${k.snapshot.reviewed} reviewed, ${k.snapshot.stale} stale${k.snapshot.verifiedAt ? ` · oldest verification ${k.snapshot.verifiedAt}` : ""}`, `- ${k.snapshot.note}`, "");
    out.push("### Known vulnerability applicability", "", `| Product (evidence) | Record | Identifiers | ${t.severity} (source) | Applicability | Case | Caveats |`, "|---|---|---|---|---|---|---|");
    for (const a of k.applicability) {
      const rec = a.recordId ? SNAPSHOT.records.find((x) => x.id === a.recordId) : undefined;
      const sv = rec?.severity ? `${rec.severity.score ?? "—"}${rec.severity.vector ? ` ${rec.severity.vector}` : ""} (${rec.severity.source})` : "—";
      out.push(`| ${esc(a.product)} (${a.provenance}) | ${a.recordId ?? "—"} | ${esc((a.identifiers ?? []).join(", ")) || "—"} | ${esc(sv)} | **${a.applicability}** | ${a.case} | ${esc(a.caveats.join("; ")) || "—"} |`);
    }
    if (!k.applicability.length) out.push(`| — ${t.noKnown} | | | | | | |`);
    out.push("");
  } else out.push(t.noKnown, "");

  // 5. Coverage
  out.push(`## ${t.coverage}`, "", "| Case | Title | Status | Targets | Reason |", "|---|---|---|---|---|");
  for (const c of r.coverage) out.push(`| ${c.ruleId} | ${esc(CASE_BY_ID.get(c.ruleId)?.titleEn ?? "")} | ${c.status} | ${c.targets} | ${esc(c.reason ?? "")} |`);
  out.push("", "### Coverage by template", "");
  if (r.spider) {
    const sp = r.spider;
    out.push(`Pages fetched: ${sp.pagesFetched} · Skipped: ${sp.skippedTotal}${sp.frontierOverflow ? " · frontier limit reached" : ""}`, "", "> Only fetched representatives are covered. Sampled-out pages are NOT_TESTED and never inherit a PASS; a shape hash is a grouping heuristic, never evidence.", "", "| Origin | Actor | Pattern | Query keys | Representatives | Shape hashes | Mixed shape | Spread | Sampled-out |", "|---|---|---|---|---|---|---|---|---|");
    for (const g of sp.groups) out.push(`| ${esc(g.origin)} | ${g.actor} | \`${esc(g.pattern)}\` | ${esc(g.queryKeys.join(", ")) || "—"} | ${g.representatives.length} | ${g.shapeHashes.map((h) => `\`${h}\``).join(" ") || "—"} | ${g.mixedShape ? "**mixed-shape**" : "no"} | ${g.spread} | ${g.sampledOut} |`);
    out.push("", "#### robots.txt", "", "| Origin | Result | Detail | Enforced |", "|---|---|---|---|");
    for (const x of sp.robots) out.push(`| ${esc(x.origin)} | ${x.status} | ${esc(x.status === "policy" ? `group ${x.group}, ${x.rules} rule(s)` : x.reason ?? "")} | ${x.enforced ? "yes (production)" : "recorded only (development)"} |`);
    const reasons = new Map<string, number>();
    for (const s of sp.skipped) reasons.set(s.reason, (reasons.get(s.reason) ?? 0) + 1);
    out.push("", "#### Skipped pages", "", ...(reasons.size ? [...reasons].map(([x, n]) => `- ${esc(x)}: ${n}`) : [t.none]));
    if (sp.skippedTotal > sp.skipped.length) out.push(`- (${sp.skippedTotal - sp.skipped.length} more not listed)`);
    out.push("");
  } else out.push(t.notSpider, "");

  // 6. Not tested and limitations
  out.push(`## ${t.limits}`, "", ...(r.incompleteReasons.length ? r.incompleteReasons.map((x) => `- ${x}`) : [t.none]), "", `- ${t.notTested}: ${counts("NOT_TESTED")} (${t.coverage})`, "");

  // 7. Transports and engine
  out.push(`## ${t.transports}`, "", "| Transport | Available | Usable | Version | Reason |", "|---|---|---|---|---|");
  for (const tr of r.transports) out.push(`| ${tr.id} | ${tr.available} | ${tr.usable} | ${tr.version ?? "—"} | ${esc(tr.reason)} |`);
  out.push("");

  // 8. Requests refused before sending
  out.push(`## ${t.denials}`, "", ...(r.denials.length ? r.denials.map((d) => `- ${d.method} \`${esc(d.url)}\` — ${d.reason}`) : [t.none]), "");

  // 9. Redirect chains
  out.push(`## ${t.redirects}`, "");
  if (r.redirectChains?.length) {
    out.push("Every hop was checked by ScopeGate before it was requested.", "");
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
  } else out.push(t.none, "");

  // 10. Client assets and browser
  out.push(`## ${t.assets}`, "", "### Client assets", "");
  if (r.assets) {
    const a = r.assets;
    out.push(`Engine: \`${a.engine}\` (detector version ${a.detectorVersion}). Only masked previews are kept; bundles and maps never leave the machine.`, "");
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
  } else out.push(t.noAssets, "");
  out.push("### Browser console", "");
  if (r.console) {
    const c = r.console;
    out.push(`Engine: \`${c.engine}\`. ${c.messages} message(s) inspected (${c.bytes} bytes)${c.dropped ? `, ${c.dropped} not inspected at the capture limit (incomplete)` : ""}. Message text is never kept; previews are masked and templates hash a value-free shape.`, "");
    out.push("| Case | Detector | Level | Source | Preview | Template | Flow step | Basis |", "|---|---|---|---|---|---|---|---|");
    for (const f of c.facts) out.push(`| ${f.caseId} | ${f.detector} | ${esc(f.level)} | \`${esc(f.source)}\` | \`${f.preview}\` | \`${f.template}\` | ${f.flow ? `${esc(f.flow)}/${esc(f.step ?? "")}` : "—"} | ${f.exact ? "exact known value" : "pattern"} |`);
    if (!c.facts.length) out.push("| — | | | | | | | |");
    if (c.observations) out.push("", `- Observations only (development profile): ${c.observations}`);
    out.push("");
  } else out.push(t.noConsole, "");
  out.push("### Analyzer", "");
  if (r.analyzer) {
    const a = r.analyzer;
    out.push(`- Engine \`${a.engine}\` · page models ${a.pages} (in \`page-models/\`) · incomplete ${a.incomplete} · withheld by the leak scan ${a.withheld}`, `- Free text: ${a.includeText ? "included (titles and headings, redacted, 120 characters; pattern redaction cannot prove free text free of personal data)" : "omitted (default)"}`);
    for (const e of a.extractors) out.push(`- Extractor \`${e.id}\` (${e.source}) sha256 \`${e.sha256.slice(0, 16)}\` — ${e.status}`);
    for (const x of a.refused) out.push(`- Refused \`${esc(x.file)}\`: ${esc(x.reason)}`);
    out.push("");
  } else out.push(t.noAnalyzer, "");

  // 11. Knowledge gaps
  out.push(`## ${t.kgaps}`, "", "### Knowledge gaps / proposed updates", "", "| Gap | Product | Detail |", "|---|---|---|");
  for (const g of k?.gaps ?? []) out.push(`| ${g.kind} | ${esc(g.product ?? "—")} | ${esc(g.detail)} |`);
  if (!k?.gaps.length) out.push(`| — ${t.none} | | |`);
  if (k?.proposals.length) out.push("", `Proposals written to \`.navsentry/knowledge/proposals/\`: ${k.proposals.map((p) => `${p.id} (${p.status})`).join(", ")}`);
  out.push("");

  // 12. Run details
  out.push(`## ${t.details}`, "", `- Budget: ${r.budget.requestsUsed}/${r.budget.requestsMax} requests · denied before execution ${r.budget.deniedBeforeExecution}`, "");
  out.push("### Fixtures and cleanup", "");
  if (r.fixtures) {
    // safe-validate (SPEC-0.2.0 §7): fixtures, cleanup, leftovers with the exact manual action, and mutations.
    const fx = r.fixtures;
    out.push(`- Marker: \`${fx.marker}\` · Created: ${fx.created} · Cleaned: ${fx.cleaned} · Verified gone: ${fx.verifiedGone} · Non-observe requests: ${fx.mutationsUsed}/${fx.mutationsMax}`, "");
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
    if (r.observations?.length) {
      out.push("### Marker reflections (facts, not results)", "", "NSC-INJ-004 stays NOT_TESTED: testing output encoding needs an injection payload (active-approved).", "", "| Context | Count | URL |", "|---|---|---|");
      for (const o of r.observations) out.push(`| ${o.context} | ${o.count} | \`${esc(o.url)}\` |`);
      out.push("");
    }
    out.push("### Mutations", "", "| Method | Path | Entry | Actor | Status | Body sha256 |", "|---|---|---|---|---|---|");
    for (const x of r.mutations ?? []) out.push(`| ${x.method} | \`${esc(x.path)}\` | ${esc(x.entry)} | ${esc(x.actor)} | ${x.status ?? esc(x.error ?? "—")} | ${x.bodySha256 ? `\`${x.bodySha256.slice(0, 16)}…\`` : "—"} |`);
    out.push("");
  } else out.push(t.noFixtures, "");
  out.push(`### ${t.capture}`, "");
  if (r.capture) {
    const c = r.capture;
    out.push("| Wire bytes | Decoded bytes | Truncated | Aborted | Partially inspected bodies |", "|---|---|---|---|---|", `| ${c.wireBytes} | ${c.decodedBytes} | ${c.truncated} | ${c.aborted} | ${c.partialBodies} |`, "");
  } else out.push(t.none, "");
  out.push(`### ${t.workspace}`, "");
  if (r.workspace) {
    const w = r.workspace;
    out.push(`- Leftover check: **${w.status}**${w.reason ? ` — ${esc(w.reason)}` : ""} · Cleanup: **${w.cleanup}**${w.cleanupReason ? ` (${esc(w.cleanupReason)})` : ""} · Report files written: ${w.promoted}`);
    for (const [kk, v] of [["Created", w.created], ["Modified", w.modified], ["Deleted", w.deleted]] as const) if (v.length) out.push(`- ${kk}: ${v.map((x) => `\`${esc(x)}\``).join(", ")}`);
    out.push(...w.limitations.map((x) => `- Limitation: ${x}`), "");
  } else out.push(t.none, "");
  return out.join("\n");
}
