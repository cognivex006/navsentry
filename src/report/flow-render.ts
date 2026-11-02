/** Renders a FlowRunResult: TEST-REPORT.md (en/th), JUnit XML, and the REPORT.md flows section. */
import type { FlowRunResult, FlowStatus, RunResult, TestLevel } from "../types.js";
import { securityResult } from "./render.js";

const L = {
  en: {
    title: "NavSentry Test Report", sec: "Security result", func: "Functional result", summary: "Summary", flows: "Flows", level: "Level", status: "Status",
    integration: "Integration (API/service)", e2e: "E2E (user journey)", httpOnly: "E2E (HTTP-level only)", story: "Story", reasons: "Level reasons", exec: "Executability", review: "Review",
    steps: "| Step | Actor | Action | Request (template) | Status | Assertions | Security case |", failed: "Failed or inconclusive assertions", findings: "Security findings raised during this flow",
    manual: "Manual replay checklist", manualNote: "These steps need a transport that is not usable in this release. Record a manual replay separately in MANUAL-REPLAY.md (docs/reports/templates); it never changes flows.json.",
    notRun: "Steps not executed", limits: "Limitations", none: "None",
    disclaimer: "A flow PASS means the asserted behaviour matched in the tested scope; it does not prove the feature correct or secure. HTTP-level page checks see server-rendered HTML only.",
    secFirst: "Read the security report first:",
  },
  th: {
    title: "รายงานการทดสอบ NavSentry", sec: "ผลด้านความปลอดภัย", func: "ผลการทดสอบการทำงาน", summary: "สรุป", flows: "โฟลว์", level: "ระดับ", status: "สถานะ",
    integration: "Integration (ระดับ API/บริการ)", e2e: "E2E (เส้นทางผู้ใช้ตั้งแต่ต้นจนจบ)", httpOnly: "E2E (ทดสอบได้เฉพาะระดับ HTTP)", story: "เรื่องราวผู้ใช้", reasons: "เหตุผลของการจัดระดับ", exec: "ความสามารถในการรัน", review: "สถานะการอนุมัติ",
    steps: "| ขั้นตอน | Actor | Action | Request (template) | สถานะ | ผลการตรวจ | เคสความปลอดภัย |", failed: "ผลตรวจที่ไม่ผ่านหรือสรุปไม่ได้", findings: "ช่องโหว่ที่พบระหว่างโฟลว์นี้",
    manual: "รายการทดสอบซ้ำด้วยมือ", manualNote: "ขั้นตอนเหล่านี้ต้องใช้ transport ที่รุ่นนี้ยังไม่รองรับ ให้บันทึกผลการทดสอบด้วยมือแยกไว้ใน MANUAL-REPLAY.md (docs/reports/templates) ผลนี้ไม่เปลี่ยน flows.json",
    notRun: "ขั้นตอนที่ไม่ได้รัน", limits: "ข้อจำกัด", none: "ไม่มี",
    disclaimer: "ผล PASS ของโฟลว์หมายถึงพฤติกรรมที่ระบุตรงตามที่คาดในขอบเขตที่ทดสอบเท่านั้น ไม่ได้รับรองว่าฟีเจอร์ถูกต้องทั้งหมดหรือปลอดภัย การตรวจหน้าเว็บระดับ HTTP เห็นเฉพาะ HTML ที่ server ส่งมา",
    secFirst: "อ่านรายงานความปลอดภัยก่อน:",
  },
} as const;

const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
const STATUSES: FlowStatus[] = ["PASS", "FAIL", "INCOMPLETE", "ERROR", "NOT_TESTED"];

export function levelLabel(f: FlowRunResult["flows"][number], lang: "en" | "th"): string {
  const t = L[lang];
  if (f.level === "integration") return t.integration;
  return f.executability === "full" ? t.e2e : t.httpOnly;
}

export function renderTestMarkdown(fr: FlowRunResult, run: RunResult | undefined, lang: "en" | "th" = "en"): string {
  const t = L[lang];
  const out: string[] = [];
  out.push(`# ${t.title} — ${fr.project} (${fr.environment})`, "");
  out.push(`- Run ID: \`${fr.runId}\` · Tool: ${fr.tool.name} ${fr.tool.version} · Node ${fr.tool.node} · Mode: \`${fr.mode}\``, `- Flow set: ${fr.flowSet.flows} flows, ${fr.flowSet.steps} steps · \`${fr.flowSet.sha256.slice(0, 16)}\``);
  if (run) out.push(`- **${t.sec}: ${securityResult(run)}** (${run.findings.length} findings) — ${t.secFirst} [REPORT.md](REPORT.md)`);
  out.push(`- **${t.func}: ${fr.functionalResult}**`, "");
  out.push(`## ${t.summary}`, "", `| ${t.level} | ${STATUSES.join(" | ")} |`, `|---|${STATUSES.map(() => "---").join("|")}|`);
  for (const lv of ["integration", "e2e"] as TestLevel[]) out.push(`| ${t[lv]} | ${STATUSES.map((s) => fr.summary[lv][s]).join(" | ")} |`);
  out.push("", `> ${t.disclaimer}`, "", `## ${t.flows}`, "");
  if (!fr.flows.length) out.push(t.none, "");
  for (const f of fr.flows) {
    out.push(`### ${f.id} — ${esc(f.title)}`, "");
    out.push(`- ${t.status}: **${f.status}** · ${t.level}: **${levelLabel(f, lang)}** · ${t.exec}: ${f.executability} · ${t.review}: ${f.review.status}${f.review.status === "approved" ? ` (${f.review.approvedBy ?? "?"}, ${f.review.approvedAt ?? "?"}${f.review.hashValid ? "" : ", hash INVALID"})` : ""}`);
    out.push(`- ${t.story}: ${esc(f.story)}`, `- ${t.reasons}: ${f.levelReasons.map(esc).join("; ")}`, `- File: \`${f.file}\``, "");
    out.push(t.steps, "|---|---|---|---|---|---|---|");
    for (const s of f.steps) {
      const passed = s.assertions.filter((a) => a.status === "PASS").length;
      out.push(`| ${s.id} ${esc(s.title)} | ${s.actor} | ${s.action} | ${s.request ? `\`${esc(s.request)}\`` : "—"} | ${s.status} | ${s.assertions.length ? `${passed}/${s.assertions.length}` : "—"} | ${s.securityCase ?? "—"} |`);
    }
    const bad = f.steps.flatMap((s) => s.assertions.filter((a) => a.status !== "PASS").map((a) => `- ${s.id} ${a.kind}: expected ${esc(a.expected)} · observed ${esc(a.observed)} → **${a.status}**`));
    if (bad.length) out.push("", `**${t.failed}:**`, ...bad);
    const notRun = f.steps.filter((s) => s.status === "NOT_TESTED" || s.status === "ERROR").map((s) => `- ${s.id} ${s.status}: ${esc(s.reason ?? "")}`);
    if (notRun.length) out.push("", `**${t.notRun}:**`, ...notRun);
    if (f.findings.length) out.push("", `**${t.findings}:**`, ...f.findings.map((fp) => `- \`${fp}\` (REPORT.md)`));
    if (f.manualReplay.length) out.push("", `**${t.manual}:**`, `> ${t.manualNote}`, ...f.manualReplay.map((x, i) => `${i + 1}. ${esc(x)}`));
    out.push("");
  }
  out.push(`## ${t.limits}`, "", `- ${t.disclaimer}`, "");
  return out.join("\n");
}

/** Short section appended to REPORT.md (security report stays primary). */
export function renderFlowSection(fr: FlowRunResult, run: RunResult, lang: "en" | "th" = "en"): string {
  const t = L[lang];
  const seedUrls = new Set(run.requests.filter((q) => !q.flow).map((q) => q.url));
  const flowUrls = new Set(run.requests.filter((q) => q.flow).map((q) => q.url));
  const extra = [...flowUrls].filter((u) => !seedUrls.has(u)).length;
  const fps = new Set(fr.flows.flatMap((f) => f.findings));
  return [
    `## ${t.flows}`, "",
    `- ${fr.flowSet.flows} flows / ${fr.flowSet.steps} steps · ${t.func}: **${fr.functionalResult}**`,
    `- URLs covered beyond seed paths: ${extra}`,
    `- Findings raised by flow requests: ${fps.size}`,
    "- Details: [TEST-REPORT.md](TEST-REPORT.md)", "",
  ].join("\n");
}

const xml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "");

export function renderJunit(fr: FlowRunResult): string {
  const out = ['<?xml version="1.0" encoding="UTF-8"?>', `<testsuites name="navsentry-flows" tests="${fr.flowSet.steps}">`];
  for (const f of fr.flows) {
    const count = (s: string) => f.steps.filter((x) => x.status === s).length;
    out.push(`  <testsuite name="${xml(f.id)}" tests="${f.steps.length}" failures="${count("FAIL")}" errors="${count("ERROR")}" skipped="${count("NOT_TESTED") + count("INCONCLUSIVE")}">`);
    for (const s of f.steps) {
      const msg = xml(s.reason ?? s.assertions.filter((a) => a.status !== "PASS").map((a) => `${a.kind}: expected ${a.expected}, observed ${a.observed}`).join("; "));
      const open = `    <testcase classname="${xml(f.id)}" name="${xml(s.key)}">`;
      if (s.status === "FAIL") out.push(open, `      <failure message="${msg}"/>`, "    </testcase>");
      else if (s.status === "ERROR") out.push(open, `      <error message="${msg}"/>`, "    </testcase>");
      else if (s.status === "NOT_TESTED" || s.status === "INCONCLUSIVE") out.push(open, `      <skipped message="${msg}"/>`, "    </testcase>");
      else out.push(`    <testcase classname="${xml(f.id)}" name="${xml(s.key)}"/>`);
    }
    out.push("  </testsuite>");
  }
  out.push("</testsuites>", "");
  return out.join("\n");
}

/** Structural validation for imported flow results (report/compare inputs are untrusted). */
export function validateFlowRunResult(x: unknown): FlowRunResult {
  const o = x as FlowRunResult;
  const ok = !!o && o.kind === "navsentry-flow-result" && o.schemaVersion === "1" && typeof o.runId === "string" && Array.isArray(o.flows) && o.flowSet && typeof o.functionalResult === "string";
  if (!ok) throw new Error("input is not a NavSentry flow result (schemaVersion 1)");
  for (const f of o.flows) {
    if (!Array.isArray(f.steps) || !STATUSES.includes(f.status)) throw new Error("invalid flow entry");
    for (const s of f.steps) if (!["PASS", "FAIL", "INCONCLUSIVE", "NOT_TESTED", "ERROR"].includes(s.status)) throw new Error("invalid step status");
  }
  return o;
}
