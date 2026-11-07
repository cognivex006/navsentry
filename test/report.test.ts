/** SPEC-0.3.0 0.3.0-c: report skeleton, finding cards, fix examples, HTML, colour, compare by path. 127.0.0.1 only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { CASES } from "../src/catalog.js";
import { compareRuns } from "../src/compare.js";
import { FIXES, actionLevel } from "../src/fixes.js";
import { renderHtml, markdownToHtml } from "../src/report/html.js";
import { colourEnabled, paint } from "../src/report/color.js";
import { renderMarkdown, verdict } from "../src/report/render.js";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { executeTest } from "../src/runner.js";
import type { RunResult } from "../src/types.js";
import { startDemo } from "./fixtures/demo-server.js";
import { localManifest } from "./helpers.js";

const SECTIONS_EN = ["Summary", "Findings", "Fix verification", "Known vulnerabilities", "Coverage", "Not tested and limitations", "Transports and engine", "Requests refused before sending", "Redirect chains", "Client assets and browser", "Knowledge gaps", "Run details"];

async function demoRun(mode: "vulnerable" | "secure"): Promise<RunResult> {
  const d = await startDemo(mode);
  try {
    return (await executeTest(localManifest(d.origin), {})).run;
  } finally {
    await d.close();
  }
}

const h2 = (md: string) => md.split("\n").filter((l) => l.startsWith("## ")).map((l) => l.slice(3));

test("action levels: info is INFO, low planned hardening is OPTIONAL, the rest keep their priority", () => {
  assert.equal(actionLevel("info", "PLANNED"), "INFO");
  assert.equal(actionLevel("low", "PLANNED"), "OPTIONAL");
  assert.equal(actionLevel("low", "CAUTION"), "CAUTION");
  assert.equal(actionLevel("high", "IMMEDIATE"), "IMMEDIATE");
  assert.equal(actionLevel("medium", "PLANNED"), "PLANNED");
});

test("every automated case has at least one before/after fix example without real secrets", () => {
  for (const c of CASES.filter((x) => x.automation === "auto" || x.automation === "flow")) {
    const s = FIXES[c.id];
    assert.ok(s && s.length, `${c.id} has fix examples`);
    for (const x of s) {
      assert.ok(x.before.trim() && x.after.trim() && x.before !== x.after, `${c.id} ${x.stack} has distinct before/after`);
      assert.ok(!/\b(sk_live|ghp_|AKIA)[A-Za-z0-9]/.test(x.before + x.after), `${c.id} uses placeholders only`);
    }
  }
});

test("every report has the same twelve sections in order, with empty states (en and th)", async () => {
  const vuln = await demoRun("vulnerable");
  const sec = await demoRun("secure");
  const empty: RunResult = { ...sec, findings: [] };
  for (const r of [vuln, sec, empty]) assert.deepEqual(h2(renderMarkdown(r, "en")), SECTIONS_EN);
  assert.equal(h2(renderMarkdown(vuln, "th")).length, 12);
  assert.deepEqual(h2(renderMarkdown(vuln, "th")), h2(renderMarkdown(empty, "th")));
  const md = renderMarkdown(empty, "en");
  assert.match(md, /No findings in tested scope\. This is not proof of security\./);
  assert.match(md, /No previous run compared\./);
  assert.match(md, /Not a spider run/);
  assert.match(md, /Not used \(observe mode\)\./);
});

test("findings: one card per case, grouped by action level, fix examples inline, no links into NavSentry docs", async () => {
  const run = await demoRun("vulnerable");
  const md = renderMarkdown(run, "en");
  assert.ok(!md.includes("docs/cases"), "the report does not point into the skill's docs");
  const cards = md.split("\n").filter((l) => l.startsWith("#### "));
  assert.equal(cards.length, new Set(run.findings.map((f) => f.ruleId)).size, "one card per case");
  const order = ["### 🔴 IMMEDIATE", "### 🟠 CAUTION", "### 🟡 PLANNED", "### 🔵 OPTIONAL", "### ⚪ INFO"].map((h) => md.indexOf(h)).filter((i) => i >= 0);
  assert.deepEqual(order, [...order].sort((a, b) => a - b), "levels are in order");
  const err = md.slice(md.indexOf("#### 🔴 NSC-ERR-001"));
  assert.match(err, /\*\*How to fix:\*\*/);
  assert.match(err, /Fix examples \(reviewed examples; NavSentry does not execute them\)/);
  assert.match(err, /Before:[\s\S]*res\.status\(500\)\.send\(err\.stack\)[\s\S]*After:/);
  assert.match(err, /\*\*How to recheck:\*\*/);
  assert.match(err, /\*\*Fixed when:\*\*/);
  assert.match(md, /#### ⚪ NSC-INFO-004/);
  assert.match(md, /#### 🔵 NSC-CONF-004/);
});

test("HTML report: same content, offline, CSP-hashed, hostile target text escaped", async () => {
  const run = await demoRun("vulnerable");
  const hostile = '<script>alert(1)</script><img src=x onerror=alert(2)>';
  const f = run.findings[0]!;
  const r2: RunResult = { ...run, findings: [{ ...f, target: `GET http://127.0.0.1/${hostile}`, actual: [hostile] }, ...run.findings.slice(1)] };
  const md = renderMarkdown(r2, "en");
  const html = renderHtml(md, `NavSentry report — ${hostile}`, "en");
  assert.ok(!html.includes("<script>alert(1)"), "no injected script");
  assert.ok(!html.includes("<img"), "no injected element");
  assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
  assert.ok(!/\b(src|href)=["']?https?:/i.test(html), "no external resources");
  const csp = html.match(/content="(default-src 'none';[^"]+)"/)?.[1] ?? "";
  const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1] ?? "";
  const style = html.match(/<style>([\s\S]*?)<\/style>/)?.[1] ?? "";
  assert.ok(csp.includes(`'sha256-${createHash("sha256").update(script).digest("base64")}'`), "script hash in CSP");
  assert.ok(csp.includes(`'sha256-${createHash("sha256").update(style).digest("base64")}'`), "style hash in CSP");
  const data = html.match(/<script type="application\/json" id="report-md">([\s\S]*?)<\/script>/)?.[1] ?? "";
  assert.ok(!data.includes("<"), "embedded Markdown cannot close its script element");
  assert.equal(JSON.parse(data), md, "Export Markdown returns exactly REPORT.md");
  for (const s of SECTIONS_EN) assert.ok(html.includes(`<h2>${s}</h2>`), `HTML has ${s}`);
  assert.match(markdownToHtml("| a | b |\n|---|---|\n| FAIL | PASS |"), /st-fail[\s\S]*st-pass/);
  assert.ok(!markdownToHtml("NSC-INFO-004").includes("st-info"), "case IDs are not coloured as statuses");
});

test("terminal colour only on a TTY, never with NO_COLOR or --no-color", () => {
  assert.equal(colourEnabled([], {}, false), false);
  assert.equal(colourEnabled([], {}, true), true);
  assert.equal(colourEnabled([], { NO_COLOR: "" }, true), false);
  assert.equal(colourEnabled(["--no-color"], {}, true), false);
  assert.equal(paint("execution=COMPLETE security=FINDINGS", false), "execution=COMPLETE security=FINDINGS");
  const on = paint("execution=COMPLETE security=FINDINGS NSC-INFO-004", true);
  assert.match(on, /\x1b\[32mCOMPLETE/);
  assert.match(on, /\x1b\[31mFINDINGS/);
  assert.match(on, /NSC-INFO-004$/, "case IDs stay plain");
});

test("compare matches requests by path when the origin changes, and reports the change once", async () => {
  const before = await demoRun("vulnerable");
  const after = await demoRun("secure");
  assert.notDeepEqual(before.scope.origins, after.scope.origins);
  const c = compareRuns(before, after);
  assert.deepEqual(c.missingInAfter, []);
  assert.ok(c.originChange);
  assert.equal(c.verdict, "IMPROVED_NO_DRIFT");
});

test("verdict answers 'fix now?' in one line: findings first, incomplete runs never read as no-fix", async () => {
  const vuln = await demoRun("vulnerable");
  const sec = await demoRun("secure");
  const v = verdict(vuln, "en");
  assert.equal(v.kind, "FIX_NOW");
  assert.ok(v.count > 0);
  const md = renderMarkdown(vuln, "en");
  const summary = md.slice(md.indexOf("## Summary"));
  assert.ok(summary.split("\n")[2]!.startsWith("> 🔴 **Do I need to fix something now?** Yes."), "verdict is the first line of the summary");
  assert.match(renderMarkdown(vuln, "th"), /> 🔴 \*\*ต้องแก้อะไรตอนนี้ไหม\?\*\* ต้องแก้/);
  const planned = vuln.findings.filter((f) => actionLevel(f.severity, f.priority) === "PLANNED");
  if (planned.length) assert.equal(verdict({ ...vuln, findings: planned }).kind, "PLAN");
  const clean: RunResult = { ...sec, findings: [], executionStatus: "COMPLETE", coverage: sec.coverage.filter((c) => c.status !== "ERROR" && c.status !== "INCONCLUSIVE") };
  assert.equal(verdict(clean).kind, "NO_URGENT");
  assert.match(verdict(clean).text, /not proof of security/);
  assert.equal(verdict({ ...clean, executionStatus: "PARTIAL" }).kind, "CANNOT_TELL");
  const info = vuln.findings.filter((f) => actionLevel(f.severity, f.priority) === "INFO" || actionLevel(f.severity, f.priority) === "OPTIONAL");
  assert.ok(info.length, "fixture has INFO/OPTIONAL findings");
  assert.equal(verdict({ ...clean, findings: info }).kind, "NO_URGENT");
  assert.equal(verdict({ ...clean, findings: info, executionStatus: "PARTIAL" }).kind, "CANNOT_TELL", "an incomplete run with only minor findings is never no-fix");
  assert.equal(verdict(clean, "en", "FAIL").kind, "CANNOT_TELL", "failed flows mean their checks did not run");
  assert.equal(verdict(clean, "en", "PASS").kind, "NO_URGENT");
  const html = renderHtml(md, "t", "en");
  assert.match(html, /<blockquote class="verdict v-fix_now">/);
  assert.match(renderHtml(renderMarkdown({ ...clean, executionStatus: "PARTIAL" }), "t", "en"), /class="verdict v-cannot_tell"/);
});

test("report --out writes the file, never overwrites, and HTML is not dumped on a terminal", async () => {
  const run = await demoRun("vulnerable");
  const dir = mkdtempSync(join(tmpdir(), "navsentry-report-out-"));
  try {
    const input = join(dir, "run.json");
    writeFileSync(input, JSON.stringify(run));
    const out = join(dir, "r.html");
    const cli = (args: string[]) => spawnSync(process.execPath, ["dist/src/cli.js", "report", "--input", input, ...args], { encoding: "utf8" });
    const a = cli(["--format", "html", "--out", out]);
    assert.equal(a.status, 0, a.stderr);
    assert.match(a.stdout, /^Wrote /);
    assert.match(readFileSync(out, "utf8"), /class="verdict v-fix_now"/);
    const b = cli(["--format", "html", "--out", out]);
    assert.equal(b.status, 3, "an existing file is never overwritten");
    assert.match(b.stderr, /already exists/);
    const piped = cli(["--format", "markdown"]);
    assert.match(piped.stdout, /Do I need to fix something now\?/, "without --out, stdout still works when piped");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
