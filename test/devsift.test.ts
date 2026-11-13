/** SPEC-0.4.0 D3: DevSift correlation reads report files only; unknown versions are refused. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli.js";
import { DEVSIFT_RULE_MAP, DevsiftError, correlate, parseDevsiftReport } from "../src/devsift.js";
import { CASES } from "../src/catalog.js";
import type { RunResult } from "../src/types.js";
import { startDemo } from "./fixtures/demo-server.js";

/** A synthetic DevSift v1 report: only the fields the adapter reads, plus a code excerpt it must ignore. */
const report = (cases: { id: string; rule: string; path?: string }[], over: Record<string, unknown> = {}) => JSON.stringify({
  schema_version: "1", tool: "devsift", complete: true, status: "enforced", exit_code: 1, enforced_count: cases.length, errors: [], contextual_recommendations: [],
  cases: cases.map((c) => ({ case_id: c.id, rule_id: c.rule, severity: "Error", confidence: "high", source: c.path ? { status: "VERIFIED", location: { repository: "r", source_sha: "0".repeat(40), path: c.path, region: { start_line: 7, start_column: 1, end_line: 7, end_column: 9 }, symbol: null }, before: "SECRET_CODE_EXCERPT", reason: null, lookup_plan: null } : { status: "SOURCE_UNRESOLVED", location: null, before: null }, implement_prompt: "IGNORE ME" })),
  ...over,
});

const fakeRun = (ruleIds: string[]) => ({ runId: "run-1", findings: ruleIds.map((r, i) => ({ ruleId: r, fingerprint: `fp${i}`, target: `GET http://127.0.0.1/x${i}` })) }) as unknown as RunResult;

test("the rule table maps only to real catalog cases", () => {
  const ids = new Set(CASES.map((c) => c.id));
  for (const [rule, cases] of Object.entries(DEVSIFT_RULE_MAP)) for (const c of cases) assert.ok(ids.has(c), `${rule} → ${c}`);
});

test("correlates mapped rules, lists unmapped ones, and never carries code or prompts", () => {
  const r = correlate(fakeRun(["NSC-INJ-001", "NSC-CONF-001"]), parseDevsiftReport(report([{ id: "c1", rule: "SEC003", path: "src/db.py" }, { id: "c2", rule: "SEC002" }])));
  assert.equal(r.correlations.length, 1);
  assert.deepEqual(r.correlations[0]!.devsift, { caseId: "c1", ruleId: "SEC003", severity: "Error", confidence: "high", path: "src/db.py", line: 7 });
  assert.equal(r.correlations[0]!.navsentry.ruleId, "NSC-INJ-001");
  assert.deepEqual(r.devsift.unmappedRules, ["SEC002"]);
  const text = JSON.stringify(r);
  assert.ok(!text.includes("SECRET_CODE_EXCERPT") && !text.includes("IGNORE ME"));
  assert.ok(r.limitations.some((l) => l.includes("not proof")));
});

test("unsupported or malformed reports are refused", () => {
  assert.throws(() => parseDevsiftReport(report([], { schema_version: "2" })), DevsiftError);
  assert.throws(() => parseDevsiftReport(JSON.stringify({ tool: "other", schema_version: "1" })), DevsiftError);
  assert.throws(() => parseDevsiftReport(report([{ id: "c1", rule: "bad rule" }])), DevsiftError);
  assert.throws(() => parseDevsiftReport("{"), DevsiftError);
  const inc = correlate(fakeRun([]), parseDevsiftReport(report([], { complete: false, status: "incomplete" })));
  assert.ok(inc.limitations.some((l) => l.includes("incomplete")));
});

test("CLI: correlate reads a real run folder and a DevSift file", async () => {
  const demo = await startDemo("vulnerable");
  const dir = mkdtempSync(join(tmpdir(), "navsentry-devsift-"));
  try {
    const m = join(dir, "m.json");
    writeFileSync(m, JSON.stringify({ version: "1", project: "demo", environment: "local", authorization: { acknowledged: true, owner: "t" }, targets: { origins: [demo.origin], seed_paths: ["/", "/api/profile", "/api/error", "/api/token"] }, network: { allow_private: [{ host: "127.0.0.1", approved_by: "t", reason: "fixture" }] }, safety: { mode: "observe", max_requests: 100, max_requests_per_second: 20, max_duration_seconds: 60 }, report: { language: "en", formats: ["json"] } }));
    const out = join(dir, "run");
    await main(["test", "--config", m, "--project", dir, "--out", out]);
    const found = (JSON.parse(readFileSync(join(out, "run.json"), "utf8")) as RunResult).findings.map((f) => f.ruleId);
    const rule = Object.entries(DEVSIFT_RULE_MAP).find(([, cs]) => cs.some((c) => found.includes(c)))?.[0];
    const ds = join(dir, "devsift.json");
    writeFileSync(ds, report([{ id: "c1", rule: rule ?? "SEC003", path: "app/x.py" }]));
    assert.equal(await main(["correlate", "--run", out, "--devsift", ds, "--json"]), 0);
    writeFileSync(ds, report([], { schema_version: "9" }));
    assert.equal(await main(["correlate", "--run", out, "--devsift", ds]), 3);
  } finally {
    await demo.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
