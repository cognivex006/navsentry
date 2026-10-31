import { test } from "node:test";
import assert from "node:assert/strict";
import { compareRuns } from "../src/compare.js";
import { parseManifest } from "../src/config.js";
import { renderJson, renderMarkdown, renderSarif, securityResult } from "../src/report/render.js";
import { executeRun, planRun } from "../src/runner.js";
import { SYNTHETIC_NATIONAL_ID, startDemo } from "./fixtures/demo-server.js";
import { localManifest } from "./helpers.js";

const status = (r: Awaited<ReturnType<typeof executeRun>>, id: string) => r.coverage.find((c) => c.ruleId === id)?.status;

test("dry-run plan performs zero network traffic", async () => {
  const demo = await startDemo("vulnerable");
  try {
    const plan = planRun(localManifest(demo.origin), {});
    assert.equal(plan.networkEffects, "none");
    assert.ok(plan.steps.length > 0);
    assert.ok(plan.skippedCases.some((c) => c.id === "NSC-INJ-001" && c.automation === "manual-active"));
    assert.equal(demo.hits(), 0, "the demo server must not receive any request");
  } finally {
    await demo.close();
  }
});

test("vulnerable fixture: deterministic checks FAIL with redacted evidence", async () => {
  const demo = await startDemo("vulnerable");
  try {
    const r = await executeRun(localManifest(demo.origin));
    for (const id of ["NSC-CONF-002", "NSC-CONF-003", "NSC-CONF-004", "NSC-CONF-006", "NSC-CONF-007", "NSC-INFO-001", "NSC-ERR-001", "NSC-INFO-003", "NSC-INFO-004", "NSC-PRIV-001", "NSC-SESS-002", "NSC-SESS-003", "NSC-SESS-004", "NSC-AC-004", "NSC-CRYPT-006"]) {
      assert.equal(status(r, id), "FAIL", `${id} should FAIL`);
    }
    assert.equal(status(r, "NSC-CONF-001"), "NOT_TESTED", "HSTS is not evaluated on plain HTTP");
    assert.equal(status(r, "NSC-INJ-001"), "NOT_TESTED", "active cases are never automated");
    const pii = r.findings.find((f) => f.ruleId === "NSC-PRIV-001")!;
    assert.equal(pii.lifecycle, "SUSPECTED", "pattern evidence needs human confirmation");
    assert.equal(r.findings.find((f) => f.ruleId === "NSC-CONF-002")!.lifecycle, "VALIDATED");
    const all = renderJson(r) + renderMarkdown(r, "th") + JSON.stringify(renderSarif(r));
    for (const secret of [SYNTHETIC_NATIONAL_ID, "abc123def456", "dev.team@internal.example", "10.20.30.40"]) {
      assert.ok(!all.includes(secret), `artifact leaked ${secret}`);
    }
    assert.equal(securityResult(r), "FINDINGS");
  } finally {
    await demo.close();
  }
});

test("secure fixture passes and compare proves no legitimate-response drift", async () => {
  const vuln = await startDemo("vulnerable");
  const sec = await startDemo("secure");
  try {
    const before = await executeRun(localManifest(vuln.origin));
    const after = await executeRun(localManifest(sec.origin));
    for (const id of ["NSC-CONF-002", "NSC-CONF-003", "NSC-CONF-004", "NSC-CONF-006", "NSC-CONF-007", "NSC-INFO-001", "NSC-ERR-001", "NSC-INFO-003", "NSC-INFO-004", "NSC-PRIV-001", "NSC-SESS-002", "NSC-SESS-003", "NSC-SESS-004", "NSC-AC-004"]) {
      assert.equal(status(after, id), "PASS", `${id} should PASS on the secure fixture`);
    }
    // Same paths on different ports: normalize origin so requests line up.
    const norm = (r: typeof before, o: string) => ({ ...r, requests: r.requests.map((q) => ({ ...q, url: q.url.replace(o, "http://demo") })) });
    const c = compareRuns(norm(before, vuln.origin), norm(after, sec.origin));
    assert.ok(c.fixed.includes("NSC-ERR-001"));
    assert.deepEqual(c.contractDrift, [], "fix must not change status, content type, headers or JSON shape");
    assert.equal(c.verdict, "IMPROVED_NO_DRIFT");
  } finally {
    await vuln.close();
    await sec.close();
  }
});

test("compare detects a fix that changes the legitimate response contract", async () => {
  const vuln = await startDemo("vulnerable");
  try {
    const before = await executeRun(localManifest(vuln.origin));
    const after = structuredClone(before);
    const q = after.requests.find((x) => x.url.endsWith("/api/error"))!;
    q.contract = { ...q.contract!, status: 200, jsonShapeHash: "different" };
    const c = compareRuns(before, after);
    assert.ok(c.contractDrift.some((d) => d.field === "status"));
    assert.ok(c.contractDrift.some((d) => d.field === "jsonShapeHash"));
  } finally {
    await vuln.close();
  }
});

test("redirect escapes are not followed and are recorded as denials", async () => {
  const demo = await startDemo("vulnerable");
  try {
    const r = await executeRun(localManifest(demo.origin, { targets: { origins: [demo.origin], seed_paths: ["/go-out", "/go-in"] } }));
    assert.ok(r.denials.some((d) => d.reason.startsWith("redirect not followed") && d.url.includes("evil.example")));
    assert.ok(!r.requests.some((q) => q.url.includes("evil.example")));
    assert.ok(r.requests.some((q) => q.url === `${demo.origin}/`), "in-scope redirect is followed");
  } finally {
    await demo.close();
  }
});

test("hostname resolving to loopback without approval is refused at connect time", async () => {
  const demo = await startDemo("vulnerable");
  try {
    const port = new URL(demo.origin).port;
    const origin = `http://localhost:${port}`;
    const m = parseManifest({ version: "1", project: "p", environment: "local", authorization: { acknowledged: true, owner: "t" }, targets: { origins: [origin], seed_paths: ["/"] }, safety: { max_requests_per_second: 20 } });
    const r = await executeRun(m);
    assert.equal(demo.hits(), 0, "no byte may reach the private address");
    assert.ok(r.requests.every((q) => q.error?.startsWith("scope denied at connect")));
    assert.equal(status(r, "NSC-CONF-002"), "ERROR", "a denied request is ERROR, never PASS");
    assert.notEqual(securityResult(r), "NO_FINDINGS_IN_TESTED_SCOPE");
  } finally {
    await demo.close();
  }
});

test("request budget is enforced and the run is marked PARTIAL", async () => {
  const demo = await startDemo("secure");
  try {
    const r = await executeRun(localManifest(demo.origin, { safety: { max_requests: 3, max_requests_per_second: 20 } }));
    assert.equal(demo.hits(), 3);
    assert.equal(r.executionStatus, "PARTIAL");
    assert.ok(r.incompleteReasons.some((x) => x.includes("budget")));
  } finally {
    await demo.close();
  }
});

test("unreachable target yields ERROR / NOT_TESTED, never PASS", async () => {
  const demo = await startDemo("secure");
  const origin = demo.origin;
  await demo.close();
  const r = await executeRun(localManifest(origin, { targets: { origins: [origin], seed_paths: ["/"] } }));
  assert.ok(r.coverage.every((c) => c.status !== "PASS"));
  assert.notEqual(securityResult(r), "NO_FINDINGS_IN_TESTED_SCOPE");
});

test("SARIF 2.1.0 structure", async () => {
  const demo = await startDemo("vulnerable");
  try {
    const s = renderSarif(await executeRun(localManifest(demo.origin))) as { version: string; runs: { tool: { driver: { rules: { id: string }[] } }; results: { ruleId: string; ruleIndex: number }[] }[] };
    assert.equal(s.version, "2.1.0");
    const run = s.runs[0]!;
    for (const res of run.results) assert.equal(run.tool.driver.rules[res.ruleIndex]!.id, res.ruleId);
  } finally {
    await demo.close();
  }
});
