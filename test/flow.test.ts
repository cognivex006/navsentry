import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli.js";
import { loadManifest } from "../src/config.js";
import { compareRuns } from "../src/compare.js";
import { analyzeRun } from "../src/flow/analyze.js";
import { approveText, initTemplate } from "../src/flow/author.js";
import { classify, flowHash } from "../src/flow/classify.js";
import { lintFlows } from "../src/flow/lint.js";
import { loadFlowFiles, parseFlowText, type FlowDoc } from "../src/flow/parse.js";
import { renderJunit, renderTestMarkdown, validateFlowRunResult } from "../src/report/flow-render.js";
import { renderJson, renderMarkdown, renderSarif } from "../src/report/render.js";
import { executeRun, executeTest, planRun } from "../src/runner.js";
import type { FlowRunResult } from "../src/types.js";
import { FIXTURE_TOKENS, startDemo } from "./fixtures/demo-server.js";
import { localManifest } from "./helpers.js";

const FIX = join(process.cwd(), "test", "fixtures");
const ENV = { NAVSENTRY_TEST_READER_A_AUTH: FIXTURE_TOKENS.reader_a, NAVSENTRY_TEST_READER_B_AUTH: FIXTURE_TOKENS.reader_b, NAVSENTRY_TEST_ADMIN_AUTH: FIXTURE_TOKENS.admin };
const ACTORS = { reader_a: { authorization_header_env: "NAVSENTRY_TEST_READER_A_AUTH" }, reader_b: { authorization_header_env: "NAVSENTRY_TEST_READER_B_AUTH" }, admin: { authorization_header_env: "NAVSENTRY_TEST_ADMIN_AUTH" } };
const manifest = (origin: string, over: Record<string, unknown> = {}) => localManifest(origin, { actors: ACTORS, ...over });

function docs(dir = "flows"): FlowDoc[] {
  const r = loadFlowFiles(join(FIX, dir));
  assert.deepEqual(r.problems, []);
  return r.docs;
}

const wrap = (header: object, ...steps: object[]) =>
  ["# t", "", "```navsentry-flow", JSON.stringify(header), "```", "", ...steps.flatMap((s, i) => [`## S${i + 1}`, "```navsentry-step", JSON.stringify(s), "```", ""])].join("\n");
const H = { flow: "1", id: "t-flow", title: "T", story: "A story", actors: ["anonymous"] };
const S = { id: "S1", action: "http", actor: "anonymous", request: { method: "GET", path: "/" }, expect: { status: "2xx" } };

test("parser: strict keys, block typos, nested fences and limits; messages carry no values", () => {
  const ok = parseFlowText(wrap(H, S), "a.flow.md");
  assert.deepEqual(ok.problems, []);
  const secret = parseFlowText(wrap({ ...H, token: "sk-live-very-secret" }, S), "a.flow.md").problems.join("\n");
  assert.match(secret, /plaintext secrets are forbidden/);
  assert.ok(!secret.includes("sk-live-very-secret"));
  assert.match(parseFlowText(wrap(H, { ...S, extra: 1 }), "a.flow.md").problems.join(), /\/extra: unknown key/);
  assert.match(parseFlowText(wrap(H, S).replace("navsentry-step", "navsentry-stpe"), "a.flow.md").problems.join(), /unknown block type/);
  assert.match(parseFlowText(wrap(H, S) + "\n> ```navsentry-step\n", "a.flow.md").problems.join(), /must be top-level/);
  assert.match(parseFlowText("x".repeat(300 * 1024), "a.flow.md").problems.join(), /larger than/);
  assert.match(parseFlowText("\u0000", "a.flow.md").problems.join(), /NUL/);
  assert.deepEqual(parseFlowText("﻿" + wrap(H, S).replace(/\n/g, "\r\n"), "a.flow.md").problems, [], "BOM and CRLF are accepted");
  assert.match(parseFlowText(wrap(H, { ...S, request: { method: "POST", path: "/" } }), "a.flow.md").problems.join(), /needs "fixture"/);
  assert.match(parseFlowText(wrap(H, S, S), "a.flow.md").problems.join(), /duplicate step id/);
  const narrative = parseFlowText(wrap(H, S).replace("# t", "# t\n\n```json\n{\"not\": \"parsed\"}\n```"), "a.flow.md");
  assert.deepEqual(narrative.problems, [], "non-navsentry fences are narrative");
});

test("lint and plan are zero network; out-of-scope, secrets and level mismatch are rejected", async () => {
  const demo = await startDemo("vulnerable");
  try {
    const m = manifest(demo.origin);
    assert.deepEqual(lintFlows(docs(), m).errors, []);
    const bad = (h: object, ...s: object[]) => lintFlows([parseFlowText(wrap(h, ...s), "b.flow.md").doc!], m).errors.join("\n");
    assert.match(bad(H, { ...S, request: { method: "GET", path: "/admin/x" } }), /out of scope/);
    assert.match(bad({ ...H, origin: "https://other.example.test" }, S), /origin is not in the manifest/);
    assert.match(bad({ ...H, story: "contact dev.team@internal.example" }, S), /looks like a secret or personal data/);
    assert.match(bad({ ...H, level: "e2e" }, S), /declared e2e but derived integration/);
    assert.match(bad(H, { ...S, expect: { access: "denied" } }), /needs a positive control/);
    assert.match(bad(H, { ...S, expect: { headers_present: ["content-security-policy"] } }), /covered by the security checks/);
    assert.match(bad(H, { ...S, request: { method: "GET", path: "/api/{{nope}}" } }), /used before it is defined/);
    assert.match(bad(H, { ...S, actor: "ghost" }), /not listed in the flow header/);
    const risky = lintFlows([parseFlowText(wrap(H, { ...S, request: { method: "GET", path: "/logout" } }), "r.flow.md").doc!], m);
    assert.deepEqual(risky.errors, []);
    assert.match(risky.warnings.join(), /suggests a side effect/);
    const plan = planRun(m, ENV, { flows: docs() });
    assert.equal(plan.networkEffects, "none");
    assert.ok(plan.flows!.find((f) => f.id === "profile-journey")!.steps.some((s) => !s.willRun && /playwright/.test(s.reason)));
    assert.ok((plan.estimatedRequests ?? 0) > 0);
    assert.equal(demo.hits(), 0, "lint and plan must not contact the target");
  } finally {
    await demo.close();
  }
});

test("classification is deterministic with reasons", () => {
  const [orders, profile] = [docs().find((d) => d.header.id === "orders-access")!, docs().find((d) => d.header.id === "profile-journey")!];
  assert.deepEqual(classify(orders), classify(orders));
  assert.equal(classify(orders).level, "integration");
  assert.equal(classify(orders).executability, "full");
  assert.ok(classify(orders).stateful && classify(orders).hasSecurityExpectations);
  const p = classify(profile);
  assert.equal(p.level, "e2e");
  assert.equal(p.executability, "partial");
  assert.ok(p.levelReasons.some((r) => /S2 click needs a browser/.test(r)));
  const nav = parseFlowText(wrap(H, { ...S, action: "navigate", request: { method: "GET", path: "/" } }), "n.flow.md").doc!;
  assert.equal(classify(nav).level, "e2e");
  assert.equal(classify(nav).executability, "full");
});

test("vulnerable fixture: access expectations FAIL as SUSPECTED for drafts; flow URLs are security-checked", async () => {
  const demo = await startDemo("vulnerable");
  try {
    const { run, flowRun } = await executeTest(manifest(demo.origin), { env: ENV, flows: docs() });
    const cov = (id: string) => run.coverage.find((c) => c.ruleId === id)?.status;
    for (const id of ["NSC-AC-002", "NSC-AC-003", "NSC-AC-007"]) {
      assert.equal(cov(id), "FAIL", `${id} should FAIL`);
      const f = run.findings.find((x) => x.ruleId === id)!;
      assert.equal(f.lifecycle, "SUSPECTED", "draft flows never produce VALIDATED findings");
      assert.ok(f.target.includes("{{orderA}}") || !f.target.includes("o-a-1"), "targets use the template form");
    }
    const orders = flowRun!.flows.find((f) => f.id === "orders-access")!;
    assert.equal(orders.status, "FAIL");
    assert.equal(orders.steps.find((s) => s.id === "S3")!.securityCase, "NSC-AC-003");
    assert.ok(orders.findings.length > 0);
    assert.ok(run.requests.some((q) => q.flow?.id === "orders-access" && q.url.endsWith("/api/orders/{{orderA}}")));
    assert.ok(run.requests.filter((q) => q.flow).every((q) => q.requestHeaders["x-navsentry-flow"]));
    assert.ok(run.checks.some((c) => c.ruleId === "NSC-INFO-001" && c.target.includes("/api/admin/stats")), "flow-only URLs go through the per-exchange security checks");
    assert.ok(JSON.stringify(renderSarif(run)).includes("NSC-AC-003"));
    const profile = flowRun!.flows.find((f) => f.id === "profile-journey")!;
    assert.equal(profile.status, "FAIL", "anonymous gets the profile page in the vulnerable variant");
    const all = renderJson(run) + JSON.stringify(flowRun) + renderTestMarkdown(flowRun!, run, "th") + renderMarkdown(run, "en") + renderJunit(flowRun!) + JSON.stringify(renderSarif(run));
    for (const secret of [...Object.values(FIXTURE_TOKENS), "fixture-reader-a-token"]) assert.ok(!all.includes(secret), `artifact leaked ${secret}`);
    assert.ok(!JSON.stringify(flowRun).includes("o-a-1"), "variable values are not written to flows.json");
  } finally {
    await demo.close();
  }
});

test("secure fixture: access expectations PASS; approved flows yield VALIDATED and UI steps stay NOT_TESTED", async () => {
  const sec = await startDemo("secure");
  const vuln = await startDemo("vulnerable");
  try {
    const approved = docs().map((d) => parseFlowText(approveText(d, "navsentry-tests", "2026-11-01"), d.file).doc!);
    assert.deepEqual(lintFlows(approved, manifest(sec.origin)).errors, []);
    const s = await executeTest(manifest(sec.origin), { env: ENV, flows: approved, flowsOnly: true });
    for (const id of ["NSC-AC-002", "NSC-AC-003", "NSC-AC-007"]) assert.equal(s.run.coverage.find((c) => c.ruleId === id)?.status, "PASS", id);
    const orders = s.flowRun!.flows.find((f) => f.id === "orders-access")!;
    assert.equal(orders.status, "PASS");
    assert.ok(orders.review.hashValid);
    const profile = s.flowRun!.flows.find((f) => f.id === "profile-journey")!;
    assert.equal(profile.status, "INCOMPLETE", "an E2E flow with UI steps is never PASS");
    assert.equal(profile.steps.find((x) => x.id === "S2")!.status, "NOT_TESTED");
    assert.match(profile.steps.find((x) => x.id === "S2")!.reason!, /playwright-browser/);
    assert.equal(profile.manualReplay.length, 2);
    assert.equal(s.flowRun!.functionalResult, "INCOMPLETE");
    assert.equal(s.flowRun!.summary.integration.PASS, 1);
    const v = await executeTest(manifest(vuln.origin), { env: ENV, flows: approved, flowsOnly: true });
    assert.equal(v.run.findings.find((f) => f.ruleId === "NSC-AC-003")!.lifecycle, "VALIDATED");
  } finally {
    await sec.close();
    await vuln.close();
  }
});

test("hostile extracted values never leave scope (0 bytes to denied paths)", async () => {
  const demo = await startDemo("vulnerable");
  try {
    const m = manifest(demo.origin, { targets: { origins: [demo.origin], allowed_paths: ["/**"], denied_paths: ["/admin/**", "/api/orders/o-*"], seed_paths: ["/"] } });
    const hostile = docs("flows-hostile");
    assert.deepEqual(lintFlows(hostile, m).errors, []);
    const { run, flowRun } = await executeTest(m, { flows: hostile, flowsOnly: true });
    const steps = flowRun!.flows[0]!.steps;
    for (const id of ["S2", "S3", "S4", "S5"]) {
      assert.equal(steps.find((x) => x.id === id)!.status, "ERROR", id);
      assert.match(steps.find((x) => x.id === id)!.reason!, /rejected by safety rule/);
    }
    assert.equal(steps.find((x) => x.id === "S6")!.status, "NOT_TESTED");
    assert.ok(run.denials.some((d) => d.url.includes("{{ok}}")), "the runtime denial is recorded in template form");
    assert.equal(demo.hits(), 1, "only S1 reached the target");
  } finally {
    await demo.close();
  }
});

test("budget exhaustion marks remaining steps NOT_TESTED and the run PARTIAL", async () => {
  const demo = await startDemo("secure");
  try {
    const m = manifest(demo.origin, { safety: { mode: "observe", max_requests: 2, max_requests_per_second: 20, max_duration_seconds: 60 } });
    const { run, flowRun } = await executeTest(m, { env: ENV, flows: docs(), flowsOnly: true });
    assert.equal(run.executionStatus, "PARTIAL");
    assert.ok(flowRun!.flows.flatMap((f) => f.steps).some((s) => s.reason === "budget exhausted"));
    assert.notEqual(flowRun!.functionalResult, "PASS");
  } finally {
    await demo.close();
  }
});

test("approval is pinned to content: editing an approved flow fails lint", async () => {
  const d = docs().find((x) => x.header.id === "orders-access")!;
  const text = approveText(d, "owner", "2026-11-01", "TICKET-1");
  const approved = parseFlowText(text, d.file).doc!;
  assert.equal(approved.header.review.content_sha256, flowHash(d));
  assert.ok(text.includes("Synthetic fixture flow"), "narrative is preserved");
  const edited = parseFlowText(text.replace('"min_items": 1', '"min_items": 2'), d.file).doc!;
  const m = manifest("http://127.0.0.1:9");
  assert.match(lintFlows([edited], m).errors.join(), /changed after approval/);
  assert.deepEqual(parseFlowText(initTemplate("new-flow", "New", "Story", "auto"), "n.flow.md").problems, []);
});

test("analyzer: zero network, deterministic, never encodes errors or values, leaves decisions to the owner", async () => {
  const demo = await startDemo("vulnerable");
  try {
    const m = manifest(demo.origin, { targets: { origins: [demo.origin], allowed_paths: ["/**"], denied_paths: ["/admin/**"], seed_paths: ["/", "/api/me", "/api/orders", "/api/admin/stats", "/api/error", "/go-in", "/app/profile"] } });
    const run = await executeRun(m, { env: ENV });
    const hits = demo.hits();
    const a = analyzeRun(run, m, new Set());
    const b = analyzeRun(run, m, new Set());
    assert.deepEqual([...a.files.entries()], [...b.files.entries()], "byte-identical output");
    assert.equal(demo.hits(), hits, "analyze must not contact the target");
    const flows = [...a.files.entries()].filter(([n]) => n.endsWith(".flow.md"));
    assert.ok(flows.length >= 2);
    const parsed = flows.map(([n, t]) => parseFlowText(t, n));
    for (const p of parsed) assert.deepEqual(p.problems, []);
    assert.deepEqual(lintFlows(parsed.map((p) => p.doc!), m).errors, []);
    const text = flows.map(([, t]) => t).join("\n");
    assert.ok(!text.includes("/api/error"), "server errors are not encoded");
    assert.ok(!/content-security-policy|set-cookie|"equals"/.test(text), "no security headers, cookies or values");
    assert.ok(parsed.every((p) => p.doc!.header.review.status === "draft"));
    const analysis = a.files.get("ANALYSIS.md")!;
    assert.match(analysis, /Is `\/api\/me` public\?/);
    assert.match(analysis, /status 500 observed/);
    const skip = analyzeRun(run, m, new Set(parsed.map((p) => p.doc!.header.id)));
    assert.equal([...skip.files.keys()].filter((n) => n.endsWith(".flow.md")).length, 0, "existing flows are never overwritten");
  } finally {
    await demo.close();
  }
});

test("compare: fix without story breakage, functional regression, changed steps", async () => {
  const vuln = await startDemo("vulnerable");
  const sec = await startDemo("secure");
  try {
    const d = docs().filter((x) => x.header.id === "orders-access");
    const b = await executeTest(manifest(vuln.origin), { env: ENV, flows: d, flowsOnly: true });
    const a = await executeTest(manifest(sec.origin), { env: ENV, flows: d, flowsOnly: true });
    const norm = (r: typeof b.run, o: string) => ({ ...r, requests: r.requests.map((q) => ({ ...q, url: q.url.replace(o, "http://demo") })) });
    const ok = compareRuns(norm(b.run, vuln.origin), norm(a.run, sec.origin), { before: b.flowRun!, after: a.flowRun! });
    assert.deepEqual(ok.flows!.regressions, []);
    assert.deepEqual(ok.contractDrift, [], "denied probes are not legitimate-caller contracts");
    assert.ok(ok.flows!.fixed.includes("orders-access/S3"));
    assert.ok(ok.fixed.includes("NSC-AC-003"));
    const broken: FlowRunResult = structuredClone(a.flowRun!);
    broken.flows[0]!.steps.find((s) => s.id === "S2")!.status = "FAIL";
    const reg = compareRuns(a.run, a.run, { before: a.flowRun!, after: broken });
    assert.equal(reg.verdict, "FUNCTIONAL_REGRESSION");
    const changed: FlowRunResult = structuredClone(a.flowRun!);
    changed.flows[0]!.steps[0]!.contentSha256 = "0".repeat(64);
    assert.ok(compareRuns(a.run, a.run, { before: a.flowRun!, after: changed }).flows!.notComparable.some((x) => x.includes("step changed")));
    assert.doesNotThrow(() => validateFlowRunResult(JSON.parse(JSON.stringify(a.flowRun))));
    assert.throws(() => validateFlowRunResult({ kind: "other" }));
  } finally {
    await vuln.close();
    await sec.close();
  }
});

test("CLI: test --flows writes flows.json, TEST-REPORT.md and junit; exit codes follow the spec", async () => {
  const demo = await startDemo("secure");
  const dir = mkdtempSync(join(tmpdir(), "navsentry-flow-"));
  const saved = { ...process.env };
  try {
    Object.assign(process.env, ENV);
    const mpath = join(dir, "m.json");
    writeFileSync(mpath, JSON.stringify({
      version: "1", project: "demo", environment: "local", authorization: { acknowledged: true, owner: "navsentry-tests" },
      targets: { origins: [demo.origin], allowed_paths: ["/**"], denied_paths: ["/admin/**"], seed_paths: ["/"] },
      network: { allow_private: [{ host: "127.0.0.1", approved_by: "navsentry-tests", reason: "local disposable demo app" }] },
      safety: { mode: "observe", max_requests: 100, max_requests_per_second: 20, max_duration_seconds: 60 },
      actors: ACTORS, checks: { disabled: ["NSC-CRYPT-006"] }, report: { language: "th", formats: ["json", "markdown", "sarif"] },
    }));
    const out = join(dir, "run");
    const flows = join(FIX, "flows");
    assert.equal(await main(["flow", "lint", "--config", mpath, "--flows", flows]), 0);
    assert.equal(await main(["test", "--config", mpath, "--flows", flows, "--out", out]), 3, "drafts are not selected without --include-drafts");
    assert.equal(await main(["test", "--config", mpath, "--flows", flows, "--include-drafts", "--level", "integration", "--flows-only", "--junit", "--out", out]), 0);
    assert.ok(readdirSync(out).includes("TEST-REPORT.md") && readdirSync(out).includes("flows.json") && readdirSync(out).includes("junit.xml"));
    assert.match(readFileSync(join(out, "REPORT.md"), "utf8"), /TEST-REPORT\.md/);
    assert.match(readFileSync(join(out, "TEST-REPORT.md"), "utf8"), /ผลการทดสอบการทำงาน/);
    assert.equal(await main(["test", "--config", mpath, "--flows", flows, "--include-drafts", "--flows-only", "--out", out]), 2, "E2E with UI steps is INCOMPLETE");
    assert.equal(await main(["compare", "--before", out, "--after", out]), 0);
    assert.equal(await main(["report", "--input", join(out, "flows.json"), "--format", "junit"]), 0);
    const init = join(dir, "flows");
    assert.equal(await main(["flow", "init", "--id", "my-story", "--title", "My story", "--out", init]), 0);
    assert.equal(await main(["flow", "init", "--id", "my-story", "--title", "My story", "--out", init]), 3, "never overwrites");
    assert.equal(await main(["flow", "approve", "--flows", join(init, "my-story.flow.md"), "--by", "owner"]), 0);
    assert.equal(await main(["flow", "lint", "--config", mpath, "--flows", init]), 0);
    const prod = join(dir, "prod.json");
    writeFileSync(prod, readFileSync(mpath, "utf8").replace('"environment":"local"', '"environment":"production"').replace('"owner":"navsentry-tests"}', '"owner":"navsentry-tests","reference":"CHG-1","expires_at":"2099-01-01"}'));
    assert.equal(await main(["test", "--config", prod, "--flows", flows, "--include-drafts", "--out", out]), 3, "drafts refused for production");
  } finally {
    process.env = saved;
    await demo.close();
  }
});

test("src/flow has no network path of its own", () => {
  const dir = join(process.cwd(), "src", "flow");
  for (const f of readdirSync(dir)) {
    const text = readFileSync(join(dir, f), "utf8");
    assert.ok(!/from "node:(http|https|net|tls|dns)"|transports\/direct-http|new DirectHttpAdapter/.test(text), `${f} must use the runner's send`);
  }
});

test("shipped example flows lint against the example manifest", () => {
  const m = loadManifest(join(process.cwd(), "examples", "manifest.flows.example.json"));
  const r = loadFlowFiles(join(process.cwd(), "examples", "flows"));
  assert.deepEqual(r.problems, []);
  assert.deepEqual(lintFlows(r.docs, m).errors, []);
});
