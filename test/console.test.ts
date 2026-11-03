/**
 * 0.1.3-k: runtime console checks (SPEC-0.1.3 §6.4-A, §10 test 13, S8, S9). Browser tests need the
 * approved Chromium headless shell (PLAYWRIGHT_BROWSERS_PATH) and are skipped with the reason otherwise.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConsoleInspector, templateOf } from "../src/console/detect.js";
import { parseFlowText, resolveDeps, type FlowDoc } from "../src/flow/parse.js";
import { executeTest } from "../src/runner.js";
import { probePlaywright } from "../src/transports/playwright.js";
import { CONSOLE_TEST_TOKEN, startBrowserFixture } from "./fixtures/browser-server.js";
import { localManifest } from "./helpers.js";

const probe = probePlaywright();
const skip = probe.usable ? false : `playwright engine unavailable: ${probe.reason}`;
const ENV = { NS_CONSOLE_READER: `Bearer ${CONSOLE_TEST_TOKEN}` };

const text = (header: object, ...steps: object[]) =>
  ["# t", "", "```navsentry-flow", JSON.stringify(header, null, 2), "```", "", ...steps.flatMap((s, i) => [`## S${i + 1}`, "```navsentry-step", JSON.stringify(s), "```", ""])].join("\n");

function flow(id: string, path: string, over: Record<string, unknown> = {}): FlowDoc[] {
  const r = parseFlowText(text({ flow: "1", id, title: id, story: `story ${id}`, actors: ["anonymous"], level: "e2e", ...over },
    { id: "S1", action: "navigate", actor: "anonymous", request: { method: "GET", path }, expect: { status: "2xx" } },
    { id: "S2", action: "see", actor: "anonymous", target: { role: "heading", name: path.split("/").pop()!.replace(/^./, (c) => c.toUpperCase()) } }), `${id}.flow.md`);
  assert.deepEqual(r.problems, []);
  resolveDeps([r.doc!]);
  return [r.doc!];
}

const manifest = (origin: string) =>
  localManifest(origin, { transports: { order: ["direct-http", "playwright-browser"] }, actors: { reader: { authorization_header_env: "NS_CONSOLE_READER" } }, checks: { disabled: ["NSC-CRYPT-006"] } });

const run = (origin: string, docs: FlowDoc[], browser = true) => executeTest(manifest(origin), { env: ENV, flows: docs, flowsOnly: true, ...(browser ? { browser: {} } : {}) });

test("a known test token in console output is NSC-INFO-006 VALIDATED with a masked preview only", { skip }, async () => {
  const fx = await startBrowserFixture();
  try {
    const r = await run(fx.origin, flow("leak", "/ui/leak"));
    const c = r.run.checks.find((x) => x.ruleId === "NSC-INFO-006" && x.status === "FAIL");
    assert.ok(c, JSON.stringify(r.run.checks.filter((x) => x.ruleId === "NSC-INFO-006")));
    assert.equal(c.lifecycle, "VALIDATED");
    const f = r.run.findings.find((x) => x.ruleId === "NSC-INFO-006")!;
    assert.equal(f.lifecycle, "VALIDATED");
    const fact = r.run.console!.facts.find((x) => x.caseId === "NSC-INFO-006")!;
    assert.match(fact.preview, /^\[known-secret,len=\d+\]$/);
    assert.ok(fact.exact);
    assert.ok(!JSON.stringify(r).includes(CONSOLE_TEST_TOKEN), "the token never reaches an artifact (S8)");
    // The page HTML has its own redacted excerpt; the console artifacts must carry no message text at all.
    const consoleArtifacts = JSON.stringify([r.run.console, r.run.checks.filter((x) => x.target.startsWith("console") || x.target === "browser console")]);
    assert.ok(!consoleArtifacts.includes("debug token"), "message text never reaches an artifact (S8)");
  } finally {
    await fx.close();
  }
});

test('console: "silent" turns harmless output into a functional FAIL, not a security finding', { skip }, async () => {
  const fx = await startBrowserFixture();
  try {
    const noisy = await run(fx.origin, flow("noisy", "/ui/noisy", { console: "silent" }));
    const f = noisy.flowRun!.flows[0]!;
    assert.equal(f.status, "FAIL");
    const a = f.steps.flatMap((s) => s.assertions).find((x) => x.kind === "console_silent" && x.status === "FAIL")!;
    assert.equal(a.observed, "1 console message(s)");
    assert.equal(noisy.run.checks.find((x) => x.ruleId === "NSC-INFO-006")!.status, "PASS");
    assert.ok(!noisy.run.findings.some((x) => x.ruleId === "NSC-INFO-006"));

    const quiet = await run(fx.origin, flow("quiet", "/ui/quiet", { console: "silent" }));
    assert.equal(quiet.flowRun!.flows[0]!.status, "PASS");
  } finally {
    await fx.close();
  }
});

test("a secret in a later same-template message is still detected", { skip }, async () => {
  const fx = await startBrowserFixture();
  try {
    const r = await run(fx.origin, flow("twice", "/ui/twice"));
    assert.ok(r.run.checks.some((x) => x.ruleId === "NSC-INFO-006" && x.status === "FAIL" && x.lifecycle === "VALIDATED"));
    assert.equal(r.run.console!.messages, 2);
  } finally {
    await fx.close();
  }
});

test("a console.log override and a ?debug toggle are observations only, and the toggle is never set (S9)", { skip }, async () => {
  const fx = await startBrowserFixture();
  try {
    const m = localManifest(fx.origin, { checks: { disabled: ["NSC-CRYPT-006"] } });
    const work = mkdtempSync(join(tmpdir(), "navsentry-console-"));
    let r: Awaited<ReturnType<typeof executeTest>>;
    try {
      r = await executeTest(m, { assets: true, workDir: work, urls: [`${fx.origin}/ui/hidden`] });
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
    const obs = r.run.checks.find((x) => x.ruleId === "NSC-INFO-006" && x.target.includes("/ui/hidden.js"))!;
    assert.equal(obs.status, "NOT_TESTED");
    assert.match(obs.reason ?? "", /static observation only/);
    assert.ok(obs.observations.some((o) => o.includes("console-override")), obs.observations.join("; "));
    assert.ok(!r.run.findings.some((x) => x.ruleId === "NSC-INFO-006"));
    assert.ok(!fx.hits.some((h) => /debug/i.test(h)), "a debug toggle was requested");

    // The page itself, in the browser: harmless output is hidden, so nothing is captured and nothing fails.
    const b = await run(fx.origin, flow("hidden", "/ui/hidden"));
    assert.equal(b.run.checks.find((x) => x.ruleId === "NSC-INFO-006" && x.target === "browser console")!.status, "PASS");
    assert.ok(!fx.hits.some((h) => /debug/i.test(h)));
  } finally {
    await fx.close();
  }
});

test("with the http engine the console checks are NOT_TESTED: no JS runtime", async () => {
  const fx = await startBrowserFixture();
  try {
    const r = await run(fx.origin, flow("leak", "/ui/leak", { console: "silent" }), false);
    const c = r.run.checks.find((x) => x.ruleId === "NSC-INFO-006")!;
    assert.equal(c.status, "NOT_TESTED");
    assert.equal(c.reason, "no JS runtime (http engine)");
    const silent = r.flowRun!.flows[0]!.steps[0]!.assertions.find((a) => a.kind === "console_silent")!;
    assert.equal(silent.status, "NOT_TESTED");
  } finally {
    await fx.close();
  }
});

test("inspector: bounded capture, value-free templates, every message inspected before dedup", () => {
  assert.equal(templateOf("session ref abcdef123456"), templateOf(`session ref ${CONSOLE_TEST_TOKEN}`));
  const i = new ConsoleInspector([CONSOLE_TEST_TOKEN], 2, 1024 * 1024, (u) => u);
  i.inspect({ type: "log", text: "session ref abcdef123456", sourceUrl: "http://127.0.0.1/a.js" });
  i.inspect({ type: "log", text: `session ref ${CONSOLE_TEST_TOKEN}`, sourceUrl: "http://127.0.0.1/a.js" });
  i.inspect({ type: "log", text: "third", sourceUrl: "" });
  assert.equal(i.summary.messages, 2);
  assert.equal(i.summary.dropped, 1, "messages past the limit are counted, not inspected");
  assert.deepEqual(i.summary.facts.map((f) => [f.caseId, f.exact]), [["NSC-INFO-006", true]]);
  assert.ok(!JSON.stringify(i.summary.facts).includes(CONSOLE_TEST_TOKEN));
  const pii = new ConsoleInspector([], 10, 1024 * 1024, (u) => u);
  pii.inspect({ type: "error", text: "TypeError: x\n    at f (http://127.0.0.1/app.js:10:5)", sourceUrl: "" });
  pii.inspect({ type: "log", text: "user jane@example.test", sourceUrl: "" });
  assert.deepEqual(pii.summary.facts.map((f) => f.caseId).sort(), ["NSC-ERR-001", "NSC-INFO-004"]);
});
