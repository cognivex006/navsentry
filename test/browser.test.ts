/**
 * M1b: Playwright browser engine and the S1 invariant (SPEC-0.1.3 §6.3, §9, §10 test 10).
 * Needs the governance-approved playwright-core and its Chromium headless shell
 * (PLAYWRIGHT_BROWSERS_PATH); without them every test here is skipped with the reason.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli.js";
import { lintFlows } from "../src/flow/lint.js";
import { parseFlowText, resolveDeps, type FlowDoc } from "../src/flow/parse.js";
import { executeTest } from "../src/runner.js";
import { ISOLATION_ARGS, probePlaywright } from "../src/transports/playwright.js";
import { startBrowserFixture } from "./fixtures/browser-server.js";
import { localManifest } from "./helpers.js";

const probe = probePlaywright();
const skip = probe.usable ? false : `playwright engine unavailable: ${probe.reason}`;

const text = (header: object, ...steps: object[]) =>
  ["# t", "", "```navsentry-flow", JSON.stringify(header, null, 2), "```", "", ...steps.flatMap((s, i) => [`## S${i + 1}`, "```navsentry-step", JSON.stringify(s), "```", ""])].join("\n");

function flow(id: string, ...steps: object[]): FlowDoc[] {
  const r = parseFlowText(text({ flow: "1", id, title: id, story: `story ${id}`, actors: ["anonymous"], level: "e2e" }, ...steps), `${id}.flow.md`);
  assert.deepEqual(r.problems, []);
  resolveDeps([r.doc!]);
  return [r.doc!];
}

const manifest = (origin: string, over: Record<string, unknown> = {}) =>
  localManifest(origin, { transports: { order: ["direct-http", "playwright-browser"] }, checks: { disabled: ["NSC-CRYPT-006"] }, ...over });

const SHOP = [
  { id: "S1", action: "navigate", actor: "anonymous", request: { method: "GET", path: "/ui/" }, expect: { status: "2xx" } },
  { id: "S2", action: "see", actor: "anonymous", target: { role: "heading", name: "Shop" } },
  { id: "S3", action: "click", actor: "anonymous", target: { role: "link", name: "Next page" } },
  { id: "S4", action: "see", actor: "anonymous", target: { text: "Signed cookie seen" } },
  { id: "S5", action: "see", actor: "anonymous", target: { text: "Not on this page" } },
] as const;

test("browser steps run and every channel stays inside ScopeGate (S1)", { skip }, async () => {
  const fx = await startBrowserFixture();
  try {
    const m = manifest(fx.origin);
    const docs = flow("shop", ...SHOP);
    assert.deepEqual(lintFlows(docs, m).errors, []);
    const r = await executeTest(m, { flows: docs, flowsOnly: true, browser: {} });
    const steps = r.flowRun!.flows[0]!.steps;
    assert.deepEqual(steps.map((s) => s.status), ["PASS", "PASS", "PASS", "PASS", "FAIL"], JSON.stringify(steps.map((s) => s.reason ?? s.assertions)));
    assert.equal(steps[4]!.assertions[0]!.observed, "not visible before timeout");

    // Pre-request scope: the off-scope image and fetch never reached the canary origin.
    assert.equal(fx.canaryHits(), 0, "off-scope origin was contacted");
    assert.ok(r.run.denials.some((d) => d.url.startsWith(fx.canary)), "off-scope requests are recorded as denials");
    // Disabled channels: WebSocket, service worker, state-changing request.
    assert.equal(fx.upgrades(), 0, "WebSocket upgrade reached the app");
    assert.ok(r.run.denials.some((d) => /WebSocket is disabled/.test(d.reason)));
    assert.ok(!fx.hits.includes("GET /ui/sw.js"), "service worker script was fetched");
    assert.ok(!fx.hits.some((h) => h.startsWith("POST ")), "a POST reached the app");
    assert.ok(r.run.denials.some((d) => d.method === "POST" && /state-changing/.test(d.reason)));
    // Every request the app saw is one NavSentry recorded (and counted against the Budget).
    assert.equal(fx.hits.length, r.run.requests.length, `app saw ${fx.hits.join(", ")}`);
    assert.ok(r.run.requests.every((q) => q.transport === "direct-http"));
    // Cookies stay in the browser context (S4 saw the cookie) but never reach artifacts.
    assert.ok(!JSON.stringify(r).includes("fixture_session=s1"));
  } finally {
    await fx.close();
  }
});

test("the shared Budget bounds browser requests; nothing goes past it", { skip }, async () => {
  const fx = await startBrowserFixture();
  try {
    const m = manifest(fx.origin, { safety: { mode: "observe", max_requests: 2, max_requests_per_second: 20, max_duration_seconds: 60 } });
    const r = await executeTest(m, { flows: flow("shop", ...SHOP), flowsOnly: true, browser: {} });
    assert.ok(fx.hits.length <= 2, `app saw ${fx.hits.length} requests`);
    assert.ok(r.run.requests.length <= 2);
    assert.ok(r.run.incompleteReasons.some((x) => /budget/i.test(x)) || r.flowRun!.flows[0]!.steps.some((s) => s.reason === "budget exhausted"));
  } finally {
    await fx.close();
  }
});

test("state-changing UI steps stay NOT_TESTED until M2, even with the browser", { skip }, async () => {
  const fx = await startBrowserFixture();
  try {
    const m = manifest(fx.origin);
    const docs = flow("fill", SHOP[0], { id: "S2", action: "fill", actor: "anonymous", target: { label: "Name" }, value: { var: "who" } });
    docs[0]!.header.vars = { who: { value: "x" } };
    const r = await executeTest(m, { flows: docs, flowsOnly: true, browser: {} });
    const s = r.flowRun!.flows[0]!.steps[1]!;
    assert.equal(s.status, "NOT_TESTED");
    assert.match(s.reason ?? "", /safe-validate \(M2\)/);
  } finally {
    await fx.close();
  }
});

test("without a usable browser, UI steps are NOT_TESTED and nothing falls back to http (S6)", async () => {
  const fx = await startBrowserFixture();
  try {
    const m = manifest(fx.origin);
    const absent = () => ({ available: false, usable: false, reason: "optional package 'playwright-core' is not installed" });
    const r = await executeTest(m, { flows: flow("shop", ...SHOP), flowsOnly: true, browser: { probe: absent } });
    const steps = r.flowRun!.flows[0]!.steps;
    assert.ok(steps.slice(1).every((s) => s.status === "NOT_TESTED"), JSON.stringify(steps.map((s) => s.status)));
    assert.ok(r.run.incompleteReasons.some((x) => x.startsWith("playwright engine unavailable")));
    assert.deepEqual(fx.hits, ["GET /ui/"], "only the navigate step ran, over http");
  } finally {
    await fx.close();
  }
});

test("launch flags alone leave the browser without a network path (defence in depth)", { skip }, async () => {
  const fx = await startBrowserFixture();
  const { chromium } = createRequire(import.meta.url)("playwright-core") as { chromium: { launch(o: object): Promise<{ newPage(): Promise<{ goto(u: string, o: object): Promise<unknown> }>; close(): Promise<void> }> } };
  const b = await chromium.launch({ headless: true, args: ISOLATION_ARGS });
  try {
    const p = await b.newPage();
    // No route() here on purpose: only the launch flags stand between the page and the canary.
    await assert.rejects(p.goto(`${fx.canary}/direct`, { timeout: 5000 }));
    await assert.rejects(p.goto("http://localhost:9/", { timeout: 5000 }));
    assert.equal(fx.canaryHits(), 0);
  } finally {
    await b.close();
    await fx.close();
  }
});

test("CLI: scan --mode flow --engine playwright runs the UI flow end to end", { skip }, async () => {
  const fx = await startBrowserFixture();
  const dir = mkdtempSync(join(tmpdir(), "navsentry-browser-"));
  try {
    const flows = join(dir, "flows");
    mkdirSync(flows);
    writeFileSync(join(flows, "shop.flow.md"), text({ flow: "1", id: "shop", title: "shop", story: "story shop", actors: ["anonymous"], level: "e2e" }, ...SHOP.slice(0, 4)));
    const mpath = join(dir, "m.json");
    writeFileSync(mpath, JSON.stringify({
      version: "1", project: "browser", environment: "local", authorization: { acknowledged: true, owner: "t" },
      targets: { origins: [fx.origin], seed_paths: ["/ui/"] },
      network: { allow_private: [{ host: "127.0.0.1", approved_by: "t", reason: "fixture" }] },
      safety: { mode: "observe", max_requests: 50, max_requests_per_second: 20, max_duration_seconds: 60 },
      transports: { order: ["direct-http", "playwright-browser"] }, checks: { disabled: ["NSC-CRYPT-006"] }, report: { language: "en", formats: ["json"] },
    }));
    const out = join(dir, "run");
    // Exit 1: the fixture page lacks security headers, so security findings are expected; the flow itself passes.
    assert.equal(await main(["scan", "--config", mpath, "--mode", "flow", "--engine", "playwright", "--flows", flows, "--include-drafts", "--project", dir, "--out", out]), 1);
    const fr = JSON.parse(readFileSync(join(out, "flows.json"), "utf8")) as { flows: { id: string; status: string; steps: { status: string }[] }[] };
    assert.deepEqual(fr.flows[0]!.steps.map((x) => x.status), ["PASS", "PASS", "PASS", "PASS"]);
    assert.equal(fx.canaryHits(), 0);
    // Replay timeline: one viewport PNG per browser step, beside the report, git-ignored.
    const shots = (fr.flows[0]!.steps as { screenshot?: string }[]).map((x) => x.screenshot);
    assert.deepEqual(shots, ["shop-S1.png", "shop-S2.png", "shop-S3.png", "shop-S4.png"]);
    for (const s of shots) assert.deepEqual([...readFileSync(join(out, "shots", s!)).subarray(0, 4)], [0x89, 0x50, 0x4e, 0x47], `${s} is a PNG`);
    assert.equal(readFileSync(join(out, "shots", ".gitignore"), "utf8"), "*\n");
    const tr = readFileSync(join(out, "TEST-REPORT.md"), "utf8");
    assert.match(tr, /## Replay timeline/);
    assert.match(tr, /!\[shop S3 PASS\]\(shots\/shop-S3\.png\)/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    await fx.close();
  }
});
