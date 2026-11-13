/** SPEC-0.4.0 M1b+ DOM checks: script-readable cookies, cross-origin framing and CSP enforcement in the browser. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { executeTest } from "../src/runner.js";
import { parseFlowText, resolveDeps, type FlowDoc } from "../src/flow/parse.js";
import { probePlaywright } from "../src/transports/playwright.js";
import type { CheckResult } from "../src/types.js";
import { startBrowserFixture } from "./fixtures/browser-server.js";
import { localManifest } from "./helpers.js";

const probe = probePlaywright();
const skip = probe.usable ? false : `playwright engine unavailable: ${probe.reason}`;

function flow(path: string): FlowDoc[] {
  const t = ["# t", "", "```navsentry-flow", JSON.stringify({ flow: "1", id: "dom", title: "dom", story: "story dom", actors: ["anonymous"], level: "e2e" }), "```", "", "## S1", "```navsentry-step",
    JSON.stringify({ id: "S1", action: "navigate", actor: "anonymous", request: { method: "GET", path }, expect: { status: "2xx" } }), "```", ""].join("\n");
  const r = parseFlowText(t, "dom.flow.md");
  assert.deepEqual(r.problems, []);
  resolveDeps([r.doc!]);
  return [r.doc!];
}

const dom = (checks: CheckResult[], id: string) => checks.filter((c) => c.ruleId === id && c.transport === "playwright-browser");

async function run(path: string) {
  const fx = await startBrowserFixture();
  try {
    const m = localManifest(fx.origin, { transports: { order: ["direct-http", "playwright-browser"] }, checks: { disabled: ["NSC-CRYPT-006"] } });
    const r = await executeTest(m, { flows: flow(path), flowsOnly: true, browser: {} });
    return { r, hits: [...fx.hits], canary: fx.canaryHits() };
  } finally {
    await fx.close();
  }
}

test("vulnerable page: session cookie readable by scripts and the page frames cross-origin", { skip }, async () => {
  const { r, canary } = await run("/dom/vuln");
  const [c] = dom(r.run.checks, "NSC-SESS-002");
  assert.equal(c?.status, "FAIL", JSON.stringify(c));
  assert.ok(c!.observations.some((o) => o.includes("dom_session")));
  assert.ok(!JSON.stringify(r.run).includes("d1;") && !c!.observations.some((o) => o.includes("=d1")), "cookie values never reach run.json");
  const [f] = dom(r.run.checks, "NSC-CONF-003");
  assert.equal(f?.status, "FAIL", JSON.stringify(f));
  assert.equal(f!.lifecycle, "VALIDATED");
  assert.equal(dom(r.run.checks, "NSC-CONF-002").length, 0, "no CSP, no violations");
  assert.equal(canary, 0);
  assert.ok(!r.run.requests.some((q) => q.url.includes("navsentry-frame-probe")), "the probe parent page is never sent");
});

test("secure page: HttpOnly cookie, framing refused, CSP enforced in the browser", { skip }, async () => {
  const { r } = await run("/dom/secure");
  assert.equal(dom(r.run.checks, "NSC-SESS-002")[0]?.status, "PASS");
  assert.equal(dom(r.run.checks, "NSC-CONF-003")[0]?.status, "PASS", JSON.stringify(dom(r.run.checks, "NSC-CONF-003")));
  const [p] = dom(r.run.checks, "NSC-CONF-002");
  assert.equal(p?.status, "PASS", JSON.stringify(p));
  assert.ok(p!.observations.some((o) => /script-src/.test(o)));
  assert.equal(r.flowRun!.flows[0]!.steps[0]!.status, "PASS", "the secure variant keeps the response contract");
});
