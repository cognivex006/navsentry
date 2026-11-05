/**
 * SPEC-0.2.0 milestone 0.2.0-d acceptance tests 11 and 14 (fixture only, 127.0.0.1):
 * NSC-BIZ-001 owner-declared invariants and NSC-INJ-004 marker reflection as an observation.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConfigError, parseManifest, type Manifest } from "../src/config.js";
import { markerContexts } from "../src/fixtures/lifecycle.js";
import { parseFlowText, resolveDeps, type FlowDoc } from "../src/flow/parse.js";
import { renderMarkdown } from "../src/report/render.js";
import { executeTest } from "../src/runner.js";
import { startFixtureServer, type FixtureMode } from "./fixtures/fixture-server.js";

const ENV = { NS_A: "Bearer sv-reader-a", NS_ADMIN: "Bearer sv-fixture-admin" };
const RULES = {
  invariants: [{ name: "total-not-negative", pointer: "/total", op: ">=", value: 0 }, { name: "known-status", pointer: "/status", op: "in", value: ["open", "cancelled", "refunded"] }],
  forbidden_transitions: [{ name: "no-refund-while-open", pointer: "/status", from: "open", to: "refunded" }],
};
const fixture = (rules: object = RULES) => ({
  owner_actor: "reader_a", cleanup_actor: "fixture_admin",
  create: { method: "POST", path: "/api/test-fixtures/orders", body: { json: { note: "{{marker}}" } }, extract: { id: "/id" } },
  exists: { method: "GET", path: "/api/orders/{{id}}", expect_status: [200] },
  cleanup: { method: "DELETE", path: "/api/test-fixtures/orders/{{id}}", expect_status: [204, 404] },
  allowed_mutations: [{ method: "PATCH", path: "/api/orders/{{id}}", content_type: "application/json" }],
  ...rules,
});
function manifest(origin: string, fx: object = fixture()): Manifest {
  return parseManifest({
    version: "1", project: "svd", environment: "local",
    authorization: { acknowledged: true, owner: "navsentry-tests" },
    targets: { origins: [origin], allowed_paths: ["/api/**", "/ui/**"], denied_paths: [], seed_paths: [] },
    network: { allow_private: [{ host: "127.0.0.1", approved_by: "navsentry-tests", reason: "local fixture app" }] },
    safety: { mode: "safe-validate", max_requests: 100, max_requests_per_second: 20, max_duration_seconds: 120 },
    actors: { reader_a: { authorization_header_env: "NS_A" }, fixture_admin: { authorization_header_env: "NS_ADMIN" } },
    fixtures: { orders: fx },
    report: { language: "en", formats: ["json", "markdown"] },
  });
}
const flow = (steps: object[]): FlowDoc => {
  const text = ["# d", "", "```navsentry-flow", JSON.stringify({ flow: "1", id: "svd", title: "svd", story: "story", actors: ["reader_a"] }), "```", "",
    ...steps.flatMap((s, i) => [`## S${i + 1}`, "```navsentry-step", JSON.stringify(s), "```", ""])].join("\n");
  const r = parseFlowText(text, "svd.flow.md");
  assert.deepEqual(r.problems, []);
  resolveDeps([r.doc!]);
  return r.doc!;
};
async function run(mode: FixtureMode, steps: object[], fx?: object) {
  const s = await startFixtureServer(mode);
  try {
    const out = await executeTest(manifest(s.origin, fx), { env: ENV, flows: [flow(steps)], flowsOnly: true, fixtureWorkDir: mkdtempSync(join(tmpdir(), "ns-svd-")) });
    return { ...out, log: [...s.log], objects: new Set(s.objects) };
  } finally {
    await s.close();
  }
}
const CREATE = { id: "S1", action: "fixture_create", actor: "reader_a", fixture: "orders", as: "o" };
const BAD_PATCH = { id: "S2", action: "http", actor: "reader_a", fixture: "orders", request: { method: "PATCH", path: "/api/orders/{{o}}", body: { json: { total: -5, status: "refunded" } } }, expect: { status: [200, 422] } };
const biz = (r: Awaited<ReturnType<typeof run>>) => r.run.checks.filter((c) => c.ruleId === "NSC-BIZ-001");

test("11: config — invariants are owner-declared and strictly typed", () => {
  const bad = (rules: object, re: RegExp) => assert.throws(() => manifest("http://127.0.0.1:9", fixture(rules)), (e: unknown) => e instanceof ConfigError && re.test(e.message), String(re));
  bad({ invariants: [{ name: "x", pointer: "/total", op: ">", value: 0 }] }, /op: >=, <=, ==, != or in/);
  bad({ invariants: [{ name: "x", pointer: "/total", op: ">=", value: "0" }] }, /a number for >=/);
  bad({ invariants: [{ name: "x", pointer: "total", op: "==", value: 1 }] }, /a JSON pointer/);
  bad({ invariants: [{ name: "x", pointer: "/s", op: "in", value: [] }] }, /non-empty array/);
  bad({ forbidden_transitions: [{ name: "x", pointer: "/s", from: {}, to: "a" }] }, /scalars/);
  bad({ invariants: [{ name: "x", pointer: "/s", op: "==", value: 1, extra: 1 }] }, /extra: unknown key/);
});

test("11: NSC-BIZ-001 — violated invariant and forbidden transition FAIL; secure PASS; none declared NOT_TESTED", async () => {
  const vuln = await run("vulnerable", [CREATE, BAD_PATCH]);
  const v = biz(vuln)[0]!;
  assert.equal(v.status, "FAIL", JSON.stringify(v));
  assert.ok(v.observations.some((o) => /violated total-not-negative/.test(o)));
  assert.ok(v.observations.some((o) => /violated no-refund-while-open/.test(o)));
  assert.ok(!JSON.stringify(vuln.run).includes("\"total\":-5"), "observed values are not recorded");
  assert.equal(vuln.run.findings.find((f) => f.ruleId === "NSC-BIZ-001")?.lifecycle, "SUSPECTED", "a draft flow stays suspected");
  assert.equal(vuln.objects.size, 0, "invariants are read before cleanup, and cleanup still runs");

  const secure = await run("secure", [CREATE, BAD_PATCH]);
  assert.equal(biz(secure)[0]?.status, "PASS", JSON.stringify(biz(secure)));

  const none = await run("vulnerable", [CREATE, BAD_PATCH], fixture({}));
  assert.equal(biz(none)[0]?.status, "NOT_TESTED");
  assert.match(biz(none)[0]!.reason!, /never invents/);
});

test("14: NSC-INJ-004 — a reflected marker is a fact in observations; the case stays NOT_TESTED", async () => {
  assert.deepEqual(markerContexts('<div title="nsv-1">x</div><script>var a="nsv-1"</script><p>nsv-1</p>', "nsv-1"), { attribute: 1, script: 1 });
  const r = await run("secure", [CREATE, { id: "S2", action: "navigate", actor: "reader_a", request: { method: "GET", path: "/ui/orders/{{o}}" }, expect: { status: "2xx" } }]);
  const obs = r.run.observations!;
  assert.deepEqual(obs.map((o) => o.context).sort(), ["attribute", "script"]);
  const inj = r.run.checks.filter((c) => c.ruleId === "NSC-INJ-004");
  assert.equal(inj.length, 1);
  assert.equal(inj[0]!.status, "NOT_TESTED");
  assert.match(inj[0]!.reason!, /needs an injection payload \(active-approved\)/);
  assert.ok(!r.run.findings.some((f) => f.ruleId === "NSC-INJ-004"));
  assert.match(renderMarkdown(r.run), /Marker reflections \(facts, not results\)/);
});
