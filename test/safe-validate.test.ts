/**
 * SPEC-0.2.0 milestone 0.2.0-a acceptance tests 1–7 (fixture only, 127.0.0.1).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Budget, BudgetExceeded } from "../src/budget.js";
import { ConfigError, parseManifest, type Manifest } from "../src/config.js";
import { fillBody, PENDING_FILE, readPending, type FixtureLifecycle } from "../src/fixtures/lifecycle.js";
import { SignalCoordinator } from "../src/fixtures/signals.js";
import { lintFlows } from "../src/flow/lint.js";
import { parseFlowText } from "../src/flow/parse.js";
import { fillTemplate, ScopeGate, templateRegExp, validMutationId } from "../src/scope.js";
import { executeTest, type ExecuteOptions } from "../src/runner.js";
import { startFixtureServer, type FixtureMode } from "./fixtures/fixture-server.js";

const ENV = { NS_SV_A: "Bearer sv-reader-a", NS_SV_ADMIN: "Bearer sv-fixture-admin" };
const ORDERS = {
  owner_actor: "reader_a",
  cleanup_actor: "fixture_admin",
  create: { method: "POST", path: "/api/test-fixtures/orders", body: { json: { note: "{{marker}}" } }, extract: { id: "/id" } },
  exists: { method: "GET", path: "/api/orders/{{id}}", expect_status: [200] },
  cleanup: { method: "DELETE", path: "/api/test-fixtures/orders/{{id}}", expect_status: [200, 204, 404] },
  verify_gone: { method: "GET", path: "/api/orders/{{id}}", expect_status: [404, 410] },
  allowed_mutations: [{ method: "PATCH", path: "/api/orders/{{id}}", content_type: "application/json", max_body_bytes: 4096 }],
};

function raw(origin: string, over: { safety?: object; fixtures?: object; environment?: string; [k: string]: unknown } = {}): Record<string, unknown> {
  const host = new URL(origin).hostname;
  const { safety, fixtures, ...rest } = over;
  return {
    version: "1", project: "sv", environment: "local",
    authorization: { acknowledged: true, owner: "navsentry-tests" },
    targets: { origins: [origin], allowed_paths: ["/api/**"], denied_paths: ["/api/admin/**"], seed_paths: [] },
    network: { allow_private: [{ host, approved_by: "navsentry-tests", reason: "local fixture app" }] },
    safety: { mode: "safe-validate", max_requests: 100, max_requests_per_second: 20, max_duration_seconds: 120, ...(safety ?? {}) },
    actors: { reader_a: { authorization_header_env: "NS_SV_A" }, fixture_admin: { authorization_header_env: "NS_SV_ADMIN" } },
    fixtures: fixtures ?? { orders: ORDERS },
    report: { language: "en", formats: ["json"] },
    ...rest,
  };
}
const manifest = (origin: string, over: Parameters<typeof raw>[1] = {}): Manifest => parseManifest(raw(origin, over));

const flow = (...steps: object[]) => {
  const text = ["# sv", "", "```navsentry-flow", JSON.stringify({ flow: "1", id: "sv-flow", title: "SV", story: "Fixture lifecycle", actors: ["reader_a"] }), "```", "",
    ...steps.flatMap((s, i) => [`## S${i + 1}`, "```navsentry-step", JSON.stringify(s), "```", ""])].join("\n");
  const r = parseFlowText(text, "sv.flow.md");
  assert.deepEqual(r.problems, []);
  return r.doc!;
};
const CREATE = { id: "S1", action: "fixture_create", actor: "reader_a", fixture: "orders", as: "orderA" };
const PATCH = { id: "S2", action: "http", actor: "reader_a", fixture: "orders", request: { method: "PATCH", path: "/api/orders/{{orderA}}", body: { json: { note: "{{marker}}" } } }, expect: { status: "2xx" } };

async function run(mode: FixtureMode, steps: object[], over: Parameters<typeof raw>[1] = {}, opts: ExecuteOptions = {}) {
  const s = await startFixtureServer(mode);
  try {
    const m = manifest(s.origin, over);
    const dir = mkdtempSync(join(tmpdir(), "ns-sv-"));
    const out = await executeTest(m, { env: ENV, flows: [flow(...steps)], flowsOnly: true, fixtureWorkDir: dir, fixtureRetryDelayMs: 10, ...opts });
    return { ...out, log: [...s.log], objects: new Set(s.objects), dir };
  } finally {
    await s.close();
  }
}

test("1: config refusals (observe, production profile, out-of-scope path, allow_mutations)", () => {
  const o = "http://127.0.0.1:9";
  const bad = (over: Parameters<typeof raw>[1], re: RegExp) => assert.throws(() => manifest(o, over), (e: unknown) => e instanceof ConfigError && re.test(e.message));
  bad({ safety: { mode: "observe" } }, /fixtures, auth_endpoints: need safety.mode safe-validate/);
  for (const environment of ["staging", "production", "qa-cluster"]) bad({ environment, authorization: { acknowledged: true, owner: "o", reference: "CHG-1", expires_at: "2099-01-01" } }, /production profile .* limited to observe/);
  bad({ fixtures: { orders: { ...ORDERS, cleanup: { ...ORDERS.cleanup, path: "/api/admin/orders/{{id}}" } } } }, /cleanup\.path: matches targets\.denied_paths/);
  bad({ fixtures: { orders: { ...ORDERS, exists: { ...ORDERS.exists, path: "/other/{{id}}" } } } }, /exists\.path: not in targets\.allowed_paths/);
  bad({ safety: { allow_mutations: true } }, /allow_mutations/);
  bad({ fixtures: { orders: { ...ORDERS, exists: { ...ORDERS.exists, path: "/api/orders/x{{id}}" } } } }, /whole path segment/);
  bad({ safety: { max_mutations: 201 } }, /max_mutations/);
  const m = manifest(o);
  assert.equal(m.safety.max_mutations, 20);
  assert.equal(m.safety.cleanup_window_seconds, 30);
});

test("2: S13 — only declared entries; observe checkRequest still refuses mutations; lint refuses undeclared steps", async () => {
  const m = manifest("http://127.0.0.1:9");
  const g = new ScopeGate(m);
  const e = { method: "PATCH", path: "/api/orders/{{id}}" };
  assert.equal(g.checkMutation("http://127.0.0.1:9/api/orders/o1", "PATCH", e).allowed, true);
  assert.equal(g.checkMutation("http://127.0.0.1:9/api/orders/o1", "DELETE", e).allowed, false, "method must equal the entry");
  assert.equal(g.checkMutation("http://127.0.0.1:9/api/orders", "PATCH", e).allowed, false, "collection path");
  assert.equal(g.checkMutation("http://127.0.0.1:9/api/orders/o1/x", "PATCH", e).allowed, false, "extra segment");
  assert.equal(g.checkMutation("http://127.0.0.1:9/api/orders/a/../o1", "PATCH", e).allowed, true, "normalised before matching");
  assert.equal(g.checkMutation("http://127.0.0.1:9/api/orders/a%2fb", "PATCH", e).allowed, false);
  assert.equal(g.checkMutation("http://127.0.0.2:9/api/orders/o1", "PATCH", e).allowed, false, "other origin");
  assert.equal(g.checkRequest("http://127.0.0.1:9/api/orders/o1", "PATCH").allowed, false, "observe path keeps refusing");
  const obs = (() => { const r = raw("http://127.0.0.1:9", { safety: { mode: "observe" } }); delete r.fixtures; return new ScopeGate(parseManifest(r)); })();
  assert.equal(obs.checkMutation("http://127.0.0.1:9/api/orders/o1", "PATCH", e).allowed, false, "observe mode never mutates");
  // Lint: undeclared method/path, redirects and missing fixture.
  const lint = (s: object) => lintFlows([flow(CREATE, s)], m).errors.join("\n");
  assert.match(lint({ ...PATCH, request: { ...PATCH.request, method: "PUT" } }), /matches no allowed_mutations entry/);
  assert.match(lint({ ...PATCH, request: { ...PATCH.request, path: "/api/orders" } }), /matches no allowed_mutations entry/);
  assert.match(lint({ ...PATCH, follow_redirects: true }), /never follow redirects/);
  assert.match(parseFlowText(["```navsentry-flow", JSON.stringify({ flow: "1", id: "x", title: "x", story: "x", actors: ["reader_a"] }), "```", "```navsentry-step", JSON.stringify({ ...PATCH, fixture: undefined }), "```"].join("\n"), "x.flow.md").problems.join(), /needs "fixture"/);
  // Runtime: a 307 from a mutation is a result; the undeclared target never sees a request.
  const r = await run("patch-redirect", [CREATE, { ...PATCH, expect: { status: [307] } }]);
  assert.ok(!r.log.includes("PATCH /api/undeclared") && !r.log.some((l) => l.endsWith("/api/undeclared")));
  assert.equal(r.run.fixtures!.leftovers.length, 0);
});

test("3: ids — unsafe values are refused before a URL is built", async () => {
  for (const v of ["..", ".", "%2e%2e", "a/b", "?x", "#", "~", "", "x".repeat(200), -1, 1.5, null, {}]) assert.equal(validMutationId(v), undefined, JSON.stringify(v));
  assert.equal(validMutationId("o-1_A"), "o-1_A");
  assert.equal(validMutationId(42), "42");
  assert.throws(() => fillTemplate("/api/orders/{{id}}", ".."), /id rule/);
  assert.ok(!templateRegExp("/api/orders/{{id}}").test("/api/orders/a/b"));
  assert.match(fillBody({ a: "x{{marker}}" }, () => "m").error!, /whole string/);
  assert.equal(fillBody({ a: "{{marker}}", b: [1, true] }, () => "nsv-1").data!.toString(), '{"a":"nsv-1","b":[1,true]}');
  // A create returning ".." is an unknown outcome; no DELETE is ever sent, least of all to the collection.
  const r = await run("bad-id", [CREATE]);
  assert.equal(r.run.executionStatus, "FAILED");
  assert.equal(r.run.fixtures!.leftovers[0]!.status, "unknown-outcome");
  assert.ok(!r.log.some((l) => l.startsWith("DELETE")), r.log.join(","));
});

test("4: cleanup runs at normal end, after a failing step, after max_mutations, and on a first signal", async () => {
  const ok = await run("secure", [CREATE, PATCH]);
  assert.equal(ok.run.executionStatus, "COMPLETE", ok.run.incompleteReasons.join("; "));
  assert.deepEqual(ok.log, ["POST /api/test-fixtures/orders", "GET /api/orders/o1", "PATCH /api/orders/o1", "DELETE /api/test-fixtures/orders/o1", "GET /api/orders/o1"]);
  assert.equal(ok.objects.size, 0);
  assert.deepEqual({ c: ok.run.fixtures!.created, k: ok.run.fixtures!.cleaned, v: ok.run.fixtures!.verifiedGone }, { c: 1, k: 1, v: 1 });
  assert.match(ok.run.marker!, /^nsv-[0-9a-f]{16}$/);
  assert.ok(ok.run.mutations!.every((x) => !("body" in x)) && ok.run.mutations!.some((x) => x.bodySha256));
  assert.ok(!existsSync(join(ok.dir, PENDING_FILE)) || readPending(ok.dir).length === 0, "pending intents resolved");

  const failing = await run("secure", [CREATE, { id: "S2", action: "http", actor: "reader_a", request: { method: "GET", path: "/api/ok" }, expect: { status: [418] } }]);
  assert.ok(failing.log.includes("DELETE /api/test-fixtures/orders/o1"));
  assert.equal(failing.objects.size, 0);

  const limited = await run("secure", [CREATE, PATCH], { safety: { max_mutations: 1 } });
  assert.ok(!limited.log.includes("PATCH /api/orders/o1"), "the mutation limit stops the PATCH");
  assert.ok(limited.log.includes("DELETE /api/test-fixtures/orders/o1"), "the reserve still covers cleanup");
  assert.equal(limited.objects.size, 0);

  // First SIGINT while the fixture server holds a request: no new steps, cleanup still runs.
  const s = await startFixtureServer("secure");
  try {
    const coord = new SignalCoordinator(() => assert.fail("no second signal"));
    const held = s.held().then(() => { coord.handle("SIGINT"); s.release(); });
    const r = await executeTest(manifest(s.origin), { env: ENV, flowsOnly: true, fixtureWorkDir: mkdtempSync(join(tmpdir(), "ns-sv-")), fixtureRetryDelayMs: 10, onFixtures: (l) => coord.attach(l),
      flows: [flow(CREATE, { id: "S2", action: "http", actor: "reader_a", request: { method: "GET", path: "/api/hold" }, expect: { status: [200] } }, { ...PATCH, id: "S3" })] });
    await held;
    assert.equal(coord.signal, "SIGINT");
    assert.ok(!s.log.includes("PATCH /api/orders/o1"), "nothing new after the signal");
    assert.ok(s.log.includes("DELETE /api/test-fixtures/orders/o1"));
    assert.equal(s.objects.size, 0);
    assert.ok(r.run.incompleteReasons.some((x) => /stopped: SIGINT/.test(x)));
  } finally {
    await s.close();
  }

  // Second signal: cleanup skipped, leftovers listed, pending file kept for the next sweep.
  const s2 = await startFixtureServer("secure");
  try {
    const dir = mkdtempSync(join(tmpdir(), "ns-sv-"));
    let exited: { code: number; lines: string[] } | undefined;
    let life: FixtureLifecycle | undefined;
    const coord = new SignalCoordinator((code, lines) => { exited = { code, lines }; });
    const held = s2.held().then(() => { coord.handle("SIGINT"); coord.handle("SIGINT"); s2.release(); });
    await executeTest(manifest(s2.origin), { env: ENV, flowsOnly: true, fixtureWorkDir: dir, onFixtures: (l) => { life = l; coord.attach(l); },
      flows: [flow(CREATE, { id: "S2", action: "http", actor: "reader_a", request: { method: "GET", path: "/api/hold" }, expect: { status: [200] } })] });
    await held;
    assert.equal(exited?.code, 130);
    assert.match(exited!.lines[0]!, /LEFTOVER orders o1: DELETE \/api\/test-fixtures\/orders\/o1 as fixture_admin/);
    assert.ok(!s2.log.some((l) => l.startsWith("DELETE")));
    assert.deepEqual(readPending(dir).map((p) => [p.fixture, p.id, p.state]), [["orders", "o1", "created"]]);
    assert.equal(life!.leftovers.length, 1);
  } finally {
    await s2.close();
  }
});

test("5: reserve and cleanup window refuse creates; nothing is sent after the authorization window", async () => {
  const noReserve = await run("secure", [CREATE], { safety: { max_requests: 3 } });
  assert.ok(!noReserve.log.some((l) => l.startsWith("POST")), "reserve of 4 does not fit beside the create");
  assert.match(JSON.stringify(noReserve.run.incompleteReasons) + JSON.stringify(noReserve.flowRun?.flows[0]?.steps[0]?.reason), /cleanup reserve/);

  const window = await run("secure", [CREATE], { safety: { max_duration_seconds: 20, cleanup_window_seconds: 30 } });
  assert.deepEqual(window.log, []);
  assert.match(window.flowRun!.flows[0]!.steps[0]!.reason!, /cleanup_window_seconds/);

  const b = new Budget(10, 20, 60_000, new Date(Date.now() + 50));
  b.reserve(2);
  await new Promise((r) => setTimeout(r, 80));
  await assert.rejects(b.acquire(true), (e: unknown) => e instanceof BudgetExceeded && /authorization window ended/.test((e as Error).message));
  b.close();
  const c = new Budget(4, 20, 60_000);
  c.reserve(3);
  await c.acquire();
  await assert.rejects(c.acquire(), /exhausted/, "ordinary requests cannot use reserved slots");
  await c.acquire(true);
  assert.equal(c.reservedSlots, 2);
  assert.throws(() => c.reserve(5), /does not fit/);
  c.close();
});

test("6: a lost create (reset or truncated) is FAILED with an unknown-outcome leftover and is not retried", async () => {
  for (const mode of ["create-reset", "create-truncated"] as const) {
    const r = await run(mode, [CREATE]);
    assert.equal(r.run.executionStatus, "FAILED", mode);
    const l = r.run.fixtures!.leftovers[0]!;
    assert.equal(l.status, "unknown-outcome");
    assert.equal(l.marker, r.run.marker);
    assert.equal(r.log.filter((x) => x.startsWith("POST")).length, 1, `${mode}: never retried`);
    assert.ok(!r.log.some((x) => x.startsWith("DELETE")));
  }
});

test("7: refused DELETE and an object still present are leftovers; the sweep reports pending intents and deletes nothing", async () => {
  const del = await run("delete-500", [CREATE]);
  assert.equal(del.run.executionStatus, "FAILED");
  assert.equal(del.log.filter((x) => x.startsWith("DELETE")).length, 2, "one retry on 5xx");
  assert.equal(del.run.fixtures!.leftovers[0]!.status, "cleanup-failed");
  assert.match(del.run.fixtures!.leftovers[0]!.manualAction, /^DELETE \/api\/test-fixtures\/orders\/o1 as fixture_admin$/);

  const stays = await run("stays", [CREATE]);
  assert.equal(stays.run.executionStatus, "FAILED");
  assert.equal(stays.run.fixtures!.leftovers[0]!.status, "still-present");

  // Simulated kill: the pending file of a dead run is read back as possible leftovers.
  const dead = mkdtempSync(join(tmpdir(), "ns-sv-dead-"));
  const s = await startFixtureServer("secure");
  try {
    const coord = new SignalCoordinator(() => undefined);
    const held = s.held().then(() => { coord.handle("SIGTERM"); coord.handle("SIGTERM"); s.release(); });
    await executeTest(manifest(s.origin), { env: ENV, flowsOnly: true, fixtureWorkDir: dead, onFixtures: (l) => coord.attach(l), flows: [flow(CREATE, { id: "S2", action: "http", actor: "reader_a", request: { method: "GET", path: "/api/hold" }, expect: { status: [200] } })] });
    await held;
  } finally {
    await s.close();
  }
  const pend = readPending(dead);
  assert.equal(pend.length, 1);
  assert.ok(JSON.parse(readFileSync(join(dead, PENDING_FILE), "utf8")).marker.startsWith("nsv-"));
  const next = await run("secure", [{ id: "S1", action: "http", actor: "reader_a", request: { method: "GET", path: "/api/ok" }, expect: { status: [200] } }], {}, { pendingFromPreviousRuns: pend.map((p) => ({ ...p, workDir: "dead" })) });
  assert.equal(next.run.fixtures!.pendingFromPreviousRuns!.length, 1);
});

test("fixture_verify_gone: PASS after a declared delete, FAIL while the object exists; cleanup still runs; lint needs a producer", async () => {
  const withDelete = { orders: { ...ORDERS, allowed_mutations: [...ORDERS.allowed_mutations, { method: "DELETE", path: "/api/test-fixtures/orders/{{id}}", content_type: "application/json" }] } };
  const DEL = { id: "S2", action: "http", actor: "reader_a", fixture: "orders", request: { method: "DELETE", path: "/api/test-fixtures/orders/{{orderA}}" }, expect: { status: [204] } };
  const GONE = { id: "S3", action: "fixture_verify_gone", actor: "reader_a", var: "orderA" };
  const gone = await run("secure", [CREATE, DEL, GONE], { fixtures: withDelete });
  assert.equal(gone.flowRun!.flows[0]!.steps[2]!.status, "PASS", gone.flowRun!.flows[0]!.steps[2]!.reason);
  assert.equal(gone.run.executionStatus, "COMPLETE", gone.run.incompleteReasons.join("; "));
  assert.equal(gone.run.fixtures!.leftovers.length, 0, "a 404 on cleanup counts as done");

  const present = await run("secure", [CREATE, { ...GONE, id: "S2" }]);
  assert.equal(present.flowRun!.flows[0]!.steps[1]!.status, "FAIL");
  assert.match(present.flowRun!.flows[0]!.steps[1]!.reason!, /still present/);
  assert.ok(present.log.includes("DELETE /api/test-fixtures/orders/o1"), "cleanup still runs");

  const m = manifest("http://127.0.0.1:9");
  assert.match(lintFlows([flow({ ...GONE, id: "S1" })], m).errors.join("\n"), /not created by an earlier fixture_create/);
  const noVerify = manifest("http://127.0.0.1:9", { fixtures: { orders: { ...ORDERS, verify_gone: undefined } } });
  assert.match(lintFlows([flow(CREATE, { ...GONE, id: "S2" })], noVerify).errors.join("\n"), /declares no verify_gone/);
});
