/**
 * SPEC-0.2.0 milestone 0.2.0-c acceptance tests 8–10 (fixture only, 127.0.0.1):
 * NSC-AC-003 modification, NSC-AC-006 CSRF and NSC-AUTH-002 session after logout,
 * each against a vulnerable and a secure variant with the same response contract.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseManifest, type Manifest } from "../src/config.js";
import { approveText } from "../src/flow/author.js";
import { CSRF_PROBE_ORIGIN } from "../src/flow/execute.js";
import { lintFlows } from "../src/flow/lint.js";
import { parseFlowText, resolveDeps, type FlowDoc } from "../src/flow/parse.js";
import { executeTest } from "../src/runner.js";
import { FIXTURE_LOGIN, startFixtureServer, type FixtureMode } from "./fixtures/fixture-server.js";

const ENV = { NS_A: "Bearer sv-reader-a", NS_B: "Bearer sv-reader-b", NS_ADMIN: "Bearer sv-fixture-admin", NS_ALICE_USER: FIXTURE_LOGIN.user, NS_ALICE_PASS: FIXTURE_LOGIN.password };
const HTTP_LOGIN = { http: "login", body: { json: { user: "{{username}}", password: "{{password}}" } } };
const fixture = (owner: string) => ({
  owner_actor: owner, cleanup_actor: "fixture_admin",
  create: { method: "POST", path: "/api/test-fixtures/orders", body: { json: { note: "{{marker}}" } }, extract: { id: "/id" } },
  exists: { method: "GET", path: "/api/orders/{{id}}", expect_status: [200] },
  cleanup: { method: "DELETE", path: "/api/test-fixtures/orders/{{id}}", expect_status: [204, 404] },
  verify_gone: { method: "GET", path: "/api/orders/{{id}}", expect_status: [404] },
  allowed_mutations: [
    { method: "PATCH", path: "/api/orders/{{id}}", content_type: "application/json", max_body_bytes: 1024 },
    { method: "POST", path: "/api/orders/{{id}}/cancel", content_type: "application/x-www-form-urlencoded", max_body_bytes: 512, csrf: { token_from: { cookie: "csrf_token" }, send_as: { header: "x-csrf-token" } } },
  ],
});

function manifest(origin: string, owner = "reader_a", over: Record<string, unknown> = {}): Manifest {
  return parseManifest({
    version: "1", project: "svc", environment: "local",
    authorization: { acknowledged: true, owner: "navsentry-tests" },
    targets: { origins: [origin], allowed_paths: ["/api/**"], denied_paths: [], seed_paths: [] },
    network: { allow_private: [{ host: "127.0.0.1", approved_by: "navsentry-tests", reason: "local fixture app" }] },
    safety: { mode: "safe-validate", max_requests: 200, max_requests_per_second: 20, max_duration_seconds: 120 },
    actors: {
      reader_a: { authorization_header_env: "NS_A" }, reader_b: { authorization_header_env: "NS_B" }, fixture_admin: { authorization_header_env: "NS_ADMIN" },
      alice: { login: HTTP_LOGIN, username_env: "NS_ALICE_USER", password_env: "NS_ALICE_PASS" },
    },
    auth_endpoints: { login: { method: "POST", path: "/api/session", content_type: "application/json" }, logout: { method: "POST", path: "/api/session/logout" } },
    fixtures: { orders: fixture(owner) },
    report: { language: "en", formats: ["json"] },
    ...over,
  });
}

const flow = (actors: string[], steps: object[], id = "svc-flow"): FlowDoc => {
  const text = ["# c", "", "```navsentry-flow", JSON.stringify({ flow: "1", id, title: id, story: `story ${id}`, actors }, null, 2), "```", "",
    ...steps.flatMap((s, i) => [`## S${i + 1}`, "```navsentry-step", JSON.stringify(s), "```", ""])].join("\n");
  const r = parseFlowText(text, `${id}.flow.md`);
  assert.deepEqual(r.problems, []);
  resolveDeps([r.doc!]);
  return r.doc!;
};

/** Lints (which binds the manifest entries), approves, and re-parses: an owner-approved flow. */
function approved(d: FlowDoc, m: Manifest): FlowDoc {
  assert.deepEqual(lintFlows([d], m).errors, []);
  const r = parseFlowText(approveText(d, "owner", "2026-11-05"), d.file);
  resolveDeps([r.doc!]);
  assert.deepEqual(lintFlows([r.doc!], m).errors, []);
  return r.doc!;
}

async function run(mode: FixtureMode, owner: string, steps: (origin: string) => object[], actors: string[], approve = false) {
  const s = await startFixtureServer(mode);
  try {
    const m = manifest(s.origin, owner);
    const d0 = flow(actors, steps(s.origin));
    const d = approve ? approved(d0, m) : d0;
    const out = await executeTest(m, { env: ENV, flows: [d], flowsOnly: true, fixtureWorkDir: mkdtempSync(join(tmpdir(), "ns-svc-")) });
    return { ...out, log: [...s.log], origin: s.origin, objects: new Set(s.objects) };
  } finally {
    await s.close();
  }
}
const check = (r: Awaited<ReturnType<typeof run>>, id: string) => r.run.checks.filter((c) => c.ruleId === id);

const CREATE = { id: "S1", action: "fixture_create", actor: "reader_a", fixture: "orders", as: "o" };
const OWN_PATCH = { id: "S2", action: "http", actor: "reader_a", fixture: "orders", request: { method: "PATCH", path: "/api/orders/{{o}}", body: { json: { note: "{{marker}}" } } }, expect: { access: "allowed" } };
const CROSS_PATCH = { id: "S3", action: "http", actor: "reader_b", fixture: "orders", object_owner: "reader_a", request: { method: "PATCH", path: "/api/orders/{{o}}", body: { json: { note: "{{marker}}" } } }, expect: { access: "denied", deny_status: [403, 404] } };

test("8: NSC-AC-003 modification — vulnerable FAIL VALIDATED (approved), secure PASS, no positive control INCONCLUSIVE", async () => {
  const steps = () => [CREATE, OWN_PATCH, CROSS_PATCH];
  const vuln = await run("vulnerable", "reader_a", steps, ["reader_a", "reader_b"], true);
  assert.equal(check(vuln, "NSC-AC-003")[0]?.status, "FAIL");
  const f = vuln.run.findings.find((x) => x.ruleId === "NSC-AC-003");
  assert.equal(f?.lifecycle, "VALIDATED", "an approved flow gives a validated finding");
  assert.equal(vuln.objects.size, 0, "the fixture is cleaned up");

  const draft = await run("vulnerable", "reader_a", steps, ["reader_a", "reader_b"]);
  assert.equal(draft.run.findings.find((x) => x.ruleId === "NSC-AC-003")?.lifecycle, "SUSPECTED", "a draft flow stays suspected");

  const secure = await run("secure", "reader_a", steps, ["reader_a", "reader_b"]);
  assert.equal(check(secure, "NSC-AC-003")[0]?.status, "PASS");
  assert.ok(!secure.run.findings.some((x) => x.ruleId === "NSC-AC-003"));

  const noControl = await run("vulnerable", "reader_a", () => [CREATE, { ...OWN_PATCH, expect: { access: "allowed", status: [201] } }, CROSS_PATCH], ["reader_a", "reader_b"]);
  assert.equal(check(noControl, "NSC-AC-003")[0]?.status, "INCONCLUSIVE");
});

const ALICE_CREATE = { ...CREATE, actor: "alice" };
const CANCEL = (actor = "alice") => ({ id: "S2", action: "http", actor, fixture: "orders", check: "csrf", request: { method: "POST", path: "/api/orders/{{o}}/cancel", body: { json: { reason: "navsentry" } } } });

test("9: NSC-AC-006 CSRF — vulnerable FAIL, secure PASS, header-token actor NOT_TESTED; only the .invalid origin is used", async () => {
  const vuln = await run("vulnerable", "alice", () => [ALICE_CREATE, CANCEL()], ["alice"]);
  assert.equal(check(vuln, "NSC-AC-006")[0]?.status, "FAIL", JSON.stringify(check(vuln, "NSC-AC-006")));
  assert.equal(vuln.log.filter((l) => l.endsWith("/cancel")).length, 3, "two probes and one control");
  const origins = new Set(vuln.run.requests.map((q) => q.requestHeaders["origin"]).filter(Boolean));
  assert.deepEqual([...origins].sort(), [vuln.origin, CSRF_PROBE_ORIGIN].sort());
  assert.equal(vuln.run.mutations!.filter((x) => x.path === "/api/orders/{{id}}/cancel").length, 3, "every probe counts against max_mutations");

  const secure = await run("secure", "alice", () => [ALICE_CREATE, CANCEL()], ["alice"]);
  const c = check(secure, "NSC-AC-006")[0]!;
  assert.equal(c.status, "PASS", JSON.stringify(c));
  assert.equal(secure.objects.size, 0);

  const header = await run("secure", "reader_a", () => [CREATE, CANCEL("reader_a")], ["reader_a"]);
  assert.equal(check(header, "NSC-AC-006")[0]?.status, "NOT_TESTED");
  assert.match(check(header, "NSC-AC-006")[0]!.reason!, /CSRF needs a cookie session/);
  assert.ok(!header.log.some((l) => l.endsWith("/cancel")), "nothing is sent for a header-token actor");
});

const LOGOUT = { id: "S1", action: "logout", actor: "alice", request: { method: "GET", path: "/api/me" } };
const AFTER = { id: "S2", action: "http", actor: "alice", request: { method: "GET", path: "/api/me" }, expect: { status: [200] } };

test("10: NSC-AUTH-002 — vulnerable FAIL, secure PASS; the actor is logged out afterwards; logging out a cleanup_actor is a lint error", async () => {
  const vuln = await run("vulnerable", "reader_a", () => [LOGOUT, AFTER], ["alice"]);
  assert.equal(check(vuln, "NSC-AUTH-002")[0]?.status, "FAIL");
  assert.equal(vuln.flowRun!.flows[0]!.steps[1]!.status, "NOT_TESTED");
  assert.match(vuln.flowRun!.flows[0]!.steps[1]!.reason!, /logged out/);
  assert.ok(vuln.run.mutations!.some((x) => x.entry === "auth_endpoints.logout" && x.status === 200));

  const secure = await run("secure", "reader_a", () => [LOGOUT], ["alice"]);
  assert.equal(check(secure, "NSC-AUTH-002")[0]?.status, "PASS");
  assert.deepEqual(secure.log, ["POST /api/session", "GET /api/me", "POST /api/session/logout", "GET /api/me"]);

  const m = manifest("http://127.0.0.1:9", "reader_a", { fixtures: { orders: { ...fixture("reader_a"), cleanup_actor: "alice" } } });
  const errs = lintFlows([flow(["alice"], [LOGOUT])], m).errors.join("\n");
  assert.match(errs, /cleanup_actor of orders; logging it out would leave fixtures behind/);
});

test("review: a logout of a cleanup_actor is refused at runtime too; fixture_create must run as owner_actor (lint)", async () => {
  const s = await startFixtureServer("secure");
  try {
    const m = manifest(s.origin, "reader_a", { fixtures: { orders: { ...fixture("reader_a"), cleanup_actor: "alice" } } });
    const out = await executeTest(m, { env: ENV, flows: [flow(["alice"], [LOGOUT])], flowsOnly: true, fixtureWorkDir: mkdtempSync(join(tmpdir(), "ns-svc-")) });
    const st = out.flowRun!.flows[0]!.steps[0]!;
    assert.equal(st.status, "ERROR");
    assert.match(st.reason!, /cleanup_actor of orders; logout refused/);
    assert.ok(!s.log.includes("POST /api/session/logout"));
  } finally {
    await s.close();
  }
  const errs = lintFlows([flow(["reader_b"], [{ ...CREATE, actor: "reader_b" }])], manifest("http://127.0.0.1:9")).errors.join("\n");
  assert.match(errs, /is created by its owner_actor reader_a/);
});
