/**
 * SPEC-0.2.0 milestone 0.2.0-b acceptance tests 2 (browser), 12, 13 and 15 (fixture only, 127.0.0.1).
 * Browser tests need the governance-approved playwright-core and its Chromium headless shell; without them they skip.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConfigError, parseManifest, type Manifest } from "../src/config.js";
import { approveText } from "../src/flow/author.js";
import { lintFlows } from "../src/flow/lint.js";
import { parseFlowText, resolveDeps, type FlowDoc } from "../src/flow/parse.js";
import { executeTest } from "../src/runner.js";
import { probePlaywright } from "../src/transports/playwright.js";
import { sendCommand, startSession } from "../src/visual/session.js";
import { endRun } from "../src/workspace.js";
import { FIXTURE_LOGIN, startFixtureServer } from "./fixtures/fixture-server.js";

const probe = probePlaywright();
const skip = probe.usable ? false : `playwright engine unavailable: ${probe.reason}`;

const ENV = { NS_ALICE_USER: FIXTURE_LOGIN.user, NS_ALICE_PASS: FIXTURE_LOGIN.password, NS_BAD_PASS: "wrong-password-value", NS_CAROL_COOKIE: FIXTURE_LOGIN.presetCookie, NS_ADMIN: "Bearer sv-fixture-admin" };
const ORDERS = {
  owner_actor: "alice", cleanup_actor: "fixture_admin",
  create: { method: "POST", path: "/api/test-fixtures/orders", body: { json: { note: "{{marker}}" } }, extract: { id: "/id" } },
  exists: { method: "GET", path: "/api/orders/{{id}}", expect_status: [200] },
  cleanup: { method: "DELETE", path: "/api/test-fixtures/orders/{{id}}", expect_status: [204, 404] },
  allowed_mutations: [
    { method: "POST", path: "/api/echo", content_type: "application/json", max_body_bytes: 256 },
    { method: "POST", path: "/api/echo-redirect", content_type: "application/json", max_body_bytes: 256 },
  ],
};
const HTTP_LOGIN = { http: "login", body: { json: { user: "{{username}}", password: "{{password}}" } } };

function raw(origin: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: "1", project: "svb", environment: "local",
    authorization: { acknowledged: true, owner: "navsentry-tests" },
    targets: { origins: [origin], allowed_paths: ["/api/**", "/ui/**"], denied_paths: [], seed_paths: [] },
    network: { allow_private: [{ host: "127.0.0.1", approved_by: "navsentry-tests", reason: "local fixture app" }] },
    safety: { mode: "safe-validate", max_requests: 200, max_requests_per_second: 20, max_duration_seconds: 120 },
    transports: { order: ["direct-http", "playwright-browser"] },
    checks: { disabled: ["NSC-CRYPT-006"] },
    actors: {
      alice: { login: HTTP_LOGIN, username_env: "NS_ALICE_USER", password_env: "NS_ALICE_PASS" },
      mallory: { login: HTTP_LOGIN, username_env: "NS_ALICE_USER", password_env: "NS_BAD_PASS" },
      bob: { login: { flow: "login-bob" }, username_env: "NS_ALICE_USER", password_env: "NS_ALICE_PASS" },
      carol: { cookie_env: "NS_CAROL_COOKIE" },
      fixture_admin: { authorization_header_env: "NS_ADMIN" },
    },
    auth_endpoints: { login: { method: "POST", path: "/api/session", content_type: "application/json", max_body_bytes: 512 } },
    fixtures: { orders: ORDERS },
    report: { language: "en", formats: ["json"] },
    ...over,
  };
}
const manifest = (origin: string, over: Record<string, unknown> = {}): Manifest => parseManifest(raw(origin, over));

const flowText = (id: string, actors: string[], steps: object[]) =>
  ["# f", "", "```navsentry-flow", JSON.stringify({ flow: "1", id, title: id, story: `story ${id}`, actors }, null, 2), "```", "",
    ...steps.flatMap((s, i) => [`## S${i + 1}`, "```navsentry-step", JSON.stringify(s), "```", ""])].join("\n");
function docs(...defs: [string, string[], object[]][]): FlowDoc[] {
  const out = defs.map(([id, actors, steps]) => { const r = parseFlowText(flowText(id, actors, steps), `${id}.flow.md`); assert.deepEqual(r.problems, []); return r.doc!; });
  resolveDeps(out);
  return out;
}
const ME = (id: string, actor: string) => ({ id, action: "http", actor, request: { method: "GET", path: "/api/me" }, expect: { status: [200] } });
const LOGIN_BOB: [string, string[], object[]] = ["login-bob", ["bob"], [
  { id: "S1", action: "navigate", actor: "bob", request: { method: "GET", path: "/ui/login" }, expect: { status: "2xx" } },
  { id: "S2", action: "fill", actor: "bob", target: { label: "Username" }, value: { var: "username" } },
  { id: "S3", action: "fill", actor: "bob", target: { label: "Password" }, value: { var: "password" } },
  { id: "S4", action: "submit", actor: "bob", target: { role: "button", name: "Sign in" } },
  { id: "S5", action: "see", actor: "bob", target: { text: "Signed in" } },
]];

test("12: config — login and cookie_env rules", () => {
  const o = "http://127.0.0.1:9";
  const bad = (over: Record<string, unknown>, re: RegExp) => assert.throws(() => manifest(o, over), (e: unknown) => e instanceof ConfigError && re.test(e.message), String(re));
  bad({ actors: { x: { login: { http: "login", body: { json: { u: "{{token}}" } } }, username_env: "A", password_env: "B" } } }, /only \{\{username\}\} and \{\{password\}\}/);
  bad({ actors: { x: { login: HTTP_LOGIN } } }, /needs username_env and password_env/);
  bad({ actors: { x: { login: HTTP_LOGIN, username_env: "A", password_env: "B", cookie_env: "C" } } }, /use one of/);
  bad({ auth_endpoints: undefined, actors: { x: { login: HTTP_LOGIN, username_env: "A", password_env: "B" } } }, /declare auth_endpoints\.login/);
  const prod = { environment: "staging", authorization: { acknowledged: true, owner: "o", reference: "CHG-1", expires_at: "2099-01-01" }, safety: { mode: "observe" }, fixtures: undefined, auth_endpoints: undefined };
  bad({ ...prod, actors: { c: { cookie_env: "NS_C" } } }, /cookie_env: refused in the production profile/);
});

test("12: http login, cookie-session actor, failed login; no credential or session value in artifacts", async () => {
  const s = await startFixtureServer("secure");
  try {
    const m = manifest(s.origin);
    const d = docs(["me", ["alice", "carol", "mallory"], [ME("S1", "alice"), ME("S2", "carol"), ME("S3", "mallory"), { id: "S4", action: "fixture_create", actor: "mallory", fixture: "orders", as: "o" }]]);
    const out = await executeTest(m, { env: ENV, flows: d, flowsOnly: true, fixtureWorkDir: mkdtempSync(join(tmpdir(), "ns-svb-")) });
    const steps = out.flowRun!.flows[0]!.steps;
    assert.equal(steps[0]!.status, "PASS", steps[0]!.reason);
    assert.equal(steps[1]!.status, "PASS", steps[1]!.reason);
    assert.equal(steps[2]!.status, "NOT_TESTED");
    assert.match(steps[2]!.reason!, /login failed: status 401/);
    assert.equal(steps[3]!.status, "NOT_TESTED", "a failed login never creates fixtures");
    assert.ok(!s.log.includes("POST /api/test-fixtures/orders"));
    assert.equal(s.log.filter((l) => l === "POST /api/session").length, 2, "one login per login actor, never retried");
    assert.ok(out.run.mutations!.some((x) => x.entry === "auth_endpoints.login" && x.status === 200 && x.bodySha256));
    const all = JSON.stringify(out);
    for (const secret of [FIXTURE_LOGIN.password, "wrong-password-value", "preset-session-cookie-0001"]) assert.ok(!all.includes(secret), `${secret} leaked`);
    assert.ok(!/sess-[a-z0-9]{6}/.test(all), "session cookie value leaked");
  } finally {
    await s.close();
  }
});

test("12: browser login flow gives the actor a session for later http steps", { skip }, async () => {
  const s = await startFixtureServer("secure");
  try {
    const m = manifest(s.origin);
    const d = docs(LOGIN_BOB, ["after-login", ["bob"], [ME("S1", "bob")]]);
    assert.deepEqual(lintFlows(d, m).errors, []);
    const out = await executeTest(m, { env: ENV, flows: d, flowsOnly: true, browser: {}, fixtureWorkDir: mkdtempSync(join(tmpdir(), "ns-svb-")) });
    const byId = new Map(out.flowRun!.flows.map((f) => [f.id, f]));
    assert.equal(byId.get("login-bob")!.status, "PASS", JSON.stringify(byId.get("login-bob")!.reasons));
    assert.equal(byId.get("after-login")!.status, "PASS", JSON.stringify(byId.get("after-login")!.reasons));
    assert.ok(out.run.mutations!.some((x) => x.entry === "auth_endpoints.login" && x.status === 200));
    const all = JSON.stringify(out);
    assert.ok(!all.includes(FIXTURE_LOGIN.password) && !/sess-[a-z0-9]{6}/.test(all));
  } finally {
    await s.close();
  }
});

test("2 (browser): only declared, correctly typed browser requests are sent; redirects and forms are re-matched", { skip }, async () => {
  const s = await startFixtureServer("secure");
  try {
    const m = manifest(s.origin);
    const steps = [
      { id: "S1", action: "navigate", actor: "anonymous", request: { method: "GET", path: "/ui/probe" }, expect: { status: "2xx" } },
      ...["Declared", "Undeclared", "Redirected", "Wrong type"].map((n, i) => ({ id: `S${i + 2}`, action: "submit", actor: "anonymous", target: { role: "button", name: n } })),
      { id: "S6", action: "see", actor: "anonymous", target: { text: "declared:200" } },
      { id: "S7", action: "see", actor: "anonymous", target: { text: "undeclared:blocked" } },
      { id: "S8", action: "see", actor: "anonymous", target: { text: "redirected:blocked" } },
      { id: "S9", action: "see", actor: "anonymous", target: { text: "wrongtype:blocked" } },
      { id: "S10", action: "submit", actor: "anonymous", target: { role: "button", name: "Form post" } },
    ];
    const out = await executeTest(m, { env: ENV, flows: docs(["probe", ["anonymous"], steps]), flowsOnly: true, browser: {}, fixtureWorkDir: mkdtempSync(join(tmpdir(), "ns-svb-")) });
    const f = out.flowRun!.flows[0]!;
    for (const st of f.steps.slice(0, 9)) assert.equal(st.status, "PASS", `${st.id}: ${st.reason ?? ""}`);
    assert.equal(s.log.filter((l) => l === "POST /api/echo").length, 1, "only the correctly typed declared request");
    assert.ok(s.log.includes("POST /api/echo-redirect"), "the declared request is sent");
    assert.ok(!s.log.some((l) => /undeclared/.test(l)), `undeclared targets never reached: ${s.log.join(", ")}`);
    const reasons = out.run.denials.map((x) => x.reason).join("\n");
    assert.match(reasons, /matches no declared entry/);
    assert.match(reasons, /content type text\/plain does not match/);
  } finally {
    await s.close();
  }
});

test("13: editing a referenced fixture entry, auth entry or login flow invalidates approval", () => {
  const o = "http://127.0.0.1:9";
  const m = manifest(o);
  const make = () => docs(LOGIN_BOB, ["uses", ["alice", "bob"], [{ id: "S1", action: "fixture_create", actor: "alice", fixture: "orders", as: "o" }, ME("S2", "bob")]]);
  const d = make();
  lintFlows(d, m);
  const approved = parseFlowText(approveText(d[1]!, "owner", "2026-11-05"), "uses.flow.md").doc!;
  const withLogin = () => { const x = [make()[0]!, approved]; resolveDeps(x); return x; };
  const approvalErr = (mm: Manifest, ds = withLogin()) => lintFlows(ds, mm).errors.some((e) => /changed after approval/.test(e));
  assert.equal(approvalErr(m), false, "unchanged entries keep the approval");
  assert.equal(approvalErr(manifest(o, { fixtures: { orders: { ...ORDERS, exists: { ...ORDERS.exists, expect_status: [200, 204] } } } })), true, "fixture entry edited");
  assert.equal(approvalErr(manifest(o, { auth_endpoints: { login: { method: "POST", path: "/api/session2", content_type: "application/json" } } })), true, "auth entry edited");
  const editedLogin = docs([LOGIN_BOB[0], LOGIN_BOB[1], [...LOGIN_BOB[2].slice(0, 4), { id: "S5", action: "see", actor: "bob", target: { text: "Welcome" } }]]);
  const ds = [editedLogin[0]!, approved];
  resolveDeps(ds);
  assert.equal(approvalErr(m, ds), true, "login flow edited");
});

test("15: the visual driver stays observe-only in safe-validate", { skip }, async () => {
  const s = await startFixtureServer("secure");
  const dir = mkdtempSync(join(tmpdir(), "ns-svb-visual-"));
  try {
    const m = manifest(s.origin, { transports: { order: ["direct-http", "playwright-browser", "visual-computer-use"], visual_computer_use: true } });
    const h = await startSession({ manifest: m, projectDir: dir, url: `${s.origin}/ui/autopost` });
    await new Promise((r) => setTimeout(r, 300));
    assert.equal((await sendCommand(join(dir, ".navsentry", "work", h.id), { cmd: "end" })).ok, true);
    const { result, workspace } = await h.done;
    endRun(workspace, 0);
    assert.ok(!s.log.includes("POST /api/echo"), "a declared entry is still refused from the visual driver");
    assert.ok(result.denials.some((d) => d.method === "POST" && /observe engine/.test(d.reason)), JSON.stringify(result.denials));
  } finally {
    await s.close();
  }
});
