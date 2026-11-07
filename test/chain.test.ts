/** SPEC-0.1.3 milestone f: chained flows (`requires` / `imports`), SPEC §10 test 8. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { approveCommand, main } from "../src/cli.js";
import { flowHash } from "../src/flow/classify.js";
import { lintFlows, topoOrder } from "../src/flow/lint.js";
import { parseFlowText, resolveDeps, type FlowDoc } from "../src/flow/parse.js";
import { executeTest } from "../src/runner.js";
import { FIXTURE_TOKENS, startDemo } from "./fixtures/demo-server.js";
import { localManifest } from "./helpers.js";

const ENV = { NAVSENTRY_TEST_READER_A_AUTH: FIXTURE_TOKENS.reader_a, NAVSENTRY_TEST_READER_B_AUTH: FIXTURE_TOKENS.reader_b };
const ACTORS = { reader_a: { authorization_header_env: "NAVSENTRY_TEST_READER_A_AUTH" }, reader_b: { authorization_header_env: "NAVSENTRY_TEST_READER_B_AUTH" } };

const text = (header: object, ...steps: object[]) =>
  ["# t", "", "```navsentry-flow", JSON.stringify(header, null, 2), "```", "", ...steps.flatMap((s, i) => [`## S${i + 1}`, "```navsentry-step", JSON.stringify(s), "```", ""])].join("\n");
const hdr = (id: string, over: Record<string, unknown> = {}) => ({ flow: "1", id, title: id, story: `story ${id}`, actors: ["reader_a", "reader_b"], ...over });

const LIST = (id = "list-orders", status: unknown = "2xx") => [hdr(id), { id: "S1", action: "http", actor: "reader_a", request: { method: "GET", path: "/api/orders", accept: "json" }, expect: { status }, extract: { orderId: { from: "json", pointer: "/items/0/id" } } }] as const;
const DETAIL = (id = "order-detail", over: Record<string, unknown> = {}, actor = "reader_a") => [hdr(id, { requires: ["list-orders"], imports: { orderId: "list-orders.orderId" }, ...over }), { id: "S1", action: "http", actor, request: { method: "GET", path: "/api/orders/{{orderId}}", accept: "json" }, expect: { status: "2xx", json: [{ pointer: "/id", type: "string" }] } }] as const;

function load(...files: (readonly [object, ...object[]])[]): FlowDoc[] {
  const docs = files.map(([h, ...s], i) => {
    const r = parseFlowText(text(h, ...s), `f${i}.flow.md`);
    assert.deepEqual(r.problems, []);
    return r.doc!;
  });
  resolveDeps(docs);
  return docs;
}

test("chain A→B: B runs with A's PASS value; if A fails, B is NOT_TESTED with the dependency reason", async () => {
  const demo = await startDemo("secure");
  try {
    const m = localManifest(demo.origin, { actors: ACTORS, checks: { disabled: ["NSC-CRYPT-006"] } });
    const ok = load(LIST(), DETAIL());
    assert.deepEqual(lintFlows(ok, m).errors, []);
    const r = await executeTest(m, { env: ENV, flows: ok, flowsOnly: true });
    const b = r.flowRun!.flows.find((f) => f.id === "order-detail")!;
    assert.equal(r.flowRun!.flows.find((f) => f.id === "list-orders")!.status, "PASS");
    assert.equal(b.status, "PASS", b.reasons.join("; "));
    assert.ok(!JSON.stringify(r).includes("/api/orders/o-a-1"), "imported values never appear in reports");

    const bad = load(LIST("list-orders", [500]), DETAIL());
    const r2 = await executeTest(m, { env: ENV, flows: bad, flowsOnly: true });
    const b2 = r2.flowRun!.flows.find((f) => f.id === "order-detail")!;
    assert.equal(r2.flowRun!.flows.find((f) => f.id === "list-orders")!.status, "FAIL");
    assert.equal(b2.status, "NOT_TESTED", "never FAIL or PASS");
    assert.deepEqual(b2.reasons, ["dependency list-orders is FAIL"]);
    assert.ok(b2.steps.every((s) => s.status === "NOT_TESTED" && s.requestIds.length === 0), "no request for a blocked flow");
  } finally {
    await demo.close();
  }
});

test("a diamond dependency runs once, in dependency order", async () => {
  const demo = await startDemo("secure");
  try {
    const m = localManifest(demo.origin, { actors: ACTORS, checks: { disabled: ["NSC-CRYPT-006"] } });
    const top = [hdr("z-top", { requires: ["order-detail", "order-detail-2"] }), { id: "S1", action: "http", actor: "reader_a", request: { method: "GET", path: "/api/orders", accept: "json" }, expect: { status: "2xx" } }] as const;
    const docs = load(top, DETAIL("order-detail-2"), DETAIL(), LIST());
    assert.deepEqual(lintFlows(docs, m).errors, []);
    assert.deepEqual(topoOrder(docs).map((d) => d.header.id), ["list-orders", "order-detail", "order-detail-2", "z-top"]);
    const r = await executeTest(m, { env: ENV, flows: docs, flowsOnly: true });
    assert.equal(r.flowRun!.flows.filter((f) => f.id === "list-orders").length, 1);
    assert.equal(r.run.requests.filter((q) => q.flow?.id === "list-orders").length, 1, "shared dependency requested once");
    assert.ok(r.flowRun!.flows.every((f) => f.status === "PASS"));
  } finally {
    await demo.close();
  }
});

test("lint rejects cycles, missing flows, undeclared imports, missing exports, collisions and actor-boundary transfers", () => {
  const m = localManifest("http://127.0.0.1:9", { actors: ACTORS });
  const errs = (...f: (readonly [object, ...object[]])[]) => lintFlows(load(...f), m).errors.join("\n");
  const S = { id: "S1", action: "http", actor: "reader_a", request: { method: "GET", path: "/api/orders" }, expect: { status: "2xx" } };
  assert.match(errs([hdr("a-flow", { requires: ["b-flow"] }), S], [hdr("b-flow", { requires: ["a-flow"] }), S]), /dependency cycle a-flow → b-flow → a-flow/);
  assert.match(errs([hdr("a-flow", { requires: ["a-flow"] }), S]), /cannot require itself/);
  assert.match(errs(DETAIL()), /no flow "list-orders" in the selected flow root/);
  assert.match(errs(LIST(), DETAIL("order-detail", { requires: [] })), /undeclared dependency/);
  assert.match(errs(LIST(), DETAIL("order-detail", { imports: { orderId: "list-orders.nope" } })), /missing export/);
  assert.match(errs(LIST(), DETAIL("order-detail", { vars: { orderId: { value: "x" } } })), /collides with a local variable/);
  assert.match(errs(LIST(), DETAIL("order-detail", {}, "reader_b")), /crosses an actor boundary/);
  assert.deepEqual(lintFlows(load(LIST(), DETAIL("order-detail", { imports: { orderId: { from: "list-orders.orderId", allow_cross_actor: true } } }, "reader_b")), m).errors, [], "declared in the reviewed contract");
  assert.match(parseFlowText(text(hdr("x-flow", { imports: { v: "not-a-ref" } }), S), "x.flow.md").problems.join(), /must be "<flowId>.<variable>"/);
});

test("editing a required flow invalidates dependent approvals transitively; unchained hashes are unchanged", () => {
  const m = localManifest("http://127.0.0.1:9", { actors: ACTORS });
  const top = [hdr("z-top", { requires: ["order-detail"] }), { id: "S1", action: "http", actor: "reader_a", request: { method: "GET", path: "/api/orders" }, expect: { status: "2xx" } }] as const;
  const v1 = load(LIST(), DETAIL(), top);
  const approve = (d: FlowDoc) => ({ status: "approved", approved_by: "owner", approved_at: "2026-11-02", content_sha256: flowHash(d) });
  const [, b1, c1] = v1;
  const approved = (list: readonly [object, ...object[]]) => load(list, [{ ...DETAIL()[0], review: approve(b1!) }, DETAIL()[1]], [{ ...top[0], review: approve(c1!) }, top[1]]);
  assert.deepEqual(lintFlows(approved(LIST()), m).errors, [], "approvals valid before the edit");
  const edited = lintFlows(approved(LIST("list-orders", [200])), m).errors.join("\n");
  assert.match(edited, /f1\.flow\.md.*flow changed after approval/, "direct dependent invalidated");
  assert.match(edited, /f2\.flow\.md.*flow changed after approval/, "transitive dependent invalidated");
  const plain = load(LIST())[0]!;
  plain.deps = [];
  assert.equal(flowHash(plain), flowHash(load(LIST())[0]!), "a flow without requires hashes only itself (0.1.2 hash)");
});

test("CLI: approve covers the closure; selection pulls in eligible dependencies; drafts stay out in production", async () => {
  const demo = await startDemo("secure");
  const dir = mkdtempSync(join(tmpdir(), "navsentry-chain-"));
  const saved = { ...process.env };
  try {
    Object.assign(process.env, ENV);
    const flows = join(dir, "flows");
    const write = (name: string, f: readonly [object, ...object[]]) => { const [h, ...s] = f; writeFileSync(join(flows, name), text(h, ...s)); };
    (await import("node:fs")).mkdirSync(flows);
    write("list.flow.md", LIST());
    write("detail.flow.md", DETAIL());
    const mpath = join(dir, "m.json");
    const base = {
      version: "1", project: "chain", authorization: { acknowledged: true, owner: "t" },
      targets: { origins: [demo.origin], seed_paths: ["/"] },
      network: { allow_private: [{ host: "127.0.0.1", approved_by: "t", reason: "fixture" }] },
      safety: { mode: "observe", max_requests: 50, max_requests_per_second: 20, max_duration_seconds: 60 },
      actors: ACTORS, checks: { disabled: ["NSC-CRYPT-006"] }, report: { language: "en", formats: ["json"] },
    };
    writeFileSync(mpath, JSON.stringify({ ...base, environment: "local" }));
    assert.equal(await main(["flow", "lint", "--config", mpath, "--flows", flows]), 0);
    // --only the dependent: the dependency is pulled in because drafts are allowed here.
    const out = join(dir, "run");
    assert.equal(await main(["test", "--config", mpath, "--flows", flows, "--include-drafts", "--only", "order-detail", "--flows-only", "--project", dir, "--out", out]), 0);
    const fr = JSON.parse(readFileSync(join(out, "flows.json"), "utf8")) as { flows: { id: string; status: string }[] };
    assert.deepEqual(fr.flows.map((f) => `${f.id}:${f.status}`).sort(), ["list-orders:PASS", "order-detail:PASS"]);
    // Approve only the dependent; in production the draft dependency is not selected.
    assert.equal(await approveCommand(["--flows", join(flows, "detail.flow.md"), "--by", "owner"], { ask: async () => "yes", say: () => {} }), 0);
    const prod = join(dir, "prod.json");
    writeFileSync(prod, JSON.stringify({ ...base, environment: "production", authorization: { ...base.authorization, reference: "CHG-9", expires_at: "2099-01-01" } }));
    const pout = join(dir, "prod-run");
    assert.equal(await main(["test", "--config", prod, "--flows", flows, "--flows-only", "--project", dir, "--out", pout]), 2);
    const pr = JSON.parse(readFileSync(join(pout, "flows.json"), "utf8")) as { flows: { id: string; status: string; reasons: string[] }[] };
    assert.equal(pr.flows.length, 1);
    assert.equal(pr.flows[0]!.status, "NOT_TESTED");
    assert.match(pr.flows[0]!.reasons[0]!, /dependency list-orders is not selected/);
    // Editing the dependency invalidates the approved dependent.
    write("list.flow.md", LIST("list-orders", [200]));
    assert.equal(await main(["flow", "lint", "--config", mpath, "--flows", flows]), 3);
  } finally {
    process.env = saved;
    await demo.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
