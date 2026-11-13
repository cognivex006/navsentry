/** SPEC-0.4.0 D4: `--resume` starts a new run that continues an earlier PARTIAL one, never resending its requests. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli.js";
import { MANIFEST_FILE, buildManifest } from "../src/integrity.js";
import type { RunResult } from "../src/types.js";
import { startDemo } from "./fixtures/demo-server.js";

const tmp = () => mkdtempSync(join(tmpdir(), "navsentry-resume-"));
const SEEDS = ["/", "/api/profile", "/api/error", "/api/token"];

function manifest(dir: string, origin: string, over: Record<string, unknown> = {}): string {
  const f = join(dir, "m.json");
  writeFileSync(f, JSON.stringify({
    version: "1", project: "demo", environment: "local", authorization: { acknowledged: true, owner: "navsentry-tests" },
    targets: { origins: [origin], allowed_paths: ["/**"], denied_paths: ["/admin/**"], seed_paths: SEEDS },
    network: { allow_private: [{ host: "127.0.0.1", approved_by: "navsentry-tests", reason: "local disposable demo app" }] },
    safety: { mode: "observe", max_requests: 100, max_requests_per_second: 20, max_duration_seconds: 60 },
    report: { language: "en", formats: ["json"] }, ...over,
  }));
  return f;
}

const read = (d: string) => JSON.parse(readFileSync(join(d, "run.json"), "utf8")) as RunResult;

/** Turns a finished run into an interrupted one: keeps the requests of the first two seeds, marks it PARTIAL, re-signs. */
function interrupt(dir: string, origin: string): RunResult {
  const r = read(dir);
  const keep = new Set([`${origin}/`, `${origin}/api/profile`]);
  r.requests = r.requests.filter((q) => keep.has(q.url));
  r.budget.requestsUsed = r.requests.length;
  r.executionStatus = "PARTIAL";
  r.incompleteReasons = ["interrupted (test)"];
  writeFileSync(join(dir, "run.json"), JSON.stringify(r));
  writeFileSync(join(dir, MANIFEST_FILE), JSON.stringify(buildManifest(dir, r.runId, "test", ["run.json"])));
  return r;
}

test("resume sends only the seeds the earlier run never sent, within the budget it had left", async () => {
  const demo = await startDemo("vulnerable");
  const dir = tmp();
  try {
    const m = manifest(dir, demo.origin);
    const first = join(dir, "first"), second = join(dir, "second");
    await main(["test", "--config", m, "--project", dir, "--out", first]);
    const before = interrupt(first, demo.origin);
    await main(["test", "--config", m, "--project", dir, "--out", second, "--resume", first]);
    const r = read(second);
    assert.notEqual(r.runId, before.runId, "a resume is a new run");
    assert.equal(r.resumedFrom?.runId, before.runId);
    assert.equal(r.budget.requestsMax, 100 - before.budget.requestsUsed, "only the budget the earlier run had left");
    const sent = new Set(r.requests.map((q) => q.url));
    assert.ok(!sent.has(`${demo.origin}/`) && !sent.has(`${demo.origin}/api/profile`), "never resends what the earlier run sent");
    assert.ok(sent.has(`${demo.origin}/api/error`) && sent.has(`${demo.origin}/api/token`));
    assert.ok(r.incompleteReasons.some((x) => x.includes("not sent again")));
  } finally {
    await demo.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("resume is refused when the earlier folder fails verify, is not PARTIAL, or the scope changed", async () => {
  const demo = await startDemo("vulnerable");
  const dir = tmp();
  try {
    const m = manifest(dir, demo.origin);
    const first = join(dir, "first");
    await main(["test", "--config", m, "--project", dir, "--out", first]);
    // A COMPLETE (or FAILED) run has nothing to resume.
    if (read(first).executionStatus !== "PARTIAL") assert.equal(await main(["test", "--config", m, "--project", dir, "--out", join(dir, "x1"), "--resume", first]), 3);
    interrupt(first, demo.origin);
    const changed = manifest(join(dir), demo.origin, { targets: { origins: [demo.origin], allowed_paths: ["/api/**"], denied_paths: [], seed_paths: ["/api/profile"] } });
    assert.equal(await main(["test", "--config", changed, "--project", dir, "--out", join(dir, "x2"), "--resume", first]), 3, "scope changed");
    const m2 = manifest(dir, demo.origin);
    writeFileSync(join(first, "run.json"), readFileSync(join(first, "run.json"), "utf8") + " ");
    assert.equal(await main(["test", "--config", m2, "--project", dir, "--out", join(dir, "x3"), "--resume", first]), 3, "a tampered folder fails verify");
  } finally {
    await demo.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an exhausted budget cannot be resumed, even if the manifest raises max_requests", async () => {
  const demo = await startDemo("vulnerable");
  const dir = tmp();
  try {
    const first = join(dir, "first");
    await main(["test", "--config", manifest(dir, demo.origin, { safety: { mode: "observe", max_requests: 4, max_requests_per_second: 20, max_duration_seconds: 60 } }), "--project", dir, "--out", first]);
    const r = read(first);
    assert.equal(r.executionStatus, "PARTIAL");
    assert.equal(r.budget.requestsUsed, 4);
    const raised = manifest(dir, demo.origin, { safety: { mode: "observe", max_requests: 100, max_requests_per_second: 20, max_duration_seconds: 60 } });
    assert.equal(await main(["test", "--config", raised, "--project", dir, "--out", join(dir, "x"), "--resume", first]), 3);
  } finally {
    await demo.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
