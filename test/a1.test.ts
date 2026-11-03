/** SPEC-0.1.3 milestone a1: profiles, guards, scanMode, streamed capture, Budget, workspace hygiene. */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { Budget, BudgetExceeded } from "../src/budget.js";
import { exitCode, main } from "../src/cli.js";
import { ConfigError, assertAuthorizationWindow, parseManifest, type Manifest } from "../src/config.js";
import { Redactor } from "../src/redact.js";
import { executeTest } from "../src/runner.js";
import { ScopeGate } from "../src/scope.js";
import { DirectHttpAdapter } from "../src/transports/direct-http.js";
import type { RunResult } from "../src/types.js";
import { beginRun, createWorkDir, diffSnapshots, endRun, ensureStateDir, ignoreGlob, projectRoot, removeTree, snapshot, sweepStale } from "../src/workspace.js";
import { startDemo } from "./fixtures/demo-server.js";
import { localManifest } from "./helpers.js";

const prodBase = (over: Record<string, unknown> = {}) => ({
  version: "1", project: "p", environment: "production",
  authorization: { acknowledged: true, owner: "o", reference: "CHG-42", expires_at: "2099-01-01" },
  targets: { origins: ["https://app.example.test"] },
  ...over,
});

function problems(x: unknown): string[] {
  try { parseManifest(x); return []; } catch (e) { assert.ok(e instanceof ConfigError); return e.problems; }
}

const tmp = (p: string) => mkdtempSync(join(tmpdir(), `navsentry-a1-${p}-`));

/** Writes a manifest for a local demo origin into `dir`. */
function writeManifest(dir: string, origin: string, over: Record<string, unknown> = {}): string {
  const host = new URL(origin).hostname;
  const f = join(dir, "m.json");
  writeFileSync(f, JSON.stringify({
    version: "1", project: "demo", environment: "local", authorization: { acknowledged: true, owner: "navsentry-tests" },
    targets: { origins: [origin], allowed_paths: ["/**"], denied_paths: ["/admin/**"], seed_paths: ["/"] },
    network: { allow_private: [{ host, approved_by: "navsentry-tests", reason: "local disposable demo app" }] },
    safety: { mode: "observe", max_requests: 50, max_requests_per_second: 20, max_duration_seconds: 60 },
    report: { language: "en", formats: ["json", "markdown"] },
    checks: { disabled: ["NSC-CRYPT-006"] },
    ...over,
  }));
  return f;
}

// ───────────── Profiles and production guards ─────────────

test("profile is derived from environment; staging and production use the production profile", () => {
  assert.equal(localManifest("http://127.0.0.1:1").profile, "development");
  assert.equal(parseManifest(prodBase()).profile, "production");
  assert.equal(parseManifest(prodBase({ environment: "staging" })).profile, "production");
});

test("production profile requires reference and expires_at, with migration guidance", () => {
  const p = problems(prodBase({ authorization: { acknowledged: true, owner: "o" } }));
  assert.ok(p.some((x) => x.startsWith("authorization.reference: required") && x.includes("migration")));
  assert.ok(p.some((x) => x.startsWith("authorization.expires_at: required")));
  assert.ok(problems(prodBase({ authorization: { acknowledged: true, owner: "o", reference: "https://x.test/t", expires_at: "2099-01-01" } })).some((x) => x.includes("no hostnames")));
  assert.ok(problems(prodBase({ authorization: { acknowledged: true, owner: "o", reference: "CHG-1", expires_at: "2099-01-01", not_before: "2099-02-01" } })).some((x) => x.includes("before expires_at")));
  // Development keeps its 0.1.2 defaults: no reference needed.
  assert.doesNotThrow(() => localManifest("http://127.0.0.1:1"));
});

test("profile defaults apply before parsing; explicit values win within range", () => {
  const prod = parseManifest(prodBase());
  assert.equal(prod.safety.max_requests, 100);
  assert.equal(prod.safety.max_requests_per_second, 1);
  assert.equal(prod.safety.max_depth, 2);
  assert.equal(prod.safety.representatives_per_pattern, 2);
  assert.equal(prod.safety.max_frontier, 1000);
  const dev = parseManifest({ ...prodBase(), environment: "dev" });
  assert.equal(dev.safety.max_requests, 200, "development request default unchanged");
  assert.equal(dev.safety.representatives_per_pattern, 3);
  // An explicit value equal to the development default is kept in production (never inferred as "omitted").
  assert.equal(parseManifest(prodBase({ safety: { max_requests: 200 } })).safety.max_requests, 200);
  assert.equal(prod.capture.max_response_bytes, 256 * 1024 * 1024);
  assert.equal(prod.capture.memory_buffer_bytes, 8 * 1024 * 1024);
});

test("new keys are validated with ranges; wildcard origins and unsafe ignore globs are refused", () => {
  assert.ok(problems(prodBase({ targets: { origins: ["https://*.example.test"] } })).some((x) => x.includes("wildcard")));
  assert.ok(problems(prodBase({ safety: { max_depth: 11 } })).some((x) => x.includes("max_depth")));
  assert.ok(problems(prodBase({ safety: { representatives_per_pattern: 1.5 } })).some((x) => x.includes("integer")));
  assert.ok(problems(prodBase({ capture: { max_response_bytes: 1024 } })).some((x) => x.includes("max_response_bytes")));
  assert.ok(problems(prodBase({ capture: { max_response_bytes: 1 << 20, memory_buffer_bytes: 1 << 21 } })).some((x) => x.includes("memory_buffer_bytes")));
  assert.ok(problems(prodBase({ capture: { bogus: 1 } })).some((x) => x.includes("unknown key")));
  for (const g of ["../x", "/abs/**", "C:/x", "\\\\server\\share", "a/../b"]) assert.ok(problems(prodBase({ workspace: { ignore: [g] } })).length, g);
  assert.deepEqual(parseManifest(prodBase({ workspace: { ignore: [".next/**"] } })).workspace.ignore, [".next/**"]);
  assert.ok(problems(prodBase({ analyzer: { timeout_seconds: 9999 } })).length);
});

test("authorization window: before not_before or after expires_at refuses to start with zero requests", async () => {
  const demo = await startDemo("secure");
  try {
    const m = localManifest(demo.origin, { authorization: { acknowledged: true, owner: "t", not_before: "2098-01-01", expires_at: "2099-01-01" } });
    assert.throws(() => assertAuthorizationWindow(m), /has not started/);
    await assert.rejects(executeTest(m), ConfigError);
    assert.throws(() => assertAuthorizationWindow(m, new Date("2099-06-01")), /has ended/);
    assert.equal(demo.hits(), 0);
  } finally {
    await demo.close();
  }
});

test("production profile refuses live-key credentials unless allowed", async () => {
  const demo = await startDemo("secure");
  try {
    const host = new URL(demo.origin).hostname;
    const m = parseManifest(prodBase({
      targets: { origins: [demo.origin], seed_paths: ["/"] },
      network: { allow_private: [{ host, approved_by: "t", reason: "fixture" }] },
      actors: { reader: { authorization_header_env: "NS_A1_TOKEN" } },
    }));
    await assert.rejects(executeTest(m, { env: { NS_A1_TOKEN: "Bearer sk_live_abcdefghijklmnop" } }), /live-key prefix/);
    assert.equal(demo.hits(), 0);
  } finally {
    await demo.close();
  }
});

// ───────────── CLI: scan, --env, exit codes ─────────────

test("scan rejects invalid or unavailable combinations before any request (exit 3)", async () => {
  const demo = await startDemo("secure");
  const dir = tmp("scan");
  try {
    const m = writeManifest(dir, demo.origin);
    const cases: string[][] = [
      ["scan", "--config", m],
      ["scan", "--config", m, "--mode", "nope"],
      ["scan", "--config", m, "--mode", "page", "--engine", "computer-use"],
      ["scan", "--config", m, "--mode", "page", "--engine", "playwright"],
      ["scan", "--config", m, "--mode", "flow", "--engine", "playwright", "--flows", dir],
      ["scan", "--config", m, "--mode", "page", "--url", "http://elsewhere.invalid/"],
      ["scan", "--config", m, "--mode", "page", "--url", `${demo.origin}/admin/x`],
      ["scan", "--config", m, "--mode", "page", "--url", "not a url"],
      ["scan", "--config", m, "--mode", "spider", "--url", `${demo.origin}/`],
      ["scan", "--config", m, "--mode", "flow"],
      ["scan", "--config", m, "--mode", "flow", "--flows", dir, "--analyze"],
      ["scan", "--config", m, "--mode", "page", "--env", "production"],
      ["test", "--config", m, "--env", "production"],
      ["plan", "--config", m, "--env", "staging"],
    ];
    for (const c of cases) assert.equal(await main([...c, "--project", dir, "--out", join(dir, "out")]), 3, c.join(" "));
    assert.equal(demo.hits(), 0, "invalid flag pairs and forbidden engines make zero requests");
  } finally {
    await demo.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("scan --mode page equals the seed scan; run.json keeps mode and scanMode apart", async () => {
  const demo = await startDemo("secure");
  const dir = tmp("page");
  try {
    const m = writeManifest(dir, demo.origin);
    const out = join(dir, "out");
    assert.equal(await main(["scan", "--config", m, "--mode", "page", "--env", "development", "--project", dir, "--out", out]), 0);
    const r = JSON.parse(readFileSync(join(out, "run.json"), "utf8")) as RunResult;
    assert.equal(r.mode, "observe");
    assert.equal(r.scanMode, "page");
    assert.equal(r.profile, "development");
    assert.deepEqual(r.engine, { requested: "http", used: "http", analyze: false });
    assert.equal(r.workspace?.status, "PASS");
    assert.equal(r.workspace?.cleanup, "COMPLETE");
    const t = join(dir, "out-test");
    assert.equal(await main(["test", "--config", m, "--project", dir, "--out", t]), 0);
    const rt = JSON.parse(readFileSync(join(t, "run.json"), "utf8")) as RunResult;
    assert.deepEqual(rt.findings.map((f) => f.ruleId), r.findings.map((f) => f.ruleId));
    assert.equal(rt.scanMode, undefined, "legacy test keeps its 0.1.2 shape");
    assert.deepEqual(readdirSync(join(dir, ".navsentry", "work")), [], "work directories are removed");
    assert.equal(readFileSync(join(dir, ".navsentry", ".gitignore"), "utf8"), "*\n");
  } finally {
    await demo.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("--engine analyzer is shorthand for --engine http --analyze and produces page models (0.1.3-b)", async () => {
  const demo = await startDemo("secure");
  const dir = tmp("analyze");
  try {
    const m = writeManifest(dir, demo.origin);
    const out = join(dir, "out");
    const code = await main(["scan", "--config", m, "--mode", "page", "--engine", "analyzer", "--project", dir, "--out", out]);
    const r = JSON.parse(readFileSync(join(out, "run.json"), "utf8")) as RunResult;
    assert.ok(code === 0 || code === 1, `exit ${code}: ${r.incompleteReasons.join("; ")}`);
    assert.equal(r.analyzer?.engine, "node-page-model");
    assert.ok(!r.incompleteReasons.some((x) => x.startsWith("analysis NOT_TESTED")));
    assert.deepEqual(r.engine, { requested: "analyzer", used: "http", analyze: true });
  } finally {
    await demo.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a file planted in the project during the run gives WORKSPACE_DIRTY (exit 4)", async () => {
  const dir = tmp("dirty");
  const server = http.createServer((_q, res) => {
    writeFileSync(join(dir, "planted.cjs"), "leftover");
    res.writeHead(200, { "content-type": "text/plain" }).end("ok");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const m = writeManifest(dir, origin, { checks: { disabled: ["NSC-AC-004", "NSC-CONF-006", "NSC-CRYPT-006"] } });
    const out = join(dir, "out");
    assert.equal(await main(["test", "--config", m, "--project", dir, "--out", out]), 4);
    const r = JSON.parse(readFileSync(join(out, "run.json"), "utf8")) as RunResult;
    assert.equal(r.workspace?.status, "FAIL");
    assert.deepEqual(r.workspace?.created, ["planted.cjs"]);
    assert.ok(!r.workspace?.created.some((x) => x.startsWith("out")), "explicit --out files are authorized writes");
  } finally {
    await new Promise((r) => server.close(r));
    rmSync(dir, { recursive: true, force: true });
  }
});

test("exit precedence is 4 > 1 > 2 > 0", () => {
  const base = { findings: [], executionStatus: "COMPLETE", coverage: [], checks: [], incompleteReasons: [] } as unknown as RunResult;
  const finding = [{ ruleId: "X" }] as unknown as RunResult["findings"];
  const ws = (status: "PASS" | "FAIL" | "NOT_TESTED") => ({ status, created: [], modified: [], deleted: [], cleanup: "COMPLETE" as const, promoted: 0, limitations: [] });
  assert.equal(exitCode({ ...base, findings: finding, workspace: ws("FAIL") }), 4);
  assert.equal(exitCode({ ...base, findings: finding, executionStatus: "PARTIAL" }), 1);
  assert.equal(exitCode({ ...base, executionStatus: "PARTIAL" }), 2);
  assert.equal(exitCode({ ...base, workspace: ws("NOT_TESTED") }), 2, "an unreadable tree is incomplete, never PASS");
});

// ───────────── Budget ─────────────

test("Budget serializes concurrent reservations and never exceeds the limit", async () => {
  const b = new Budget(5, 1000, 60_000);
  const results = await Promise.allSettled(Array.from({ length: 20 }, () => b.acquire()));
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 5);
  assert.equal(b.requestsUsed, 5);
  assert.ok(results.filter((r) => r.status === "rejected").every((r) => (r as PromiseRejectedResult).reason instanceof BudgetExceeded));
});

test("Budget re-checks the deadline after the rate wait and aborts in-flight work", async () => {
  const b = new Budget(10, 2, 60_000, new Date(Date.now() + 200));
  await b.acquire();
  // The next slot opens after 500 ms, past the 200 ms deadline: it must be refused after the wait.
  await assert.rejects(b.acquire(), /authorization window ended/);
  assert.equal(b.requestsUsed, 1);
  assert.equal(b.signal.aborted, true);
  b.close();
});

// ───────────── Streamed capture ─────────────

async function serve(handler: http.RequestListener): Promise<{ origin: string; close: () => Promise<unknown> }> {
  const s = http.createServer(handler);
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  return { origin: `http://127.0.0.1:${(s.address() as { port: number }).port}`, close: () => new Promise((r) => { s.closeAllConnections(); s.close(r); }) };
}

function adapter(m: Manifest, cap: { maxResponseBytes: number; memoryBufferBytes: number }) {
  return new DirectHttpAdapter(new ScopeGate(m), new Budget(100, 100, 60_000), new Redactor([], ["127.0.0.1"]), () => {}, cap);
}

test("capture streams past the memory buffer, counts every byte and flags partial bodies", async () => {
  const size = 3 * 1024 * 1024;
  const srv = await serve((_q, res) => { res.writeHead(200, { "content-type": "application/octet-stream" }); for (let i = 0; i < size / 65536; i++) res.write(Buffer.alloc(65536, 97)); res.end(); });
  try {
    const m = localManifest(srv.origin);
    const ex = await adapter(m, { maxResponseBytes: 16 * 1024 * 1024, memoryBufferBytes: 256 * 1024 }).send({ method: "GET", url: `${srv.origin}/big`, actor: "anonymous" });
    const c = ex.record.capture!;
    assert.equal(c.status, "complete");
    assert.equal(c.decodedBytes, size, "Content-Length is never trusted; observed bytes are counted");
    assert.equal(c.retainedBytes, 256 * 1024);
    assert.equal(ex.raw!.body.length, 256 * 1024);
    assert.match(c.sha256, /^[0-9a-f]{64}$/);
  } finally {
    await srv.close();
  }
});

test("capture stops at max_response_bytes (truncated) and reports early close (aborted)", async () => {
  const srv = await serve((q, res) => {
    if (q.url === "/close") { res.writeHead(200, { "content-length": "100000" }); res.write(Buffer.alloc(1000)); setTimeout(() => res.socket?.destroy(), 20); return; }
    res.writeHead(200); for (let i = 0; i < 40; i++) res.write(Buffer.alloc(65536)); res.end();
  });
  try {
    const m = localManifest(srv.origin);
    const a = adapter(m, { maxResponseBytes: 1024 * 1024, memoryBufferBytes: 64 * 1024 });
    const t = (await a.send({ method: "GET", url: `${srv.origin}/big`, actor: "anonymous" })).record.capture!;
    assert.equal(t.status, "truncated");
    assert.equal(t.decodedBytes, 1024 * 1024, "exactly the limit, never limit + 1");
    const ab = (await a.send({ method: "GET", url: `${srv.origin}/close`, actor: "anonymous" })).record;
    assert.ok(ab.capture?.status === "aborted" || ab.error, "a premature close is never a complete capture");
  } finally {
    await srv.close();
  }
});

test("a truncated capture makes the run PARTIAL, never a clean PASS", async () => {
  const srv = await serve((_q, res) => { res.writeHead(200, { "content-type": "text/html" }); for (let i = 0; i < 40; i++) res.write(Buffer.alloc(65536, 32)); res.end(); });
  try {
    const m = localManifest(srv.origin, { targets: { origins: [srv.origin], seed_paths: ["/"] }, capture: { max_response_bytes: 1024 * 1024, memory_buffer_bytes: 64 * 1024 }, checks: { disabled: ["NSC-AC-004", "NSC-CONF-006"] } });
    const { run } = await executeTest(m);
    assert.equal(run.executionStatus, "PARTIAL");
    assert.equal(run.capture?.truncated, 1);
    assert.ok(run.incompleteReasons.some((x) => x.includes("truncated")));
  } finally {
    await srv.close();
  }
});

// ───────────── Workspace lifecycle and deletion safety ─────────────

test("stale sweep removes only proven-stale same-host work and preserves everything uncertain", () => {
  const root = projectRoot(tmp("sweep"));
  try {
    ensureStateDir(root);
    const work = join(root, ".navsentry", "work");
    mkdirSync(work, { recursive: true });
    const mk = (name: string, lock: unknown) => { mkdirSync(join(work, name)); if (lock !== undefined) writeFileSync(join(work, name, "lock.json"), typeof lock === "string" ? lock : JSON.stringify(lock)); };
    const lock = (o: Record<string, unknown>) => ({ kind: "navsentry-work-lock", nonce: "n", host: hostname(), pid: 1, processStart: 0, createdAt: "x", ...o });
    mk("dead", lock({ pid: 2 ** 22 + 12345 }));
    mk("live", lock({ pid: process.ppid }));
    mk("foreign", lock({ host: "another-host.invalid", pid: 2 ** 22 + 12345 }));
    mk("unreadable", "{not json");
    mk("nolock", undefined);
    const live = createWorkDir(root, "self-run-0001");
    const r = sweepStale(root, { self: live.lock });
    assert.deepEqual(r.removed, ["dead"]);
    assert.deepEqual(r.preserved.map((p) => p.dir).sort(), ["foreign", "live", "nolock", "self-run-0001", "unreadable"]);
    assert.ok(existsSync(join(work, "live")) && existsSync(live.path));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("removeTree unlinks junctions inside the work dir and leaves the target intact; linked roots are refused", () => {
  const root = projectRoot(tmp("links"));
  const outside = tmp("outside");
  try {
    writeFileSync(join(outside, "keep.txt"), "precious");
    const w = createWorkDir(root, "link-run-0001");
    symlinkSync(outside, join(w.path, "j"), "junction");
    removeTree(root, w.path);
    assert.equal(existsSync(w.path), false);
    assert.equal(readFileSync(join(outside, "keep.txt"), "utf8"), "precious", "link target untouched");
    // A linked ancestor (the .navsentry/work root replaced by a junction) is refused.
    rmSync(join(root, ".navsentry", "work"), { recursive: true });
    symlinkSync(outside, join(root, ".navsentry", "work"), "junction");
    assert.throws(() => createWorkDir(root, "link-run-0002"), /linked path refused/);
    assert.ok(existsSync(join(outside, "keep.txt")));
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test("snapshots exclude fixed and ignored trees, and the diff names created, modified and deleted paths", () => {
  const root = projectRoot(tmp("snap"));
  try {
    writeFileSync(join(root, "a.txt"), "1");
    writeFileSync(join(root, "gone.txt"), "1");
    mkdirSync(join(root, ".next"));
    const before = snapshot(root, [".next/**"]);
    writeFileSync(join(root, "a.txt"), "22");
    rmSync(join(root, "gone.txt"));
    writeFileSync(join(root, "new.txt"), "1");
    writeFileSync(join(root, ".next", "build.js"), "x");
    mkdirSync(join(root, "node_modules"));
    writeFileSync(join(root, "node_modules", "x.js"), "x");
    const d = diffSnapshots(before, snapshot(root, [".next/**"]));
    assert.deepEqual(d, { created: ["new.txt"], modified: ["a.txt"], deleted: ["gone.txt"] });
    assert.equal(snapshot(root, [], 2).complete, false, "an oversized tree is reported, never PASS");
    assert.ok(ignoreGlob("src/**/*.map").test("src/a/b/c.map"));
    assert.ok(!ignoreGlob("*.log").test("dir/a.log"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("beginRun/endRun: work dir removed, cleanup recorded, nothing left behind", () => {
  const root = projectRoot(tmp("life"));
  try {
    const ws = beginRun(root, "life-run-0001", []);
    writeFileSync(join(ws.work.path, "raw.bin"), "raw capture");
    const r = endRun(ws, 0);
    assert.equal(r.status, "PASS");
    assert.equal(r.cleanup, "COMPLETE");
    assert.equal(existsSync(ws.work.path), false);
    assert.ok(r.limitations.length >= 2);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("workspace status and clean: dry run changes nothing", async () => {
  const root = projectRoot(tmp("cmd"));
  try {
    ensureStateDir(root);
    const dead = join(root, ".navsentry", "work", "dead-run");
    mkdirSync(dead, { recursive: true });
    writeFileSync(join(dead, "lock.json"), JSON.stringify({ kind: "navsentry-work-lock", nonce: "n", host: hostname(), pid: 2 ** 22 + 12345, processStart: 0, createdAt: "x" }));
    assert.equal(await main(["workspace", "status", "--project", root]), 4, "a stale leftover is reported");
    assert.equal(await main(["workspace", "clean", "--project", root, "--dry-run"]), 0);
    assert.ok(existsSync(dead));
    assert.equal(await main(["workspace", "clean", "--project", root]), 0);
    assert.equal(existsSync(dead), false);
    assert.equal(await main(["workspace", "status", "--project", root]), 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
