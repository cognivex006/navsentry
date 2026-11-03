/** SPEC-0.1.3 milestone s: static asset scan (SPEC §10 tests 11, 12 and the static parts of 16). */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LiteralScanner, StreamScanner, exposureMatch } from "../src/assets/detect.js";
import { main } from "../src/cli.js";
import type { RunResult } from "../src/types.js";

const TOKEN = "Bearer fixture-asset-reader-token-0001";
const AKIA = "AKIA" + "Q7ZX3MBN4KL2PW9R";
const MiB = 1024 * 1024;

interface Site { vuln: boolean; bigBundle?: number; authMap?: boolean; pages?: number }

async function site(o: Site) {
  const hits = new Map<string, number>();
  const s = http.createServer((q, res) => {
    const u = new URL(q.url ?? "/", "http://x");
    hits.set(u.pathname, (hits.get(u.pathname) ?? 0) + 1);
    const html = (body: string) => res.writeHead(200, { "content-type": "text/html; charset=utf-8", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'", "referrer-policy": "no-referrer", "cache-control": "no-store" }).end(`<!doctype html><html><head><script src="/static/app.js"></script><link rel="stylesheet" href="/static/app.css"><link rel="icon" href="/favicon.png"></head><body>${body}</body></html>`);
    if (u.pathname === "/" || u.pathname.startsWith("/item/")) return html(o.pages ? Array.from({ length: o.pages }, (_, i) => `<a href="/item/${i + 1}">i</a>`).join("") : "<p>home</p>");
    if (u.pathname === "/static/app.js") {
      if (o.bigBundle) return big(res, o.bigBundle);
      const code = o.vuln
        ? `var api="https://api.corp.internal/v1";var auth="${TOKEN}";fetch(api);\n//# sourceMappingURL=app.js.map\n`
        : `var api="/v1";var auth=null;fetch(api);\n//# sourceMappingURL=app.js.map\n`;
      return res.writeHead(200, { "content-type": "application/javascript" }).end(code);
    }
    if (u.pathname === "/static/app.css") return res.writeHead(200, { "content-type": "text/css" }).end("body{margin:0}");
    if (u.pathname === "/static/app.js.map") {
      const authed = !!q.headers.authorization;
      if (!o.vuln || (o.authMap && !authed)) return res.writeHead(404, { "content-type": "text/plain" }).end("nf");
      return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ version: 3, sources: ["src/app.ts"], sourcesContent: ["const api = 'x';"], mappings: "AAAA" }));
    }
    if (u.pathname === "/env.js") return res.writeHead(200, { "content-type": "application/javascript" }).end(o.vuln ? `window.__ENV={API_SECRET:"s3cr3t-value-xyz-123",NEXT_PUBLIC_URL:"https://x.test"}` : `window.__ENV={NEXT_PUBLIC_URL:"https://x.test"}`);
    if (u.pathname === "/.git/HEAD" && o.vuln) return res.writeHead(200, { "content-type": "text/plain" }).end("ref: refs/heads/main\n");
    // SPA fallback: every unknown path returns the app shell with 200 (both variants), including /.env.
    return html("<div id=app></div>");
  });
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(s.address() as { port: number }).port}`;
  return { origin, hits, close: () => new Promise((r) => { s.closeAllConnections(); s.close(r); }) };
}

/** Streams a generated bundle with synthetic secrets after 5 MiB, across a 1 MiB read boundary and at the end. */
function big(res: http.ServerResponse, size: number): void {
  res.writeHead(200, { "content-type": "application/javascript" });
  const line = Buffer.from("x".repeat(99) + "\n");
  const plant = new Map<number, string>([[5 * MiB + 17, `k="${AKIA}";\n`], [3 * MiB - 9, `k="${AKIA}";\n`], [size - 40, `k="${AKIA}";\n`]]);
  let written = 0;
  const pump = () => {
    while (written < size) {
      const at = [...plant.keys()].find((p) => p >= written && p < written + MiB);
      let chunk: Buffer;
      if (at !== undefined) {
        const s = plant.get(at)!;
        plant.delete(at);
        chunk = Buffer.concat([Buffer.alloc(at - written, line.toString().repeat(Math.ceil((at - written) / 100) + 1)), Buffer.from(s)]);
      } else chunk = Buffer.alloc(Math.min(MiB, size - written), line.toString());
      if (written + chunk.length > size) chunk = chunk.subarray(0, size - written);
      written += chunk.length;
      if (!res.write(chunk)) { res.once("drain", pump); return; }
    }
    res.end();
  };
  pump();
}

function manifest(dir: string, origin: string, env: "local" | "production", over: Record<string, unknown> = {}): string {
  const f = join(dir, `m-${env}.json`);
  writeFileSync(f, JSON.stringify({
    version: "1", project: "assets", environment: env,
    authorization: { acknowledged: true, owner: "t", ...(env === "production" ? { reference: "CHG-11", expires_at: "2099-01-01" } : {}) },
    targets: { origins: [origin], seed_paths: ["/"] },
    network: { allow_private: [{ host: "127.0.0.1", approved_by: "t", reason: "asset fixture" }] },
    safety: { mode: "observe", max_requests: 300, max_requests_per_second: 20, max_duration_seconds: 300 },
    actors: { reader: { authorization_header_env: "NS_ASSET_TOKEN" } },
    checks: { disabled: ["NSC-CRYPT-006", "NSC-AC-004", "NSC-CONF-006"] },
    report: { language: "en", formats: ["json", "markdown"] },
    ...over,
  }));
  return f;
}

async function scan(dir: string, m: string, mode = "page", label = "out") {
  const out = join(dir, label);
  const code = await main(["scan", "--config", m, "--mode", mode, "--project", dir, "--out", out]);
  return { code, out, run: JSON.parse(readFileSync(join(out, "run.json"), "utf8")) as RunResult };
}

const cov = (r: RunResult, id: string) => r.coverage.find((c) => c.ruleId === id)!.status;

// ───────────── Units ─────────────

test("stream scanner finds values split across chunk boundaries and keeps only masked facts", () => {
  const text = `const a = 1;\nconst k = "${AKIA}";\nconst h = "https://db.corp.internal/x";\n`;
  for (const size of [1, 3, 7, 64, 4096]) {
    const sc = new StreamScanner();
    const b = Buffer.from(text);
    for (let i = 0; i < b.length; i += size) sc.feed(b.subarray(i, i + size));
    const r = sc.end();
    const key = r.facts.find((f) => f.marker === "aws-access-key");
    assert.ok(key, `split size ${size}`);
    assert.deepEqual([key.line, key.col, key.len], [2, 12, 20]);
    assert.equal(r.facts.filter((f) => f.marker === "aws-access-key").length, 1, "no duplicate across the overlap");
    assert.ok(r.facts.some((f) => f.kind === "internal-host"));
    assert.ok(!JSON.stringify(r).includes("Q7ZX"), "facts never carry value characters");
  }
  const lit = new LiteralScanner([TOKEN]);
  const b = Buffer.from(`xx${TOKEN}yy`);
  for (let i = 0; i < b.length; i += 5) lit.feed(b.subarray(i, i + 5));
  assert.equal(lit.matches, 1);
});

test("exposure formats: an SPA HTML fallback never matches; public prefixes are not secrets", () => {
  assert.equal(exposureMatch("dotenv", "<!doctype html><html>").match, false);
  assert.equal(exposureMatch("dotenv", "DB_PASSWORD=x\nAPI=1\n").match, true);
  assert.deepEqual(exposureMatch("dotenv", "DB_PASSWORD=x\n").keys, ["DB_PASSWORD"]);
  assert.equal(exposureMatch("git-head", "ref: refs/heads/main\n").match, true);
  assert.equal(exposureMatch("js-config", `{NEXT_PUBLIC_API_TOKEN:"abcdef123"}`).match, false);
  assert.equal(exposureMatch("js-config", `{API_SECRET:"abcdef123"}`).match, true);
});

// ───────────── Vulnerable vs secure (test 11) ─────────────

test("vulnerable fixture: INFO-007, INFO-008, CONF-009 and INFO-003; no raw value in any artifact", async () => {
  const s = await site({ vuln: true });
  const dir = mkdtempSync(join(tmpdir(), "navsentry-assets-"));
  const saved = { ...process.env };
  try {
    process.env.NS_ASSET_TOKEN = TOKEN;
    const { code, out, run } = await scan(dir, manifest(dir, s.origin, "production"));
    assert.equal(code, 1);
    const f = (id: string) => run.findings.filter((x) => x.ruleId === id);
    assert.equal(f("NSC-INFO-007")[0]?.lifecycle, "VALIDATED", "exact known-token match");
    assert.equal(f("NSC-INFO-008")[0]?.lifecycle, "VALIDATED", "anonymous map with sourcesContent in production");
    assert.equal(f("NSC-CONF-009").length, 2, "/env.js and /.git/HEAD");
    assert.ok(f("NSC-INFO-003").length >= 1);
    assert.ok(!run.findings.some((x) => x.ruleId === "NSC-CONF-009" && x.target.includes("/.env ")), "SPA fallback for /.env is not a finding");
    assert.equal(run.assets!.probes.find((p) => p.path === "/.env")!.result, "PASS");
    assert.equal(s.hits.get("/favicon.png"), undefined, "images are never fetched");
    const files = readdirSync(out);
    assert.ok(files.includes("client-findings.json"));
    const all = files.map((n) => readFileSync(join(out, n), "utf8")).join("\n");
    for (const secret of ["fixture-asset-reader-token", "s3cr3t-value", "api.corp.internal", "const api = 'x'"]) assert.ok(!all.includes(secret), `artifact leaked ${secret}`);
    const cf = JSON.parse(readFileSync(join(out, "client-findings.json"), "utf8")) as { entries: { caseId: string; preview: string }[] };
    assert.ok(cf.entries.length > 0 && cf.entries.length <= 200);
    assert.ok(cf.entries.every((e) => /^\[[a-z0-9-]+,[a-z]+=[a-z0-9]+\]$/.test(e.preview)), "masked previews only");
    assert.ok(run.assets!.cost!.agentVisibleBytes > 0);
    assert.match(readFileSync(join(out, "REPORT.md"), "utf8"), /## Client assets/);
  } finally {
    process.env = saved;
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("secure fixture keeps the bundle contract and passes; development maps are observations", async () => {
  const s = await site({ vuln: false });
  const dir = mkdtempSync(join(tmpdir(), "navsentry-assets-"));
  try {
    const { code, run } = await scan(dir, manifest(dir, s.origin, "production", { actors: {} }));
    assert.equal(code, 0, JSON.stringify(run.findings.map((x) => [x.ruleId, x.target, x.actual])) + run.incompleteReasons.join("; "));
    for (const id of ["NSC-INFO-007", "NSC-INFO-008", "NSC-CONF-009", "NSC-INFO-003"]) assert.equal(cov(run, id), "PASS", id);
    assert.equal(run.requests.find((x) => x.url.endsWith("/static/app.js"))!.contract!.contentType, "application/javascript");
  } finally {
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
  const v = await site({ vuln: true });
  const dir2 = mkdtempSync(join(tmpdir(), "navsentry-assets-"));
  try {
    const { run } = await scan(dir2, manifest(dir2, v.origin, "local", { actors: {} }));
    const map = run.checks.find((c) => c.ruleId === "NSC-INFO-008" && c.target.endsWith("/static/app.js.map"))!;
    assert.equal(map.status, "NOT_TESTED", "development profile: observation only");
    assert.match(map.reason!, /observation only/);
    assert.ok(!run.findings.some((x) => x.ruleId === "NSC-INFO-008"));
  } finally {
    await v.close();
    rmSync(dir2, { recursive: true, force: true });
  }
});

test("a source map reachable only by an authenticated actor is authenticated-only exposure (SUSPECTED)", async () => {
  const s = await site({ vuln: true, authMap: true });
  const dir = mkdtempSync(join(tmpdir(), "navsentry-assets-"));
  const saved = { ...process.env };
  try {
    process.env.NS_ASSET_TOKEN = TOKEN;
    const { run } = await scan(dir, manifest(dir, s.origin, "production"));
    const f = run.findings.find((x) => x.ruleId === "NSC-INFO-008")!;
    assert.equal(f.lifecycle, "SUSPECTED");
    assert.ok(f.actual.some((a) => a.includes("authenticated-only exposure")));
  } finally {
    process.env = saved;
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ───────────── Cost and cache (test 12) ─────────────

test("a bundle referenced by many pages is fetched once; a second run reuses facts and recomputes known-token verdicts", async () => {
  const s = await site({ vuln: true, pages: 50 });
  const dir = mkdtempSync(join(tmpdir(), "navsentry-assets-"));
  const saved = { ...process.env };
  try {
    process.env.NS_ASSET_TOKEN = TOKEN;
    const m = manifest(dir, s.origin, "production", { actors: {}, checks: { disabled: ["NSC-CRYPT-006", "NSC-AC-004", "NSC-CONF-006", "NSC-CONF-009"] } });
    const a = await scan(dir, m, "spider", "first");
    assert.equal(s.hits.get("/static/app.js"), 1, "one fetch per request identity");
    assert.equal(a.run.assets!.cost!.cacheHits, 0);
    const b = await scan(dir, m, "spider", "second");
    assert.equal(s.hits.get("/static/app.js"), 2, "the complete current bytes are fetched again");
    assert.ok(b.run.assets!.cost!.cacheHits >= 1, "unchanged asset reuses facts");
    assert.deepEqual(b.run.findings.map((x) => `${x.ruleId}:${x.lifecycle}`).sort(), a.run.findings.map((x) => `${x.ruleId}:${x.lifecycle}`).sort(), "verdicts recomputed from facts give the same result");
    const cache = readdirSync(join(dir, ".navsentry", "cache", "assets"));
    assert.ok(cache.length >= 1);
    for (const c of cache) assert.ok(!readFileSync(join(dir, ".navsentry", "cache", "assets", c), "utf8").match(/PASS|VALIDATED|fixture-asset|corp\.internal/), "facts only: no verdicts, no values");
    const zero = manifest(dir, s.origin, "production", { actors: {}, capture: { cache_max_age_days: 0 } });
    const c = await scan(dir, zero, "page", "nocache");
    assert.equal(c.run.assets!.cost!.cacheHits, 0, "0 days means never reuse");
  } finally {
    process.env = saved;
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ───────────── Large inputs (test 16, static parts) ─────────────

for (const [label, size, over] of [["16 MiB", 16 * MiB, {}], ["300 MiB with a raised budget", 300 * MiB, { capture: { max_response_bytes: 512 * MiB } }]] as const) {
  test(`large bundle (${label}): secrets after 5 MiB, across a read boundary and at the end; bounded memory`, async () => {
    const s = await site({ vuln: false, bigBundle: size });
    const dir = mkdtempSync(join(tmpdir(), "navsentry-assets-"));
    try {
      const { run } = await scan(dir, manifest(dir, s.origin, "local", { actors: {}, checks: { disabled: ["NSC-CRYPT-006", "NSC-AC-004", "NSC-CONF-006", "NSC-CONF-009"] }, ...over }));
      const req = run.requests.find((x) => x.url.endsWith("/static/app.js"))!;
      assert.equal(req.capture!.status, "complete");
      assert.equal(req.capture!.decodedBytes, size);
      assert.ok(req.capture!.retainedBytes <= 64 * 1024, "the body is spooled, not buffered");
      const f = run.findings.find((x) => x.ruleId === "NSC-INFO-007")!;
      assert.ok(f, "secrets found");
      assert.equal(f.actual.filter((a) => a.startsWith("[aws-access-key")).length, 3, f.actual.join("; "));
      assert.ok(run.assets!.cost!.agentVisibleBytes < size / 100, "agent-visible bytes below 1 %");
      assert.ok(!readdirSync(join(dir, ".navsentry", "work")).length, "spool removed with the work directory");
    } finally {
      await s.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

test("a bundle above max_response_bytes is truncated and never a clean scan", async () => {
  const s = await site({ vuln: false, bigBundle: 2 * MiB });
  const dir = mkdtempSync(join(tmpdir(), "navsentry-assets-"));
  try {
    const { run } = await scan(dir, manifest(dir, s.origin, "local", { actors: {}, capture: { max_response_bytes: MiB }, checks: { disabled: ["NSC-CRYPT-006", "NSC-AC-004", "NSC-CONF-006", "NSC-CONF-009"] } }));
    assert.equal(cov(run, "NSC-INFO-007"), "INCONCLUSIVE");
    assert.equal(run.executionStatus, "PARTIAL");
  } finally {
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("workspace clean removes only expired, well-formed cache entries", async () => {
  const { cleanCache, ensureStateDir, projectRoot } = await import("../src/workspace.js");
  const { mkdirSync, utimesSync, existsSync } = await import("node:fs");
  const root = projectRoot(mkdtempSync(join(tmpdir(), "navsentry-cache-")));
  try {
    ensureStateDir(root);
    const dir = join(root, ".navsentry", "cache", "assets");
    mkdirSync(dir, { recursive: true });
    const old = join(dir, `${"a".repeat(64)}.json`), fresh = join(dir, `${"b".repeat(64)}.json`), other = join(dir, "notes.txt");
    for (const p of [old, fresh, other]) writeFileSync(p, "{}");
    const past = new Date(Date.now() - 40 * 86_400_000);
    utimesSync(old, past, past);
    utimesSync(other, past, past);
    assert.deepEqual(cleanCache(root, 30, { dryRun: true }), { removed: 1, preserved: 1 });
    assert.ok(existsSync(old), "dry run changes nothing");
    cleanCache(root, 30);
    assert.deepEqual([existsSync(old), existsSync(fresh), existsSync(other)], [false, true, true]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
