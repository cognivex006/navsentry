/** SPEC-0.1.3 milestone a2: spider, robots.txt, redirect chains, page --url, NSC-AC-008. */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli.js";
import { parseManifest } from "../src/config.js";
import { executeTest } from "../src/runner.js";
import { groupKey, pathPattern, scanHtml } from "../src/spider/html.js";
import { classifyRobots, parseRobots, robotsAllows } from "../src/spider/robots.js";
import type { RunResult } from "../src/types.js";
import { renderMarkdown } from "../src/report/render.js";

const SECURE = {
  "content-type": "text/html; charset=utf-8",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
};
const DISABLED = ["NSC-CRYPT-006", "NSC-AC-004", "NSC-CONF-006", "NSC-CONF-009"];

interface SiteOpts {
  items?: number;
  mixed?: boolean;
  hostile?: boolean;
  robots?: { status: number; type?: string; body: string };
  redirect?: "open" | "safe";
}

async function site(o: SiteOpts = {}) {
  const hits = new Map<string, number>();
  const items = o.items ?? 50;
  const s = http.createServer((q, res) => {
    const u = new URL(q.url ?? "/", "http://x");
    hits.set(u.pathname, (hits.get(u.pathname) ?? 0) + 1);
    const page = (body: string) => res.writeHead(200, SECURE).end(`<!doctype html><html><head><title>t</title><script>var s = "<a href='/never'>";</script></head><body>${body}</body></html>`);
    if (u.pathname === "/robots.txt") {
      if (!o.robots) return res.writeHead(404, { "content-type": "text/plain" }).end("none");
      return res.writeHead(o.robots.status, { "content-type": o.robots.type ?? "text/plain" }).end(o.robots.body);
    }
    if (u.pathname === "/") {
      const links = Array.from({ length: items }, (_, i) => `<a href="/item/${i + 1}">item</a>`).join("");
      const extra = o.hostile ? `<a href="http://elsewhere.invalid/x">off</a><a href="javascript:alert(1)">js</a><a href="mailto:a@b.test">m</a><a href="/loop-a">loop</a><a href="/admin/secret">adm</a><a href="/item/1#frag">dup</a>` : "";
      const redir = o.redirect ? `<a href="/go?next=${encodeURIComponent("http://evil.example/landing")}">go</a>` : "";
      return page(`${links}<a href="/about">a</a><a href="contact">c</a><a href="/help?topic=x">h</a>${extra}${redir}`);
    }
    const item = /^\/item\/(\d+)$/.exec(u.pathname);
    if (item) {
      const odd = o.mixed && Number(item[1]) % 2 === 1;
      return page(`<main><h1>Item</h1>${odd ? "<section><div>extra</div></section>" : ""}<p>x</p></main>`);
    }
    if (u.pathname === "/about" || u.pathname === "/contact") return page(`<nav><a href="/">home</a></nav><div>${u.pathname}</div>`);
    if (u.pathname === "/help") return page("<article><p>help</p></article>");
    if (u.pathname === "/loop-a") return res.writeHead(302, { location: "/loop-b" }).end();
    if (u.pathname === "/loop-b") return res.writeHead(302, { location: "/loop-a" }).end();
    if (u.pathname === "/go") return res.writeHead(302, { location: o.redirect === "open" ? u.searchParams.get("next")! : "/" }).end();
    res.writeHead(404, SECURE).end("<p>nf</p>");
  });
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(s.address() as { port: number }).port}`;
  return { origin, hits, total: () => [...hits.values()].reduce((a, b) => a + b, 0), close: () => new Promise((r) => { s.closeAllConnections(); s.close(r); }) };
}

function manifest(origin: string, over: Record<string, unknown> = {}, env: "local" | "production" = "local") {
  return parseManifest({
    version: "1", project: "spider", environment: env,
    authorization: { acknowledged: true, owner: "navsentry-tests", ...(env === "production" ? { reference: "CHG-7", expires_at: "2099-01-01" } : {}) },
    targets: { origins: [origin], allowed_paths: ["/**"], denied_paths: ["/admin/**"], seed_paths: ["/"] },
    network: { allow_private: [{ host: "127.0.0.1", approved_by: "navsentry-tests", reason: "local spider fixture" }] },
    safety: { mode: "observe", max_requests: 200, max_requests_per_second: 20, max_duration_seconds: 60, max_pages: 200 },
    checks: { disabled: DISABLED },
    ...over,
  });
}

// ───────────── Units ─────────────

test("path patterns replace ids, uuids, hashes and long slugs; grouping keeps actor and query keys apart", () => {
  assert.equal(pathPattern("/product/9999/reviews"), "/product/{id}/reviews");
  assert.equal(pathPattern("/u/3f2b8c1a-1111-4222-8333-944455556666"), "/u/{id}");
  assert.equal(pathPattern("/blob/a3f9c0d1e2b4a5f6c7d8"), "/blob/{id}");
  assert.equal(pathPattern("/blog/how-to-configure-security-headers-today"), "/blog/{id}");
  assert.equal(pathPattern("/about"), "/about");
  const u = new URL("https://a.test/item/1?b=1&a=2");
  assert.notEqual(groupKey(u, "anonymous"), groupKey(u, "reader"));
  assert.notEqual(groupKey(u, "anonymous"), groupKey(new URL("https://a.test/item/2?a=9"), "anonymous"));
  assert.equal(groupKey(u, "anonymous"), groupKey(new URL("https://a.test/item/7?a=0&b=0"), "anonymous"));
});

test("tag scan: skeleton ignores text and attribute values, skips script bodies, honours <base>", () => {
  const a = scanHtml('<html><body class="x"><a href="/p?a=1&amp;b=2">One</a><script>"<a href=/no>"</script></body></html>');
  const b = scanHtml('<html><body id="y"><a href="/q">Other text</a><script>other()</script></body></html>');
  assert.equal(a.shapeHash, b.shapeHash, "same skeleton, different values");
  assert.deepEqual(a.hrefs, ["/p?a=1&b=2"], "links inside script bodies are never extracted");
  assert.notEqual(scanHtml("<div><p></p></div>").shapeHash, scanHtml("<div></div><p></p>").shapeHash, "nesting matters");
  assert.equal(scanHtml('<base href="/sub/"><a href="x">').base, "/sub/");
});

test("robots.txt follows RFC 9309: product token group, longest match, allow wins ties, * and $", () => {
  const p = parseRobots("User-agent: *\nDisallow: /\n\nUser-agent: NavSentry\nDisallow: /private\nAllow: /private/ok\nDisallow: /*.pdf$\nAllow: /tie\nDisallow: /tie\n");
  assert.equal(p.group, "navsentry");
  assert.equal(robotsAllows(p, "/public"), true);
  assert.equal(robotsAllows(p, "/private/x"), false);
  assert.equal(robotsAllows(p, "/private/ok/y"), true, "longest match wins");
  assert.equal(robotsAllows(p, "/a/b.pdf"), false);
  assert.equal(robotsAllows(p, "/a/b.pdf?x"), true, "$ anchors the end");
  assert.equal(robotsAllows(p, "/tie"), true, "allow wins a tie");
  assert.equal(parseRobots("User-agent: *\nDisallow: /x").group, "*");
  assert.equal(classifyRobots(200, "text/html", "<!doctype html><html>").kind, "no-policy", "SPA fallback is no policy (D10)");
  assert.equal(classifyRobots(404, "text/plain", "").kind, "no-policy");
  assert.equal(classifyRobots(403, "text/plain", "").kind, "unreachable");
  assert.equal(classifyRobots(503, "text/plain", "").kind, "unreachable");
  assert.equal(classifyRobots(undefined, "", "").kind, "unreachable");
});

// ───────────── Spider acceptance (SPEC §10 tests 2, 3, 15) ─────────────

test("spider samples 3 per pattern, records 47 sampled-out, ≤ 15 requests including robots.txt", async () => {
  const s = await site();
  try {
    const { run } = await executeTest(manifest(s.origin), { spider: true, scanMode: "spider" });
    const sp = run.spider!;
    const items = sp.groups.find((g) => g.pattern === "/item/{id}")!;
    assert.equal(items.representatives.length, 3);
    assert.equal(items.sampledOut, 47);
    assert.equal(items.mixedShape, false);
    assert.equal(sp.skipped.filter((x) => x.reason === "sampled-out").length, 47);
    assert.ok(sp.groups.some((g) => g.pattern === "/help" && g.queryKeys.join() === "topic"));
    assert.equal(run.findings.length, 0, "the fixture items have no findings");
    assert.ok(s.total() <= 15, `requests ${s.total()}`);
    assert.equal(s.hits.get("/robots.txt"), 1, "robots fetched once per origin");
    assert.equal(s.hits.get("/never"), undefined, "script bodies are never crawled");
    assert.equal(run.executionStatus, "PARTIAL", "sampled-out pages leave coverage incomplete");
    assert.ok(run.incompleteReasons.some((x) => x.includes("sampled-out")));
    const md = renderMarkdown(run);
    assert.match(md, /Coverage by template/);
    assert.match(md, /`\/item\/\{id\}`/);
  } finally {
    await s.close();
  }
});

test("mixed shapes are reported and follow-ups stay within 2N fetches", async () => {
  const s = await site({ items: 10, mixed: true });
  try {
    const { run } = await executeTest(manifest(s.origin), { spider: true });
    const g = run.spider!.groups.find((x) => x.pattern === "/item/{id}")!;
    assert.equal(g.mixedShape, true);
    assert.ok(g.representatives.length <= 6 && g.representatives.length > 3, `fetched ${g.representatives.length}`);
    const itemHits = [...s.hits].filter(([k]) => k.startsWith("/item/")).reduce((a, [, n]) => a + n, 0);
    assert.ok(itemHits <= 6);
  } finally {
    await s.close();
  }
});

test("hostile links: off-scope, javascript:, mailto:, denied paths and redirect loops are recorded, never followed", async () => {
  const s = await site({ items: 2, hostile: true });
  try {
    const { run } = await executeTest(manifest(s.origin), { spider: true });
    const reasons = run.spider!.skipped.map((x) => x.reason);
    assert.ok(reasons.some((r) => r.startsWith("out of scope") ), "off-origin link recorded");
    assert.ok(reasons.some((r) => r.includes("javascript")));
    assert.ok(reasons.some((r) => r.includes("mailto")));
    assert.equal(s.hits.get("/admin/secret"), undefined, "denied path never requested");
    assert.ok((s.hits.get("/loop-a") ?? 0) <= 2 && (s.hits.get("/loop-b") ?? 0) <= 1, "loop stopped");
    const loop = run.redirectChains!.find((c) => c.start.endsWith("/loop-a"))!;
    assert.match(loop.hops.at(-1)!.decision, /loop/);
    assert.equal(s.hits.get("/item/1"), 1, "fragments do not create new identities");
  } finally {
    await s.close();
  }
});

test("production enforces robots: disallowed paths are skipped, an unreachable policy blocks the origin", async () => {
  const deny = await site({ items: 5, robots: { status: 200, body: "User-agent: *\nDisallow: /item/\n" } });
  try {
    const { run } = await executeTest(manifest(deny.origin, {}, "production"), { spider: true });
    assert.ok(run.spider!.skipped.some((x) => x.reason === "robots: disallowed"));
    assert.equal([...deny.hits.keys()].some((k) => k.startsWith("/item/")), false);
    assert.equal(run.spider!.robots[0]!.enforced, true);
  } finally {
    await deny.close();
  }
  const blocked = await site({ items: 5, robots: { status: 403, body: "no" } });
  try {
    const { run } = await executeTest(manifest(blocked.origin, {}, "production"), { spider: true });
    assert.equal(run.spider!.robots[0]!.status, "unreachable");
    assert.equal(blocked.hits.get("/"), undefined, "crawling the origin is blocked");
    assert.ok(run.incompleteReasons.some((x) => x.includes("robots.txt") && x.includes("blocked")));
  } finally {
    await blocked.close();
  }
  const spa = await site({ items: 2, robots: { status: 200, type: "text/html", body: "<!doctype html><html></html>" } });
  try {
    const { run } = await executeTest(manifest(spa.origin, {}, "production"), { spider: true });
    assert.equal(run.spider!.robots[0]!.status, "no-policy");
    assert.equal(spa.hits.get("/"), 1, "an SPA fallback is no policy (D10): crawl proceeds");
  } finally {
    await spa.close();
  }
});

test("development records robots without enforcing it; the run budget counts robots and redirects", async () => {
  const s = await site({ items: 4, robots: { status: 200, body: "User-agent: *\nDisallow: /item/\n" } });
  try {
    const { run } = await executeTest(manifest(s.origin), { spider: true });
    assert.equal(run.spider!.robots[0]!.enforced, false);
    assert.ok((s.hits.get("/item/1") ?? 0) + (s.hits.get("/item/2") ?? 0) > 0);
    assert.equal(run.budget.requestsUsed, s.total(), "every request, including robots.txt, draws on the one budget");
  } finally {
    await s.close();
  }
  const tight = await site({ items: 50 });
  try {
    const { run } = await executeTest(manifest(tight.origin, { safety: { mode: "observe", max_requests: 4, max_requests_per_second: 20, max_duration_seconds: 60 } }), { spider: true });
    assert.equal(tight.total(), 4);
    assert.equal(run.executionStatus, "PARTIAL");
    assert.ok(run.incompleteReasons.some((x) => x.includes("request budget exhausted")));
  } finally {
    await tight.close();
  }
});

// ───────────── Open redirect (NSC-AC-008) and redirect chains ─────────────

test("NSC-AC-008: a parameter-driven off-origin redirect FAILs as SUSPECTED; the safe variant PASSes", async () => {
  const vuln = await site({ items: 1, redirect: "open" });
  try {
    const { run } = await executeTest(manifest(vuln.origin), { spider: true });
    const f = run.findings.find((x) => x.ruleId === "NSC-AC-008")!;
    assert.ok(f, "finding present");
    assert.equal(f.lifecycle, "SUSPECTED");
    assert.ok(run.denials.some((d) => d.reason.startsWith("redirect not followed")), "the off-origin hop is never requested");
    const chain = run.redirectChains!.find((c) => c.start.includes("/go"))!;
    assert.match(chain.hops[0]!.decision, /^not followed/);
    assert.ok(!JSON.stringify(run).includes("evil.example/landing?"), "no raw parameter values");
  } finally {
    await vuln.close();
  }
  const safe = await site({ items: 1, redirect: "safe" });
  try {
    const { run } = await executeTest(manifest(safe.origin), { spider: true });
    assert.equal(run.coverage.find((c) => c.ruleId === "NSC-AC-008")!.status, "PASS");
    const chain = run.redirectChains!.find((c) => c.start.includes("/go"))!;
    assert.equal(chain.hops.length, 2);
    assert.equal(chain.hops[1]!.decision, "final");
  } finally {
    await safe.close();
  }
});

// ───────────── CLI ─────────────

test("CLI: scan --mode spider and page --url write scanMode and stay in scope", async () => {
  const s = await site({ items: 3 });
  const dir = mkdtempSync(join(tmpdir(), "navsentry-a2-"));
  try {
    const m = join(dir, "m.json");
    writeFileSync(m, JSON.stringify({
      version: "1", project: "spider", environment: "local", authorization: { acknowledged: true, owner: "t" },
      targets: { origins: [s.origin], seed_paths: ["/"], denied_paths: ["/admin/**"] },
      network: { allow_private: [{ host: "127.0.0.1", approved_by: "t", reason: "fixture" }] },
      safety: { mode: "observe", max_requests: 100, max_requests_per_second: 20, max_duration_seconds: 60 },
      checks: { disabled: DISABLED }, report: { language: "th", formats: ["json", "markdown"] },
    }));
    const out = join(dir, "spider");
    assert.equal(await main(["scan", "--config", m, "--mode", "spider", "--project", dir, "--out", out]), 0, "3 items with N=3: nothing sampled out, complete");
    const r = JSON.parse(readFileSync(join(out, "run.json"), "utf8")) as RunResult;
    assert.equal(r.scanMode, "spider");
    assert.equal(r.mode, "observe");
    assert.ok(r.spider && r.spider.groups.length >= 4);
    assert.equal(r.workspace?.status, "PASS");
    const before = s.total();
    const page = join(dir, "page");
    assert.equal(await main(["scan", "--config", m, "--mode", "page", "--url", `${s.origin}/about`, "--project", dir, "--out", page]), 0);
    assert.equal(s.total() - before, 1, "only the requested URL");
    assert.equal(await main(["discover", "--config", m]), 3, "live discover points to scan --mode spider");
  } finally {
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
