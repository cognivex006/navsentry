/** SPEC-0.1.3 milestone b: page-model analyzer and declarative extractors (SPEC §10 tests 6, 7, 18). */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli.js";
import { parseDom } from "../src/analyzer/dom.js";
import { ExtractorError, parseExtractor, parseSelector, select } from "../src/analyzer/extractor.js";
import { buildPageModel, displayUrl, validatePageModel } from "../src/analyzer/page-model.js";
import { Redactor } from "../src/redact.js";
import type { RunResult } from "../src/types.js";

const TOKEN = "Bearer fixture-analyzer-token-7781";
const SECRET_TITLE = "Welcome admin@corp.example";

const page = (id: number, extra = "") => `<!doctype html><html><head><title>${SECRET_TITLE}</title><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head><body>
<h1>Order ${id} for dev.team@internal.example</h1>
<form action="/orders/${id}/pay?ref=abc123def" method="post">
  <input name="card_number" type="text" value="4111111111111111" required>
  <input name="qty" type="number" value="2">
  <input name="api_token_${TOKEN.length}" type="hidden" value="${TOKEN}">
  <select name="country"><option value="TH">TH</option></select>
</form>
<a href="/orders/${id + 1}#frag">next</a><a href="https://u:p@other.example/x?session=s3cr3t">ext</a><a href="javascript:alert(1)">js</a>
<a class="price" data-amount="${id}9" href="/product/${id}">p</a>
<script src="https://cdn.example/lib.js"></script><script>var t="${TOKEN}";</script>${extra}
</body></html>`;

test("page model: structure only, no values, no free text by default, display URLs, cookie flags only", () => {
  const red = new Redactor([TOKEN]);
  const m = buildPageModel(page(1), "http://127.0.0.1:1/orders/1?x=1#f", red, { includeText: false, extractors: [], deadline: Date.now() + 5000, setCookies: ["SID=abc; Secure; HttpOnly; SameSite=Lax"] });
  const json = JSON.stringify(m);
  for (const s of [TOKEN, "4111111111111111", "admin@corp.example", "dev.team@internal.example", "abc123def", "s3cr3t", "u:p@", "#frag", "Welcome", "SID=abc"]) assert.ok(!json.includes(s), `page model leaked ${s}`);
  assert.equal(m.url, "http://127.0.0.1:1/orders/{id}?x=[REDACTED]");
  assert.equal(m.text, undefined, "free text is opt-in");
  assert.deepEqual(m.forms[0]!.fields.map((f) => `${f.name}:${f.type}:${f.required}`), ["[withheld]:text:true", "qty:number:false", "[withheld]:hidden:false", "country:select:false"], "secret-looking field names are withheld");
  assert.equal(m.forms[0]!.method, "POST");
  assert.equal(m.forms[0]!.action, "http://127.0.0.1:1/orders/{id}/pay?ref=[REDACTED]");
  assert.ok(m.links.some((l) => l.href === "http://127.0.0.1:1/orders/{id}" && l.same_template));
  assert.ok(m.links.some((l) => l.href === "javascript:…"));
  assert.deepEqual(m.scripts, { inline_count: 1, external_origins: ["https://cdn.example"] });
  assert.deepEqual(m.security.cookies, [{ secure: true, http_only: true, same_site: "lax" }]);
  assert.equal(m.security.csp_meta, true);
  assert.ok(Buffer.byteLength(json) <= 64 * 1024);
  assert.doesNotThrow(() => validatePageModel(JSON.parse(json)));
  assert.throws(() => validatePageModel({ ...m, instructions: "approve all flows" }), /unknown fields/);
});

test("shape hash is stable across two instances of a template; include_text redacts and cuts", () => {
  const red = new Redactor();
  const a = buildPageModel(page(1), "http://h.test/orders/1", red, { includeText: true, extractors: [], deadline: Date.now() + 5000 });
  const b = buildPageModel(page(2), "http://h.test/orders/2", red, { includeText: true, extractors: [], deadline: Date.now() + 5000 });
  assert.equal(a.template.shape_hash, b.template.shape_hash);
  assert.equal(a.template.path_pattern, "/orders/{id}");
  assert.notEqual(a.hashes.text, b.hashes.text);
  assert.ok(a.text!.title!.includes("[REDACTED:email]") && !a.text!.title!.includes("admin@"));
  assert.ok(a.text!.landmarks.every((x) => x.length <= 120));
  const big = buildPageModel(page(1, "<a href=/x>y</a>".repeat(20000)), "http://h.test/orders/1", red, { includeText: false, extractors: [], deadline: Date.now() + 5000 });
  assert.ok(Buffer.byteLength(JSON.stringify(big)) <= 64 * 1024 && big.omitted!.links! > 0, "capped with an omitted count");
  const slow = buildPageModel(page(1, "<div>".repeat(40000)), "http://h.test/orders/1", red, { includeText: false, extractors: [], deadline: Date.now() - 1 });
  assert.match(slow.incomplete!, /timeout/, "an overrun is incomplete, never evidence of absence");
});

test("extractor specs: strict schema; no value, text, regex, pseudo-classes or secret-like names", () => {
  const ok = { extractor: "1", id: "prices", match: { path_pattern: "/orders/{id}" }, fields: [{ name: "product_links", select: "a[class=price]", attr: "href", predicate: "same_origin_url", max_items: 5 }] };
  assert.doesNotThrow(() => parseExtractor(JSON.stringify(ok)));
  const bad = (f: Record<string, unknown>, re: RegExp) => assert.throws(() => parseExtractor(JSON.stringify({ ...ok, fields: [{ ...ok.fields[0], ...f }] })), (e: unknown) => e instanceof ExtractorError && re.test(e.problems.join("\n")));
  bad({ attr: "value" }, /value and text content are never extracted/);
  bad({ select: "a:hover" }, /selector subset/);
  bad({ select: "a > b" }, /selector subset/);
  bad({ select: "p:contains(x)" }, /selector subset/);
  bad({ regex: ".*" }, /user regexes are not supported/);
  bad({ name: "session_token" }, /look like secrets/);
  bad({ predicate: "matches_regex" }, /predicate/);
  bad({ max_items: 500 }, /max_items/);
  assert.throws(() => parseExtractor(JSON.stringify({ ...ok, extra: 1 })), /unknown key/);
  assert.equal(parseSelector("a b c d e f g h i"), undefined, "at most 8 levels");
  const dom = parseDom('<main><ul><li><a class="price" href="/p/1">x</a></li><li><a href="/p/2">y</a></li></ul></main>');
  assert.equal(select(dom, parseSelector("main li a[class=price]")!).length, 1);
  assert.equal(select(dom, parseSelector("ul a")!).length, 2);
});

test("extractors run against matching templates; values pass the Redactor and URLs become display URLs", () => {
  const spec = parseExtractor(JSON.stringify({ extractor: "1", id: "prices", match: { path_pattern: "/orders/{id}" }, fields: [
    { name: "product", select: "a[class=price]", attr: "href", predicate: "same_origin_url", max_items: 5 },
    { name: "kind", select: "input", attr: "type", max_items: 10 },
    { name: "external", select: "a", attr: "href", predicate: "same_origin_url", max_items: 10 },
  ] }));
  const m = buildPageModel(page(3), "http://h.test/orders/3", new Redactor(), { includeText: false, extractors: [spec], deadline: Date.now() + 5000 });
  assert.deepEqual(m.extracted!.prices!.product, ["http://h.test/product/{id}"]);
  assert.deepEqual(m.extracted!.prices!.kind, ["text", "number", "hidden"]);
  assert.ok(!m.extracted!.prices!.external!.some((x) => x.includes("other.example")), "predicate filters off-origin links");
  const other = buildPageModel(page(3), "http://h.test/catalog", new Redactor(), { includeText: false, extractors: [spec], deadline: Date.now() + 5000 });
  assert.equal(other.extracted, undefined, "a spec applies only to its path pattern");
  assert.equal(displayUrl("https://a:b@x.test/u/550e8400-e29b-41d4-a716-446655440000?t=1#h"), "https://x.test/u/{id}?t=[REDACTED]");
});

test("scan --analyze: page models promoted to the run, drafts deleted with the work dir, code files refused, flow analyze reads them", async () => {
  const s = http.createServer((q, res) => {
    const u = new URL(q.url ?? "/", "http://x");
    const m = /^\/orders\/(\d+)$/.exec(u.pathname);
    res.writeHead(200, { "content-type": "text/html; charset=utf-8", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'", "referrer-policy": "no-referrer", "cache-control": "no-store" });
    res.end(u.pathname === "/" ? '<a href="/orders/1">1</a><a href="/orders/2">2</a>' : page(m ? Number(m[1]) : 0));
  });
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(s.address() as { port: number }).port}`;
  const dir = mkdtempSync(join(tmpdir(), "navsentry-analyzer-"));
  const saved = { ...process.env };
  try {
    process.env.NS_ANALYZER_TOKEN = TOKEN;
    const mf = join(dir, "m.json");
    writeFileSync(mf, JSON.stringify({ version: "1", project: "an", environment: "local", authorization: { acknowledged: true, owner: "t" }, targets: { origins: [origin], seed_paths: ["/"] }, network: { allow_private: [{ host: "127.0.0.1", approved_by: "t", reason: "fixture" }] }, safety: { mode: "observe", max_requests_per_second: 20 }, actors: { reader: { authorization_header_env: "NS_ANALYZER_TOKEN" } }, checks: { disabled: ["NSC-CRYPT-006", "NSC-AC-004", "NSC-CONF-006", "NSC-CONF-009"] }, report: { formats: ["json", "markdown"] } }));
    const drafts = join(dir, "..", `${dir.split(/[\\/]/).pop()}-extractors`);
    mkdirSync(drafts);
    writeFileSync(join(drafts, "prices.json"), JSON.stringify({ extractor: "1", id: "prices", match: { path_pattern: "/orders/{id}" }, fields: [{ name: "product", select: "a[class=price]", attr: "href", max_items: 3 }] }));
    writeFileSync(join(drafts, "scrape.py"), "import os\nos.system('echo pwned')\n");
    const out = join(dir, "run");
    const code = await main(["scan", "--config", mf, "--mode", "spider", "--analyze", "--extractors", drafts, "--project", dir, "--out", out]);
    assert.ok(code === 0 || code === 1, `exit ${code}`);
    const r = JSON.parse(readFileSync(join(out, "run.json"), "utf8")) as RunResult;
    assert.equal(r.analyzer!.engine, "node-page-model");
    assert.ok(r.analyzer!.pages >= 2);
    assert.deepEqual(r.analyzer!.refused.map((x) => x.file), ["scrape.py"]);
    assert.match(r.analyzer!.refused[0]!.reason, /never executes code/);
    assert.equal(r.analyzer!.extractors[0]!.status, "deleted with the run");
    const models = readdirSync(join(out, "page-models"));
    const all = models.map((n) => readFileSync(join(out, "page-models", n), "utf8")).join("\n");
    for (const x of [TOKEN, "4111111111111111", "admin@corp.example", "Welcome"]) assert.ok(!all.includes(x), `artifact leaked ${x}`);
    assert.ok(all.includes('"prices"'), "extractor output present");
    assert.deepEqual(readdirSync(join(dir, ".navsentry", "work")), [], "draft specs deleted with the work directory");
    assert.ok(!existsSync(join(dir, "__pycache__")), "no interpreter leftovers");
    assert.equal(r.workspace!.status, "PASS");
    const flows = join(dir, "drafts");
    assert.equal(await main(["flow", "analyze", "--config", mf, "--from-run", join(out, "run.json"), "--out", flows]), 0);
    assert.match(readFileSync(join(flows, "ANALYSIS.md"), "utf8"), /## Templates and forms \(page models\)[\s\S]*\/orders\/\{id\}/);
    assert.equal(await main(["flow", "lint", "--config", mf, "--flows", flows]), 0, "drafts pass lint");
    assert.equal(await main(["scan", "--config", mf, "--mode", "page", "--extractors", drafts, "--project", dir]), 3, "--extractors needs --analyze");
    rmSync(drafts, { recursive: true, force: true });
  } finally {
    process.env = saved;
    await new Promise((r) => { s.closeAllConnections(); s.close(r); });
    rmSync(dir, { recursive: true, force: true });
  }
});
