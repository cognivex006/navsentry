/** SPEC-0.3.0 0.3.0-a: `navsentry init`, default navsentry.json, short `scan`, demo v2. 127.0.0.1 only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli.js";
import { parseManifest } from "../src/config.js";
import { InitError, askInit, buildInitManifest, environmentWarning, insideNavSentryCheckout, parseTarget, type Prompter } from "../src/init.js";
import { startDemoSite } from "./fixtures/demo-site.js";

const scripted = (answers: string[]): Prompter & { asked: string[] } => {
  const asked: string[] = [];
  return { asked, ask: async (q) => { asked.push(q); return answers.shift() ?? ""; }, say: () => {} };
};

async function inDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "navsentry-init-"));
  const cwd = process.cwd();
  process.chdir(dir);
  try { return await fn(dir); } finally { process.chdir(cwd); rmSync(dir, { recursive: true, force: true }); }
}

test("parseTarget: http(s) only, no credentials, metadata refused, local hosts labelled", () => {
  assert.throws(() => parseTarget("ftp://x.test/"), InitError);
  assert.throws(() => parseTarget("https://u:p@x.test/"), InitError);
  assert.throws(() => parseTarget("http://169.254.169.254/"), /metadata/);
  assert.throws(() => parseTarget("not a url"), InitError);
  assert.equal(parseTarget("http://localhost:3000/app").privateLabel, "loopback");
  assert.equal(parseTarget("http://127.0.0.1:4173/").privateLabel, "loopback");
  assert.equal(parseTarget("http://10.1.2.3/").privateLabel !== undefined, true);
  const pub = parseTarget("https://shop.example.test/catalog?x=1");
  assert.equal(pub.privateLabel, undefined);
  assert.equal(pub.origin, "https://shop.example.test");
  assert.equal(pub.seedPath, "/catalog");
});

test("buildInitManifest: valid observe manifest; private hosts and production need explicit answers", () => {
  const local = buildInitManifest({ url: "http://127.0.0.1:4173/", environment: "local", owner: "me", allowPrivate: true });
  const m = parseManifest(local);
  assert.equal(m.safety.mode, "observe");
  assert.deepEqual(m.targets.origins, ["http://127.0.0.1:4173"]);
  assert.equal(m.network.allow_private[0]?.host, "127.0.0.1");
  assert.throws(() => buildInitManifest({ url: "http://127.0.0.1:4173/", environment: "local", owner: "me" }), /explicit approval/);
  assert.throws(() => buildInitManifest({ url: "https://shop.example.test/", environment: "staging", owner: "me" }), /reference/);
  assert.throws(() => buildInitManifest({ url: "https://shop.example.test/", environment: "staging", owner: "me", reference: "CHG-1" }), /expiry/);
  assert.throws(() => buildInitManifest({ url: "https://shop.example.test/", environment: "staging", owner: " " }), /owner/);
  const st = parseManifest(buildInitManifest({ url: "https://shop.example.test/", environment: "staging", owner: "me", reference: "CHG-1", expiresAt: "2099-01-01" }));
  assert.equal(st.profile, "production");
  assert.equal(st.network.allow_private.length, 0);
});

test("askInit: authorization must be confirmed; a no stops before anything else", async () => {
  const p = scripted(["", "no"]);
  await assert.rejects(askInit(p, "http://127.0.0.1:4173/"), /authorization not confirmed/);
  assert.equal(p.asked.length, 2);
  await assert.rejects(askInit(scripted(["local", "yes", "me", "no"]), "http://127.0.0.1:4173/"), /private address not approved/);
  const ok = await askInit(scripted(["", "yes", "Team A", "yes"]), "http://127.0.0.1:4173/");
  assert.equal(ok.environment, "local");
  assert.equal(ok.allowPrivate, true);
  const prod = await askInit(scripted(["yes", "Team A", "CHG-9", "2099-01-01"]), "https://shop.example.test/", { environment: "production" });
  assert.equal(prod.reference, "CHG-9");
  parseManifest(buildInitManifest(prod));
});

test("CLI init refuses without a terminal and never overwrites; other commands find navsentry.json", async () => {
  await inDir(async (dir) => {
    assert.equal(await main(["init", "http://127.0.0.1:4173/"]), 3);
    assert.equal(existsSync(join(dir, "navsentry.json")), false);
    assert.equal(await main(["init"]), 3);
    assert.equal(await main(["init", "http://127.0.0.1:4173/", "--environment", "qa"]), 3);
    assert.equal(await main(["validate"]), 3, "no manifest and no --config");
    writeFileSync(join(dir, "navsentry.json"), JSON.stringify(buildInitManifest({ url: "http://127.0.0.1:4173/", environment: "local", owner: "me", allowPrivate: true })));
    const before = readFileSync(join(dir, "navsentry.json"), "utf8");
    assert.equal(await main(["init", "http://127.0.0.1:4173/"]), 3);
    assert.equal(readFileSync(join(dir, "navsentry.json"), "utf8"), before);
    assert.equal(await main(["validate"]), 0);
    assert.equal(await main(["scan", "--deep", "--mode", "page"]), 3);
  });
});

test("short scan: no --mode scans the seed page; --deep crawls the demo shop by template", async () => {
  const site = await startDemoSite("vulnerable");
  try {
    await inDir(async (dir) => {
      const mf = buildInitManifest({ url: `${site.origin}/`, environment: "local", owner: "me", allowPrivate: true });
      writeFileSync(join(dir, "navsentry.json"), JSON.stringify(mf));
      assert.equal(await main(["scan", "--project", dir, "--out", join(dir, "page")]), 1);
      const page = JSON.parse(readFileSync(join(dir, "page", "run.json"), "utf8"));
      assert.equal(page.scanMode, "page");
      assert.equal(await main(["scan", "--deep", "--project", dir, "--out", join(dir, "deep")]), 1);
      const deep = JSON.parse(readFileSync(join(dir, "deep", "run.json"), "utf8"));
      assert.equal(deep.scanMode, "spider");
      assert.equal(deep.engine.analyze, true);
      const paths = new Set((deep.requests as { url: string }[]).map((r) => new URL(r.url).pathname));
      for (const p of ["/products", "/search", "/login", "/about"]) assert.ok(paths.has(p), `spider reached ${p}`);
      assert.ok([...paths].some((p) => /^\/products\/[0-9]+$/.test(p)), "spider reached a product page");
    });
  } finally {
    await site.close();
  }
});

test("demo v2: secure variant keeps the pages and encodes the search reflection", async () => {
  const v = await startDemoSite("vulnerable");
  const s = await startDemoSite("secure");
  try {
    const q = "<b>m</b>";
    const rv = await (await fetch(`${v.origin}/search?q=${encodeURIComponent(q)}`)).text();
    const rs = await (await fetch(`${s.origin}/search?q=${encodeURIComponent(q)}`)).text();
    assert.ok(rv.includes(q));
    assert.ok(!rs.includes(q));
    for (const o of [v.origin, s.origin]) {
      const home = await fetch(`${o}/`);
      assert.equal(home.status, 200);
      assert.ok((await home.text()).includes('href="/products"'));
      assert.equal((await fetch(`${o}/products/1`)).status, 200);
      assert.equal((await fetch(`${o}/products/99`)).status, 404);
    }
  } finally {
    await v.close();
    await s.close();
  }
});

test("init: development profile on a public host warns and asks; browser engine only on development; never inside a checkout", async () => {
  assert.match(environmentWarning(parseTarget("https://shop.example.test/"), "local") ?? "", /not a loopback or private address/);
  assert.equal(environmentWarning(parseTarget("http://127.0.0.1:4173/"), "local"), undefined);
  assert.equal(environmentWarning(parseTarget("https://shop.example.test/"), "staging"), undefined);
  await assert.rejects(askInit(scripted(["local", "no"]), "https://shop.example.test/"), /environment not confirmed/);
  const kept = await askInit(scripted(["dev", "yes", "yes", "Team A"]), "https://shop.example.test/");
  assert.equal(kept.environment, "dev");
  const dev = parseManifest(buildInitManifest({ url: "http://127.0.0.1:4173/", environment: "local", owner: "me", allowPrivate: true }));
  assert.deepEqual(dev.transports.order, ["direct-http", "playwright-browser"]);
  const st = parseManifest(buildInitManifest({ url: "https://shop.example.test/", environment: "staging", owner: "me", reference: "CHG-1", expiresAt: "2099-01-01" }));
  assert.deepEqual(st.transports.order, ["direct-http"]);
  const dir = mkdtempSync(join(tmpdir(), "navsentry-checkout-"));
  try {
    assert.equal(insideNavSentryCheckout(join(dir, "navsentry.json"), dir), false, "not a git checkout");
    mkdirSync(join(dir, ".git"));
    assert.equal(insideNavSentryCheckout(join(dir, "navsentry.json"), dir), true);
    assert.equal(insideNavSentryCheckout(join(dir, "..", "elsewhere.json"), dir), false);
    assert.equal(insideNavSentryCheckout(join(dir, "..cfg", "x.json"), dir), true, "a child folder named ..cfg is inside");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
