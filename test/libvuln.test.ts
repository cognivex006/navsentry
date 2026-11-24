/**
 * STA-LIBVULN → NSC-SUPPLY-002 (SPEC-0.1.3 §6.4-B): a client library licence banner matched against
 * reviewed advisory records. Vulnerable and secure variants keep the same response contract.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { StreamScanner } from "../src/assets/detect.js";
import { SNAPSHOT } from "../src/knowledge/advisories.js";
import { applicability, type Snapshot } from "../src/knowledge/model.js";
import { executeTest } from "../src/runner.js";
import { localManifest } from "./helpers.js";

/** Synthetic stand-ins for a minified jQuery bundle: only the licence banner is real-shaped. */
const bundle = (version: string) => `/*! jQuery v${version} | (c) OpenJS Foundation and other contributors | jquery.org/license */\n!function(e){"use strict";e.ready=function(){}}(window);\n`;
const PLUGIN = "/* tiny-plugin 1.0: requires jQuery v1.7 or later */\n(function($){$.fn.tiny=function(){return this}})(jQuery);\n";

function start(version: string): Promise<{ origin: string; close(): Promise<void> }> {
  const server = http.createServer((req, res) => {
    const p = new URL(req.url ?? "/", "http://x").pathname;
    if (p === "/") return void res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end('<!doctype html><title>Lib</title><script src="/js/jquery.min.js"></script><script src="/js/plugin.js"></script>');
    if (p === "/js/jquery.min.js") return void res.writeHead(200, { "content-type": "text/javascript" }).end(bundle(version));
    if (p === "/js/plugin.js") return void res.writeHead(200, { "content-type": "text/javascript" }).end(PLUGIN);
    res.writeHead(404, { "content-type": "text/plain" }).end("not found");
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r({ origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, close: () => new Promise<void>((c) => server.close(() => c())) })));
}

async function scan(version: string, snapshot: Snapshot = SNAPSHOT) {
  const app = await start(version);
  const work = mkdtempSync(join(tmpdir(), "navsentry-libvuln-"));
  try {
    const m = localManifest(app.origin, { checks: { disabled: ["NSC-CRYPT-006", "NSC-CONF-009"] } });
    return await executeTest(m, { assets: true, workDir: work, urls: [`${app.origin}/`], snapshot });
  } finally {
    rmSync(work, { recursive: true, force: true });
    await app.close();
  }
}

const supply = (r: Awaited<ReturnType<typeof scan>>) => r.run.checks.filter((c) => c.ruleId === "NSC-SUPPLY-002");

test("vulnerable: jQuery 3.4.1 banner → NSC-SUPPLY-002 SUSPECTED with the matching reviewed advisories", async () => {
  const r = await scan("3.4.1");
  const fail = supply(r).find((c) => c.status === "FAIL")!;
  assert.ok(fail, JSON.stringify(supply(r)));
  assert.equal(fail.lifecycle, "SUSPECTED", "a banner match never validates exploitability");
  assert.ok(fail.observations.some((o) => o.includes("CVE-2020-11022")) && fail.observations.some((o) => o.includes("CVE-2020-11023")));
  assert.ok(!fail.observations.some((o) => o.includes("CVE-2019-11358")), "3.4.1 is already fixed for CVE-2019-11358");
  assert.ok(fail.observations.some((o) => /licence banner/.test(o)), "the banner caveat is shown");
  assert.equal(r.clientFindings!.filter((f) => f.caseId === "NSC-SUPPLY-002").length, 2);
  assert.ok(r.clientFindings!.every((f) => f.caseId !== "NSC-SUPPLY-002" || /^\[jquery,v=3\.4\.1,GHSA-[a-z0-9-]+\]$/.test(f.preview)));
  assert.ok(r.run.findings.some((f) => f.ruleId === "NSC-SUPPLY-002" && f.lifecycle === "SUSPECTED"));
  // A library banner never suppresses another detector on the same asset.
  assert.ok(r.run.checks.some((c) => c.ruleId === "NSC-INFO-007" && c.target.includes("jquery.min.js")));
});

test("secure: jQuery 3.7.1 keeps the same contract and gets no SUPPLY-002 finding", async () => {
  const r = await scan("3.7.1");
  assert.ok(supply(r).length > 0);
  assert.ok(supply(r).every((c) => c.status === "NOT_TESTED"), JSON.stringify(supply(r)));
  assert.match(supply(r)[0]!.reason ?? "", /cannot prove that no other advisory exists/);
  assert.ok(!r.run.findings.some((f) => f.ruleId === "NSC-SUPPLY-002"));
  const v = await scan("3.4.1");
  const shape = (x: typeof r) => x.run.requests.filter((q) => q.url.includes("/js/")).map((q) => `${q.status} ${q.contract?.contentType}`).sort();
  assert.deepEqual(shape(r), shape(v), "same response contract for legitimate callers");
});

test("candidate-only records are not used: NOT_TESTED with the reason", async () => {
  const candidates: Snapshot = { ...SNAPSHOT, records: SNAPSHOT.records.map((x) => ({ ...x, state: "candidate" as const })) };
  const r = await scan("3.4.1", candidates);
  assert.ok(supply(r).every((c) => c.status === "NOT_TESTED"));
  assert.match(supply(r)[0]!.reason ?? "", /not reviewed yet/);
});

test("only the banner comment form counts; a plugin mentioning an old jQuery is not a library match", () => {
  const facts = (text: string) => { const s = new StreamScanner(); s.feed(Buffer.from(text)); return s.end().facts.filter((f) => f.detector === "STA-LIBVULN"); };
  assert.deepEqual(facts(PLUGIN), []);
  assert.deepEqual(facts(bundle("3.4.1")).map((f) => f.library), [{ ecosystem: "npm", name: "jquery", version: "3.4.1" }]);
  assert.deepEqual(facts("/*!\n * jQuery JavaScript Library v1.12.4\n */").map((f) => f.library?.version), ["1.12.4"]);
});

// ───────────── Bootstrap (npm `bootstrap`, reviewed 2026-11-24) ─────────────

const bsJs = (v: string) => `/*!\n * Bootstrap v${v} (https://getbootstrap.com/)\n * Copyright 2011-2019 The Bootstrap Authors\n * Licensed under MIT\n */\n!function(t){"use strict";t.tooltip=function(){}}(window);\n`;
const bsCss = (v: string) => `/*!\n * Bootstrap v${v} (https://getbootstrap.com/)\n * Licensed under MIT\n */\n:root{--blue:#007bff}\n`;

function startBs(js: string, css: string): Promise<{ origin: string; close(): Promise<void> }> {
  const server = http.createServer((req, res) => {
    const p = new URL(req.url ?? "/", "http://x").pathname;
    if (p === "/") return void res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end('<!doctype html><title>Bs</title><link rel="stylesheet" href="/css/bootstrap.min.css"><script src="/js/bootstrap.min.js"></script>');
    if (p === "/js/bootstrap.min.js") return void res.writeHead(200, { "content-type": "text/javascript" }).end(bsJs(js));
    if (p === "/css/bootstrap.min.css") return void res.writeHead(200, { "content-type": "text/css" }).end(bsCss(css));
    res.writeHead(404, { "content-type": "text/plain" }).end("not found");
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r({ origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, close: () => new Promise<void>((c) => server.close(() => c())) })));
}

async function scanBs(js: string, css = js) {
  const app = await startBs(js, css);
  const work = mkdtempSync(join(tmpdir(), "navsentry-libvuln-bs-"));
  try {
    const m = localManifest(app.origin, { checks: { disabled: ["NSC-CRYPT-006", "NSC-CONF-009"] } });
    return await executeTest(m, { assets: true, workDir: work, urls: [`${app.origin}/`], snapshot: SNAPSHOT });
  } finally {
    rmSync(work, { recursive: true, force: true });
    await app.close();
  }
}

test("vulnerable: Bootstrap 3.3.7 JS banner → SUSPECTED with the 3.x advisories, including the unfixed CVE-2024-6485", async () => {
  const r = await scanBs("3.3.7");
  const fail = supply(r).find((c) => c.status === "FAIL" && c.target.includes("bootstrap.min.js"))!;
  assert.ok(fail, JSON.stringify(supply(r)));
  assert.equal(fail.lifecycle, "SUSPECTED");
  for (const cve of ["CVE-2018-14040", "CVE-2016-10735", "CVE-2019-8331", "CVE-2018-20676", "CVE-2018-20677", "CVE-2018-14042", "CVE-2024-6485"]) assert.ok(fail.observations.some((o) => o.includes(cve)), cve);
  assert.ok(!fail.observations.some((o) => o.includes("CVE-2018-14041")), "scrollspy advisory is 4.x only");
  assert.ok(!fail.observations.some((o) => o.includes("CVE-2024-6484")), "withdrawn advisory is not in the snapshot");
  const css = supply(r).find((c) => c.target.includes("bootstrap.min.css"))!;
  assert.equal(css.status, "NOT_TESTED", "a stylesheet banner is not a JavaScript match");
  assert.match(css.reason ?? "", /stylesheet alone is not affected/);
});

test("vulnerable: Bootstrap 4.1.1 → CVE-2018-14040/14041/14042 and CVE-2019-8331; 3.4.1 → only the unfixed CVE-2024-6485", async () => {
  const four = supply(await scanBs("4.1.1")).find((c) => c.status === "FAIL")!;
  assert.deepEqual(["CVE-2018-14040", "CVE-2018-14041", "CVE-2018-14042", "CVE-2019-8331"].filter((c) => four.observations.some((o) => o.includes(c))).length, 4);
  assert.ok(!four.observations.some((o) => o.includes("CVE-2024-6485")));
  const last3 = supply(await scanBs("3.4.1")).find((c) => c.status === "FAIL")!;
  assert.match(last3.summary, /matches 1 reviewed/);
  assert.ok(last3.observations.some((o) => o.includes("CVE-2024-6485")));
});

test("secure: Bootstrap 5.3.3 keeps the same contract and gets no SUPPLY-002 finding", async () => {
  const r = await scanBs("5.3.3");
  assert.ok(supply(r).length > 0 && supply(r).every((c) => c.status === "NOT_TESTED"), JSON.stringify(supply(r)));
  assert.ok(!r.run.findings.some((f) => f.ruleId === "NSC-SUPPLY-002"));
  const v = await scanBs("3.3.7");
  const shape = (x: typeof r) => x.run.requests.filter((q) => /\/(js|css)\//.test(q.url)).map((q) => `${q.status} ${q.contract?.contentType}`).sort();
  assert.deepEqual(shape(r), shape(v));
});

test("Bootstrap banner forms: v3 and v4 comment blocks match; a component file or prose mention does not", () => {
  const facts = (text: string) => { const s = new StreamScanner(); s.feed(Buffer.from(text)); return s.end().facts.filter((f) => f.detector === "STA-LIBVULN").map((f) => f.library); };
  assert.deepEqual(facts("/*!\n * Bootstrap v3.3.7 (http://getbootstrap.com)\n */"), [{ ecosystem: "npm", name: "bootstrap", version: "3.3.7" }]);
  assert.deepEqual(facts("/*!\n  * Bootstrap v4.1.1 (https://getbootstrap.com/)\n  */"), [{ ecosystem: "npm", name: "bootstrap", version: "4.1.1" }]);
  assert.deepEqual(facts("/* theme: requires Bootstrap v3.3.7 or later */"), []);
  assert.deepEqual(facts("/*!\n  * Bootstrap tooltip.js v4.1.1 (https://getbootstrap.com/)\n  */"), []);
});

test("CVE-2016-10735: 4.0.0-beta / beta.1 affected, beta.2 / 4.0.0 not (prerelease range)", async () => {
  const rec = SNAPSHOT.records.find((x) => x.id === "GHSA-4p24-vmcr-4gqj")!;
  const at = (version: string) => applicability(rec, { ecosystem: "npm", name: "bootstrap", version, provenance: "client-banner" }).applicability;
  assert.deepEqual(["4.0.0-beta", "4.0.0-beta.1", "4.0.0-beta.2", "4.0.0", "2.0.3", "2.0.4", "3.3.7", "3.4.0"].map(at),
    ["affected", "affected", "not-affected", "not-affected", "not-affected", "affected", "affected", "not-affected"]);
  const beta = supply(await scanBs("4.0.0-beta")).find((c) => c.status === "FAIL");
  assert.ok(beta?.observations.some((o) => o.includes("CVE-2016-10735")), JSON.stringify(supply(await scanBs("4.0.0-beta"))));
});

test("CVE-2018-14040: 2.3.0–3.3.x and 4.0.0–4.1.1 affected; 2.2.2, 3.4.0, 4.1.2 not", () => {
  const rec = SNAPSHOT.records.find((x) => x.id === "GHSA-3wqf-4x89-9g79")!;
  const at = (version: string) => applicability(rec, { ecosystem: "npm", name: "bootstrap", version, provenance: "client-banner" }).applicability;
  assert.deepEqual(["2.2.2", "2.3.0", "3.3.7", "3.4.0", "4.0.0", "4.1.1", "4.1.2"].map(at),
    ["not-affected", "affected", "affected", "not-affected", "affected", "affected", "not-affected"]);
});

// ───────────── AngularJS (npm `angular`, reviewed 2026-11-24) ─────────────

const ngFull = (v: string) => `/**\n * @license AngularJS v${v}\n * (c) 2010-2020 Google LLC. http://angularjs.org\n * License: MIT\n */\n(function(window){"use strict";window.angular={};})(window);\n`;
const ngMin = (v: string) => `/*\n AngularJS v${v}\n (c) 2010-2020 Google LLC. http://angularjs.org\n License: MIT\n*/\n(function(w){w.angular={}})(window);\n`;

async function scanNg(body: string) {
  const server = http.createServer((req, res) => {
    const p = new URL(req.url ?? "/", "http://x").pathname;
    if (p === "/") return void res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end('<!doctype html><title>Ng</title><script src="/js/angular.min.js"></script>');
    if (p === "/js/angular.min.js") return void res.writeHead(200, { "content-type": "text/javascript" }).end(body);
    res.writeHead(404, { "content-type": "text/plain" }).end("not found");
  });
  const origin = await new Promise<string>((r) => server.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
  const work = mkdtempSync(join(tmpdir(), "navsentry-libvuln-ng-"));
  try {
    const m = localManifest(origin, { checks: { disabled: ["NSC-CRYPT-006", "NSC-CONF-009"] } });
    return await executeTest(m, { assets: true, workDir: work, urls: [`${origin}/`], snapshot: SNAPSHOT });
  } finally {
    rmSync(work, { recursive: true, force: true });
    await new Promise<void>((c) => server.close(() => c()));
  }
}

test("vulnerable: AngularJS 1.7.8 → SUSPECTED, including the pre-1.7.9 merge() and pre-1.8.0 JQLite advisories", async () => {
  const r = await scanNg(ngMin("1.7.8"));
  const fail = supply(r).find((c) => c.status === "FAIL")!;
  assert.ok(fail, JSON.stringify(supply(r)));
  assert.equal(fail.lifecycle, "SUSPECTED");
  for (const id of ["CVE-2019-10768", "GHSA-5cp4-xmrw-59wf", "CVE-2020-7676", "CVE-2022-25844", "CVE-2026-11998"]) assert.ok(fail.observations.some((o) => o.includes(id)), id);
  assert.ok(!fail.observations.some((o) => o.includes("CVE-2019-14863")), "fixed in 1.5.0-beta.1");
  assert.ok(!fail.observations.some((o) => o.includes("GHSA-28hp-fgcr-2r4h")), "fixed in 1.6.0");
});

test("AngularJS 1.8.3 (last release) still matches the unfixed advisories only; ranges at their boundaries", async () => {
  const fail = supply(await scanNg(ngFull("1.8.3"))).find((c) => c.status === "FAIL")!;
  assert.match(fail.summary, /matches 10 reviewed/);
  assert.ok(!fail.observations.some((o) => o.includes("CVE-2019-10768") || o.includes("CVE-2020-7676")));
  const at = (id: string, version: string) => applicability(SNAPSHOT.records.find((x) => x.id === id)!, { ecosystem: "npm", name: "angular", version, provenance: "client-banner" }).applicability;
  assert.deepEqual(["1.6.10", "1.7.0", "1.8.3"].map((v) => at("GHSA-m2h2-264f-f486", v)), ["not-affected", "affected", "affected"]);
  assert.deepEqual(["1.2.0-rc.2", "1.2.0-rc.3", "1.8.3"].map((v) => at("GHSA-7x27-g8rg-x87w", v)), ["not-affected", "affected", "affected"]);
  assert.deepEqual(["1.4.14", "1.5.0-beta.1"].map((v) => at("GHSA-r5fx-8r73-v86c", v)), ["affected", "not-affected"]);
});

test("secure contract: a non-AngularJS bundle on the same path gets no SUPPLY-002 finding and the same response shape", async () => {
  const r = await scanNg("/*! app 2.0 | MIT */\n(function(w){w.app={}})(window);\n");
  assert.ok(!r.run.findings.some((f) => f.ruleId === "NSC-SUPPLY-002"));
  const v = await scanNg(ngMin("1.7.8"));
  const shape = (x: typeof r) => x.run.requests.filter((q) => q.url.includes("/js/")).map((q) => `${q.status} ${q.contract?.contentType}`).sort();
  assert.deepEqual(shape(r), shape(v));
});

test("AngularJS banner forms: full and minified banner lines match; prose and Angular 2+ do not", () => {
  const facts = (text: string) => { const s = new StreamScanner(); s.feed(Buffer.from(text)); return s.end().facts.filter((f) => f.detector === "STA-LIBVULN").map((f) => f.library); };
  assert.deepEqual(facts(ngFull("1.8.2")), [{ ecosystem: "npm", name: "angular", version: "1.8.2" }]);
  assert.deepEqual(facts(ngMin("1.5.0-beta.1")), [{ ecosystem: "npm", name: "angular", version: "1.5.0-beta.1" }]);
  assert.deepEqual(facts(ngFull("1.8.2").replace(/\n/g, "\r\n")).map((l) => l?.version), ["1.8.2"]);
  assert.deepEqual(facts("// requires AngularJS v1.5.0 or later\n"), []);
  assert.deepEqual(facts("/**\n * @license Angular v17.3.0\n */"), []);
});
