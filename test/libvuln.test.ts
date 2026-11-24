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
