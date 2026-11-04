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
import type { Snapshot } from "../src/knowledge/model.js";
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
