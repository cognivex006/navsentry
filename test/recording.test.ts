/** SPEC-0.3.0 0.3.0-e: DevTools Recorder JSON → draft flow. Zero network; fixture data only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { main } from "../src/cli.js";
import { parseFlowText } from "../src/flow/parse.js";
import { MAX_RECORDING_STEPS, RecordingError, cleanText, importRecording, recordingOrigin, targetFrom, truncationHint } from "../src/flow/recording.js";
import { localManifest } from "./helpers.js";

const ORIGIN = "http://127.0.0.1:4173";
const m = localManifest(ORIGIN);
const demo = JSON.parse(readFileSync("examples/demo/recordings/shop-search.recording.json", "utf8"));

test("selectors: aria with role, aria without role, text; CSS and XPath only are not guessed", () => {
  assert.deepEqual(targetFrom([["aria/Search[role=\"link\"]"], ["a.x"]], false), { role: "link", name: "Search" });
  assert.deepEqual(targetFrom([["aria/Product name"]], true), { label: "Product name" });
  assert.deepEqual(targetFrom([["aria/Buy"]], false), { text: "Buy" });
  assert.deepEqual(targetFrom([["#id"], ["text/Products"]], false), { text: "Products" });
  assert.equal(targetFrom([["main > a.card"], ["xpath///html/body/a"]], false), undefined);
  assert.equal(targetFrom([["aria/x[role=\"bogus\"]"]], false)?.hasOwnProperty("role"), false, "unknown roles fall back to text");
  assert.equal(targetFrom([["pierce/a", "aria/inside-shadow"]], false), undefined, "nested chains are not supported");
});

test("the demo recording becomes a parseable draft: values dropped, scope and unknown steps listed", () => {
  const r = importRecording(demo, m, "shop-search.recording.json");
  assert.equal(r.id, "rec-shop-search");
  const doc = parseFlowText(r.flow, `${r.id}.flow.md`).doc!;
  assert.ok(doc, "parses");
  assert.equal(doc.header.review.status, "draft");
  assert.deepEqual(doc.steps.map((s) => s.action), ["navigate", "click", "fill", "see"]);
  assert.ok(!r.flow.includes("rice"), "the recorded value is never written");
  assert.ok(!r.flow.includes("elsewhere.example.test"), "out-of-scope URLs are never encoded");
  assert.match(r.flow, /"env": "NAVSENTRY_REC_SHOP_SEARCH_1"/);
  const reasons = r.skipped.map((s) => `${s.type}:${s.reason}`).join("\n");
  assert.match(reasons, /keyDown:Enter key/);
  assert.match(reasons, /click:only CSS or XPath/);
  assert.match(reasons, /scroll:not supported/);
  assert.match(reasons, /navigate:navigate outside the manifest scope/);
  assert.match(r.report, /fill steps run only in safe-validate/);
});

test("refusals: not a recording, too many steps, no in-scope navigate; a second origin stops encoding", () => {
  assert.throws(() => importRecording({ title: "x" }, m, "x.json"), RecordingError);
  assert.throws(() => importRecording({ steps: Array.from({ length: MAX_RECORDING_STEPS + 1 }, () => ({ type: "scroll" })) }, m, "x.json"), /more than/);
  assert.throws(() => importRecording({ steps: [{ type: "navigate", url: "https://elsewhere.example.test/" }, { type: "click", selectors: [["aria/A[role=\"link\"]"]] }] }, m, "x.json"), /no in-scope navigate/);
  const r = importRecording({ steps: [
    { type: "navigate", url: `${ORIGIN}/` },
    { type: "click", selectors: [["aria/Out[role=\"link\"]"]], assertedEvents: [{ type: "navigation", url: "https://elsewhere.example.test/x" }] },
    { type: "click", selectors: [["aria/After[role=\"link\"]"]] },
  ] }, m, "x.json");
  assert.equal(r.encoded, 1, "a click that leaves the scope is not encoded, nor are later steps");
  assert.equal(r.skipped.length, 2);
});

test("CLI: writes the draft and IMPORT.md, never overwrites, refuses non-JSON", async () => {
  const dir = mkdtempSync(join(tmpdir(), "navsentry-rec-"));
  try {
    const mf = join(dir, "m.json");
    writeFileSync(mf, JSON.stringify({ version: "1", project: "rec", environment: "local", authorization: { acknowledged: true, owner: "t" }, targets: { origins: [ORIGIN] }, network: { allow_private: [{ host: "127.0.0.1", approved_by: "t", reason: "fixture" }] } }));
    const rec = join(dir, "r.json");
    writeFileSync(rec, JSON.stringify(demo));
    const out = join(dir, "flows");
    assert.equal(await main(["flow", "from-recording", "--config", mf, "--input", rec, "--out", out]), 0);
    assert.ok(existsSync(join(out, "rec-shop-search.flow.md")) && existsSync(join(out, "rec-shop-search.IMPORT.md")));
    const before = readFileSync(join(out, "rec-shop-search.flow.md"), "utf8");
    assert.equal(await main(["flow", "from-recording", "--config", mf, "--input", rec, "--out", out]), 3, "never overwrites");
    assert.equal(readFileSync(join(out, "rec-shop-search.flow.md"), "utf8"), before);
    assert.equal(await main(["flow", "lint", "--config", mf, "--flows", out]), 0);
    writeFileSync(rec, "not json");
    assert.equal(await main(["flow", "from-recording", "--config", mf, "--input", rec, "--out", join(dir, "o2")]), 3);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("import strips invisible characters, lists cut-looking targets, and explains a missing manifest", () => {
  assert.equal(cleanText("‎TS.md‬"), "TS.md");
  assert.equal(cleanText("Save ​changes\u0085"), "Save changes");
  assert.equal(truncationHint("TS.md"), "looks like the end of a longer file name");
  assert.ok(truncationHint("Download the quarterly…"));
  assert.equal(truncationHint("README.md"), undefined);
  assert.equal(truncationHint("Sign in"), undefined);
  const rec = { title: "cut", steps: [{ type: "navigate", url: `${ORIGIN}/` }, { type: "click", selectors: [["aria/‎TS.md"]] }, { type: "click", selectors: [["aria/Search[role=\"button\"]"]] }] };
  const imp = importRecording(rec, m, "cut.json");
  assert.match(imp.flow, /"text":"TS\.md"/, "the LRM is gone from the encoded target");
  assert.equal(imp.warnings.length, 1);
  assert.match(imp.warnings[0]!, /^S2: target text "TS\.md" looks like the end/);
  assert.match(imp.report, /## Targets to check\n\n- S2:/);
  assert.equal(recordingOrigin(rec), ORIGIN);
  assert.equal(recordingOrigin({ steps: [{ type: "navigate", url: "file:///x" }] }), undefined);
  const dir = mkdtempSync(join(tmpdir(), "navsentry-rec-nocfg-"));
  try {
    const f = join(dir, "r.json");
    writeFileSync(f, JSON.stringify(rec));
    const r = spawnSync(process.execPath, [resolve("dist/src/cli.js"), "flow", "from-recording", "--input", f, "--out", join(dir, "o")], { cwd: dir, encoding: "utf8" });
    assert.equal(r.status, 3);
    assert.match(r.stderr, /does not carry a manifest/);
    assert.ok(r.stderr.includes(`navsentry init ${ORIGIN}`), r.stderr);
    assert.ok(!existsSync(join(dir, "o")), "nothing written");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
