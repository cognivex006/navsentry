/** SPEC-0.4.0 §3: run integrity manifest and `navsentry verify`. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli.js";
import { MANIFEST_FILE, buildManifest, parseManifest, verifyRun, type RunManifest } from "../src/integrity.js";
import { startDemo } from "./fixtures/demo-server.js";

const tmp = (p: string) => mkdtempSync(join(tmpdir(), `navsentry-int-${p}-`));

function writeManifest(dir: string, origin: string): string {
  const f = join(dir, "m.json");
  writeFileSync(f, JSON.stringify({
    version: "1", project: "demo", environment: "local", authorization: { acknowledged: true, owner: "navsentry-tests" },
    targets: { origins: [origin], allowed_paths: ["/**"], seed_paths: ["/"] },
    network: { allow_private: [{ host: new URL(origin).hostname, approved_by: "navsentry-tests", reason: "local disposable demo app" }] },
    safety: { mode: "observe", max_requests: 50, max_requests_per_second: 20, max_duration_seconds: 60 },
    report: { language: "en", formats: ["json", "markdown"] },
  }));
  return f;
}

test("a scan writes MANIFEST.json for exactly its own files and verify passes", async () => {
  const demo = await startDemo("secure");
  const dir = tmp("scan");
  try {
    const out = join(dir, "out");
    // A file the owner already had in --out is not part of the run.
    const { mkdirSync } = await import("node:fs");
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, "owner-notes.txt"), "mine\n");
    // The exit code reflects findings on the demo; only the written files matter here.
    await main(["scan", "--config", writeManifest(dir, demo.origin), "--mode", "page", "--env", "development", "--project", dir, "--out", out]);
    const m = parseManifest(readFileSync(join(out, MANIFEST_FILE), "utf8"));
    const paths = m.files.map((f) => f.path);
    assert.ok(paths.includes("run.json") && paths.includes("REPORT.md") && paths.includes("REPORT.html"));
    assert.ok(!paths.includes("owner-notes.txt") && !paths.includes(MANIFEST_FILE));
    const run = JSON.parse(readFileSync(join(out, "run.json"), "utf8")) as { runId: string };
    assert.equal(m.runId, run.runId);
    // An unlisted file would be reported as added; remove the owner file before checking.
    unlinkSync(join(out, "owner-notes.txt"));
    assert.equal(verifyRun(out).status, "PASS");
    assert.equal(await main(["verify", "--run", out]), 0);
    assert.equal(await main(["verify", "--run", join(out, "run.json")]), 0, "a run.json path resolves to its folder");
  } finally {
    await demo.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("verify reports modified, missing and added files and exits 1", async () => {
  const dir = tmp("tamper");
  try {
    for (const [n, c] of [["run.json", "{}\n"], ["REPORT.md", "# r\n"], ["sub-a.txt", "a\n"]]) writeFileSync(join(dir, n!), c!);
    writeFileSync(join(dir, MANIFEST_FILE), JSON.stringify(buildManifest(dir, "run-1", "0.0.0", ["run.json", "REPORT.md", "sub-a.txt"])));
    assert.equal(verifyRun(dir).status, "PASS");
    appendFileSync(join(dir, "run.json"), " ");
    unlinkSync(join(dir, "sub-a.txt"));
    writeFileSync(join(dir, "extra.txt"), "x");
    const v = verifyRun(dir);
    assert.equal(v.status, "FAIL");
    assert.deepEqual(v.modified, ["run.json"]);
    assert.deepEqual(v.missing, ["sub-a.txt"]);
    assert.deepEqual(v.added, ["extra.txt"]);
    assert.ok(v.limitations.some((l) => l.includes("not signed")), "the limitation is stated, not hidden");
    assert.equal(await main(["verify", "--run", dir]), 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a manifest entry that escapes the run folder is refused", () => {
  const base: RunManifest = { kind: "navsentry-run-manifest", schemaVersion: "1", runId: "r", toolVersion: "0", algorithm: "sha256", files: [] };
  for (const path of ["../x", "/etc/x", "C:/x", "a\\b", "a//b"]) {
    assert.throws(() => parseManifest(JSON.stringify({ ...base, files: [{ path, bytes: 1, sha256: "0".repeat(64) }] })), /escapes/, path);
  }
  assert.throws(() => parseManifest("{\"kind\":\"other\"}"), /not a navsentry-run-manifest/);
});

test("verify without a manifest says so instead of passing", async () => {
  const dir = tmp("none");
  try {
    writeFileSync(join(dir, "run.json"), "{}");
    assert.throws(() => verifyRun(dir), /not found/);
    assert.notEqual(await main(["verify", "--run", dir]), 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
