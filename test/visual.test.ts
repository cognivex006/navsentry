/**
 * Visual driver (ADR-0009): Computer Use on a NavSentry-owned browser. S1 must hold wherever the agent
 * clicks; the session refuses to start without its preconditions; screenshots never outlive the run.
 * Browser tests need the approved Chromium headless shell and are skipped with the reason otherwise.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { probePlaywright } from "../src/transports/playwright.js";
import { SessionRefused, sendCommand, startSession } from "../src/visual/session.js";
import { endRun } from "../src/workspace.js";
import { startBrowserFixture } from "./fixtures/browser-server.js";
import { localManifest } from "./helpers.js";

const probe = probePlaywright();
const skip = probe.usable ? false : `playwright engine unavailable: ${probe.reason}`;
const VISUAL = { order: ["direct-http", "playwright-browser", "visual-computer-use"], visual_computer_use: true };
const manifest = (origin: string, over: Record<string, unknown> = {}) => localManifest(origin, { transports: VISUAL, checks: { disabled: ["NSC-CRYPT-006"] }, ...over });

async function withProject<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "navsentry-visual-"));
  try { return await fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

test("preconditions refuse before any browser or request", async () => {
  const fx = await startBrowserFixture();
  try {
    await withProject(async (dir) => {
      const url = `${fx.origin}/ui/visual`;
      const cases: [string, Record<string, unknown>, string, RegExp][] = [
        ["no consent", { transports: { order: VISUAL.order } }, url, /visual_computer_use must be true/],
        ["order", { transports: { order: ["direct-http"], visual_computer_use: true } }, url, /transports.order must include/],
        ["off scope", {}, `${fx.canary}/x`, /outside the manifest scope/],
      ];
      for (const [name, over, u, re] of cases) await assert.rejects(startSession({ manifest: manifest(fx.origin, over), projectDir: dir, url: u }), (e: Error) => e instanceof SessionRefused && re.test(e.message), name);
      await assert.rejects(startSession({ manifest: manifest(fx.origin), projectDir: dir, url, probe: () => ({ available: false, usable: false, reason: "not installed" }) }), /playwright engine unavailable/);
      const prod = localManifest(fx.origin, { environment: "production", transports: VISUAL, authorization: { acknowledged: true, owner: "t", reference: "CHG-1", expires_at: "2099-01-01" } });
      await assert.rejects(startSession({ manifest: prod, projectDir: dir, url }), /development only/);
      assert.equal(fx.hits.length + fx.canaryHits(), 0, "nothing was sent");
      assert.ok(!existsSync(join(dir, ".navsentry", "work")) || !readdirSync(join(dir, ".navsentry", "work")).length, "no work directory left");
    });
  } finally {
    await fx.close();
  }
});


test("clicks drive the page, but every request still goes through ScopeGate and the Budget (S1)", { skip }, async () => {
  const fx = await startBrowserFixture();
  try {
    await withProject(async (dir) => {
      const h = await startSession({ manifest: manifest(fx.origin), projectDir: dir, url: `${fx.origin}/ui/visual` });
      const work = join(dir, ".navsentry", "work", h.id);
      const shot = await sendCommand(work, { cmd: "screenshot" });
      assert.equal(shot.ok, true);
      const png = readFileSync(String(shot.path));
      assert.equal(png.subarray(1, 4).toString(), "PNG");
      assert.ok(String(shot.path).startsWith(work), "screenshots stay in the run's work directory");

      const inn = await sendCommand(work, { cmd: "click", x: 50, y: 40 });
      assert.match(String(inn.url), /\/ui\/next$/);
      const bad = await sendCommand(work, { cmd: "click", x: 5000, y: 5 });
      assert.equal(bad.ok, false);
      const forged = await (async () => { const info = JSON.parse(readFileSync(join(work, "session.json"), "utf8")) as { pipe: string; token: string };
        const net = await import("node:net");
        return new Promise<string>((r) => { const s = net.connect(info.pipe); let b = ""; s.on("connect", () => s.write(`${JSON.stringify({ token: "0".repeat(64), cmd: "status" })}\n`)); s.on("data", (c) => { b += c; }); s.on("end", () => r(b)); }); })();
      assert.match(forged, /bad token/);

      assert.equal((await sendCommand(work, { cmd: "end" })).ok, true);
      const { result, workspace } = await h.done;
      const ws = endRun(workspace, 0);
      assert.equal(ws.status, "PASS", JSON.stringify(ws));
      assert.ok(!existsSync(work), "work directory (and every screenshot) is deleted");
      assert.equal(result.endReason, "ended by command");
      assert.deepEqual(result.actions.map((a) => a.action), ["navigate", "screenshot", "click", "click"]);
      assert.equal(result.actions[3]!.result, "error");
      assert.ok(result.denials.some((d) => d.url.startsWith(fx.canary)), "the page's off-scope image and fetch are recorded denials");
      assert.ok(result.denials.some((d) => /WebSocket is disabled/.test(d.reason)));
      assert.ok(!fx.hits.some((x) => x.startsWith("POST ")) && !fx.hits.includes("GET /ui/sw.js") && fx.upgrades() === 0);
      assert.equal(fx.hits.length, result.requests.length, "every request the app saw is a recorded exchange");
      assert.ok(result.requests.every((q) => q.transport === "direct-http"));

      // A click on the off-scope link: the navigation is refused and Chromium shows its own error page.
      const before = fx.hits.length;
      const h2 = await startSession({ manifest: manifest(fx.origin), projectDir: dir, url: `${fx.origin}/ui/visual` });
      const out = await sendCommand(join(dir, ".navsentry", "work", h2.id), { cmd: "click", x: 50, y: 140 });
      assert.equal(out.ok, true);
      assert.doesNotMatch(String(out.url), /escape/, "the browser never reached the off-scope page");
      await sendCommand(join(dir, ".navsentry", "work", h2.id), { cmd: "end" });
      const r2 = await h2.done;
      endRun(r2.workspace, 0);
      assert.equal(fx.canaryHits(), 0, "the off-scope link did not reach the canary");
      assert.ok(r2.result.denials.some((d) => d.url.includes("/escape")), "the escape is a recorded denial");
      assert.equal(fx.hits.length - before, r2.result.requests.length);
    });
  } finally {
    await fx.close();
  }
});

test("the Budget ends the session; an idle session ends itself", { skip }, async () => {
  const fx = await startBrowserFixture();
  try {
    await withProject(async (dir) => {
      const m = manifest(fx.origin, { safety: { mode: "observe", max_requests: 2, max_requests_per_second: 20, max_duration_seconds: 60 } });
      const h = await startSession({ manifest: m, projectDir: dir, url: `${fx.origin}/ui/visual` });
      await sendCommand(join(dir, ".navsentry", "work", h.id), { cmd: "click", x: 50, y: 40 }).catch(() => undefined);
      const { result, workspace } = await h.done;
      endRun(workspace, 0);
      assert.ok(fx.hits.length <= 2, `app saw ${fx.hits.length}`);
      assert.match(result.endReason, /budget/);
      assert.equal(result.executionStatus, "PARTIAL");

      const idle = await startSession({ manifest: manifest(fx.origin), projectDir: dir, url: `${fx.origin}/ui/quiet`, idleSeconds: 1 });
      const r2 = await idle.done;
      endRun(r2.workspace, 0);
      assert.equal(r2.result.endReason, "idle timeout");
      assert.ok(!existsSync(join(dir, ".navsentry", "work", idle.id)));
    });
  } finally {
    await fx.close();
  }
});

test("CLI: browse start runs until browse end, then writes VISUAL-SESSION.md and session.json", { skip }, async () => {
  const fx = await startBrowserFixture();
  try {
    await withProject(async (dir) => {
      const { writeFileSync } = await import("node:fs");
      const { main } = await import("../src/cli.js");
      const mpath = join(dir, "m.json");
      writeFileSync(mpath, JSON.stringify({
        version: "1", project: "visual", environment: "local", authorization: { acknowledged: true, owner: "t" },
        targets: { origins: [fx.origin], seed_paths: ["/ui/quiet"] },
        network: { allow_private: [{ host: "127.0.0.1", approved_by: "t", reason: "fixture" }] },
        safety: { mode: "observe", max_requests: 50, max_requests_per_second: 20, max_duration_seconds: 60 },
        transports: VISUAL, checks: { disabled: ["NSC-CRYPT-006"] }, report: { language: "en", formats: ["json"] },
      }));
      const out = join(dir, "out");
      const started = main(["browse", "start", "--config", mpath, "--url", `${fx.origin}/ui/quiet`, "--project", dir, "--out", out]);
      const workRoot = join(dir, ".navsentry", "work");
      let id = "";
      for (let i = 0; i < 100 && !id; i++) { await new Promise((r) => setTimeout(r, 100)); id = existsSync(workRoot) ? (readdirSync(workRoot).find((d) => existsSync(join(workRoot, d, "session.json"))) ?? "") : ""; }
      assert.ok(id, "session started");
      assert.equal(await main(["browse", "status", "--session", id, "--project", dir]), 0);
      assert.equal(await main(["browse", "end", "--session", id, "--project", dir]), 0);
      const code = await started;
      assert.ok(code === 0 || code === 1, `exit ${code}`);
      const r = JSON.parse(readFileSync(join(out, "session.json"), "utf8")) as { workspace: { status: string }; actions: unknown[] };
      assert.equal(r.workspace.status, "PASS");
      assert.match(readFileSync(join(out, "VISUAL-SESSION.md"), "utf8"), /## Action log/);
      assert.equal(await main(["browse", "status", "--session", id, "--project", dir]), 3, "an ended session cannot be reached");
    });
  } finally {
    await fx.close();
  }
});
