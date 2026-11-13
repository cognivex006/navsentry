/**
 * SPEC-0.3.0 0.3.0-d: visual driver snapshot, click by ref, typing, keys, --save-flow and the --headed
 * governance refusal. Demo shop on 127.0.0.1 only. Browser tests need the approved Chromium headless shell.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseFlowText } from "../src/flow/parse.js";
import { probePlaywright } from "../src/transports/playwright.js";
import { draftFlowFromSession } from "../src/visual/flow-draft.js";
import { SessionRefused, sendCommand, startSession } from "../src/visual/session.js";
import { endRun } from "../src/workspace.js";
import { startDemoSite } from "./fixtures/demo-site.js";
import { localManifest } from "./helpers.js";

const probe = probePlaywright();
const skip = probe.usable ? false : `playwright engine unavailable: ${probe.reason}`;
const VISUAL = { order: ["direct-http", "playwright-browser", "visual-computer-use"], visual_computer_use: true };
const PW = "visual-test-password-77";

type Snap = { ok: boolean; url: string; elements: { ref: string; role: string; name: string; tag: string; password: boolean; href?: string; inScope?: boolean }[] };

test("--headed without the full Chromium build is refused before any browser starts", async () => {
  // A stub probe: the test never opens a visible window on the developer's desktop.
  const site = await startDemoSite("vulnerable");
  const dir = mkdtempSync(join(tmpdir(), "navsentry-vd-"));
  try {
    let asked: boolean | undefined;
    const probe = (o: { headed?: boolean } = {}) => { asked = o.headed; return { available: true, usable: false, reason: "full Chromium build not installed: npx playwright-core install chromium" }; };
    await assert.rejects(startSession({ manifest: localManifest(site.origin, { transports: VISUAL }), projectDir: dir, url: `${site.origin}/`, headed: true, probe: probe as never }), (e: Error) => e instanceof SessionRefused && /install chromium/.test(e.message));
    assert.equal(asked, true, "the probe is asked for the headed build");
  } finally {
    rmSync(dir, { recursive: true, force: true });
    await site.close();
  }
});

test("snapshot, click by ref, typing rules, keys and a draft flow from the session", { skip }, async () => {
  const site = await startDemoSite("vulnerable");
  const dir = mkdtempSync(join(tmpdir(), "navsentry-vd-"));
  try {
    const h = await startSession({ manifest: localManifest(site.origin, { transports: VISUAL }), projectDir: dir, url: `${site.origin}/login`, env: { ...process.env, NAVSENTRY_VD_PASSWORD: PW } });
    const work = join(dir, ".navsentry", "work", h.id);
    const cmd = (c: Parameters<typeof sendCommand>[1]) => sendCommand(work, c);

    // Search is a GET form: typing and Enter navigate through ScopeGate.
    const first = (await cmd({ cmd: "snapshot" })) as unknown as Snap;
    assert.equal(first.ok, true);
    const search = first.elements.find((e) => e.role === "link" && e.name === "Search")!;
    assert.equal((await cmd({ cmd: "click", ref: search.ref })).ok, true);
    const form = (await cmd({ cmd: "snapshot" })) as unknown as Snap;
    const box = form.elements.find((e) => e.name === "Product name")!;
    assert.equal((await cmd({ cmd: "type", ref: box.ref, text: "lamp" })).ok, true);
    const enter = await cmd({ cmd: "key", key: "Enter" });
    assert.match(String(enter.url), /\/search\?q=/, "Enter submitted the GET form (query values are redacted)");

    // Then the sign-in form, reached by a coordinate-free click on its link.
    const after = (await cmd({ cmd: "snapshot" })) as unknown as Snap;
    assert.equal((await cmd({ cmd: "click", ref: after.elements.find((e) => e.role === "link" && e.name === "Sign in")!.ref })).ok, true);
    const login = (await cmd({ cmd: "snapshot" })) as unknown as Snap;
    const user = login.elements.find((e) => e.name === "Username")!;
    const pass = login.elements.find((e) => e.password)!;
    const submit = login.elements.find((e) => e.role === "button" && e.name === "Sign in")!;
    assert.ok(user && pass && submit, "fields and button are listed with roles and names");
    assert.ok(login.elements.every((e) => !("value" in e)), "no field values in a snapshot");
    assert.ok(login.elements.filter((e) => e.href).every((e) => e.inScope === true), "links carry a scope flag");

    assert.match(String((await cmd({ cmd: "type", ref: pass.ref, text: "hunter2pass" })).error), /password fields/);
    assert.match(String((await cmd({ cmd: "type", ref: user.ref, text: "4111 1111 1111 1111" })).error), /secret or personal data/);
    assert.match(String((await cmd({ cmd: "type", ref: submit.ref, text: "x" })).error), /not an editable/);
    assert.match(String((await cmd({ cmd: "type", ref: user.ref, env: "NAVSENTRY_VD_NOT_SET" })).error), /not set/);
    // Rule 7: a page cannot steer the agent into typing an unrelated host secret.
    for (const env of ["AWS_SECRET_ACCESS_KEY", "PATH", "NAVSENTRY_", "navsentry_x"]) assert.match(String((await cmd({ cmd: "type", ref: user.ref, env })).error), /NAVSENTRY_\* environment variable/, env);
    assert.match(String((await cmd({ cmd: "type", ref: user.ref })).error), /exactly one/);
    assert.match(String((await cmd({ cmd: "type", ref: "x1", text: "a" })).error), /ref must look like/);
    assert.equal((await cmd({ cmd: "type", ref: user.ref, text: "demo-user" })).ok, true);
    assert.equal((await cmd({ cmd: "type", ref: pass.ref, env: "NAVSENTRY_VD_PASSWORD" })).ok, true);
    assert.match(String((await cmd({ cmd: "key", key: "F12" })).error), /key must be one of/);
    await cmd({ cmd: "click", ref: submit.ref });

    await cmd({ cmd: "end", saveFlow: join(dir, "flows") });
    const { result, workspace, saveFlow } = await h.done;
    endRun(workspace, 0);
    assert.equal(saveFlow, join(dir, "flows"));
    const all = JSON.stringify(result);
    for (const v of [PW, "hunter2pass", "4111 1111", "demo-user"]) assert.ok(!all.includes(v), `no typed value in the session log: ${v}`);
    assert.ok(result.denials.some((d) => d.method === "POST" && /state-changing/.test(d.reason)), "the sign-in POST was refused (observe)");
    const typed = result.actions.filter((a) => a.action === "type" && a.result === "ok");
    assert.deepEqual(typed.map((a) => a.env ?? "text"), ["text", "text", "NAVSENTRY_VD_PASSWORD"]);
    assert.ok(typed.every((a) => typeof a.length === "number"));

    const draft = draftFlowFromSession(result);
    const parsed = parseFlowText(draft.text, `${draft.id}.flow.md`);
    assert.ok(parsed.doc, parsed.problems.join("; "));
    assert.equal(parsed.doc!.header.review.status, "draft");
    assert.ok(!draft.text.includes(PW) && !draft.text.includes("\"lamp\"") && !draft.text.includes("demo-user"), "typed values never reach the flow");
    assert.match(draft.text, /"env": "NAVSENTRY_VD_PASSWORD"/);
    assert.match(draft.text, /"action":"click","target":\{"role":"link","name":"Search"\}/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    await site.close();
  }
});
