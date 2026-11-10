/** Login helper: a recorded sign-in draft becomes a lint-clean login flow; the manifest is never edited. No network. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli.js";
import { parseManifest } from "../src/config.js";
import { lintFlows } from "../src/flow/lint.js";
import { LoginDraftError, loginFlowFromDraft } from "../src/flow/login.js";
import { loadFlowFiles, parseFlowText } from "../src/flow/parse.js";

const ORIGIN = "http://127.0.0.1:4173";
const draft = (steps: object[], vars: Record<string, unknown>) => ["# rec", "", "```navsentry-flow", JSON.stringify({ flow: "1", id: "rec-signin", title: "Recorded sign in", story: "recorded", actors: ["anonymous"], level: "e2e", vars, review: { status: "draft" } }, null, 2), "```", "",
  ...steps.flatMap((s, i) => [`## S${i + 1}`, "```navsentry-step", JSON.stringify({ id: `S${i + 1}`, actor: "anonymous", ...s }), "```", ""])].join("\n");

const SIGNIN = [
  { action: "navigate", request: { method: "GET", path: "/signin" }, expect: { status: [200] } },
  { action: "fill", target: { label: "Email" }, value: { var: "input1" } },
  { action: "fill", target: { label: "Password" }, value: { var: "input2" } },
  { action: "fill", target: { label: "Remember me note" }, value: { var: "input3" } },
  { action: "scroll" },
  { action: "submit", target: { role: "button", name: "Sign in" } },
];
const VARS = { input1: { env: "NAVSENTRY_REC_INPUT_1" }, input2: { env: "NAVSENTRY_REC_INPUT_2_PASSWORD" }, input3: { env: "NAVSENTRY_REC_INPUT_3" } };

test("a sign-in draft becomes a login flow: {{username}}/{{password}}, the actor on every step, extra steps dropped", () => {
  const steps = SIGNIN.filter((s) => s.action !== "scroll");
  const doc = parseFlowText(draft(steps, VARS), "rec-signin.flow.md").doc!;
  const ld = loginFlowFromDraft(doc, "alice");
  assert.equal(ld.id, "login-alice");
  assert.deepEqual(ld.mapped, [{ step: "S2", to: "username" }, { step: "S3", to: "password" }]);
  assert.deepEqual(ld.dropped.map((d) => d.step), ["S4"]);
  const out = parseFlowText(ld.flow, "login-alice.flow.md").doc!;
  assert.ok(out.steps.every((s) => s.actor === "alice"));
  assert.equal(out.header.review.status, "draft");
  const snippet = JSON.parse(ld.manifestSnippet);
  assert.equal(snippet.auth_endpoints.login.path, "/<sign-in form action path>", "a placeholder the manifest parser refuses, so the owner must fill it in");
  snippet.auth_endpoints.login.path = "/signin";
  assert.deepEqual(snippet.actors.alice, { login: { flow: "login-alice" }, username_env: "NAVSENTRY_ALICE_USER", password_env: "NAVSENTRY_ALICE_PASSWORD" });
  // With the snippet added by the owner, the login flow lints clean.
  const m = parseManifest({ version: "1", project: "p", environment: "local", authorization: { acknowledged: true, owner: "t" }, targets: { origins: [ORIGIN] }, network: { allow_private: [{ host: "127.0.0.1", approved_by: "t", reason: "fixture" }] }, transports: { order: ["direct-http", "playwright-browser"] }, ...snippet });
  assert.deepEqual(lintFlows([out], m).errors, []);
  assert.ok(!ld.flow.includes("NAVSENTRY_REC_INPUT"), "recorded env names are not carried into the login flow");
});

test("refusals: no password fill, no submit, bad actor name", () => {
  const noPass = parseFlowText(draft([SIGNIN[0]!, SIGNIN[1]!, SIGNIN[5]!], { input1: VARS.input1 }), "a.flow.md").doc!;
  assert.throws(() => loginFlowFromDraft(noPass, "alice"), /no password field fill/);
  const noSubmit = parseFlowText(draft([SIGNIN[0]!, SIGNIN[1]!, SIGNIN[2]!], { input1: VARS.input1, input2: VARS.input2 }), "b.flow.md").doc!;
  assert.throws(() => loginFlowFromDraft(noSubmit, "alice"), /never submits/);
  assert.throws(() => loginFlowFromDraft(noSubmit, "Alice!"), LoginDraftError);
  assert.throws(() => loginFlowFromDraft(noSubmit, "a_b"), /letters, digits and - only/);
});

test("the password goes only into the password field: env first, then the field's own label; ambiguity is refused", () => {
  // DevTools drafts carry no _PASSWORD env: the field's own label decides, never parent selector text.
  const devtools = { input1: { env: "NAVSENTRY_REC_SIGNIN_1" }, input2: { env: "NAVSENTRY_REC_SIGNIN_2" } };
  const steps = [SIGNIN[0]!, { action: "fill", target: { label: "Email (password-login form)" }, value: { var: "input1" } }, { action: "fill", target: { label: "Password" }, value: { var: "input2" } }, SIGNIN[5]!];
  const twoHits = parseFlowText(draft(steps, devtools), "c.flow.md").doc!;
  assert.throws(() => loginFlowFromDraft(twoHits, "alice"), /more than one field looks like a password/);
  const clean = parseFlowText(draft([SIGNIN[0]!, { action: "fill", target: { label: "Email" }, value: { var: "input1" } }, { action: "fill", target: { label: "Password" }, value: { var: "input2" } }, SIGNIN[5]!], devtools), "d.flow.md").doc!;
  assert.deepEqual(loginFlowFromDraft(clean, "alice").mapped, [{ step: "S2", to: "username" }, { step: "S3", to: "password" }]);
  // The recorder's _PASSWORD env wins over labels.
  const env = parseFlowText(draft(steps, { input1: { env: "NAVSENTRY_REC_INPUT_1" }, input2: { env: "NAVSENTRY_REC_INPUT_2_PASSWORD" } }), "e.flow.md").doc!;
  assert.deepEqual(loginFlowFromDraft(env, "alice").mapped.find((x) => x.to === "password"), { step: "S3", to: "password" });
  // A fill after the password is never the username.
  const after = parseFlowText(draft([SIGNIN[0]!, { action: "fill", target: { label: "Password" }, value: { var: "input2" } }, { action: "fill", target: { label: "Email" }, value: { var: "input1" } }, SIGNIN[5]!], VARS), "f.flow.md").doc!;
  const la = loginFlowFromDraft(after, "alice");
  assert.deepEqual(la.mapped, [{ step: "S2", to: "password" }]);
  assert.match(la.dropped[0]!.reason, /before the password/);
});

test("CLI: writes the login flow, prints the manifest entries, never touches the manifest or overwrites", async () => {
  const dir = mkdtempSync(join(tmpdir(), "navsentry-login-"));
  try {
    const d = join(dir, "rec-signin.flow.md");
    writeFileSync(d, draft(SIGNIN.filter((s) => s.action !== "scroll"), VARS));
    const mf = join(dir, "navsentry.json");
    writeFileSync(mf, "{}");
    const out = join(dir, "flows");
    assert.equal(await main(["flow", "login-from-draft", "--flows", d, "--actor", "alice", "--out", out]), 0);
    assert.ok(existsSync(join(out, "login-alice.flow.md")));
    assert.equal(loadFlowFiles(out).docs[0]!.header.id, "login-alice");
    assert.equal(readFileSync(mf, "utf8"), "{}", "the manifest is never edited");
    assert.equal(await main(["flow", "login-from-draft", "--flows", d, "--actor", "alice", "--out", out]), 3, "never overwrites");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
