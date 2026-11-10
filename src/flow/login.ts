/**
 * `navsentry flow login-from-draft` (login helper): turns a recorded or visual-driver draft of a
 * sign-in journey into a login flow for one actor, and prints the manifest entries the owner adds by
 * hand. Zero network. The manifest is never edited here: login actors need safe-validate, which is
 * the owner's decision.
 */
import { FLOW_ID, parseFlowText, type FlowDoc, type FlowStep } from "./parse.js";

const LOGIN_ACTIONS = new Set(["navigate", "fill", "submit", "click", "see", "wait_for"]);
const PASSWORD_HINT = /pass(word|wd|code)?\b|รหัสผ่าน|\bpin\b/i;

export class LoginDraftError extends Error {}

export interface LoginDraft {
  id: string;
  flow: string;
  /** Manifest entries to add by hand (JSON text), never written by NavSentry. */
  manifestSnippet: string;
  dropped: { step: string; reason: string }[];
  mapped: { step: string; to: "username" | "password" }[];
}

const targetText = (s: FlowStep) => JSON.stringify(s.target ?? {});

function isPasswordFill(doc: FlowDoc, s: FlowStep): boolean {
  const src = s.value ? doc.header.vars[s.value.var] : undefined;
  const env = src && "env" in src ? src.env : "";
  return /_PASSWORD$/.test(env) || PASSWORD_HINT.test(s.title) || PASSWORD_HINT.test(targetText(s));
}

/** Builds the login flow. Throws when the draft has no password fill or no submit, since it cannot sign in. */
export function loginFlowFromDraft(doc: FlowDoc, actor: string): LoginDraft {
  if (!/^[a-z][a-z0-9_-]{0,39}$/.test(actor)) throw new LoginDraftError("--actor must be a lower-case actor name (letters, digits, - or _)");
  const id = `login-${actor}`.replace(/_/g, "-");
  if (!FLOW_ID.test(id)) throw new LoginDraftError(`cannot build a flow id from actor ${actor}`);
  const dropped: LoginDraft["dropped"] = [];
  const mapped: LoginDraft["mapped"] = [];
  const steps: Record<string, unknown>[] = [];
  let user = false, pass = false, submit = false;
  for (const s of doc.steps) {
    if (!LOGIN_ACTIONS.has(s.action)) { dropped.push({ step: s.id, reason: `${s.action} is not allowed in a login flow` }); continue; }
    const raw: Record<string, unknown> = { ...s.raw, actor };
    if (s.action === "fill") {
      if (isPasswordFill(doc, s) && !pass) { raw.value = { var: "password" }; pass = true; mapped.push({ step: s.id, to: "password" }); }
      else if (!user) { raw.value = { var: "username" }; user = true; mapped.push({ step: s.id, to: "username" }); }
      else { dropped.push({ step: s.id, reason: "a login flow fills only the username and the password" }); continue; }
    }
    // A submit, or a click on the sign-in button after the password, sends the form.
    if (s.action === "submit" || (s.action === "click" && pass)) submit = true;
    steps.push(raw);
  }
  if (!pass) throw new LoginDraftError("the draft has no password field fill: record the sign-in form, including the password field");
  if (!submit) throw new LoginDraftError("the draft never submits the form: add a submit (or a click on the sign-in button) after the password");
  const header = {
    flow: "1", id, title: `Sign in as ${actor}`,
    story: `Signs in as actor ${actor} with {{username}} and {{password}} from the actor's env variables. Made from draft ${doc.header.id}.`,
    level: "e2e", actors: [actor], review: { status: "draft" },
    provenance: { kind: "human", sources: [`login-from-draft:${doc.header.id}`] },
  };
  const flow = [
    `# Sign in as ${actor}`, "",
    `Login flow for actor \`${actor}\`, made from draft \`${doc.header.id}\` (\`${doc.file}\`). The username and password come from the actor's env variables at run time; they are never written here.`, "",
    "```navsentry-flow", JSON.stringify(header, null, 2), "```", "",
    ...steps.flatMap((s, i) => [`## ${String(s.id ?? `S${i + 1}`)}`, "", "```navsentry-step", JSON.stringify(s), "```", ""]),
  ].join("\n");
  const parsed = parseFlowText(flow, `${id}.flow.md`);
  if (!parsed.doc) throw new LoginDraftError(`the login flow did not parse: ${parsed.problems.join("; ")}`);
  const up = actor.toUpperCase().replace(/-/g, "_");
  const submitPath = doc.steps.find((s) => s.action === "submit" && s.request)?.request?.path;
  const snippet = {
    safety: { mode: "safe-validate" },
    auth_endpoints: { login: { method: "POST", path: submitPath ?? "/<sign-in form action path>", content_type: "application/x-www-form-urlencoded", max_body_bytes: 2048 } },
    actors: { [actor]: { login: { flow: id }, username_env: `NAVSENTRY_${up}_USER`, password_env: `NAVSENTRY_${up}_PASSWORD` } },
  };
  return { id, flow, manifestSnippet: JSON.stringify(snippet, null, 2), dropped, mapped };
}
