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

/** The field's own words only (label, or role name), never parent selectors. */
const fieldText = (s: FlowStep) => {
  const t = (s.target ?? {}) as Record<string, unknown>;
  return [t.label, t.name].filter((x): x is string => typeof x === "string").join(" ");
};

const envOf = (doc: FlowDoc, s: FlowStep) => {
  const src = s.value ? doc.header.vars[s.value.var] : undefined;
  return src && "env" in src ? src.env : "";
};

/**
 * The single password fill: a `*_PASSWORD` env (set by the recorder for password fields) wins;
 * otherwise exactly one fill whose label or name says password. Anything else is ambiguous and
 * refused, because typing the password into a visible field would expose it.
 */
function passwordStep(doc: FlowDoc, fills: FlowStep[]): FlowStep {
  const byEnv = fills.filter((s) => /_PASSWORD$/.test(envOf(doc, s)));
  if (byEnv.length === 1) return byEnv[0]!;
  if (byEnv.length > 1) throw new LoginDraftError(`more than one password field (${byEnv.map((s) => s.id).join(", ")}); keep only the sign-in fields in the draft`);
  const byLabel = fills.filter((s) => PASSWORD_HINT.test(fieldText(s)));
  if (byLabel.length === 1) return byLabel[0]!;
  if (!byLabel.length) throw new LoginDraftError("the draft has no password field fill: record the sign-in form, including the password field");
  throw new LoginDraftError(`more than one field looks like a password (${byLabel.map((s) => s.id).join(", ")}); keep only the sign-in fields in the draft`);
}

/** Builds the login flow. Throws when the draft has no password fill or no submit, since it cannot sign in. */
export function loginFlowFromDraft(doc: FlowDoc, actor: string): LoginDraft {
  if (!/^[a-z][a-z0-9_-]{0,39}$/.test(actor)) throw new LoginDraftError("--actor must be a lower-case actor name (letters, digits and -)");
  if (actor.includes("_")) throw new LoginDraftError("--actor uses letters, digits and - only (an _ would collide with the - form in flow ids and env names)");
  const id = `login-${actor}`;
  if (!FLOW_ID.test(id)) throw new LoginDraftError(`cannot build a flow id from actor ${actor}`);
  const dropped: LoginDraft["dropped"] = [];
  const mapped: LoginDraft["mapped"] = [];
  const steps: Record<string, unknown>[] = [];
  const pw = passwordStep(doc, doc.steps.filter((s) => s.action === "fill"));
  let user = false, pass = false, submit = false;
  for (const s of doc.steps) {
    if (!LOGIN_ACTIONS.has(s.action)) { dropped.push({ step: s.id, reason: `${s.action} is not allowed in a login flow` }); continue; }
    // Only the fields a login step uses: dependencies and owners could point at dropped steps or other actors.
    const { depends_on: _d, object_owner: _o, ...rest } = s.raw;
    void _d; void _o;
    const raw: Record<string, unknown> = { ...rest, actor };
    if (s.action === "fill") {
      if (s === pw) { raw.value = { var: "password" }; pass = true; mapped.push({ step: s.id, to: "password" }); }
      else if (!user && !pass) { raw.value = { var: "username" }; user = true; mapped.push({ step: s.id, to: "username" }); }
      else { dropped.push({ step: s.id, reason: "a login flow fills only the username (before the password) and the password" }); continue; }
    }
    // A submit, or a click on the sign-in button after the password, sends the form.
    if (s.action === "submit" || (s.action === "click" && pass)) submit = true;
    steps.push(raw);
  }
  if (!submit) throw new LoginDraftError("the draft never submits the form: add a submit (or a click on the sign-in button) after the password");
  const header = {
    flow: "1", id, title: `Sign in as ${actor}`,
    story: `Signs in as actor ${actor} with {{username}} and {{password}} from the actor's env variables. Made from draft ${doc.header.id}.`,
    level: "e2e", actors: [actor], review: { status: "draft" },
    provenance: { kind: "agent", sources: [`login-from-draft:${doc.header.id}`] },
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
  // Always a placeholder the manifest parser refuses: the owner checks the real sign-in request.
  const snippet = {
    safety: { mode: "safe-validate" },
    auth_endpoints: { login: { method: "POST", path: "/<sign-in form action path>", content_type: "application/x-www-form-urlencoded", max_body_bytes: 2048 } },
    actors: { [actor]: { login: { flow: id }, username_env: `NAVSENTRY_${up}_USER`, password_env: `NAVSENTRY_${up}_PASSWORD` } },
  };
  return { id, flow, manifestSnippet: JSON.stringify(snippet, null, 2), dropped, mapped };
}
