/**
 * Chrome / Edge DevTools Recorder JSON → one draft flow (SPEC-0.3.0 §6). Zero network: the file is
 * read as untrusted data. Recorded values (`change` steps) are dropped and become env-backed
 * variables. URLs outside the manifest scope are listed, never encoded. Unknown or ambiguous steps
 * (CSS-only selectors, scrolls, hovers) are listed for review, never guessed. Step titles are
 * generated; only the accessible names needed to locate elements are copied. The flow is a draft
 * until the owner approves it.
 */
import type { Manifest } from "../config.js";
import { ScopeGate } from "../scope.js";
import { FLOW_ID, parseFlowText } from "./parse.js";

export const MAX_RECORDING_BYTES = 1024 * 1024;
/** Owner decision D10. */
export const MAX_RECORDING_STEPS = 200;
const MAX_NAME = 120;

export class RecordingError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Cannot import recording:\n- ${problems.join("\n- ")}`);
  }
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
type Target = { role: string; name: string } | { text: string } | { label: string };

export interface RecordingImport {
  id: string;
  flow: string;
  report: string;
  encoded: number;
  skipped: { index: number; type: string; reason: string }[];
}

const clean = (s: string) => s.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();
const ROLES = new Set(["button", "link", "textbox", "checkbox", "radio", "combobox", "tab", "menuitem", "heading", "searchbox", "option"]);

/** Picks a target from Recorder selectors: aria/Name[role="x"] → role+name, aria/Name → text or label, text/… → text. CSS/XPath only → undefined. */
export function targetFrom(selectors: unknown, forInput: boolean): Target | undefined {
  if (!Array.isArray(selectors)) return undefined;
  for (const group of selectors) {
    const sel = Array.isArray(group) ? group : [group];
    if (sel.length !== 1 || typeof sel[0] !== "string") continue; // nested (shadow/frame) chains are not supported
    const s = sel[0];
    const aria = s.match(/^aria\/(.+?)(?:\[role="([a-z]+)"\])?$/);
    if (aria) {
      const name = clean(aria[1]!);
      if (!name || name.length > MAX_NAME) continue;
      const role = aria[2];
      if (role && ROLES.has(role)) return { role, name };
      return forInput ? { label: name } : { text: name };
    }
    const text = s.match(/^text\/(.+)$/);
    if (text && !forInput) {
      const name = clean(text[1]!);
      if (name && name.length <= MAX_NAME) return { text: name };
    }
  }
  return undefined;
}

export function importRecording(raw: unknown, m: Manifest, file: string): RecordingImport {
  if (!isObj(raw) || !Array.isArray(raw.steps)) throw new RecordingError(["not a DevTools Recorder export: expected an object with a steps array"]);
  if (raw.steps.length > MAX_RECORDING_STEPS) throw new RecordingError([`more than ${MAX_RECORDING_STEPS} steps; split the recording`]);
  const gate = new ScopeGate(m);
  const base = (typeof raw.title === "string" ? raw.title : file).toLowerCase().replace(/\.(recording\.)?json$/, "").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 50);
  const id = FLOW_ID.test(`rec-${base}`) ? `rec-${base}` : "rec-recording";
  const steps: string[] = [];
  const skipped: RecordingImport["skipped"] = [];
  const vars: Record<string, { env: string }> = {};
  let n = 0, inputs = 0;
  let inScope = false;
  let origin: string | undefined;
  const add = (title: string, body: Obj) => {
    n++;
    steps.push(`## S${n} — ${title}`, "", "```navsentry-step", JSON.stringify({ id: `S${n}`, action: body.action, actor: "anonymous", ...body }), "```", "");
  };
  raw.steps.forEach((st, index) => {
    const type = isObj(st) && typeof st.type === "string" ? st.type : "unknown";
    const skip = (reason: string) => skipped.push({ index: index + 1, type, reason });
    if (!isObj(st)) return skip("not an object");
    if (type === "setViewport" || type === "keyUp") return; // viewport is fixed by NavSentry; keyUp pairs with keyDown
    if (type === "navigate") {
      let u: URL;
      try { u = new URL(String(st.url)); } catch { inScope = false; return skip("navigate without a valid URL"); }
      const d = gate.checkRequest(u.toString(), "GET");
      if (!d.allowed) { inScope = false; return skip(`navigate outside the manifest scope (${d.reason}); later steps are skipped until an in-scope navigate`); }
      if (origin && u.origin !== origin) { inScope = false; return skip("navigate to a second origin; one flow covers one origin"); }
      origin = u.origin;
      inScope = true;
      return add("Open a page", { action: "navigate", request: { method: "GET", path: u.pathname + u.search }, expect: { status: [200], content_type: "text/html" } });
    }
    if (!inScope) return skip("no in-scope page is open");
    if (type === "click" || type === "doubleClick") {
      // A click that only focuses the field typed into next is part of that fill step.
      const nx = (raw.steps as unknown[])[index + 1];
      if (isObj(nx) && nx.type === "change" && JSON.stringify(nx.selectors) === JSON.stringify(st.selectors)) return;
      const t = targetFrom(st.selectors, false);
      if (!t) return skip("only CSS or XPath selectors: add a role and name, label or text target by hand");
      for (const ev of Array.isArray(st.assertedEvents) ? st.assertedEvents : []) {
        if (isObj(ev) && ev.type === "navigation" && typeof ev.url === "string") {
          try {
            if (!gate.checkRequest(new URL(ev.url).toString(), "GET").allowed) { inScope = false; return skip("this click navigates outside the manifest scope; it is not encoded"); }
          } catch { /* not a URL: the click itself is still encoded */ }
        }
      }
      return add("Click an element", { action: "click", target: t });
    }
    if (type === "change") {
      const t = targetFrom(st.selectors, true);
      if (!t) return skip("only CSS or XPath selectors for this field: add a label target by hand");
      inputs++;
      const v = `input${inputs}`;
      vars[v] = { env: `NAVSENTRY_REC_${id.slice(4).toUpperCase().replace(/[^A-Z0-9]+/g, "_").slice(0, 30)}_${inputs}`.replace(/__+/g, "_") };
      // The recorded value is dropped: it is read from the environment at replay time.
      return add("Fill a field", { action: "fill", target: t, value: { var: v } });
    }
    if (type === "keyDown") {
      if (st.key === "Enter") return skip("Enter key: add a submit step on the form's button instead");
      return skip(`key ${typeof st.key === "string" ? st.key.slice(0, 20) : "?"} is not a flow step`);
    }
    if (type === "waitForElement") {
      const t = targetFrom(st.selectors, false);
      if (!t) return skip("only CSS or XPath selectors: add a see step by hand");
      return add("Element is visible", { action: "see", target: t });
    }
    return skip("not supported (scroll, hover, expressions and custom steps are listed, never guessed)");
  });
  if (!origin) throw new RecordingError(["the recording has no in-scope navigate step"]);
  const envs = Object.values(vars).map((v) => v.env);
  const header = {
    flow: "1", id, title: `Recorded journey ${id.slice(4)}`.slice(0, 120),
    story: "Imported from a DevTools Recorder export. Review each step, add see steps for what must be visible, then ask the owner to approve.",
    level: "e2e", actors: ["anonymous"], ...(inputs ? { vars } : {}),
    review: { status: "draft" }, provenance: { kind: "human", sources: ["devtools-recorder"] },
  };
  const flow = [
    `# Recorded journey ${id.slice(4)}`, "",
    "Draft flow imported from a Chrome/Edge DevTools Recorder export. Recorded input values were dropped; set the environment variables below before replaying.", "",
    "```navsentry-flow", JSON.stringify(header, null, 2), "```", "", ...steps,
  ].join("\n");
  const parsed = parseFlowText(flow, `${id}.flow.md`);
  if (!parsed.doc) throw new RecordingError([`the generated flow did not parse: ${parsed.problems.join("; ")}`]);
  const report = [
    `# Recording import — ${id}`, "",
    `- Source: \`${file}\` (DevTools Recorder JSON, read as data; nothing was sent)`,
    `- Steps in the recording: ${raw.steps.length} · encoded: ${n} · listed for review: ${skipped.length}`,
    `- Draft flow: \`${id}.flow.md\` (draft until the owner approves it)`, "",
    "## Environment variables to set before replay", "",
    ...(envs.length ? envs.map((e) => `- \`${e}\``) : ["None."]), "",
    ...(envs.length ? ["> fill steps run only in safe-validate (development profile). In observe mode they are NOT_TESTED and the flow is INCOMPLETE.", ""] : []),
    "## Steps not encoded", "",
    ...(skipped.length ? ["| Recording step | Type | Why |", "|---|---|---|", ...skipped.map((s) => `| ${s.index} | ${s.type} | ${s.reason} |`)] : ["None."]), "",
    "## Next", "",
    "- `navsentry flow lint --flows <dir>`",
    "- `navsentry scan --mode flow --flows <dir> --engine playwright` (development profile) after the owner approves it.", "",
  ].join("\n");
  return { id, flow, report, encoded: n, skipped };
}
