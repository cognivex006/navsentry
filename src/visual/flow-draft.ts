/**
 * `browse end --save-flow <dir>` (SPEC-0.3.0 §5): turns a visual session's action log into a draft
 * story flow. Only what was logged is used: the start page, clicks with a known role and name, and
 * typed fields. Typed values are never written; each becomes an env-backed variable. The draft is
 * parsed with the normal flow parser before it is written, and it stays a draft until the owner
 * approves it.
 */
import { parseFlowText } from "../flow/parse.js";
import type { VisualSessionResult } from "../types.js";

export interface FlowDraft { id: string; text: string; skipped: string[] }

const json = (o: unknown) => JSON.stringify(o);

export function draftFlowFromSession(r: VisualSessionResult): FlowDraft {
  const id = `visual-${r.id.slice(0, 8)}`;
  const vars: Record<string, { env: string }> = {};
  const steps: string[] = [];
  const skipped: string[] = [];
  let n = 0;
  const step = (title: string, body: Record<string, unknown>) => {
    n++;
    steps.push(`## S${n} — ${title.replace(/\s+/g, " ").slice(0, 100)}`, "", "```navsentry-step", json({ id: `S${n}`, ...body, actor: r.actor }), "```", "");
  };
  let start: URL | undefined;
  try { start = new URL(r.startUrl); } catch { /* reported below */ }
  if (!start) throw new Error("the session start URL is not a valid URL");
  step("Open the start page", { action: "navigate", request: { method: "GET", path: start.pathname + start.search } });
  let inputs = 0;
  for (const a of r.actions) {
    if (a.result !== "ok") continue;
    if (a.actor === "human") { skipped.push(`#${a.seq} ${a.action} by a person in the headed window: not encoded, add it by hand if it belongs to the flow`); continue; }
    if (a.action === "click") {
      if (a.target?.name && a.target.role) step(`Click ${a.target.role} "${a.target.name}"`, { action: "click", target: { role: a.target.role, name: a.target.name } });
      else skipped.push(`#${a.seq} click at ${a.x ?? "?"},${a.y ?? "?"}: no role and accessible name, add a target by hand`);
    } else if (a.action === "type") {
      inputs++;
      const v = `input${inputs}`;
      vars[v] = { env: a.env ?? `NAVSENTRY_VISUAL_INPUT_${inputs}` };
      if (a.target?.name) step(`Fill "${a.target.name}"`, { action: "fill", target: { label: a.target.name }, value: { var: v } });
      else skipped.push(`#${a.seq} typing: the field has no label, add a target by hand`);
    } else if (a.action === "key") {
      skipped.push(`#${a.seq} key ${a.key ?? ""}: keys are not flow steps; use a submit step on the button instead`);
    }
  }
  const header = {
    flow: "1", id, title: `Visual session ${r.id.slice(0, 8)}`,
    story: "Recorded from a NavSentry visual-driver session. Review every step, add see steps for what must be visible, then ask the owner to approve.",
    level: "e2e", actors: [r.actor], ...(Object.keys(vars).length ? { vars } : {}),
    review: { status: "draft" }, provenance: { kind: "agent", sources: [`visual-session:${r.id}`], created_at: r.endedAt.slice(0, 10) },
  };
  const text = [
    `# ${header.title}`, "",
    "Draft flow from a visual-driver session. Typed values were not recorded: each input is a variable read from an environment variable at replay time.", "",
    ...(skipped.length ? ["Steps that need your attention:", "", ...skipped.map((x) => `- ${x}`), ""] : []),
    "```navsentry-flow", JSON.stringify(header, null, 2), "```", "",
    ...steps,
  ].join("\n");
  const parsed = parseFlowText(text, `${id}.flow.md`);
  if (!parsed.doc) throw new Error(`generated flow did not parse: ${parsed.problems.join("; ")}`);
  return { id, text, skipped };
}
