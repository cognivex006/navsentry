/**
 * `navsentry flow approve` (authorize once): the owner reviews a short summary of every draft in a
 * file or folder and approves them with one answer on an interactive terminal. The questions are
 * asked through a Prompter, and the CLI provides one only on a TTY, so an agent cannot approve on
 * the owner's behalf. Nothing here sends network traffic.
 */
import { flowHash } from "./classify.js";
import type { FlowDoc } from "./parse.js";

export interface ApprovePrompter {
  ask(question: string): Promise<string>;
  say(line: string): void;
}

export class ApproveError extends Error {}

const yes = (s: string) => /^(y|yes|ใช่)$/i.test(s.trim());
const STATE_CHANGING = new Set(["fill", "select", "submit", "fixture_create", "logout"]);

/** True when the flow carries a valid approval for its current content. */
export function isApproved(doc: FlowDoc): boolean {
  return doc.header.review.status === "approved" && doc.header.review.content_sha256 === flowHash(doc);
}

/** A few lines the owner can judge without opening the file. Target text is shown as data. */
export function approvalSummary(doc: FlowDoc): string[] {
  const paths = [...new Set(doc.steps.filter((s) => s.request).map((s) => `${s.request!.method} ${s.request!.path}`))];
  const changes = doc.steps.filter((s) => STATE_CHANGING.has(s.action) || (s.request && s.request.method !== "GET" && s.request.method !== "HEAD"));
  return [
    `- ${doc.header.id} — ${doc.header.title} (${doc.file})`,
    `    ${doc.steps.length} step(s) · level ${doc.header.level} · actors ${doc.header.actors.join(", ")}${doc.header.requires.length ? ` · requires ${doc.header.requires.join(", ")}` : ""}`,
    `    requests: ${paths.length ? paths.slice(0, 6).join(", ") + (paths.length > 6 ? ` (+${paths.length - 6} more)` : "") : "none (UI steps only)"}`,
    `    state-changing steps: ${changes.length ? changes.map((s) => `${s.id} ${s.action}`).join(", ") : "none"}`,
  ];
}

/**
 * Picks the flows to approve: the named file, or every draft (or stale approval) in a folder.
 * Already-valid approvals are left alone.
 */
export function selectForApproval(docs: FlowDoc[], pick: (d: FlowDoc) => boolean): { todo: FlowDoc[]; current: FlowDoc[] } {
  const chosen = docs.filter(pick);
  return { todo: chosen.filter((d) => !isApproved(d)), current: chosen.filter(isApproved) };
}

/** Asks once for the whole set. Returns the approver's name; throws ApproveError on any refusal. */
export async function confirmApproval(p: ApprovePrompter, todo: FlowDoc[], opts: { by?: string; owner?: string } = {}): Promise<string> {
  if (!todo.length) throw new ApproveError("nothing to approve: every selected flow already has a valid approval");
  p.say(`Flows to approve (${todo.length}):`);
  for (const d of todo) for (const l of approvalSummary(d)) p.say(l);
  p.say("Approving lets NavSentry replay these steps and treat their findings as VALIDATED. Editing a flow later invalidates its approval.");
  let by = opts.by?.trim();
  if (!by) by = (await p.ask(`Approver name${opts.owner ? ` (${opts.owner})` : ""}: `)).trim() || opts.owner?.trim() || "";
  if (!by || by.length > 100) throw new ApproveError("an approver name (1-100 characters) is required; nothing was approved");
  if (!yes(await p.ask(`Approve these ${todo.length} flow(s) as ${by}? (yes/no): `))) throw new ApproveError("not approved; nothing was changed");
  return by;
}
