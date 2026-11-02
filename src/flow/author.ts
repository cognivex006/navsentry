/** `flow init` template and `flow approve` (rewrites only the header's review object). */
import { flowHash } from "./classify.js";
import type { FlowDoc } from "./parse.js";

export function initTemplate(id: string, title: string, story: string, level: "auto" | "integration" | "e2e"): string {
  const header = { flow: "1", id, title, story, level, actors: ["anonymous"], review: { status: "draft" }, provenance: { kind: "agent", sources: ["user-story"] } };
  const step = { id: "S1", action: "http", actor: "anonymous", request: { method: "GET", path: "/", accept: "any" }, expect: { status: "2xx" } };
  return [
    `# ${title}`, "",
    story, "",
    "Narrative outside the navsentry blocks is for people only: NavSentry never parses or reports it.", "",
    "```navsentry-flow", JSON.stringify(header, null, 2), "```", "",
    "## S1 — First step (edit me)", "",
    "```navsentry-step", JSON.stringify(step, null, 2), "```", "",
  ].join("\n");
}

/** Returns the file text with an approved review block pinned to the current content hash. */
export function approveText(doc: FlowDoc, by: string, today: string, reference?: string): string {
  const raw = { ...doc.header.raw, review: { status: "approved", approved_by: by, approved_at: today, ...(reference ? { reference } : {}), content_sha256: flowHash(doc) } };
  const lines = doc.text.split("\n");
  const { start, end } = doc.headerBlock;
  return [...lines.slice(0, start), JSON.stringify(raw, null, 2), ...lines.slice(end - 1)].join("\n");
}
