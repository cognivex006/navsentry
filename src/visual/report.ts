/** VISUAL-SESSION.md for a visual-driver session (ADR-0009). Display URLs and coordinates only. */
import { getCase } from "../catalog.js";
import type { VisualSessionResult } from "../types.js";

const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");

export function renderVisualSession(r: VisualSessionResult): string {
  const out = [
    "# NavSentry visual session", "",
    `- Session \`${r.id}\` · engine \`${r.engine}\` · actor \`${r.actor}\` · ${r.startedAt} → ${r.endedAt}`,
    `- Start URL: \`${esc(r.startUrl)}\` · ended: ${esc(r.endReason)} · execution ${r.executionStatus}`,
    `- Viewport ${r.viewport.width}x${r.viewport.height} · ${r.actions.length} action(s) · ${r.requests.length} request(s) · ${r.denials.length} denial(s) · ${r.screenshots} screenshot(s), all deleted with the work directory`,
    "- Every request the page made was fulfilled through ScopeGate and the Budget (S1); clicks only choose what the page asks for.",
    `- Workspace: ${r.workspace?.status ?? "not checked"}`,
    ...(r.flowDraft ? [`- Draft flow: \`${esc(r.flowDraft)}\` (review it; only the owner approves it)`] : []), "",
    "## Findings", "",
  ];
  if (!r.findings.length) out.push("No findings from the pages loaded in this session. Zero findings is never \"secure\": only passive checks on loaded documents ran.", "");
  else {
    out.push("| Case | Title | Lifecycle | Target |", "|---|---|---|---|");
    for (const f of r.findings) out.push(`| ${f.ruleId} | ${esc(getCase(f.ruleId).titleEn)} | ${f.lifecycle} | \`${esc(f.target)}\` |`);
    out.push("");
  }
  out.push("## Action log", "", "| # | Action | Arguments | Result | URL after | Requests |", "|---|---|---|---|---|---|");
  for (const a of r.actions) {
    const tgt = a.target ? ` ${a.target.role} "${a.target.name}"` : "";
    const args = a.action === "click" ? `${a.ref ?? `${a.x},${a.y}`}${tgt}`
      : a.action === "scroll" ? `${a.dx},${a.dy}`
      : a.action === "type" ? `${a.ref ?? ""}${tgt} · ${a.env ? `from env ${a.env}` : `text sha256 ${a.textSha256 ?? "?"}`} · ${a.length ?? 0} chars (value not recorded)`
      : a.action === "key" ? a.key ?? ""
      : "";
    out.push(`| ${a.seq} | ${a.action} | ${args} | ${a.result === "error" ? `error: ${esc(a.error ?? "")}` : "ok"} | ${a.url ? `\`${esc(a.url)}\`` : "—"} | ${a.requestIds.length} |`);
  }
  out.push("", "## Denials", "");
  if (!r.denials.length) out.push("None.");
  else {
    out.push("| Method | URL | Reason |", "|---|---|---|");
    for (const d of r.denials) out.push(`| ${d.method} | \`${esc(d.url)}\` | ${esc(d.reason)} |`);
  }
  if (r.incompleteReasons.length) out.push("", "## Incomplete", "", ...r.incompleteReasons.map((x) => `- ${esc(x)}`));
  return out.join("\n") + "\n";
}
