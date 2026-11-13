/**
 * Resumable runs (M4, SPEC-0.4.0 D4: new run, budget carried over).
 *
 * `--resume <run dir>` starts a NEW run with its own runId that points at an earlier PARTIAL run:
 * - the earlier folder must pass `navsentry verify` first;
 * - the new run may use only the request budget the earlier run had left;
 * - project, environment, safety mode and scope must be unchanged, and so must the flow set hash;
 * - a seed URL or flow that sent any request in the earlier run is never sent again (it is listed instead);
 * - spider runs and runs with logins cannot be resumed (their state cannot be rebuilt without resending).
 * The authorization window is checked again by the new run, against the same manifest.
 * The new run reports only what it ran; the earlier run's report stays the record of the rest.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Manifest } from "./config.js";
import { MANIFEST_FILE, verifyRun } from "./integrity.js";
import type { RunResult } from "./types.js";

export interface ResumePlan {
  runId: string;
  budgetLeft: number;
  /** Redacted seed URLs (as run.json records them) that already sent a request. */
  doneSeeds: Set<string>;
  /** Flow IDs that already sent a request. */
  doneFlows: Set<string>;
  manifestSha256: string;
}

export class ResumeRefused extends Error {}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

export function planResume(dir: string, m: Manifest, o: { flowSetSha256?: string; spider?: boolean; logins: number }): ResumePlan {
  const v = (() => { try { return verifyRun(dir); } catch (e) { throw new ResumeRefused(`cannot resume: ${(e as Error).message}`); } })();
  if (v.status !== "PASS") throw new ResumeRefused(`cannot resume: the earlier run folder fails verify (${[...v.modified.map((f) => `modified ${f}`), ...v.missing.map((f) => `missing ${f}`), ...v.added.map((f) => `added ${f}`)].slice(0, 5).join(", ")})`);
  const r = JSON.parse(readFileSync(join(dir, "run.json"), "utf8")) as RunResult;
  if (r.executionStatus !== "PARTIAL") throw new ResumeRefused(`cannot resume: the earlier run is ${r.executionStatus}, not PARTIAL`);
  if (o.spider || r.scanMode === "spider") throw new ResumeRefused("cannot resume a spider run: the crawl frontier cannot be rebuilt without resending requests");
  if (o.logins > 0) throw new ResumeRefused("cannot resume a run with logins: sessions would have to be created again; start a new run");
  if (r.project !== m.project || r.environment !== m.environment || r.mode !== m.safety.mode) throw new ResumeRefused("cannot resume: project, environment or safety mode changed since the earlier run");
  if (!same(r.scope, { origins: m.targets.origins, allowedPaths: m.targets.allowed_paths, deniedPaths: m.targets.denied_paths })) throw new ResumeRefused("cannot resume: the manifest scope changed since the earlier run");
  if ((r.flowSet?.sha256 ?? undefined) !== o.flowSetSha256) throw new ResumeRefused("cannot resume: the flow set changed since the earlier run (approval hashes are checked again on a new run)");
  // Only what the earlier run had left; raising max_requests in the manifest does not add to it.
  const left = Math.min(m.safety.max_requests, r.budget.requestsMax) - r.budget.requestsUsed;
  if (left <= 0) throw new ResumeRefused(`cannot resume: the earlier run used its whole request budget (${r.budget.requestsUsed} of ${r.budget.requestsMax})`);
  const doneSeeds = new Set<string>(), doneFlows = new Set<string>();
  for (const q of r.requests) {
    if (q.flow) doneFlows.add(q.flow.id);
    else doneSeeds.add(q.url);
  }
  return { runId: r.runId, budgetLeft: left, doneSeeds, doneFlows, manifestSha256: createHash("sha256").update(readFileSync(join(dir, MANIFEST_FILE))).digest("hex") };
}
