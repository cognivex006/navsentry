/**
 * Consumer workspace hygiene (SPEC-0.1.3 §7). NavSentry writes only `<project>/.navsentry/`
 * (plus explicit `--out` paths). Ephemeral files live in `.navsentry/work/<run-id>/`, owned through
 * a lock file, and are deleted when the run ends. Before/after snapshots make a leftover a
 * detected failure (`WORKSPACE_DIRTY`, exit 4) instead of a promise.
 *
 * Deletion rules (S11): only canonical work/cache roots under one explicit project root; links and
 * junctions are unlinked, never followed; ownership is re-verified before each mutation; anything
 * uncertain is preserved and reported.
 */
import { randomBytes } from "node:crypto";
import { closeSync, existsSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, rmdirSync, statSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { hostname } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { readPending } from "./fixtures/lifecycle.js";
import type { PendingFixture, WorkspaceResult } from "./types.js";

export const STATE_DIR = ".navsentry";
export const INPUT_DIR = "navsentry";
export const MAX_SNAPSHOT_ENTRIES = 200_000;
const ALWAYS_EXCLUDED = new Set([".git", "node_modules", INPUT_DIR, STATE_DIR]);
const LOCK = "lock.json";

export class WorkspaceError extends Error {}

export interface Lock {
  kind: "navsentry-work-lock";
  nonce: string;
  host: string;
  pid: number;
  /** Process start time (ms since epoch); a PID alone cannot detect reuse. */
  processStart: number;
  createdAt: string;
}

const processStart = Math.round(Date.now() - process.uptime() * 1000);

/** Resolves the project root once. It must exist, be a directory, and not be a link. */
export function projectRoot(dir: string): string {
  const abs = resolve(dir);
  const st = lstatSync(abs, { throwIfNoEntry: false });
  if (!st || !st.isDirectory() || st.isSymbolicLink()) throw new WorkspaceError(`project root is not a plain directory: ${abs}`);
  return realpathSync(abs);
}

/** True when `p` is strictly inside `root` (both absolute, already resolved). */
export function inside(root: string, p: string): boolean {
  const rel = relative(root, p);
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

/** Every component between root and target must be a real directory, never a link or junction. */
function assertNoLinkedAncestors(root: string, target: string): void {
  if (!inside(root, target) && target !== root) throw new WorkspaceError("path escapes the project root");
  let cur = root;
  for (const part of relative(root, target).split(sep).filter(Boolean)) {
    cur = join(cur, part);
    const st = lstatSync(cur, { throwIfNoEntry: false });
    if (!st) return;
    if (st.isSymbolicLink()) throw new WorkspaceError(`linked path refused: ${relative(root, cur)}`);
  }
}

/** Creates `.navsentry/` with a self-ignoring `.gitignore` the first time (never edits the root .gitignore). */
export function ensureStateDir(root: string): string {
  const dir = join(root, STATE_DIR);
  assertNoLinkedAncestors(root, dir);
  if (!existsSync(dir)) mkdirSync(dir);
  const gi = join(dir, ".gitignore");
  if (!existsSync(gi)) writeFileSync(gi, "*\n", { flag: "wx" });
  return dir;
}

export interface WorkDir {
  root: string;
  path: string;
  runId: string;
  lock: Lock;
}

/** Creates `.navsentry/work/<run-id>/` exclusively, with an ownership lock. */
export function createWorkDir(root: string, runId: string): WorkDir {
  if (!/^[A-Za-z0-9-]{8,64}$/.test(runId)) throw new WorkspaceError("invalid run id");
  ensureStateDir(root);
  const base = join(root, STATE_DIR, "work");
  assertNoLinkedAncestors(root, base);
  if (!existsSync(base)) mkdirSync(base);
  const path = join(base, runId);
  mkdirSync(path, { mode: 0o700 }); // throws EEXIST: never reuse a directory
  const lock: Lock = { kind: "navsentry-work-lock", nonce: randomBytes(16).toString("hex"), host: hostname(), pid: process.pid, processStart, createdAt: new Date().toISOString() };
  const fd = openSync(join(path, LOCK), "wx", 0o600);
  try { writeSync(fd, JSON.stringify(lock)); } finally { closeSync(fd); }
  return { root, path, runId, lock };
}

function readLock(dir: string): Lock | undefined {
  try {
    const st = lstatSync(join(dir, LOCK));
    if (!st.isFile() || st.size > 4096) return undefined;
    const l = JSON.parse(readFileSync(join(dir, LOCK), "utf8")) as Lock;
    return l?.kind === "navsentry-work-lock" && typeof l.nonce === "string" && typeof l.pid === "number" && typeof l.host === "string" && typeof l.processStart === "number" ? l : undefined;
  } catch {
    return undefined;
  }
}

function pidAlive(pid: number): boolean | undefined {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    return code === "ESRCH" ? false : code === "EPERM" ? true : undefined;
  }
}

export type Staleness = { stale: true } | { stale: false; reason: string };

/** Stale only when proven: same host, readable lock, and the owning process is gone. */
export function staleness(dir: string, self?: Lock): Staleness {
  const l = readLock(dir);
  if (!l) return { stale: false, reason: "lock missing or unreadable" };
  if (self && l.nonce === self.nonce) return { stale: false, reason: "owned by this run" };
  if (l.host !== hostname()) return { stale: false, reason: "lock belongs to another host" };
  if (l.pid === process.pid) return l.processStart === processStart ? { stale: false, reason: "owned by this process" } : { stale: true };
  const alive = pidAlive(l.pid);
  if (alive === undefined) return { stale: false, reason: "owner process state unknown" };
  // A live PID may be a reused one; without a portable start-time probe it is preserved (conservative).
  return alive ? { stale: false, reason: "owner process is running" } : { stale: true };
}

/**
 * Deletes a directory tree without following links: a link or junction entry is unlinked,
 * its target untouched. Containment is re-checked before every mutation.
 */
export function removeTree(root: string, target: string): void {
  assertNoLinkedAncestors(root, target);
  const st = lstatSync(target, { throwIfNoEntry: false });
  if (!st) return;
  if (st.isSymbolicLink()) { unlinkSync(target); return; }
  if (!st.isDirectory()) { unlinkSync(target); return; }
  for (const name of readdirSync(target)) {
    const child = join(target, name);
    if (!inside(target, child)) throw new WorkspaceError("unsafe entry name");
    const cs = lstatSync(child);
    if (cs.isSymbolicLink()) {
      // Windows junctions are reported as symbolic links by lstat; rmdir removes the link only.
      try { unlinkSync(child); } catch { rmdirSync(child); }
    } else if (cs.isDirectory()) removeTree(root, child);
    else unlinkSync(child);
  }
  assertNoLinkedAncestors(root, target);
  rmdirSync(target);
}

/** Deletes this run's own work directory after verifying the lock is still ours. */
export function releaseWorkDir(w: WorkDir): void {
  const l = readLock(w.path);
  if (existsSync(w.path) && (!l || l.nonce !== w.lock.nonce)) throw new WorkspaceError("work directory ownership changed; not deleted");
  removeTree(w.root, w.path);
}

export interface SweepResult {
  removed: string[];
  preserved: { dir: string; reason: string }[];
  /** safe-validate (SPEC-0.2.0 §6.2): pending fixture intents read from stale dirs before removal. Reported, never acted on. */
  pendingFixtures: (PendingFixture & { workDir: string })[];
}

/** Removes only same-host work directories whose ownership is proven stale (§7.2 step 3). */
export function sweepStale(root: string, opts: { dryRun?: boolean; self?: Lock } = {}): SweepResult {
  const out: SweepResult = { removed: [], preserved: [], pendingFixtures: [] };
  const base = join(root, STATE_DIR, "work");
  const st = lstatSync(base, { throwIfNoEntry: false });
  if (!st) return out;
  if (!st.isDirectory() || st.isSymbolicLink()) { out.preserved.push({ dir: "work", reason: "work root is not a plain directory" }); return out; }
  assertNoLinkedAncestors(root, base);
  for (const name of readdirSync(base)) {
    const dir = join(base, name);
    const ds = lstatSync(dir);
    if (!ds.isDirectory() || ds.isSymbolicLink()) { out.preserved.push({ dir: name, reason: "not a plain directory" }); continue; }
    const s = staleness(dir, opts.self);
    if (!s.stale) { out.preserved.push({ dir: name, reason: s.reason }); continue; }
    for (const e of readPending(dir)) out.pendingFixtures.push({ ...e, workDir: name });
    if (opts.dryRun) { out.removed.push(name); continue; }
    try {
      // Re-verify just before the mutation.
      if (!staleness(dir, opts.self).stale) { out.preserved.push({ dir: name, reason: "ownership changed during sweep" }); continue; }
      removeTree(root, dir);
      out.removed.push(name);
    } catch (e) {
      out.preserved.push({ dir: name, reason: `cleanup failed: ${(e as Error).message}` });
    }
  }
  return out;
}

// ───────────────────────── Snapshots ─────────────────────────

export interface Snapshot {
  complete: boolean;
  reason?: string;
  entries: Map<string, string>;
}

/** Minimal glob: `**` any depth, `*` within a segment, `?` one char. Paths use "/". */
export function ignoreGlob(g: string): RegExp {
  let re = "";
  for (let i = 0; i < g.length; i++) {
    const c = g[i]!;
    if (c === "*" && g[i + 1] === "*") { re += g[i + 2] === "/" ? "(?:.*/)?" : ".*"; i += g[i + 2] === "/" ? 2 : 1; }
    else if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}(?:/.*)?$`);
}

/**
 * Recursive metadata snapshot (relative path → size:mtime), never following links.
 * Excludes .git/, node_modules/, navsentry/, .navsentry/ and `ignore` globs.
 */
export function snapshot(root: string, ignore: string[] = [], limit = MAX_SNAPSHOT_ENTRIES): Snapshot {
  const res = ignore.map(ignoreGlob);
  const entries = new Map<string, string>();
  const stack = [""];
  try {
    while (stack.length) {
      const rel = stack.pop()!;
      for (const name of readdirSync(join(root, rel))) {
        const r = rel ? `${rel}/${name}` : name;
        if (!rel && ALWAYS_EXCLUDED.has(name)) continue;
        if (res.some((x) => x.test(r))) continue;
        const st = lstatSync(join(root, r));
        if (entries.size >= limit) return { complete: false, reason: `project tree has more than ${limit} entries`, entries };
        if (st.isDirectory() && !st.isSymbolicLink()) { entries.set(r + "/", "dir"); stack.push(r); }
        else entries.set(r, `${st.isSymbolicLink() ? "link" : st.size}:${Math.round(st.mtimeMs)}`);
      }
    }
  } catch (e) {
    return { complete: false, reason: `project tree could not be read completely (${(e as NodeJS.ErrnoException).code ?? "error"})`, entries };
  }
  return { complete: true, entries };
}

/** Display path for reports: relative, "/"-separated, query-like and long identifier segments masked. */
export function displayPath(rel: string): string {
  return rel.split("/").map((s) => (/^[0-9a-f]{16,}$/i.test(s) || /^[0-9a-f-]{32,}$/i.test(s) ? "{id}" : s.length > 80 ? `${s.slice(0, 40)}…` : s)).join("/");
}

export function diffSnapshots(before: Snapshot, after: Snapshot, authorized: Set<string> = new Set()): Pick<WorkspaceResult, "created" | "modified" | "deleted"> {
  const created: string[] = [], modified: string[] = [], deleted: string[] = [];
  for (const [k, v] of after.entries) {
    if (authorized.has(k) || (k.endsWith("/") && [...authorized].some((a) => a.startsWith(k)))) continue;
    const b = before.entries.get(k);
    if (b === undefined) created.push(displayPath(k));
    else if (b !== v && v !== "dir") modified.push(displayPath(k));
  }
  for (const k of before.entries.keys()) if (!after.entries.has(k) && !authorized.has(k)) deleted.push(displayPath(k));
  return { created: created.sort(), modified: modified.sort(), deleted: deleted.sort() };
}

// ───────────────────────── Run lifecycle ─────────────────────────

export const SNAPSHOT_LIMITATIONS = [
  "metadata snapshots (size, mtime) detect common changes but do not prove byte identity",
  "the check sees changes made by any process during the run, not only by NavSentry",
];

export interface RunWorkspace {
  root: string;
  work: WorkDir;
  before: Snapshot;
  sweep: SweepResult;
  ignore: string[];
  /** Exact files the owner asked for (`--out`), relative to root. */
  authorized: Set<string>;
  dispose: () => void;
}

/** Sweeps stale work, snapshots the tree, creates this run's work dir, and arms signal cleanup. */
export function beginRun(projectDir: string, runId: string, ignore: string[], opts: { coordinatedSignals?: boolean } = {}): RunWorkspace {
  const root = projectRoot(projectDir);
  ensureStateDir(root);
  const sweep = sweepStale(root);
  const before = snapshot(root, ignore);
  const work = createWorkDir(root, runId);
  // Node does not run `finally` when a signal ends the process; clean up explicitly.
  const onSignal = (sig: NodeJS.Signals) => {
    try { releaseWorkDir(work); } catch { /* reported on the next run's sweep */ }
    process.exit(sig === "SIGINT" ? 130 : 143);
  };
  // safe-validate runs use the SignalCoordinator instead: cleanup must run before the exit (SPEC-0.2.0 §6.2).
  if (!opts.coordinatedSignals) {
    process.once("SIGINT", onSignal);
    process.once("SIGTERM", onSignal);
  }
  const dispose = () => { process.off("SIGINT", onSignal); process.off("SIGTERM", onSignal); };
  return { root, work, before, sweep, ignore, authorized: new Set(), dispose };
}

/** Marks an explicit output file as an authorized write (excluded one by one, never by parent tree). */
export function authorize(ws: RunWorkspace, file: string): void {
  const abs = resolve(file);
  if (inside(ws.root, abs)) {
    const rel = relative(ws.root, abs).split(sep).join("/");
    ws.authorized.add(rel);
  }
}

/** Deletes the work directory, then compares snapshots. FAIL means exit 4. */
export function endRun(ws: RunWorkspace, promoted: number): WorkspaceResult {
  ws.dispose();
  let cleanup: WorkspaceResult["cleanup"] = "COMPLETE";
  let cleanupReason: string | undefined;
  try {
    releaseWorkDir(ws.work);
    if (existsSync(ws.work.path)) throw new WorkspaceError("work directory still present");
  } catch (e) {
    cleanup = "FAILED";
    cleanupReason = (e as Error).message;
  }
  const after = snapshot(ws.root, ws.ignore);
  const base = { cleanup, ...(cleanupReason ? { cleanupReason } : {}), promoted, limitations: SNAPSHOT_LIMITATIONS };
  if (!ws.before.complete || !after.complete) return { status: "NOT_TESTED", reason: ws.before.reason ?? after.reason ?? "snapshot incomplete", created: [], modified: [], deleted: [], ...base, ...(cleanup === "FAILED" ? { status: "FAIL" as const } : {}) };
  const d = diffSnapshots(ws.before, after, ws.authorized);
  const dirty = d.created.length + d.modified.length + d.deleted.length > 0 || cleanup === "FAILED";
  return { status: dirty ? "FAIL" : "PASS", ...(dirty && cleanup === "FAILED" ? { reason: "cleanup failed" } : dirty ? { reason: "unexpected changes in the project tree" } : {}), ...d, ...base };
}

// ───────────────────────── `workspace status|clean` ─────────────────────────

export interface WorkspaceStatus {
  root: string;
  stateDir: boolean;
  categories: { name: string; present: boolean; entries: number }[];
  work: { dir: string; stale: boolean; reason?: string }[];
}

export function workspaceStatus(projectDir: string): WorkspaceStatus {
  const root = projectRoot(projectDir);
  const count = (p: string) => { try { return statSync(p).isDirectory() ? readdirSync(p).length : 1; } catch { return 0; } };
  const cats = [
    [INPUT_DIR + "/flows/approved", join(root, INPUT_DIR, "flows", "approved")],
    [INPUT_DIR + "/flows/drafts", join(root, INPUT_DIR, "flows", "drafts")],
    [STATE_DIR + "/runs", join(root, STATE_DIR, "runs")],
    [STATE_DIR + "/work", join(root, STATE_DIR, "work")],
    [STATE_DIR + "/cache/assets", join(root, STATE_DIR, "cache", "assets")],
    [STATE_DIR + "/knowledge/proposals", join(root, STATE_DIR, "knowledge", "proposals")],
  ].map(([name, p]) => ({ name: name!, present: existsSync(p!), entries: count(p!) }));
  const base = join(root, STATE_DIR, "work");
  const work = existsSync(base) && !lstatSync(base).isSymbolicLink()
    ? readdirSync(base).map((dir) => { const s = staleness(join(base, dir)); return { dir, stale: s.stale, ...(s.stale ? {} : { reason: s.reason }) }; })
    : [];
  return { root, stateDir: existsSync(join(root, STATE_DIR)), categories: cats, work };
}

/**
 * Removes expired facts-cache entries (`.navsentry/cache/assets/*.json` older than `maxAgeDays`).
 * Only regular files with the cache naming are touched; links and anything else are preserved.
 */
export function cleanCache(root: string, maxAgeDays: number, opts: { dryRun?: boolean; now?: Date } = {}): { removed: number; preserved: number } {
  const dir = join(root, STATE_DIR, "cache", "assets");
  const out = { removed: 0, preserved: 0 };
  const st = lstatSync(dir, { throwIfNoEntry: false });
  if (!st || !st.isDirectory() || st.isSymbolicLink()) return out;
  assertNoLinkedAncestors(root, dir);
  const limit = (opts.now ?? new Date()).getTime() - maxAgeDays * 86_400_000;
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const fs = lstatSync(p);
    if (!/^[0-9a-f]{64}\.json$/.test(name) || !fs.isFile() || fs.isSymbolicLink()) { out.preserved++; continue; }
    if (fs.mtimeMs >= limit) continue;
    if (!opts.dryRun) unlinkSync(p);
    out.removed++;
  }
  return out;
}
