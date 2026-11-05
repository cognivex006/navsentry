/**
 * Fixture lifecycle for `safe-validate` (SPEC-0.2.0 §4.2, §6, invariants S13–S15).
 *
 * - A create holds its worst-case cleanup reserve in the Budget, appends a pending intent to
 *   `fixtures.pending.json` (fsync) and only then sends. The create is never retried.
 * - Every extracted id is validated and registered for cleanup before the next request.
 * - Cleanup runs in reverse creation order as `cleanup_actor`, draws from the reserve, retries once
 *   (network error or 5xx) and acts only on ids this run extracted: never by search, marker or type.
 * - Anything not cleaned and verified gone, and every create whose outcome is unknown, is a leftover;
 *   a run with leftovers is FAILED (S15). NavSentry never improvises a delete.
 *
 * Every request goes through the runner's `send` (ScopeGate → Budget → connect-time check).
 */
import { closeSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import { join } from "node:path";
import { BudgetExceeded, type Budget } from "../budget.js";
import type { Manifest } from "../config.js";
import { resolvePointer } from "../flow/assert.js";
import { fillTemplate, validMutationId } from "../scope.js";
import type { Exchange, HttpRequestSpec } from "../transports/types.js";
import type { FixtureLeftover, FixtureRunSummary, MutationRecord, PendingFixture } from "../types.js";
import type { EndpointEntry, FixtureDecl } from "./config.js";

export const PENDING_FILE = "fixtures.pending.json";
const MAX_BODY = 4096;
const EXACT_VAR = /^\{\{([a-z][a-zA-Z0-9_]{0,31})\}\}$/;

/** Thrown by the runner's send when ScopeGate refused the request (already recorded as a denial). */
export class RequestRefused extends Error {}

/** Sends one request; throws RequestRefused or BudgetExceeded. Provided by the runner. */
export type FixtureSend = (spec: HttpRequestSpec) => Promise<Exchange>;

export interface LifecycleOptions {
  manifest: Manifest;
  budget: Budget;
  marker: string;
  origin: string;
  /** Actor name → request headers for usable actors. */
  actors: Map<string, Record<string, string>>;
  send: FixtureSend;
  /** Run work directory; without it no create is sent (S14 needs the pending file). */
  workDir?: string;
  /** Delay before the single cleanup/verify retry (default 1000 ms; tests shorten it). */
  retryDelayMs?: number;
}

export interface StepOutcome {
  status: "PASS" | "ERROR" | "NOT_TESTED";
  reason?: string;
  id?: string;
  requestIds: string[];
  exchange?: Exchange;
}

interface Registered {
  seq: number;
  fixture: string;
  decl: FixtureDecl;
  id: string;
  reserved: number;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Fills a JSON body template: a string leaf that is exactly `{{name}}` takes a value; any other `{{` is refused. */
export function fillBody(template: Record<string, unknown>, lookup: (name: string) => string | undefined): { data?: Buffer; error?: string } {
  let error: string | undefined;
  const walk = (v: unknown, depth: number): unknown => {
    if (error) return undefined;
    if (depth > 8) { error = "body nests deeper than 8 levels"; return undefined; }
    if (typeof v === "string") {
      const m = v.match(EXACT_VAR);
      if (m) {
        const x = lookup(m[1]!);
        if (x === undefined) error = `body variable ${m[1]} has no value`;
        return x;
      }
      if (v.includes("{{")) error = "a body placeholder must be a whole string value";
      return v;
    }
    if (Array.isArray(v)) return v.map((x) => walk(x, depth + 1));
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x, depth + 1)]));
    return v;
  };
  const out = walk(template, 0);
  if (error) return { error };
  const data = Buffer.from(JSON.stringify(out), "utf8");
  if (data.length > MAX_BODY) return { error: `body is ${data.length} bytes after filling; at most ${MAX_BODY}` };
  return { data };
}

/** Reads a pending-intent file left by an interrupted run (sweep reporting). Never throws. */
export function readPending(workDir: string): PendingFixture[] {
  try {
    const v = JSON.parse(readFileSync(join(workDir, PENDING_FILE), "utf8")) as { entries?: PendingFixture[] };
    return Array.isArray(v.entries) ? v.entries.filter((e) => e && typeof e.fixture === "string" && e.state !== "cleaned") : [];
  } catch {
    return [];
  }
}

export class FixtureLifecycle {
  readonly mutations: MutationRecord[] = [];
  readonly leftovers: FixtureLeftover[] = [];
  private readonly registered: Registered[] = [];
  private readonly pending: PendingFixture[] = [];
  private seq = 0;
  private created = 0;
  private cleaned = 0;
  private verifiedGone = 0;
  private mutationsUsed = 0;
  private stopReason: string | undefined;
  private cleanupDone = false;

  constructor(private readonly o: LifecycleOptions) {}

  /** Stops creates and mutations (first signal, or a fatal error). Cleanup still runs. */
  stop(reason: string): void {
    this.stopReason ??= reason;
  }

  get stopped(): string | undefined {
    return this.stopReason;
  }

  /** Counts one non-observe request against `max_mutations` (cleanup is covered by the reserve instead). */
  private countMutation(): void {
    if (this.mutationsUsed >= this.o.manifest.safety.max_mutations) throw new BudgetExceeded(`mutation limit reached (max_mutations ${this.o.manifest.safety.max_mutations})`);
    this.mutationsUsed++;
  }

  private headers(actor: string): Record<string, string> | undefined {
    return this.o.actors.get(actor);
  }

  private persist(): void {
    if (!this.o.workDir) return;
    const fd = openSync(join(this.o.workDir, PENDING_FILE), "w", 0o600);
    try {
      writeSync(fd, JSON.stringify({ kind: "navsentry-fixtures-pending", marker: this.o.marker, entries: this.pending }, null, 2) + "\n");
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }

  private record(entry: EndpointEntry, kind: string, actor: string, ex: Exchange | undefined, bodySha?: string): void {
    this.mutations.push({ method: entry.method, path: entry.path, entry: kind, actor, ...(ex?.raw ? { status: ex.raw.status } : {}), ...(ex?.record.error ? { error: ex.record.error } : {}), ...(bodySha ? { bodySha256: bodySha } : {}), ...(ex ? { requestId: ex.record.id } : {}) });
  }

  /**
   * `fixture_create` (§4.2): reserve → pending intent → create → validated id → registered → `exists`.
   * NOT_TESTED when the create could not be attempted; ERROR when it was sent and something went wrong.
   */
  async create(fixture: string, actor: string, flow: { id: string; step: string }): Promise<StepOutcome> {
    const decl = this.o.manifest.fixtures[fixture];
    const ids: string[] = [];
    if (!decl) return { status: "ERROR", reason: `fixture ${fixture} is not declared`, requestIds: ids };
    if (this.stopReason) return { status: "NOT_TESTED", reason: `stopped: ${this.stopReason}`, requestIds: ids };
    if (actor !== decl.owner_actor) return { status: "ERROR", reason: `fixture ${fixture} is created by its owner_actor ${decl.owner_actor}`, requestIds: ids };
    const ownerH = this.headers(actor);
    if (!ownerH) return { status: "NOT_TESTED", reason: `actor ${actor} is not usable`, requestIds: ids };
    if (!this.headers(decl.cleanup_actor)) return { status: "NOT_TESTED", reason: `cleanup actor ${decl.cleanup_actor} is not usable, so nothing may be created`, requestIds: ids };
    if (!this.o.workDir) return { status: "NOT_TESTED", reason: "no work directory for the pending-intent file (S14)", requestIds: ids };
    const windowMs = this.o.manifest.safety.cleanup_window_seconds * 1000;
    if (this.o.budget.timeLeftMs < windowMs) return { status: "NOT_TESTED", reason: `less than cleanup_window_seconds (${this.o.manifest.safety.cleanup_window_seconds}) left before the deadline; no new creates`, requestIds: ids };
    if (this.mutationsUsed >= this.o.manifest.safety.max_mutations) return { status: "NOT_TESTED", reason: `mutation limit reached (max_mutations ${this.o.manifest.safety.max_mutations})`, requestIds: ids };
    const body = decl.create.body ? fillBody(decl.create.body.json, (n) => (n === "marker" ? this.o.marker : undefined)) : { data: undefined };
    if (body.error) return { status: "ERROR", reason: body.error, requestIds: ids };
    const reserve = 2 * (1 + (decl.verify_gone ? 1 : 0));
    try {
      this.o.budget.reserve(reserve);
    } catch (e) {
      return { status: "NOT_TESTED", reason: (e as Error).message, requestIds: ids };
    }
    const seq = ++this.seq;
    const intent: PendingFixture = { seq, fixture, state: "intent", marker: this.o.marker, at: new Date().toISOString() };
    this.pending.push(intent);
    try {
      this.persist();
    } catch (e) {
      this.pending.pop();
      this.o.budget.release(reserve);
      return { status: "ERROR", reason: `pending intent not written, create not sent: ${(e as Error).message}`, requestIds: ids };
    }
    let ex: Exchange;
    try {
      this.countMutation();
      ex = await this.o.send({
        method: decl.create.method, url: new URL(decl.create.path, this.o.origin).toString(), displayUrl: new URL(decl.create.path, this.o.origin).toString(), actor,
        headers: { ...ownerH, accept: "application/json", "x-navsentry-flow": `${flow.id}/${flow.step}` }, flow, mutation: decl.create, retainBytes: 65536,
        ...(body.data ? { body: { contentType: "application/json", data: body.data } } : {}),
      });
    } catch (e) {
      // Refused before sending (scope or budget): nothing was created.
      this.resolveIntent(intent, "refused");
      this.o.budget.release(reserve);
      if (e instanceof BudgetExceeded) return { status: "NOT_TESTED", reason: e.message, requestIds: ids };
      return { status: "ERROR", reason: `create refused before sending: ${(e as Error).message}`, requestIds: ids };
    }
    ids.push(ex.record.id);
    this.record(decl.create, `fixtures.${fixture}.create`, actor, ex, ex.record.requestBodySha256);
    const lost = (why: string): StepOutcome => {
      // S15: the object may exist; it is a leftover with the marker, and the create is never retried.
      intent.state = "unknown";
      this.safePersist();
      this.o.budget.release(reserve);
      this.leftovers.push({ fixture, displayId: "unknown — create outcome lost", status: "unknown-outcome", marker: this.o.marker, reason: why, manualAction: `look for a ${fixture} object carrying marker ${this.o.marker} and remove it; NavSentry does not search or delete by marker` });
      return { status: "ERROR", reason: `create outcome unknown: ${why}`, requestIds: ids, exchange: ex };
    };
    if (ex.record.error || !ex.raw) return lost(ex.record.error ?? "no response");
    if (ex.record.capture && ex.record.capture.status !== "complete") return lost(`response ${ex.record.capture.status}`);
    const st = ex.raw.status;
    if (st < 200 || st >= 300) {
      this.resolveIntent(intent, "refused");
      this.o.budget.release(reserve);
      return { status: "ERROR", reason: `create returned status ${st}; nothing registered`, requestIds: ids, exchange: ex };
    }
    let rawId: unknown;
    try {
      rawId = resolvePointer(JSON.parse(ex.raw.body.toString("utf8")), decl.create.extract.id).value;
    } catch {
      return lost("create response is not parseable JSON");
    }
    if (rawId === undefined) return lost(`no value at ${decl.create.extract.id} in the create response`);
    const id = validMutationId(rawId);
    if (!id) return lost("the created id was rejected by the safe-validate id rule");
    intent.state = "created";
    intent.id = id;
    this.registered.push({ seq, fixture, decl, id, reserved: reserve });
    this.created++;
    this.safePersist();
    // Positive control: the object must exist for the owner's cleanup actor.
    const exists = await this.observe(decl.exists, decl.cleanup_actor, id, flow);
    if (exists.exchange) ids.push(exists.exchange.record.id);
    if (!exists.ok) return { status: "ERROR", reason: `exists check failed: ${exists.why}; the object stays registered for cleanup`, id, requestIds: ids, exchange: ex };
    return { status: "PASS", id, requestIds: ids, exchange: ex };
  }

  /** One declared `allowed_mutations` request from an http step (§4.1). Never retried, never redirected. */
  async mutate(fixture: string, entry: EndpointEntry, url: string, displayUrl: string, actor: string, headers: Record<string, string>, body: Buffer | undefined, flow: { id: string; step: string; deniedProbe?: true }): Promise<Exchange> {
    if (this.stopReason) throw new BudgetExceeded(`stopped: ${this.stopReason}`);
    this.countMutation();
    const ex = await this.o.send({ method: entry.method, url, displayUrl, actor, headers, flow, mutation: entry, ...(body ? { body: { contentType: "application/json", data: body } } : {}) });
    this.record(entry, `fixtures.${fixture}.allowed_mutations`, actor, ex, ex.record.requestBodySha256);
    return ex;
  }

  private resolveIntent(intent: PendingFixture, state: PendingFixture["state"]): void {
    intent.state = state;
    const i = this.pending.indexOf(intent);
    if (i >= 0 && (state === "refused" || state === "cleaned")) this.pending.splice(i, 1);
    this.safePersist();
  }

  private safePersist(): void {
    try { this.persist(); } catch { /* the in-memory leftover list is still reported */ }
  }

  /** GET `exists`/`verify_gone` as `actor`; compares the status with the entry's expect_status. */
  private async observe(entry: EndpointEntry, actor: string, id: string, flow: { id: string; step: string }, fromReserve = false): Promise<{ ok: boolean; why: string; exchange?: Exchange; status?: number }> {
    const h = this.headers(actor);
    if (!h) return { ok: false, why: `actor ${actor} is not usable` };
    const url = new URL(fillTemplate(entry.path, id), this.o.origin).toString();
    try {
      const ex = await this.o.send({ method: "GET", url, displayUrl: new URL(entry.path, this.o.origin).toString(), actor, headers: { ...h, accept: "application/json" }, flow, ...(fromReserve ? { fromReserve: true as const } : {}) });
      if (ex.record.error || !ex.raw) return { ok: false, why: ex.record.error ?? "no response", exchange: ex };
      const ok = (entry.expect_status ?? []).includes(ex.raw.status);
      return { ok, why: ok ? "" : `status ${ex.raw.status}, expected ${entry.expect_status?.join("|")}`, exchange: ex, status: ex.raw.status };
    } catch (e) {
      return { ok: false, why: (e as Error).message };
    }
  }

  /** Sends `entry` (cleanup) or GETs it (verify_gone) with one retry on a network error or 5xx. */
  private async withRetry(fn: () => Promise<{ ok: boolean; why: string; status?: number; exchange?: Exchange; refused?: boolean }>, capAt: number): Promise<{ ok: boolean; why: string; status?: number; attempts: number }> {
    let r = await fn();
    let attempts = 1;
    const retryable = !r.ok && !r.refused && (r.status === undefined || r.status >= 500);
    if (retryable && Date.now() + (this.o.retryDelayMs ?? 1000) < capAt) {
      await sleep(this.o.retryDelayMs ?? 1000);
      r = await fn();
      attempts++;
    }
    return { ok: r.ok, why: r.why, ...(r.status !== undefined ? { status: r.status } : {}), attempts };
  }

  /**
   * Cleans every registered object in reverse creation order (S14). `capMs` bounds the whole cleanup
   * (30 s after a signal). Nothing is sent after the authorization window: the Budget refuses it.
   */
  async cleanupAll(capMs?: number): Promise<void> {
    if (this.cleanupDone) return;
    this.cleanupDone = true;
    const capAt = Date.now() + Math.min(capMs ?? Number.POSITIVE_INFINITY, this.o.budget.timeLeftMs);
    const flow = { id: "fixtures", step: "cleanup" };
    for (const r of [...this.registered].reverse()) {
      const action = `${r.decl.cleanup.method} ${fillTemplate(r.decl.cleanup.path, r.id)} as ${r.decl.cleanup_actor}`;
      const left = (status: FixtureLeftover["status"], reason: string, lastStatus?: number) => this.leftovers.push({ fixture: r.fixture, id: r.id, displayId: r.id, status, reason, ...(lastStatus !== undefined ? { lastStatus } : {}), manualAction: action });
      if (Date.now() >= capAt) { left("not-attempted", "cleanup time limit reached"); this.o.budget.release(r.reserved); continue; }
      const h = this.headers(r.decl.cleanup_actor);
      if (!h) { left("not-attempted", `cleanup actor ${r.decl.cleanup_actor} is not usable`); this.o.budget.release(r.reserved); continue; }
      const before = this.o.budget.reservedSlots;
      const del = await this.withRetry(async () => {
        try {
          const ex = await this.o.send({ method: r.decl.cleanup.method, url: new URL(fillTemplate(r.decl.cleanup.path, r.id), this.o.origin).toString(), displayUrl: new URL(r.decl.cleanup.path, this.o.origin).toString(), actor: r.decl.cleanup_actor, headers: { ...h, accept: "application/json" }, flow, mutation: r.decl.cleanup, fromReserve: true });
          this.mutationsUsed++;
          this.record(r.decl.cleanup, `fixtures.${r.fixture}.cleanup`, r.decl.cleanup_actor, ex);
          if (ex.record.error || !ex.raw) return { ok: false, why: ex.record.error ?? "no response" };
          const ok = (r.decl.cleanup.expect_status ?? []).includes(ex.raw.status) || ex.raw.status === 404;
          return { ok, why: ok ? "" : `status ${ex.raw.status}`, status: ex.raw.status };
        } catch (e) {
          return { ok: false, why: (e as Error).message, refused: true };
        }
      }, capAt);
      if (!del.ok) { left("cleanup-failed", del.why, del.status); this.releaseRest(r, before); continue; }
      this.cleaned++;
      if (r.decl.verify_gone) {
        const v = await this.withRetry(() => this.observe(r.decl.verify_gone!, r.decl.cleanup_actor, r.id, flow, true), capAt);
        if (!v.ok) { left("still-present", `verify_gone: ${v.why}`, v.status); this.releaseRest(r, before); continue; }
        this.verifiedGone++;
      }
      this.releaseRest(r, before);
      const p = this.pending.find((x) => x.seq === r.seq);
      if (p) this.resolveIntent(p, "cleaned");
    }
  }

  /** Returns the reserve slots this object did not use. */
  private releaseRest(r: Registered, before: number): void {
    const used = before - this.o.budget.reservedSlots;
    this.o.budget.release(Math.max(0, r.reserved - used));
  }

  /** Second signal: no cleanup; everything registered becomes a leftover. The pending file stays on disk. */
  abandon(): void {
    if (this.cleanupDone) return;
    this.cleanupDone = true;
    for (const r of [...this.registered].reverse()) this.leftovers.push({ fixture: r.fixture, id: r.id, displayId: r.id, status: "not-attempted", reason: "second signal: cleanup skipped", manualAction: `${r.decl.cleanup.method} ${fillTemplate(r.decl.cleanup.path, r.id)} as ${r.decl.cleanup_actor}` });
    this.safePersist();
  }

  summary(previous: FixtureRunSummary["pendingFromPreviousRuns"] = []): FixtureRunSummary {
    return { marker: this.o.marker, created: this.created, cleaned: this.cleaned, verifiedGone: this.verifiedGone, mutationsUsed: this.mutationsUsed, mutationsMax: this.o.manifest.safety.max_mutations, leftovers: this.leftovers, ...(previous.length ? { pendingFromPreviousRuns: previous } : {}) };
  }
}
