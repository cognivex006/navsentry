/**
 * Visual driver (Computer Use, option 1 of ADR-0009). The host agent looks at screenshots and sends
 * coordinates; NavSentry owns the browser. Every request the page makes is fulfilled through the same
 * playwright engine as M1b (ScopeGate before the request and at connect time, Budget, redaction), so
 * S1 holds no matter where the agent clicks. Development profile only; observe actions only (no typing).
 *
 * One session = one long-lived process that holds the browser and the run's safety state. Commands
 * reach it only through a local pipe (a named pipe on Windows, a Unix socket elsewhere) and must carry
 * the random session token, which is stored with mode 0600 inside the run's work directory.
 */
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import net from "node:net";
import { join } from "node:path";
import { Budget, BudgetExceeded, ByteBudget } from "../budget.js";
import { assertAuthorizationWindow, type Manifest } from "../config.js";
import { Redactor } from "../redact.js";
import { buildFindings, perExchange, resolveActors } from "../runner.js";
import { ScopeGate } from "../scope.js";
import { DirectHttpAdapter, ScopeDenied } from "../transports/direct-http.js";
import { BrowserEngine, firstLine, probePlaywright, VIEWPORT, type BrowserRequest } from "../transports/playwright.js";
import type { Exchange } from "../transports/types.js";
import type { CheckResult, VisualAction, VisualSessionResult } from "../types.js";
import { beginRun, endRun, type RunWorkspace } from "../workspace.js";

export class SessionRefused extends Error {}

export interface SessionOptions {
  manifest: Manifest;
  projectDir: string;
  /** In-scope start URL. */
  url: string;
  actor?: string;
  idleSeconds?: number;
  env?: NodeJS.ProcessEnv;
  /** Test seam for engine availability. */
  probe?: typeof probePlaywright;
  now?: () => Date;
}

export interface SessionHandle {
  id: string;
  /** Resolves with the final result once the session has ended (by `end`, idle timeout, deadline or budget). */
  done: Promise<{ result: VisualSessionResult; workspace: RunWorkspace }>;
  end(reason: string): Promise<void>;
}

const MAX_ACTIONS = 500;
const MAX_SCREENSHOTS = 200;
type Cmd = { token: string; cmd: "status" | "screenshot" | "click" | "scroll" | "end"; x?: number; y?: number; dx?: number; dy?: number };

export function pipePath(work: string, id: string): string {
  return process.platform === "win32" ? `\\\\.\\pipe\\navsentry-${id}` : join(work, "s.sock");
}

/** Refuses before any browser or request unless every precondition holds (S1, S2, S6). */
function preflight(o: SessionOptions, gate: ScopeGate): void {
  const m = o.manifest;
  if (m.profile !== "development") throw new SessionRefused("the visual driver is development only (environment local or dev)");
  if (!m.transports.visual_computer_use) throw new SessionRefused("transports.visual_computer_use must be true: the owner's consent that screenshots of the target are handed to the host agent (and its model provider)");
  for (const t of ["visual-computer-use", "playwright-browser"]) if (!m.transports.order.includes(t)) throw new SessionRefused(`transports.order must include ${t}; a flag never overrides manifest policy`);
  const d = gate.checkRequest(o.url, "GET");
  if (!d.allowed) throw new SessionRefused(`--url is outside the manifest scope: ${d.reason}; nothing was sent`);
  const p = (o.probe ?? probePlaywright)();
  if (!p.usable) throw new SessionRefused(`playwright engine unavailable: ${p.reason}`);
  assertAuthorizationWindow(m, o.now?.() ?? new Date());
}

export async function startSession(o: SessionOptions): Promise<SessionHandle> {
  const m = o.manifest;
  const env = o.env ?? process.env;
  const gate = new ScopeGate(m);
  preflight(o, gate);
  const { usable, secrets } = resolveActors(m, env);
  const actor = o.actor ?? "anonymous";
  const actorRt = usable.find((a) => a.name === actor);
  if (!actorRt) throw new SessionRefused(`actor ${actor} is not usable in this run`);

  const id = randomUUID();
  const ws = beginRun(o.projectDir, id, m.workspace.ignore);
  const screens = join(ws.work.path, "screens");
  mkdirSync(screens, { recursive: true, mode: 0o700 });
  const token = randomBytes(32).toString("hex");
  const pipe = pipePath(ws.work.path, id);

  const budget = new Budget(m.safety.max_requests, m.safety.max_requests_per_second, m.safety.max_duration_seconds * 1000, m.authorization.expires_at ? new Date(m.authorization.expires_at) : undefined);
  const bytes = new ByteBudget(m.capture.max_run_bytes, m.capture.max_wire_bytes);
  const redactor = new Redactor(secrets, m.targets.origins.map((x) => new URL(x).hostname.replace(/^\[|\]$/g, "")));
  const denials: VisualSessionResult["denials"] = [];
  const http = new DirectHttpAdapter(gate, budget, redactor, (url, method, reason) => denials.push({ url, method, reason }), { maxResponseBytes: m.capture.max_response_bytes, memoryBufferBytes: m.capture.memory_buffer_bytes, bytes });
  const exchanges: Exchange[] = [];
  const checks: CheckResult[] = [];
  const disabled = new Set(m.checks.disabled);
  const actions: VisualAction[] = [];
  const incomplete: string[] = [];
  let curIds: string[] = [];
  let budgetHit: string | undefined;

  const send = async (q: BrowserRequest): Promise<Exchange | undefined> => {
    if (budgetHit) return undefined;
    try {
      const ex = await http.send({ method: q.method as "GET", url: q.url, displayUrl: redactor.url(q.url), actor: q.actor, retainBytes: m.capture.max_response_bytes, headers: { ...q.headers, "x-navsentry-run": id } });
      exchanges.push(ex);
      curIds.push(ex.record.id);
      if (q.mainDocument && !ex.record.error) checks.push(...perExchange(ex, q.actor, q.url).filter((c) => !disabled.has(c.ruleId)));
      return ex;
    } catch (e) {
      if (e instanceof ScopeDenied) return undefined;
      if (e instanceof BudgetExceeded) { budgetHit = e.message; return undefined; }
      throw e;
    }
  };

  let engine: BrowserEngine;
  try {
    engine = await BrowserEngine.open({ send, onDenied: (url, method, reason) => denials.push({ url: redactor.url(url), method, reason }) }, new Map([[actor, actorRt.headers]]));
  } catch (e) {
    ws.dispose();
    endRun(ws, 0);
    throw new SessionRefused(`playwright engine failed to start: ${firstLine(e)}`);
  }

  const startedAt = new Date().toISOString();
  let ended = false;
  let endReason = "";
  let shots = 0;
  let resolveDone!: (v: { result: VisualSessionResult; workspace: RunWorkspace }) => void;
  const done = new Promise<{ result: VisualSessionResult; workspace: RunWorkspace }>((r) => { resolveDone = r; });

  /** Every action is serialized and logged before its result is returned; there is no unlogged path. */
  let chain = Promise.resolve();
  const run = <T>(fn: () => Promise<T>) => { const p = chain.then(fn); chain = p.then(() => undefined, () => undefined); return p; };
  const act = (action: VisualAction["action"], args: Partial<VisualAction>, fn: () => Promise<{ url: string } | { error: string }>) => run(async () => {
    if (ended) return { ok: false as const, error: "session ended" };
    if (actions.length >= MAX_ACTIONS) { void end("action limit reached"); return { ok: false as const, error: "action limit reached" }; }
    curIds = [];
    const r = await fn();
    const rec: VisualAction = { seq: actions.length + 1, at: new Date().toISOString(), action, ...args, requestIds: curIds, ...("error" in r ? { result: "error" as const, error: r.error } : { result: "ok" as const, url: redactor.url(r.url) }) };
    actions.push(rec);
    if (budgetHit) void end(`budget: ${budgetHit}`);
    return "error" in r ? { ok: false as const, error: r.error, seq: rec.seq } : { ok: true as const, url: rec.url!, seq: rec.seq, requests: curIds.length };
  });

  let idle: NodeJS.Timeout | undefined;
  const touch = () => { if (idle) clearTimeout(idle); idle = setTimeout(() => void end("idle timeout"), (o.idleSeconds ?? 300) * 1000); idle.unref(); };
  const deadline = setTimeout(() => void end("run deadline (safety.max_duration_seconds)"), m.safety.max_duration_seconds * 1000);
  deadline.unref();

  const server = net.createServer((sock) => {
    let buf = "";
    sock.setEncoding("utf8");
    sock.on("data", (chunk: string) => {
      buf += chunk;
      if (buf.length > 4096) { sock.destroy(); return; }
      const nl = buf.indexOf("\n");
      if (nl < 0) return;
      const line = buf.slice(0, nl);
      void handle(line).then((res) => sock.end(`${JSON.stringify(res)}\n`), () => sock.end(`${JSON.stringify({ ok: false, error: "internal error" })}\n`));
    });
    sock.on("error", () => undefined);
  });

  const handle = async (line: string): Promise<Record<string, unknown>> => {
    let c: Cmd;
    try { c = JSON.parse(line) as Cmd; } catch { return { ok: false, error: "bad request" }; }
    const a = Buffer.from(String(c.token ?? "")), b = Buffer.from(token);
    if (a.length !== b.length || !timingSafeEqual(a, b)) return { ok: false, error: "bad token" };
    touch();
    switch (c.cmd) {
      case "status": return { ok: true, id, actions: actions.length, requests: exchanges.length, denials: denials.length, viewport: VIEWPORT, ended };
      case "screenshot": {
        if (shots >= MAX_SCREENSHOTS) return { ok: false, error: "screenshot limit reached" };
        const path = join(screens, `${String(++shots).padStart(4, "0")}.png`);
        const r = await act("screenshot", {}, () => engine.screenshot(actor, path));
        return r.ok ? { ...r, path, viewport: VIEWPORT } : r;
      }
      case "click": return act("click", { x: c.x, y: c.y }, () => engine.clickAt(actor, Number(c.x), Number(c.y)));
      case "scroll": return act("scroll", { dx: c.dx, dy: c.dy }, () => engine.scroll(actor, Number(c.dx), Number(c.dy)));
      case "end": void end("ended by command"); return { ok: true, ending: true };
      default: return { ok: false, error: "unknown command" };
    }
  };

  const end = async (reason: string): Promise<void> => {
    if (ended) return;
    ended = true;
    endReason = reason;
    if (idle) clearTimeout(idle);
    clearTimeout(deadline);
    await chain;
    server.close();
    await engine.close();
    budget.close();
    if (budgetHit) incomplete.push(budgetHit);
    const findings = buildFindings(checks);
    const result: VisualSessionResult = {
      schemaVersion: 1, id, engine: "visual-driver/playwright-browser", actor, startUrl: redactor.url(o.url), startedAt, endedAt: new Date().toISOString(), endReason,
      viewport: VIEWPORT, screenshots: shots, actions, requests: exchanges.map((e) => e.record), denials, checks, findings, incompleteReasons: incomplete,
      executionStatus: budgetHit || endReason !== "ended by command" ? "PARTIAL" : "COMPLETE",
    };
    resolveDone({ result, workspace: ws });
  };

  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(pipe, () => resolve()); });
  // Published only once the pipe accepts connections, so a client never finds an unreachable session.
  writeFileSync(join(ws.work.path, "session.json"), JSON.stringify({ pipe, token, pid: process.pid }), { mode: 0o600 });
  touch();
  // The start page is the first logged action.
  await act("navigate", { url: redactor.url(o.url) }, async () => {
    const r = await engine.navigate(actor, o.url);
    return r.error && !curIds.length ? { error: r.error } : { url: o.url };
  });
  return { id, done, end };
}

/** Client side: one command over the session's local pipe. The token never leaves the machine. */
export function sendCommand(work: string, cmd: Omit<Cmd, "token">, timeoutMs = 30_000): Promise<Record<string, unknown>> {
  let info: { pipe: string; token: string };
  try { info = JSON.parse(readFileSync(join(work, "session.json"), "utf8")) as typeof info; } catch { return Promise.reject(new SessionRefused("no live session with this id")); }
  return new Promise((resolve, reject) => {
    const sock = net.connect(info.pipe);
    let buf = "";
    const t = setTimeout(() => { sock.destroy(); reject(new SessionRefused("session did not answer")); }, timeoutMs);
    sock.setEncoding("utf8");
    sock.on("connect", () => sock.write(`${JSON.stringify({ ...cmd, token: info.token })}\n`));
    sock.on("data", (c: string) => { buf += c; });
    sock.on("end", () => { clearTimeout(t); try { resolve(JSON.parse(buf) as Record<string, unknown>); } catch { reject(new SessionRefused("bad reply")); } });
    sock.on("error", (e) => { clearTimeout(t); reject(new SessionRefused(`session unreachable: ${e.message}`)); });
  });
}
