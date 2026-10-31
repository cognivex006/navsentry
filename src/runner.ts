/** Plan (zero network) and execute (observe mode) runs. */
import { createHash, randomUUID } from "node:crypto";
import { Budget, BudgetExceeded } from "./budget.js";
import { CASES, getCase } from "./catalog.js";
import * as P from "./checks/passive.js";
import { probeTls } from "./checks/tls.js";
import type { Manifest } from "./config.js";
import { Redactor } from "./redact.js";
import { ScopeGate } from "./scope.js";
import { DirectHttpAdapter, ScopeDenied } from "./transports/direct-http.js";
import { allAdapters } from "./transports/registry.js";
import type { Exchange } from "./transports/types.js";
import { TOOL_NAME, TOOL_VERSION, REPORT_SCHEMA_VERSION, type CheckResult, type CheckStatus, type CoverageRow, type Finding, type RunResult } from "./types.js";

/** Reserved, non-resolvable origin used to probe CORS reflection (RFC 2606 .invalid). */
export const CORS_PROBE_ORIGIN = "https://navsentry-cors-probe.invalid";
export const MAX_REDIRECTS = 5;

/** Rules whose evidence is pattern-based: FAIL becomes SUSPECTED until a human confirms semantics. */
const SUSPECT_ONLY = new Set(["NSC-INFO-003", "NSC-INFO-004", "NSC-PRIV-001", "NSC-PRIV-002"]);

export interface PlannedStep {
  kind: "http" | "tls";
  method: string;
  url: string;
  actor: string;
  transport: string;
  checks: string[];
  allowed: boolean;
  reason: string;
}

export interface Plan {
  project: string;
  mode: string;
  networkEffects: "none";
  steps: PlannedStep[];
  skippedCases: { id: string; automation: string; reason: string }[];
  actorsNotTested: { actor: string; reason: string }[];
  maxRequests: number;
}

const PER_EXCHANGE = ["NSC-CONF-001", "NSC-CONF-002", "NSC-CONF-003", "NSC-CONF-004", "NSC-CONF-007", "NSC-INFO-001", "NSC-ERR-001", "NSC-INFO-003", "NSC-INFO-004", "NSC-PRIV-001", "NSC-PRIV-002", "NSC-SESS-001", "NSC-SESS-002", "NSC-SESS-003", "NSC-SESS-004", "NSC-CRYPT-006"];

interface ActorRuntime {
  name: string;
  headers: Record<string, string>;
}

function resolveActors(m: Manifest, env: NodeJS.ProcessEnv): { usable: ActorRuntime[]; skipped: { actor: string; reason: string }[]; secrets: string[] } {
  const usable: ActorRuntime[] = [{ name: "anonymous", headers: {} }];
  const skipped: { actor: string; reason: string }[] = [];
  const secrets: string[] = [];
  for (const [name, a] of Object.entries(m.actors)) {
    if (name === "anonymous") continue;
    for (const k of [a.username_env, a.password_env, a.authorization_header_env]) if (k && env[k]) secrets.push(env[k] as string);
    if (a.authorization_header_env) {
      const v = env[a.authorization_header_env];
      if (v) usable.push({ name, headers: { authorization: v } });
      else skipped.push({ actor: name, reason: `env ${a.authorization_header_env} is not set` });
    } else {
      skipped.push({ actor: name, reason: "username/password login flows are scheduled for M2; provide authorization_header_env with a test token" });
    }
  }
  return { usable, skipped, secrets };
}

export function planRun(m: Manifest, env: NodeJS.ProcessEnv = {}): Plan {
  const gate = new ScopeGate(m);
  const { usable, skipped } = resolveActors(m, Object.fromEntries(Object.entries(env).map(([k, v]) => [k, v ? "set" : v])));
  const steps: PlannedStep[] = [];
  for (const origin of m.targets.origins) {
    if (origin.startsWith("https:") && !m.checks.disabled.includes("NSC-CRYPT-001")) {
      const d = gate.checkOrigin(origin);
      steps.push({ kind: "tls", method: "HANDSHAKE x4", url: origin, actor: "-", transport: "tls-probe", checks: ["NSC-CRYPT-001", "NSC-CRYPT-003"], ...decision(d) });
    }
    for (const path of m.targets.seed_paths) {
      const url = new URL(path, origin).toString();
      for (const actor of usable) {
        const d = gate.checkRequest(url, "GET");
        steps.push({ kind: "http", method: "GET", url, actor: actor.name, transport: "direct-http", checks: PER_EXCHANGE.filter((c) => !m.checks.disabled.includes(c)), ...decision(d) });
      }
      steps.push({ kind: "http", method: "GET +Origin", url, actor: "anonymous", transport: "direct-http", checks: ["NSC-AC-004"], ...decision(gate.checkRequest(url, "GET")) });
      steps.push({ kind: "http", method: "OPTIONS", url, actor: "anonymous", transport: "direct-http", checks: ["NSC-CONF-006"], ...decision(gate.checkRequest(url, "OPTIONS")) });
    }
  }
  const auto = new Set(steps.flatMap((s) => s.checks));
  const skippedCases = CASES.filter((c) => !auto.has(c.id)).map((c) => ({ id: c.id, automation: c.automation, reason: skipReason(c.automation, c.milestone, m.checks.disabled.includes(c.id)) }));
  return { project: m.project, mode: m.safety.mode, networkEffects: "none", steps, skippedCases, actorsNotTested: skipped, maxRequests: m.safety.max_requests };
}

function decision(d: { allowed: boolean; reason: string }) {
  return { allowed: d.allowed, reason: d.reason };
}

function skipReason(a: string, milestone: string | undefined, disabled: boolean): string {
  if (disabled) return "disabled by manifest checks.disabled";
  switch (a) {
    case "manual-active": return "requires active payloads; never automated without active-approved authorization";
    case "sast-only": return "source-code finding; use a SAST tool / DevSift";
    case "infra": return "network/host VA item outside web scope";
    case "assisted": return "evidence collection needs an operator/agent; see the case's agent prompt";
    case "planned-auto": return `deterministic check planned for ${milestone ?? "a later milestone"}`;
    default: return "not exercised by this run's targets";
  }
}

export interface ExecuteOptions {
  env?: NodeJS.ProcessEnv;
  now?: () => Date;
}

export async function executeRun(m: Manifest, opts: ExecuteOptions = {}): Promise<RunResult> {
  const env = opts.env ?? process.env;
  const startedAt = new Date().toISOString();
  const gate = new ScopeGate(m);
  const budget = new Budget(m.safety.max_requests, m.safety.max_requests_per_second, m.safety.max_duration_seconds * 1000);
  const { usable, skipped, secrets } = resolveActors(m, env);
  const redactor = new Redactor(secrets, m.targets.origins.map((o) => new URL(o).hostname.replace(/^\[|\]$/g, "")));
  const denials: RunResult["denials"] = [];
  const http = new DirectHttpAdapter(gate, budget, redactor, (url, method, reason) => denials.push({ url, method, reason }));
  const transports = await Promise.all(allAdapters().map((a) => a.probe()));
  const exchanges: Exchange[] = [];
  const checks: CheckResult[] = [];
  const incomplete: string[] = skipped.map((s) => `actor ${s.actor} not tested: ${s.reason}`);
  const disabled = new Set(m.checks.disabled);

  const send = async (method: "GET" | "OPTIONS", url: string, actor: ActorRuntime, extra: Record<string, string> = {}): Promise<Exchange | undefined> => {
    try {
      const ex = await http.send({ method, url, actor: actor.name, headers: { ...actor.headers, ...extra, "x-navsentry-run": runId } });
      exchanges.push(ex);
      return ex;
    } catch (e) {
      if (e instanceof ScopeDenied) return undefined;
      throw e;
    }
  };
  const runId = randomUUID();

  try {
    for (const origin of m.targets.origins) {
      if (origin.startsWith("https:") && !disabled.has("NSC-CRYPT-001")) {
        const tlsOut = await probeTls(gate, budget, origin);
        checks.push(...tlsOut.checks.filter((c) => !disabled.has(c.ruleId)));
      }
      for (const path of m.targets.seed_paths) {
        const seed = new URL(path, origin).toString();
        for (const actor of usable) {
          let url = seed;
          for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
            const ex = await send("GET", url, actor);
            if (!ex) break;
            if (ex.record.error) {
              const err = ex.record.error;
              checks.push(...PER_EXCHANGE.filter((id) => !disabled.has(id)).map((ruleId): CheckResult => ({ ruleId, status: "ERROR", target: `GET ${ex.record.url}`, transport: "direct-http", summary: "request failed", observations: [], requestIds: [ex.record.id], reason: err })));
              break;
            }
            checks.push(...perExchange(ex, actor.name, url).filter((c) => !disabled.has(c.ruleId)));
            const next = ex.raw?.redirectLocation;
            if (!next || !(ex.raw!.status >= 300 && ex.raw!.status < 400)) break;
            if (hop === MAX_REDIRECTS) { incomplete.push(`redirect chain from ${redactor.url(seed)} exceeded ${MAX_REDIRECTS} hops`); break; }
            // Redirect escape protection: re-check scope for every hop before following.
            const d = gate.checkRequest(next, "GET");
            if (!d.allowed) { denials.push({ url: redactor.url(next), method: "GET", reason: `redirect not followed: ${d.reason}` }); break; }
            url = next;
          }
        }
        const anon = usable[0]!;
        if (!disabled.has("NSC-AC-004")) {
          const ex = await send("GET", seed, anon, { origin: CORS_PROBE_ORIGIN });
          if (ex && !ex.record.error) checks.push(P.checkCors(ex, CORS_PROBE_ORIGIN));
        }
        if (!disabled.has("NSC-CONF-006")) {
          const ex = await send("OPTIONS", seed, anon);
          if (ex && !ex.record.error) checks.push(P.checkMethods(ex));
        }
      }
    }
  } catch (e) {
    if (e instanceof BudgetExceeded) incomplete.push(e.message);
    else incomplete.push(`run aborted: ${(e as Error).message}`);
  }

  for (const ex of exchanges) if (!ex.record.redaction.safe) incomplete.push(`evidence withheld for request ${ex.record.id} (${ex.record.redaction.kinds.join(",")})`);

  const coverage = buildCoverage(checks, disabled);
  const findings = buildFindings(checks);
  const hardFail = exchanges.length === 0 && m.targets.seed_paths.length > 0;
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: { name: TOOL_NAME, version: TOOL_VERSION, node: process.versions.node, platform: `${process.platform}-${process.arch}` },
    runId,
    startedAt,
    finishedAt: new Date().toISOString(),
    project: m.project,
    environment: m.environment,
    mode: m.safety.mode,
    scope: { origins: m.targets.origins, allowedPaths: m.targets.allowed_paths, deniedPaths: m.targets.denied_paths },
    executionStatus: hardFail ? "FAILED" : incomplete.length ? "PARTIAL" : "COMPLETE",
    incompleteReasons: [...new Set(incomplete)],
    transports,
    requests: exchanges.map((e) => e.record),
    checks,
    findings,
    coverage,
    budget: { requestsUsed: budget.requestsUsed, requestsMax: m.safety.max_requests, deniedBeforeExecution: denials.length },
    denials,
  };
}

function perExchange(ex: Exchange, actor: string, rawUrl: string): CheckResult[] {
  const ctx = { actor };
  return [
    P.checkHsts(ex), P.checkCsp(ex), P.checkFraming(ex), P.checkContentType(ex), P.checkCache(ex, ctx),
    P.checkVersionDisclosure(ex), P.checkErrorDisclosure(ex), P.checkInternalIp(ex), P.checkEmail(ex), P.checkPii(ex),
    P.checkSensitiveUrl(ex, rawUrl), ...P.checkCookies(ex), P.checkJwt(ex), P.checkHttpsRedirect(ex),
  ];
}

const RANK: Record<CheckStatus, number> = { FAIL: 5, ERROR: 4, INCONCLUSIVE: 3, PASS: 2, NOT_TESTED: 1 };

/** Aggregates over every catalog case. Missing evidence can never become PASS. */
export function buildCoverage(checks: CheckResult[], disabled: Set<string> = new Set()): CoverageRow[] {
  return CASES.map((c) => {
    const mine = checks.filter((r) => r.ruleId === c.id);
    if (!mine.length) return { ruleId: c.id, status: "NOT_TESTED", targets: 0, reason: skipReason(c.automation, c.milestone, disabled.has(c.id)) };
    const worst = mine.reduce((a, b) => (RANK[b.status] > RANK[a.status] ? b : a));
    const tested = mine.filter((r) => r.status !== "NOT_TESTED");
    return { ruleId: c.id, status: worst.status, targets: tested.length, ...(worst.reason ? { reason: worst.reason } : {}) };
  });
}

export function fingerprint(ruleId: string, target: string): string {
  const normalized = target.replace(/\?.*$/, "");
  return createHash("sha256").update(`${ruleId}\n${normalized}`).digest("hex").slice(0, 24);
}

export function buildFindings(checks: CheckResult[]): Finding[] {
  const byFp = new Map<string, Finding>();
  for (const r of checks.filter((x) => x.status === "FAIL")) {
    const c = getCase(r.ruleId);
    const fp = fingerprint(r.ruleId, r.target);
    const existing = byFp.get(fp);
    if (existing) {
      existing.requestIds.push(...r.requestIds);
      existing.actual = [...new Set([...existing.actual, ...r.observations])];
      continue;
    }
    const suspect = SUSPECT_ONLY.has(r.ruleId);
    byFp.set(fp, {
      fingerprint: fp,
      ruleId: r.ruleId,
      title: c.titleEn,
      category: c.category,
      severity: c.severity,
      confidence: suspect ? "medium" : "high",
      lifecycle: suspect ? "SUSPECTED" : "VALIDATED",
      priority: c.priority,
      target: r.target,
      expected: c.acceptance.join(" | "),
      actual: [r.summary, ...r.observations],
      reproduction: [`navsentry test --config <manifest>  (rule ${r.ruleId}, transport ${r.transport})`, ...c.webRecheck.slice(0, 1)],
      limitations: c.caveats ?? [],
      recommendation: c.fix,
      regressionGuard: c.regressionGuard,
      mappings: { owasp2021: c.owasp2021, owasp2025: c.owasp2025, cwe: c.cwe, wstg: c.wstg, asvs5Chapter: c.asvs5Chapter },
      requestIds: [...r.requestIds],
    });
  }
  const sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [...byFp.values()].sort((a, b) => sevRank[a.severity] - sevRank[b.severity] || a.ruleId.localeCompare(b.ruleId));
}
