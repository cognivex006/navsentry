/** Plan (zero network) and execute (observe mode) runs. */
import { createHash, randomUUID } from "node:crypto";
import { Budget, BudgetExceeded, ByteBudget } from "./budget.js";
import { CASES, getCase } from "./catalog.js";
import * as P from "./checks/passive.js";
import { probeTls } from "./checks/tls.js";
import { assertAuthorizationWindow, assertNoLiveTokens, type Manifest } from "./config.js";
import { Redactor } from "./redact.js";
import { ScopeGate } from "./scope.js";
import { DirectHttpAdapter, ScopeDenied } from "./transports/direct-http.js";
import { allAdapters } from "./transports/registry.js";
import type { Exchange } from "./transports/types.js";
import { functionalResult, runFlows } from "./flow/execute.js";
import { classify, flowSetHash } from "./flow/classify.js";
import { fillPath, flowOrigin, VAR_SENTINEL } from "./flow/lint.js";
import { UI_ACTIONS, type FlowDoc } from "./flow/parse.js";
import { groupKey, pathPattern, scanHtml, urlIdentity } from "./spider/html.js";
import { classifyRobots, robotsAllows, type RobotsPolicy } from "./spider/robots.js";
import { scanAssets } from "./assets/scan.js";
import { TOOL_NAME, TOOL_VERSION, REPORT_SCHEMA_VERSION, FLOW_RESULT_SCHEMA_VERSION, type CheckResult, type CheckStatus, type CoverageRow, type Finding, type FlowRunResult, type ClientFinding, type FlowStatus, type RedirectChain, type RunResult, type ScanMode, type SpiderResult, type TestLevel } from "./types.js";

/** Reserved, non-resolvable origin used to probe CORS reflection (RFC 2606 .invalid). */
export const CORS_PROBE_ORIGIN = "https://navsentry-cors-probe.invalid";
export const MAX_REDIRECTS = 5;

/** Rules whose evidence is pattern-based: FAIL becomes SUSPECTED until a human confirms semantics. */
/** Rules evaluated only from flow access expectations. */
const FLOW_RULES = new Set(["NSC-AC-002", "NSC-AC-003", "NSC-AC-007"]);
const SUSPECT_ONLY = new Set(["NSC-INFO-003", "NSC-INFO-004", "NSC-PRIV-001", "NSC-PRIV-002", "NSC-AC-008"]);
/** Security headers whose presence is compared across redirect hops. */
const HOP_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "set-cookie"];

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

export interface PlannedFlow {
  id: string;
  file: string;
  level: TestLevel;
  levelReasons: string[];
  executability: "full" | "partial" | "none";
  review: "draft" | "approved";
  steps: { id: string; action: string; actor: string; request?: string; allowed: boolean; reason: string; willRun: boolean }[];
}

export interface Plan {
  project: string;
  mode: string;
  networkEffects: "none";
  steps: PlannedStep[];
  skippedCases: { id: string; automation: string; reason: string }[];
  actorsNotTested: { actor: string; reason: string }[];
  maxRequests: number;
  flows?: PlannedFlow[];
  /** Upper bound: seed requests + flow steps (redirect hops not counted). */
  estimatedRequests?: number;
  warnings?: string[];
}

const PER_EXCHANGE = ["NSC-CONF-001", "NSC-CONF-002", "NSC-CONF-003", "NSC-CONF-004", "NSC-CONF-007", "NSC-INFO-001", "NSC-ERR-001", "NSC-INFO-003", "NSC-INFO-004", "NSC-PRIV-001", "NSC-PRIV-002", "NSC-SESS-001", "NSC-SESS-002", "NSC-SESS-003", "NSC-SESS-004", "NSC-CRYPT-006", "NSC-AC-008"];

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

export interface PlanOptions {
  flows?: FlowDoc[];
  flowsOnly?: boolean;
  warnings?: string[];
}

export function planRun(m: Manifest, env: NodeJS.ProcessEnv = {}, opts: PlanOptions = {}): Plan {
  const gate = new ScopeGate(m);
  const { usable, skipped } = resolveActors(m, Object.fromEntries(Object.entries(env).map(([k, v]) => [k, v ? "set" : v])));
  const steps: PlannedStep[] = [];
  for (const origin of m.targets.origins) {
    if (origin.startsWith("https:") && !m.checks.disabled.includes("NSC-CRYPT-001")) {
      const d = gate.checkOrigin(origin);
      steps.push({ kind: "tls", method: "HANDSHAKE x4", url: origin, actor: "-", transport: "tls-probe", checks: ["NSC-CRYPT-001", "NSC-CRYPT-003"], ...decision(d) });
    }
    for (const path of opts.flowsOnly ? [] : m.targets.seed_paths) {
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
  const plan: Plan = { project: m.project, mode: m.safety.mode, networkEffects: "none", steps, skippedCases, actorsNotTested: skipped, maxRequests: m.safety.max_requests };
  if (opts.flows) {
    const usableActors = new Set(usable.map((a) => a.name));
    plan.flows = opts.flows.map((d): PlannedFlow => {
      const c = classify(d);
      const origin = flowOrigin(d, m)!;
      return {
        id: d.header.id, file: d.file, level: c.level, levelReasons: c.levelReasons, executability: c.executability, review: d.header.review.status,
        steps: d.steps.map((s) => {
          if (UI_ACTIONS.has(s.action)) return { id: s.id, action: s.action, actor: s.actor, allowed: true, reason: "requires playwright-browser (M1b): NOT_TESTED", willRun: false };
          const dd = gate.checkRequest(new URL(fillPath(s.request!.path, () => VAR_SENTINEL), origin).toString(), s.request!.method);
          const actorOk = usableActors.has(s.actor);
          return { id: s.id, action: s.action, actor: s.actor, request: `${s.request!.method} ${s.request!.path}`, allowed: dd.allowed, reason: actorOk ? dd.reason : `actor ${s.actor} not usable`, willRun: dd.allowed && actorOk };
        }),
      };
    });
    plan.estimatedRequests = steps.filter((x) => x.kind === "http").length + plan.flows.reduce((a, f) => a + f.steps.filter((x) => x.willRun).length, 0);
    plan.warnings = [...(opts.warnings ?? [])];
    if (plan.estimatedRequests > m.safety.max_requests) plan.warnings.push(`estimated requests ${plan.estimatedRequests} exceed safety.max_requests ${m.safety.max_requests}`);
  }
  return plan;
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
    case "flow": return "needs a flow with an access expectation (docs/FLOWS.md)";
    default: return "not exercised by this run's targets";
  }
}

export interface ExecuteOptions {
  env?: NodeJS.ProcessEnv;
  now?: () => Date;
  /** Linted flows to replay after the seed phase. */
  flows?: FlowDoc[];
  flowsOnly?: boolean;
  /** 0.1.3: recorded in run.json beside the safety `mode`. */
  scanMode?: ScanMode;
  engine?: RunResult["engine"];
  /** Run ID chosen by the caller (it also names the work directory). */
  runId?: string;
  /** `scan --mode page --url`: absolute in-scope URLs fetched instead of the seed paths. */
  urls?: string[];
  /** `scan --mode spider`: template-aware crawl from the seed paths (SPEC-0.1.3 §6.2). */
  spider?: boolean;
  /** `scan --mode page|spider`: static asset scan over fetched pages (SPEC-0.1.3 §6.4-B). */
  assets?: boolean;
  /** Run work directory (spool) and facts-cache directory, both under `.navsentry/`. */
  workDir?: string;
  cacheDir?: string;
}

export async function executeRun(m: Manifest, opts: ExecuteOptions = {}): Promise<RunResult> {
  return (await executeTest(m, opts)).run;
}

/** Runs seeds and flows through one ScopeGate, Budget and Redactor. */
export async function executeTest(m: Manifest, opts: ExecuteOptions = {}): Promise<{ run: RunResult; flowRun?: FlowRunResult; clientFindings?: ClientFinding[] }> {
  const env = opts.env ?? process.env;
  // Production guards run before any network activity, for every entry point (SPEC-0.1.3 §3.1, S2).
  assertAuthorizationWindow(m, opts.now?.() ?? new Date());
  const startedAt = new Date().toISOString();
  const gate = new ScopeGate(m);
  const budget = new Budget(m.safety.max_requests, m.safety.max_requests_per_second, m.safety.max_duration_seconds * 1000, m.authorization.expires_at ? new Date(m.authorization.expires_at) : undefined);
  const bytes = new ByteBudget(m.capture.max_run_bytes, m.capture.max_wire_bytes);
  const { usable, skipped, secrets } = resolveActors(m, env);
  assertNoLiveTokens(m, secrets);
  for (const d of opts.flows ?? []) for (const v of Object.values(d.header.vars)) if ("env" in v && env[v.env]) secrets.push(env[v.env] as string);
  const redactor = new Redactor(secrets, m.targets.origins.map((o) => new URL(o).hostname.replace(/^\[|\]$/g, "")));
  const denials: RunResult["denials"] = [];
  const http = new DirectHttpAdapter(gate, budget, redactor, (url, method, reason) => denials.push({ url, method, reason }), { maxResponseBytes: m.capture.max_response_bytes, memoryBufferBytes: m.capture.memory_buffer_bytes, bytes });
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
  const runId = opts.runId ?? randomUUID();
  const chains: RedirectChain[] = [];

  /**
   * GETs a URL and follows redirects hop by hop (≤ MAX_REDIRECTS), re-checking scope for every hop.
   * Every hop runs the per-exchange checks; chains with at least one redirect are recorded (§4.2).
   */
  const finalUrlOf = new WeakMap<Exchange, string>();
  const findingsFor = (ids: Set<string>) => checks.some((c) => c.status === "FAIL" && c.requestIds.some((r) => ids.has(r)));
  const fetchChain = async (start: string, actor: ActorRuntime, runChecks = true): Promise<Exchange | undefined> => {
    let url = start;
    const chain: RedirectChain = { start: redactor.url(start), actor: actor.name, hops: [] };
    let last: Exchange | undefined;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const ex = await send("GET", url, actor);
      if (!ex) { if (chain.hops.length) chain.hops[chain.hops.length - 1]!.decision = "denied at request"; break; }
      last = ex;
      finalUrlOf.set(ex, url);
      if (ex.record.error) {
        const err = ex.record.error;
        if (runChecks) checks.push(...PER_EXCHANGE.filter((id) => !disabled.has(id)).map((ruleId): CheckResult => ({ ruleId, status: "ERROR", target: `GET ${ex.record.url}`, transport: "direct-http", summary: "request failed", observations: [], requestIds: [ex.record.id], reason: err })));
        break;
      }
      if (runChecks) checks.push(...perExchange(ex, actor.name, url).filter((c) => !disabled.has(c.ruleId)));
      const next = ex.raw?.redirectLocation;
      const isRedir = !!next && ex.raw!.status >= 300 && ex.raw!.status < 400;
      const headers = HOP_HEADERS.filter((h) => h in (ex.raw?.headers ?? {}));
      chain.hops.push({ url: ex.record.url, status: ex.raw!.status, securityHeaders: headers, decision: isRedir ? "followed" : "final", requestId: ex.record.id, ...(isRedir ? { location: redactor.url(next!) } : {}) });
      if (!isRedir) break;
      if (hop === MAX_REDIRECTS) { chain.hops[chain.hops.length - 1]!.decision = `not followed: more than ${MAX_REDIRECTS} redirects`; incomplete.push(`redirect chain from ${redactor.url(start)} exceeded ${MAX_REDIRECTS} hops`); break; }
      // Redirect escape protection: re-check scope for every hop before following.
      const d = gate.checkRequest(next!, "GET");
      if (!d.allowed) { chain.hops[chain.hops.length - 1]!.decision = `not followed: ${d.reason}`; denials.push({ url: redactor.url(next!), method: "GET", reason: `redirect not followed: ${d.reason}` }); break; }
      if (chain.hops.some((h) => h.url === redactor.url(next!))) { chain.hops[chain.hops.length - 1]!.decision = "not followed: redirect loop"; incomplete.push(`redirect loop from ${redactor.url(start)}`); break; }
      url = next!;
    }
    if (chain.hops.length > 1 || chain.hops[0]?.location) chains.push(chain);
    return last;
  };
  let spider: SpiderResult | undefined;
  let assets: RunResult["assets"];
  let clientFindings: ClientFinding[] | undefined;

  try {
    for (const origin of m.targets.origins) {
      if (origin.startsWith("https:") && !disabled.has("NSC-CRYPT-001")) {
        const tlsOut = await probeTls(gate, budget, origin);
        checks.push(...tlsOut.checks.filter((c) => !disabled.has(c.ruleId)));
      }
      const targets = opts.flowsOnly || opts.spider ? [] : opts.urls ? opts.urls.filter((u) => new URL(u).origin === origin) : m.targets.seed_paths.map((p) => new URL(p, origin).toString());
      for (const seed of targets) {
        for (const actor of usable) await fetchChain(seed, actor);
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
    if (opts.spider) {
      spider = { groups: [], skipped: [], skippedTotal: 0, robots: [], frontierOverflow: false, pagesFetched: 0 };
      await crawl(m, gate, usable, spider, fetchChain, (ex) => finalUrlOf.get(ex), findingsFor, incomplete, redactor);
    }
    if (opts.assets) {
      const out = await scanAssets({
        manifest: m, gate, redactor, pages: [...exchanges], actors: usable, literals: secrets, disabled,
        ...(opts.workDir ? { workDir: opts.workDir } : {}), ...(opts.cacheDir ? { cacheDir: opts.cacheDir } : {}), ...(opts.now ? { now: opts.now } : {}),
        send: async (spec) => {
          try {
            const ex = await http.send({ ...spec, headers: { ...spec.headers, "x-navsentry-run": runId } });
            exchanges.push(ex);
            return ex;
          } catch (e) {
            if (e instanceof ScopeDenied) return undefined;
            throw e;
          }
        },
      });
      checks.push(...out.checks);
      incomplete.push(...out.incomplete);
      assets = out.result;
      clientFindings = out.clientFindings;
    }
  } catch (e) {
    if (e instanceof BudgetExceeded) incomplete.push(e.message);
    else incomplete.push(`run aborted: ${(e as Error).message}`);
  }

  let flowOutcome: Awaited<ReturnType<typeof runFlows>> | undefined;
  if (opts.flows) {
    const actorSkipReasons = new Map(skipped.map((x) => [x.actor, x.reason]));
    try {
      flowOutcome = await runFlows(opts.flows, {
        manifest: m,
        gate,
        env,
        actors: new Map(usable.map((a) => [a.name, a.headers])),
        actorSkipReasons,
        onDenied: (url, method, reason) => denials.push({ url, method, reason }),
        displayUrl: (u) => redactor.url(u),
        securityChecks: (ex, actor, url) => perExchange(ex, actor, url).filter((c) => !disabled.has(c.ruleId)),
        send: async (q) => {
          try {
            const ex = await http.send({ method: q.method, url: q.url, displayUrl: q.displayUrl, actor: q.actor, flow: q.flow, headers: { ...q.headers, "x-navsentry-run": runId } });
            exchanges.push(ex);
            return ex;
          } catch (e) {
            if (e instanceof ScopeDenied) return undefined;
            throw e;
          }
        },
      });
      checks.push(...flowOutcome.checks.filter((c) => !disabled.has(c.ruleId)));
      incomplete.push(...flowOutcome.incomplete);
    } catch (e) {
      incomplete.push(`flow phase aborted: ${(e as Error).message}`);
    }
  }

  budget.close();
  for (const ex of exchanges) if (!ex.record.redaction.safe) incomplete.push(`evidence withheld for request ${ex.record.id} (${ex.record.redaction.kinds.join(",")})`);
  const cap = { wireBytes: bytes.wireBytes, decodedBytes: bytes.decodedBytes, truncated: 0, aborted: 0, partialBodies: 0 };
  for (const ex of exchanges) {
    const c = ex.record.capture;
    if (!c) continue;
    if (c.status === "truncated") { cap.truncated++; incomplete.push(`response ${ex.record.id} truncated: ${c.reason}`); }
    if (c.status === "aborted") { cap.aborted++; incomplete.push(`response ${ex.record.id} aborted: ${c.reason}`); }
    if (c.retainedBytes < c.decodedBytes) { cap.partialBodies++; incomplete.push(`response ${ex.record.id}: body checks covered the first ${c.retainedBytes} of ${c.decodedBytes} bytes`); }
    if (c.encoding) incomplete.push(`response ${ex.record.id}: content-encoding ${c.encoding} is not decoded; body checks are unsupported`);
  }

  const coverage = buildCoverage(checks, disabled);
  const findings = buildFindings(checks);
  const hardFail = exchanges.length === 0 && (opts.flowsOnly ? (opts.flows ?? []).some((d) => d.steps.some((s) => !UI_ACTIONS.has(s.action))) : m.targets.seed_paths.length > 0);
  const run: RunResult = {
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
    profile: m.profile,
    ...(opts.scanMode ? { scanMode: opts.scanMode } : {}),
    ...(opts.engine ? { engine: opts.engine } : {}),
    ...(m.profile === "production" && m.authorization.reference ? { authorizationReference: m.authorization.reference } : {}),
    capture: cap,
    ...(chains.length ? { redirectChains: chains } : {}),
    ...(spider ? { spider } : {}),
    ...(assets ? { assets } : {}),
  };
  if (!opts.flows || !flowOutcome) return { run, ...(clientFindings ? { clientFindings } : {}) };
  for (const f of flowOutcome.flows) {
    const ids = new Set(f.steps.flatMap((x) => x.requestIds));
    f.findings = findings.filter((x) => x.requestIds.some((id) => ids.has(id))).map((x) => x.fingerprint);
  }
  const zero = (): Record<FlowStatus, number> => ({ PASS: 0, FAIL: 0, INCOMPLETE: 0, ERROR: 0, NOT_TESTED: 0 });
  const summary: Record<TestLevel, Record<FlowStatus, number>> = { integration: zero(), e2e: zero() };
  for (const f of flowOutcome.flows) summary[f.level][f.status]++;
  const flowSet = { flows: opts.flows.length, steps: opts.flows.reduce((a, d) => a + d.steps.length, 0), sha256: flowSetHash(opts.flows) };
  run.flowSet = { ...flowSet, resultFile: "flows.json" };
  const flowRun: FlowRunResult = {
    kind: "navsentry-flow-result",
    schemaVersion: FLOW_RESULT_SCHEMA_VERSION,
    runId,
    tool: run.tool,
    startedAt,
    finishedAt: run.finishedAt,
    project: m.project,
    environment: m.environment,
    mode: m.safety.mode,
    flowSet,
    functionalResult: functionalResult(flowOutcome.flows),
    summary,
    flows: flowOutcome.flows,
  };
  return { run, flowRun };
}

function perExchange(ex: Exchange, actor: string, rawUrl: string): CheckResult[] {
  const ctx = { actor };
  return [
    P.checkHsts(ex), P.checkCsp(ex), P.checkFraming(ex), P.checkContentType(ex), P.checkCache(ex, ctx),
    P.checkVersionDisclosure(ex), P.checkErrorDisclosure(ex), P.checkInternalIp(ex), P.checkEmail(ex), P.checkPii(ex),
    P.checkSensitiveUrl(ex, rawUrl), ...P.checkCookies(ex), P.checkJwt(ex), P.checkHttpsRedirect(ex), ...P.checkOpenRedirect(ex, rawUrl),
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
      // A deterministic assertion on the same target upgrades a pattern-only finding.
      if (r.lifecycle === "VALIDATED" && r.basis !== "draft-flow" && !SUSPECT_ONLY.has(r.ruleId)) { existing.lifecycle = "VALIDATED"; existing.confidence = "high"; }
      continue;
    }
    const suspect = r.lifecycle === "SUSPECTED" || SUSPECT_ONLY.has(r.ruleId) || r.basis === "draft-flow";
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
      reproduction: [FLOW_RULES.has(r.ruleId) ? `navsentry test --config <manifest> --flows <flows-dir>  (rule ${r.ruleId}, ${r.observations.find((o) => o.startsWith("flow ")) ?? "flow step"})` : `navsentry test --config <manifest>  (rule ${r.ruleId}, transport ${r.transport})`, ...c.webRecheck.slice(0, 1)],
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

// ───────────────────────── Spider (SPEC-0.1.3 §6.2) ─────────────────────────

const SKIP_SAMPLE_CAP = 500;

interface Group {
  key: string;
  origin: string;
  actor: string;
  pattern: string;
  queryKeys: string[];
  fetched: { url: string; shape?: string; requestIds: string[] }[];
  pool: string[];
  sampledOut: number;
  spread: number;
}

/**
 * BFS from the seed paths up to safety.max_depth. Pages are grouped by (origin, actor, path pattern,
 * query-key set) before fetching; N representatives per group are fetched and the rest recorded as
 * `sampled-out`. A finding or a mixed shape leads to up to N more pages of that group (≤ 2N in all).
 * Links are queued only when the static ScopeGate allows them; the runtime check stays authoritative.
 * No forms are submitted and no parameters are changed.
 */
async function crawl(
  m: Manifest,
  gate: ScopeGate,
  actors: ActorRuntime[],
  out: SpiderResult,
  fetchChain: (url: string, actor: ActorRuntime, runChecks?: boolean) => Promise<Exchange | undefined>,
  finalUrl: (ex: Exchange) => string | undefined,
  hasFinding: (ids: Set<string>) => boolean,
  incomplete: string[],
  redactor: Redactor,
): Promise<void> {
  const n = m.safety.representatives_per_pattern;
  const finalUrlOf = finalUrl;
  const groups = new Map<string, Group>();
  let recorded = 0;
  const skip = (url: string, reason: string) => {
    out.skippedTotal++;
    if (out.skipped.length < SKIP_SAMPLE_CAP) out.skipped.push({ url: redactor.url(url), reason });
  };
  const robots = new Map<string, RobotsPolicy | "blocked" | "none">();
  for (const origin of m.targets.origins) {
    const ex = await fetchChain(new URL("/robots.txt", origin).toString(), actors[0]!, false).catch((e) => { if (e instanceof BudgetExceeded) throw e; return undefined; });
    const body = ex?.raw ? ex.raw.body.toString("utf8", 0, Math.min(ex.raw.body.length, 500 * 1024)) : "";
    const outcome = classifyRobots(ex?.raw && !ex.record.error ? ex.raw.status : undefined, ex?.raw?.headers["content-type"]?.[0] ?? "", body);
    const enforced = m.profile === "production";
    if (outcome.kind === "policy") {
      robots.set(origin, outcome.policy);
      out.robots.push({ origin, status: "policy", group: outcome.policy.group, rules: outcome.policy.rules.length, enforced });
    } else if (outcome.kind === "no-policy") {
      robots.set(origin, "none");
      out.robots.push({ origin, status: "no-policy", reason: outcome.reason, enforced });
    } else {
      robots.set(origin, enforced ? "blocked" : "none");
      out.robots.push({ origin, status: "unreachable", reason: outcome.reason, enforced });
      if (enforced) incomplete.push(`spider: robots.txt for ${origin} is unreachable (${outcome.reason}); crawling that origin is blocked in the production profile`);
    }
  }

  for (const actor of actors) {
    const seen = new Set<string>();
    const queue: { url: string; depth: number }[] = [];
    const offer = (raw: string, depth: number, from?: string): void => {
      let u: URL;
      try { u = new URL(raw, from); } catch { skip(raw.slice(0, 200), "unparseable link"); return; }
      if (!["http:", "https:"].includes(u.protocol)) { skip(`${u.protocol}…`, `${u.protocol.replace(":", "")} link (never followed)`); return; }
      const id = urlIdentity(u);
      if (seen.has(id)) return;
      seen.add(id);
      if (recorded >= m.safety.max_frontier) { out.frontierOverflow = true; return; }
      recorded++;
      const d = gate.checkRequest(id, "GET");
      if (!d.allowed) { skip(id, `out of scope: ${d.reason}`); return; }
      const pol = robots.get(u.origin);
      if (pol === "blocked") { skip(id, "robots: policy unreachable (production)"); return; }
      if (pol && pol !== "none" && !robotsAllows(pol, u.pathname + u.search)) {
        if (m.profile === "production") { skip(id, "robots: disallowed"); return; }
      }
      if (depth > m.safety.max_depth) { skip(id, "depth limit"); return; }
      const key = groupKey(u, actor.name);
      let g = groups.get(key);
      if (!g) {
        g = { key, origin: u.origin, actor: actor.name, pattern: pathPattern(u.pathname), queryKeys: [...new Set(u.searchParams.keys())].sort(), fetched: [], pool: [], sampledOut: 0, spread: 0 };
        groups.set(key, g);
      }
      if (g.fetched.length + queue.filter((q) => groupKey(new URL(q.url), actor.name) === key).length < n) queue.push({ url: id, depth });
      else { g.sampledOut++; if (g.pool.length < n) g.pool.push(id); skip(id, "sampled-out"); }
    };
    for (const p of m.targets.seed_paths) for (const o of m.targets.origins) offer(new URL(p, o).toString(), 0);
    while (queue.length) {
      if (out.pagesFetched >= m.safety.max_pages) { for (const q of queue.splice(0)) skip(q.url, "max_pages reached"); incomplete.push(`spider: safety.max_pages (${m.safety.max_pages}) reached`); break; }
      const { url, depth } = queue.shift()!;
      const g = groups.get(groupKey(new URL(url), actor.name))!;
      const ex = await fetchChain(url, actor);
      out.pagesFetched++;
      const page = visit(ex, g, url);
      if (page) for (const href of page.hrefs) offer(href, depth + 1, page.base);
    }
    // Spread: a finding or a mixed shape leads to up to N more pages of the same group (≤ 2N).
    for (const g of groups.values()) {
      if (g.actor !== actor.name) continue;
      const ids = new Set(g.fetched.flatMap((f) => f.requestIds));
      const mixed = new Set(g.fetched.map((f) => f.shape).filter(Boolean)).size > 1;
      if (!hasFinding(ids) && !mixed) continue;
      while (g.pool.length && g.fetched.length < 2 * n && out.pagesFetched < m.safety.max_pages) {
        const url = g.pool.shift()!;
        const ex = await fetchChain(url, actor);
        out.pagesFetched++;
        g.spread++;
        g.sampledOut--;
        out.skippedTotal--;
        const i = out.skipped.findIndex((x) => x.url === redactor.url(url) && x.reason === "sampled-out");
        if (i >= 0) out.skipped.splice(i, 1);
        visit(ex, g, url);
      }
    }
  }
  if (out.frontierOverflow) incomplete.push(`spider: frontier limit safety.max_frontier (${m.safety.max_frontier}) reached; further links were not recorded`);
  for (const g of groups.values()) {
    const shapes = [...new Set(g.fetched.map((f) => f.shape).filter((x): x is string => !!x))];
    out.groups.push({
      origin: g.origin, actor: g.actor, pattern: g.pattern, queryKeys: g.queryKeys,
      representatives: g.fetched.map((f) => redactor.url(f.url)), shapeHashes: shapes.map((h) => h.slice(0, 16)),
      mixedShape: shapes.length > 1, sampledOut: g.sampledOut, spread: g.spread,
      notTested: g.sampledOut ? [`${g.sampledOut} page(s) NOT_TESTED: sampled-out (never inherit a PASS)`] : [],
    });
  }
  const sampled = out.groups.reduce((a, g) => a + g.sampledOut, 0);
  if (sampled) incomplete.push(`spider: ${sampled} page(s) sampled-out and NOT_TESTED; coverage holds only for the fetched representatives`);

  function visit(ex: Exchange | undefined, g: Group, url: string): { hrefs: string[]; base?: string } | undefined {
    const entry: Group["fetched"][number] = { url, requestIds: ex ? [ex.record.id] : [] };
    g.fetched.push(entry);
    if (!ex?.raw || ex.record.error) return undefined;
    const ct = ex.raw.headers["content-type"]?.[0] ?? "";
    if (!/text\/html|application\/xhtml/i.test(ct)) return undefined;
    const scan = scanHtml(ex.raw.body.toString("utf8"));
    entry.shape = scan.shapeHash;
    if (scan.truncated) incomplete.push(`spider: tag limit reached on ${redactor.url(url)}; links and shape are partial`);
    // The final URL after redirects is the base for relative links.
    const finalUrl = finalUrlOf(ex) ?? url;
    let base = finalUrl;
    if (scan.base) { try { base = new URL(scan.base, finalUrl).toString(); } catch { /* keep the page URL */ } }
    return { hrefs: scan.hrefs, base };
  }
}
