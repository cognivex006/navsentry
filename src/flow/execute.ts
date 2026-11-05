/**
 * Flow replay (spec §8). This module performs no I/O of its own: every request goes
 * through the runner's `send` (ScopeGate → Budget → connect-time DNS check), and every
 * exchange is handed back to the runner's security checks.
 */
import { BudgetExceeded } from "../budget.js";
import { getCase } from "../catalog.js";
import type { Manifest } from "../config.js";
import { fillBody, RequestRefused, type FixtureLifecycle } from "../fixtures/lifecycle.js";
import { validMutationId, type ScopeGate } from "../scope.js";
import type { Exchange } from "../transports/types.js";
import type { AssertionResult, CheckResult, CheckStatus, FlowResult, FlowStatus, StepResult } from "../types.js";
import { evaluate, resolvePointer, worst } from "./assert.js";
import { classify, flowHash, requestTemplate, stepHash, stepTransport } from "./classify.js";
import { fillPath, flowOrigin, placeholders, topoOrder } from "./lint.js";
import { MUTATION_METHODS, UI_ACTIONS, type FlowDoc, type FlowStep, type UiTarget } from "./parse.js";

export const MAX_FLOW_REDIRECTS = 5;
/** NSC-AC-006 cross-site probe origin (SPEC-0.2.0 §5.2, owner decision D7): reserved, never resolvable. */
export const CSRF_PROBE_ORIGIN = "https://navsentry-csrf-probe.invalid";
/** Statuses that count as "rejected" for the CSRF and logout probes (§5.2, §5.3). */
const REJECTED = new Set([401, 403, 419, 422]);

/** Same media type and JSON shape: the response a legitimate caller gets. */
function sameContract(a: Exchange, b: Exchange): boolean {
  const c1 = a.record.contract, c2 = b.record.contract;
  return !!c1 && !!c2 && c1.contentType === c2.contentType && (c1.jsonShapeHash ?? "") === (c2.jsonShapeHash ?? "");
}

function cookieValue(header: string | undefined, name: string): string | undefined {
  for (const part of (header ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return undefined;
}

/** Flat JSON object → application/x-www-form-urlencoded; nested values are refused. */
function formBody(json: Buffer): { data?: Buffer; error?: string } {
  const o = JSON.parse(json.toString("utf8")) as Record<string, unknown>;
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(o)) {
    if (v !== null && typeof v === "object") return { error: "a form body takes flat string, number or boolean values" };
    q.set(k, v === null ? "" : String(v));
  }
  return { data: Buffer.from(q.toString(), "utf8") };
}
const SAFE_VALUE = /^[A-Za-z0-9._~-]{1,128}$/;
const ACCEPT = { json: "application/json", text: "text/plain, */*;q=0.1", any: "*/*", html: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8" } as const;

export interface FlowSendRequest {
  method: "GET" | "HEAD" | "OPTIONS";
  url: string;
  displayUrl: string;
  actor: string;
  headers: Record<string, string>;
  flow: { id: string; step: string; deniedProbe?: true };
}

export interface FlowContext {
  manifest: Manifest;
  gate: ScopeGate;
  /** Actor name → request headers; actors missing here are not usable in this run. */
  actors: Map<string, Record<string, string>>;
  actorSkipReasons: Map<string, string>;
  env: NodeJS.ProcessEnv;
  /** Returns undefined when ScopeGate denied the request (the denial is recorded by the runner). */
  send(req: FlowSendRequest): Promise<Exchange | undefined>;
  securityChecks(ex: Exchange, actor: string, url: string): CheckResult[];
  onDenied(url: string, method: string, reason: string): void;
  displayUrl(url: string): string;
  /** Present when the run uses the playwright engine (M1b); UI steps are NOT_TESTED without it. */
  browser?: FlowBrowser;
  /** safe-validate (SPEC-0.2.0): the run's fixture lifecycle and marker; absent in observe. */
  fixtures?: FixtureLifecycle;
  marker?: string;
}

/** Browser steps as the flow runner sees them; every request inside goes through `send`'s ScopeGate/Budget path. */
export interface FlowBrowser {
  /** Loads a page; `exchange` is the final main-document exchange (after redirects). */
  navigate(actor: string, url: string, flow: { id: string; step: string }): Promise<{ exchange?: Exchange; requestIds: string[]; error?: string }>;
  act(actor: string, action: "click" | "see" | "wait_for" | "fill" | "select" | "submit", target: UiTarget, flow: { id: string; step: string }, value?: string): Promise<{ ok: boolean; observed: string; requestIds: string[]; error?: string }>;
}

/** UI actions the observe-mode browser runs; the others may change state and wait for M2. */
export const BROWSER_ACTIONS: ReadonlySet<string> = new Set(["click", "see", "wait_for"]);
/** safe-validate (SPEC-0.2.0 §4.4): state-changing UI actions; their requests must still match a declared entry. */
export const STATEFUL_ACTIONS: ReadonlySet<string> = new Set(["fill", "select", "submit"]);

export interface FlowsOutcome {
  flows: FlowResult[];
  checks: CheckResult[];
  incomplete: string[];
}

interface StepRun {
  step: FlowStep;
  result: StepResult;
  exchange?: Exchange;
  pendingDenied: boolean;
}

export const securityCaseFor = (s: FlowStep): string => (s.actor === "anonymous" ? "NSC-AC-002" : s.object_owner ? "NSC-AC-003" : "NSC-AC-007");

function display(s: FlowStep): string | undefined {
  if (!s.request) return undefined;
  const q = Object.entries(s.request.query ?? {}).map(([k, v]) => `${k}=${v}`).join("&");
  return `${s.request.method} ${s.request.path}${q ? `?${q}` : ""}`;
}

function uiReason(s: FlowStep): string {
  const base = `${s.action} requires the playwright-browser transport (M1b), which is not usable in this release`;
  return s.action === "fill" || s.action === "submit" ? `${base}; may change state — requires safe-validate (M2)` : base;
}

/** Human checklist line for a step a person can replay manually. */
export function manualLine(s: FlowStep): string {
  const t = s.target;
  const what = !t ? "" : "role" in t ? `${t.role} “${t.name}”` : "label" in t ? `field “${t.label}”` : "text" in t ? `text “${t.text}”` : `element [data-testid=${t.test_id}]`;
  const verb = { click: "click", select: "select an option in", fill: "fill", submit: "submit", see: "check that you can see", wait_for: "wait until you can see", http: "request", navigate: "open", fixture_create: "create the declared fixture", logout: "log out, then repeat the read with the old session:" }[s.action];
  const value = s.value ? ` with the value of variable ${s.value.var} (not shown)` : "";
  return `${s.id} — as ${s.actor}: ${verb} ${what}${value}`;
}

export function flowStatus(steps: StepResult[]): FlowStatus {
  const st = steps.map((s) => s.status);
  if (st.includes("FAIL")) return "FAIL";
  if (st.includes("ERROR")) return "ERROR";
  if (st.every((s) => s === "NOT_TESTED")) return "NOT_TESTED";
  if (st.some((s) => s === "NOT_TESTED" || s === "INCONCLUSIVE")) return "INCOMPLETE";
  return "PASS";
}

interface ChainState {
  /** Dependency reason that makes every step NOT_TESTED. */
  blocked?: string;
  /** Imported values (already resolved from PASS steps of required flows). */
  imports: Map<string, string>;
  /** Out: variables this flow extracted in PASS steps. */
  exports: Map<string, string>;
}

async function runDoc(doc: FlowDoc, ctx: FlowContext, budget: { exhausted?: string }, checks: CheckResult[], chain: ChainState = { imports: new Map(), exports: new Map() }): Promise<FlowResult> {
  const origin = flowOrigin(doc, ctx.manifest)!;
  const cls = classify(doc);
  const approved = doc.header.review.status === "approved" && doc.header.review.content_sha256 === flowHash(doc);
  const vars = new Map<string, string>();
  const varMissing = new Map<string, string>();
  for (const [n, v] of Object.entries(doc.header.vars)) {
    if ("value" in v) vars.set(n, v.value);
    else if (ctx.env[v.env]) vars.set(n, ctx.env[v.env] as string);
    else varMissing.set(n, `env ${v.env} is not set`);
  }
  for (const [n, v] of chain.imports) vars.set(n, v);
  const runs: StepRun[] = [];
  const byId = new Map<string, StepRun>();

  for (const s of doc.steps) {
    const res: StepResult = { id: s.id, key: `${doc.header.id}/${s.id}`, title: s.title, action: s.action, actor: s.actor, contentSha256: stepHash(s), status: "NOT_TESTED", assertions: [], requestIds: [] };
    const req = display(s);
    if (req) res.request = req;
    if (s.expect?.access === "denied") res.securityCase = securityCaseFor(s);
    const run: StepRun = { step: s, result: res, pendingDenied: false };
    runs.push(run);
    byId.set(s.id, run);
    const skip = (reason: string) => { res.reason = reason; };

    if (chain.blocked) { skip(chain.blocked); continue; }
    const runnable = ctx.browser && (BROWSER_ACTIONS.has(s.action) || (ctx.fixtures && STATEFUL_ACTIONS.has(s.action)));
    if (UI_ACTIONS.has(s.action) && !runnable) { skip(ctx.browser ? `${s.action} may change state — requires safe-validate (M2)` : uiReason(s)); continue; }
    if (budget.exhausted) { skip("budget exhausted"); continue; }
    const actorHeaders = ctx.actors.get(s.actor);
    if (!actorHeaders) { skip(`actor ${s.actor} not tested: ${ctx.actorSkipReasons.get(s.actor) ?? "not usable"}`); continue; }
    const dep = (s.depends_on ?? []).find((d) => byId.get(d)?.result.status !== "PASS");
    if (dep) { skip(`dependency ${dep} did not pass`); continue; }
    if (s.action === "fixture_create") {
      if (!ctx.fixtures) { skip("fixture_create needs safety.mode safe-validate with declared fixtures"); continue; }
      const o = await ctx.fixtures.create(s.fixture!, s.actor, { id: doc.header.id, step: s.id }, approved);
      res.requestIds.push(...o.requestIds);
      res.status = o.status;
      if (o.reason) res.reason = o.reason;
      if (o.status !== "NOT_TESTED") res.assertions = [{ kind: "fixture", status: o.status, expected: "created, id valid, exists", observed: o.status === "PASS" ? "created and exists" : (o.reason ?? o.status) }];
      if (o.status === "PASS" && o.id) { vars.set(s.as!, o.id); chain.exports.set(s.as!, o.id); }
      continue;
    }
    if (ctx.browser && UI_ACTIONS.has(s.action)) {
      try {
        let value: string | undefined;
        if (s.value) {
          value = s.value.var === "marker" && ctx.marker ? ctx.marker : vars.get(s.value.var);
          if (value === undefined) { skip(varMissing.get(s.value.var) ?? `variable ${s.value.var} has no value`); continue; }
        }
        const a = await ctx.browser.act(s.actor, s.action as "click", s.target!, { id: doc.header.id, step: s.id }, value);
        res.requestIds.push(...a.requestIds);
        const expected = s.action === "click" ? "element clicked" : s.action === "fill" ? "field filled" : s.action === "select" ? "option selected" : s.action === "submit" ? "form submitted" : "element visible";
        res.assertions = [{ kind: "ui", status: a.error ? "ERROR" : a.ok ? "PASS" : "FAIL", expected, observed: a.observed }];
        res.status = res.assertions[0]!.status;
        if (a.error) res.reason = a.error;
      } catch (e) {
        if (e instanceof BudgetExceeded) { budget.exhausted = e.message; skip("budget exhausted"); continue; }
        throw e;
      }
      continue;
    }
    const missing = placeholders(s).find((v) => !vars.has(v));
    if (missing) {
      const producer = runs.find((r) => r.step.extract && missing in r.step.extract);
      skip(varMissing.get(missing) ?? (producer ? `dependency ${producer.step.id} did not pass` : `variable ${missing} has no value`));
      continue;
    }
    const unsafe = placeholders(s).find((v) => !SAFE_VALUE.test(vars.get(v)!) || vars.get(v) === "." || vars.get(v) === "..");
    if (unsafe) { res.status = "ERROR"; res.reason = `variable ${unsafe} value rejected by safety rule`; continue; }

    const r = s.request!;
    const u = new URL(fillPath(r.path, (n) => vars.get(n)!), origin);
    const du = new URL(r.path, origin);
    for (const [k, v] of Object.entries(r.query ?? {})) {
      const ph = v.match(/^\{\{(\w+)\}\}$/);
      u.searchParams.set(k, ph ? vars.get(ph[1] as string)! : v);
      du.searchParams.set(k, v);
    }
    if (s.action === "logout") {
      // NSC-AUTH-002 (SPEC-0.2.0 §5.3): an authenticated read, logout, then the same read with the pre-logout session.
      res.securityCase = "NSC-AUTH-002";
      const entry = ctx.manifest.auth_endpoints.logout;
      if (!ctx.fixtures || !entry) { skip("logout needs safe-validate and auth_endpoints.logout"); continue; }
      const target = `${r.method} ${du.toString()}`;
      const flowRef = { id: doc.header.id, step: s.id };
      const read = () => ctx.send({ method: r.method as FlowSendRequest["method"], url: u.toString(), displayUrl: du.toString(), actor: s.actor, headers: { ...actorHeaders, accept: ACCEPT[(r.accept as keyof typeof ACCEPT) ?? "any"] ?? ACCEPT.any, "x-navsentry-flow": `${doc.header.id}/${s.id}` }, flow: flowRef });
      const report = (status: CheckStatus, summary: string, observation: string) => checks.push({ ruleId: "NSC-AUTH-002", status, target, transport: "direct-http", summary, observations: [observation, `flow ${doc.header.id} step ${s.id}`], requestIds: [...res.requestIds], ...(status === "INCONCLUSIVE" ? { reason: observation } : {}), ...(approved ? {} : { basis: "draft-flow" as const }) });
      try {
        const before = await read();
        if (!before) { skip("denied by scope (see run.json denials)"); continue; }
        res.requestIds.push(before.record.id);
        const bs = before.raw?.status ?? 0;
        if (bs < 200 || bs >= 300) { res.status = "INCONCLUSIVE"; res.reason = `the authenticated read returned ${bs}; no positive control`; report("INCONCLUSIVE", "session after logout inconclusive", res.reason); continue; }
        const lurl = new URL(entry.path, origin).toString();
        const out = await ctx.fixtures.sendDeclared("auth_endpoints.logout", entry, { method: entry.method, url: lurl, displayUrl: lurl, actor: s.actor, headers: { ...actorHeaders, accept: "application/json" }, flow: flowRef });
        res.requestIds.push(out.record.id);
        // The actor is logged out from here on; later steps for it are NOT_TESTED.
        ctx.actors.delete(s.actor);
        ctx.actorSkipReasons.set(s.actor, `logged out in flow ${doc.header.id} step ${s.id}`);
        const ls = out.raw?.status ?? 0;
        if (ls < 200 || ls >= 400) { res.status = "INCONCLUSIVE"; res.reason = `logout returned ${ls || out.record.error}`; report("INCONCLUSIVE", "session after logout inconclusive", res.reason); continue; }
        const after = await read();
        if (!after) { skip("denied by scope (see run.json denials)"); continue; }
        res.requestIds.push(after.record.id);
        const as = after.raw?.status ?? 0;
        const toLogin = !!doc.header.login_path && as >= 300 && as < 400 && !!after.raw?.redirectLocation && new URL(after.raw.redirectLocation, origin).pathname === doc.header.login_path;
        let a: AssertionResult;
        if (as === 401 || as === 403 || toLogin) a = { kind: "access", status: "PASS", expected: "pre-logout session rejected", observed: toLogin ? `redirect to ${doc.header.login_path}` : `status ${as}` };
        else if (as >= 200 && as < 300) a = sameContract(after, before) ? { kind: "access", status: "FAIL", expected: "pre-logout session rejected", observed: `status ${as}, same contract as before logout` } : { kind: "access", status: "INCONCLUSIVE", expected: "pre-logout session rejected", observed: `status ${as} with a different contract than before logout` };
        else a = { kind: "access", status: "INCONCLUSIVE", expected: "pre-logout session rejected", observed: `status ${as}` };
        res.assertions = [{ kind: "status", status: "PASS", expected: "authenticated read 2xx before logout", observed: `status ${bs}` }, a];
        res.status = worst(res.assertions.map((x) => x.status));
        report(a.status, a.status === "FAIL" ? `${getCase("NSC-AUTH-002").titleEn}: the pre-logout session still works` : a.status === "PASS" ? "pre-logout session rejected after logout" : "session after logout inconclusive", a.observed);
      } catch (e) {
        if (e instanceof BudgetExceeded) { skip(e.message); continue; }
        if (e instanceof RequestRefused) { skip("denied by scope (see run.json denials)"); continue; }
        throw e;
      }
      continue;
    }
    if (ctx.browser && s.action === "navigate") {
      try {
        const nav = await ctx.browser.navigate(s.actor, u.toString(), { id: doc.header.id, step: s.id });
        res.requestIds.push(...nav.requestIds);
        if (!nav.exchange) { if (nav.error) { res.status = "ERROR"; res.reason = nav.error; } else skip("denied by scope (see run.json denials)"); continue; }
        run.exchange = nav.exchange;
        res.assertions = evaluate(s.expect ?? {}, nav.exchange, origin);
        run.pendingDenied = s.expect?.access === "denied";
        res.status = run.pendingDenied ? "PASS" : worst(res.assertions.map((a) => a.status));
      } catch (e) {
        if (e instanceof BudgetExceeded) { budget.exhausted = e.message; skip("budget exhausted"); continue; }
        throw e;
      }
      continue;
    }
    const accept = s.action === "navigate" ? ACCEPT.html : ACCEPT[(r.accept as keyof typeof ACCEPT) ?? "any"] ?? ACCEPT.any;
    let ex: Exchange | undefined;
    if (MUTATION_METHODS.has(r.method)) {
      // safe-validate mutation (SPEC-0.2.0 §4.1): one declared entry, validated ids, JSON body, no redirects.
      if (!ctx.fixtures) { skip(`${r.method} needs safety.mode safe-validate with declared fixtures`); continue; }
      const fx = ctx.manifest.fixtures[s.fixture ?? ""];
      const tpl = r.path.split("/").map((seg) => (/^\{\{\w+\}\}$/.test(seg) ? "{{id}}" : seg)).join("/");
      const entry = fx?.allowed_mutations.find((e) => e.method === r.method && e.path === tpl);
      if (!entry) { res.status = "ERROR"; res.reason = `${r.method} ${tpl} matches no allowed_mutations entry of fixture ${s.fixture}`; continue; }
      const badId = placeholders(s).find((v) => !validMutationId(vars.get(v)));
      if (badId) { res.status = "ERROR"; res.reason = `variable ${badId} rejected by the safe-validate id rule`; continue; }
      let body: Buffer | undefined;
      if (r.body) {
        const filled = fillBody(r.body.json, (n) => (n === "marker" ? ctx.marker : vars.get(n)));
        const b = filled.data && entry.content_type === "application/x-www-form-urlencoded" ? formBody(filled.data) : filled;
        if (b.error) { res.status = "ERROR"; res.reason = b.error; continue; }
        if (b.data!.length > (entry.max_body_bytes ?? 4096)) { res.status = "ERROR"; res.reason = `body exceeds max_body_bytes (${entry.max_body_bytes})`; continue; }
        body = b.data;
      }
      const contentType = entry.content_type ?? "application/json";
      if (s.check === "csrf") {
        // NSC-AC-006 (SPEC-0.2.0 §5.2). The two probes run before the control, because the control may change the object.
        res.securityCase = "NSC-AC-006";
        const target = `${r.method} ${du.toString()}`;
        const report = (status: CheckStatus, summary: string, observations: string[], ids: string[]) => {
          checks.push({ ruleId: "NSC-AC-006", status, target, transport: "direct-http", summary, observations: [...observations, `flow ${doc.header.id} step ${s.id}`], requestIds: ids, ...(status === "INCONCLUSIVE" || status === "NOT_TESTED" ? { reason: observations[0] ?? summary } : {}), ...(approved ? {} : { basis: "draft-flow" as const }) });
        };
        const cfg = entry.csrf;
        if (!cfg) { res.status = "ERROR"; res.reason = "check csrf needs an allowed_mutations entry with csrf"; continue; }
        if (!actorHeaders.cookie || actorHeaders.authorization) { skip("CSRF needs a cookie session"); report("NOT_TESTED", "CSRF not tested", ["CSRF needs a cookie session (login or cookie_env actor)"], []); continue; }
        const token = cookieValue(actorHeaders.cookie, cfg.token_from.cookie);
        if (!token) { res.status = "INCONCLUSIVE"; res.reason = `no ${cfg.token_from.cookie} cookie in the session`; report("INCONCLUSIVE", "CSRF token not available", [res.reason], []); continue; }
        const base = { ...actorHeaders, accept, "x-navsentry-flow": `${doc.header.id}/${s.id}` };
        const flowRef = { id: doc.header.id, step: s.id };
        const sent: Exchange[] = [];
        try {
          for (const h of <Record<string, string>[]>[{ origin, referer: `${origin}/` }, { [cfg.send_as.header]: token, origin: CSRF_PROBE_ORIGIN }, { [cfg.send_as.header]: token, origin, referer: `${origin}/` }]) {
            const x = await ctx.fixtures.mutate(s.fixture!, entry, u.toString(), du.toString(), s.actor, { ...base, ...h }, body, flowRef, contentType);
            res.requestIds.push(x.record.id);
            sent.push(x);
          }
        } catch (e) {
          if (e instanceof BudgetExceeded || e instanceof RequestRefused) { skip(e instanceof RequestRefused ? "denied by scope (see run.json denials)" : e.message); report("NOT_TESTED", "CSRF probes not completed", [res.reason ?? "not completed"], res.requestIds); continue; }
          throw e;
        }
        const [noToken, foreign, control] = sent as [Exchange, Exchange, Exchange];
        const st = (x: Exchange) => x.raw?.status ?? 0;
        const toLogin = (x: Exchange) => !!doc.header.login_path && st(x) >= 300 && st(x) < 400 && !!x.raw?.redirectLocation && new URL(x.raw.redirectLocation, origin).pathname === doc.header.login_path;
        const controlOk = st(control) >= 200 && st(control) < 300;
        const judge = (name: string, x: Exchange): AssertionResult => {
          if (REJECTED.has(st(x)) || toLogin(x)) return { kind: "access", status: "PASS", expected: `${name} rejected`, observed: `status ${st(x)}` };
          if (st(x) >= 200 && st(x) < 300) {
            if (!controlOk) return { kind: "access", status: "INCONCLUSIVE", expected: `${name} rejected`, observed: `status ${st(x)}; the same-origin control did not succeed (${st(control)})` };
            return sameContract(x, control) ? { kind: "access", status: "FAIL", expected: `${name} rejected`, observed: `status ${st(x)}, same contract as the same-origin control` } : { kind: "access", status: "INCONCLUSIVE", expected: `${name} rejected`, observed: `status ${st(x)} with a different contract than the control` };
          }
          return { kind: "access", status: "INCONCLUSIVE", expected: `${name} rejected`, observed: `status ${st(x)}` };
        };
        const a1 = judge("request without the token", noToken), a2 = judge(`request from ${CSRF_PROBE_ORIGIN}`, foreign);
        const ctl: AssertionResult = { kind: "access", status: controlOk ? "PASS" : "INCONCLUSIVE", expected: "same-origin request with the token succeeds", observed: `status ${st(control)}` };
        res.assertions = [a1, a2, ctl];
        res.status = worst(res.assertions.map((a) => a.status));
        const overall = worst([a1.status, a2.status, ...(controlOk ? [] : ["INCONCLUSIVE" as const])]);
        report(overall, overall === "FAIL" ? `${getCase("NSC-AC-006").titleEn}: a cross-site or token-less request was accepted` : overall === "PASS" ? "cross-site and token-less requests rejected" : "CSRF result inconclusive", [a1.observed, a2.observed, ctl.observed], res.requestIds);
        continue;
      }
      try {
        ex = await ctx.fixtures.mutate(s.fixture!, entry, u.toString(), du.toString(), s.actor, { ...actorHeaders, accept, "x-navsentry-flow": `${doc.header.id}/${s.id}` }, body, { id: doc.header.id, step: s.id, ...(s.expect?.access === "denied" ? { deniedProbe: true as const } : {}) }, contentType);
        res.requestIds.push(ex.record.id);
        if (!ex.record.error) checks.push(...ctx.securityChecks(ex, s.actor, u.toString()));
      } catch (e) {
        if (e instanceof BudgetExceeded) { skip(e.message); if (!e.message.startsWith("stopped") && !e.message.startsWith("mutation limit")) budget.exhausted = e.message; continue; }
        if (e instanceof RequestRefused) { skip("denied by scope (see run.json denials)"); continue; }
        throw e;
      }
    } else try {
      let url = u.toString();
      let shown = du.toString();
      for (let hop = 0; ; hop++) {
        ex = await ctx.send({ method: r.method as FlowSendRequest["method"], url, displayUrl: shown, actor: s.actor, headers: { ...actorHeaders, accept, "x-navsentry-flow": `${doc.header.id}/${s.id}` }, flow: { id: doc.header.id, step: s.id, ...(s.expect?.access === "denied" ? { deniedProbe: true as const } : {}) } });
        if (!ex) break;
        res.requestIds.push(ex.record.id);
        if (ex.record.error) break;
        checks.push(...ctx.securityChecks(ex, s.actor, url));
        const next = ex.raw?.redirectLocation;
        if (!s.follow_redirects || !next || !(ex.raw!.status >= 300 && ex.raw!.status < 400)) break;
        if (hop >= MAX_FLOW_REDIRECTS) { res.status = "ERROR"; res.reason = `redirect chain exceeded ${MAX_FLOW_REDIRECTS} hops`; ex = undefined; break; }
        const d = ctx.gate.checkRequest(next, r.method);
        if (!d.allowed) { ctx.onDenied(ctx.displayUrl(next), r.method, `redirect not followed: ${d.reason}`); res.reason = `redirect not followed: ${d.reason}`; ex = undefined; break; }
        url = next;
        shown = next;
      }
    } catch (e) {
      if (e instanceof BudgetExceeded) { budget.exhausted = e.message; skip("budget exhausted"); continue; }
      throw e;
    }
    if (res.status === "ERROR" || res.reason?.startsWith("redirect not followed")) continue;
    if (!ex) { skip("denied by scope (see run.json denials)"); continue; }
    if (ex.record.error) { res.status = "ERROR"; res.reason = ex.record.error; continue; }
    run.exchange = ex;
    res.assertions = evaluate(s.expect ?? {}, ex, origin);
    run.pendingDenied = s.expect?.access === "denied";
    res.status = run.pendingDenied ? "PASS" : worst(res.assertions.map((a) => a.status));
    if (!run.pendingDenied && res.status === "PASS") {
      for (const [name, x] of Object.entries(s.extract ?? {})) {
        let v: unknown;
        if (x.from === "json") {
          try {
            v = resolvePointer(JSON.parse(ex.raw!.body.toString("utf8")), x.pointer).value;
          } catch {
            v = undefined;
          }
        } else v = ex.raw!.headers[x.name]?.[0];
        if (typeof v === "string" || (typeof v === "number" && Number.isFinite(v))) { vars.set(name, String(v)); chain.exports.set(name, String(v)); }
      }
    }
  }

  // Post-pass: denied expectations need an executed, passing positive control.
  for (const run of runs.filter((x) => x.pendingDenied)) {
    const s = run.step;
    const ex = run.exchange!;
    const status = ex.raw!.status;
    const deny = s.expect!.deny_status ?? [401, 403];
    const tpl = requestTemplate(s);
    const control = runs.find((o) => o !== run && o.step.actor !== s.actor && o.step.expect?.access === "allowed" && requestTemplate(o.step) === tpl && o.result.status === "PASS" && o.exchange);
    let a: AssertionResult;
    let observation = "";
    const loginRedirect = doc.header.login_path && status >= 300 && status < 400 && ex.raw!.redirectLocation && new URL(ex.raw!.redirectLocation).origin === origin && new URL(ex.raw!.redirectLocation).pathname === doc.header.login_path;
    if (deny.includes(status)) a = { kind: "access", status: "PASS", expected: `denied (${deny.join("|")})`, observed: `status ${status}` };
    else if (loginRedirect) a = { kind: "access", status: "PASS", expected: "denied", observed: `redirect to ${doc.header.login_path}` };
    else if (status >= 200 && status < 300) {
      if (!control) a = { kind: "access", status: "INCONCLUSIVE", expected: "denied", observed: `status ${status}; no executed positive control` };
      else {
        const c1 = control.exchange!.record.contract, c2 = ex.record.contract;
        const same = !!c1 && !!c2 && c1.contentType === c2.contentType && (c1.jsonShapeHash ?? "") === (c2.jsonShapeHash ?? "");
        if (same) {
          observation = `actor ${s.actor} received ${status} ${c2!.contentType || "no media type"} with the same response contract as positive control ${control.step.id} (${control.step.actor})`;
          a = { kind: "access", status: "FAIL", expected: "denied", observed: `status ${status}, same contract as positive control ${control.step.id}` };
        } else a = { kind: "access", status: "INCONCLUSIVE", expected: "denied", observed: `status ${status} with a different contract than the positive control (soft-denial page?)` };
      }
    } else a = { kind: "access", status: "INCONCLUSIVE", expected: "denied", observed: `status ${status}` };
    const others = evaluate({ ...s.expect!, access: undefined }, ex, origin);
    run.result.assertions = [...others, a];
    run.result.status = worst(run.result.assertions.map((x) => x.status));
    const ruleId = run.result.securityCase!;
    checks.push({
      ruleId,
      status: a.status,
      target: `${ex.record.method} ${ex.record.url}`,
      transport: ex.record.transport,
      summary: a.status === "FAIL" ? `${getCase(ruleId).titleEn}: access was granted` : a.status === "PASS" ? "access denied as expected" : "access expectation inconclusive",
      observations: observation ? [observation, `flow ${doc.header.id} step ${s.id}`] : [a.observed, `flow ${doc.header.id} step ${s.id}`],
      requestIds: [...run.result.requestIds, ...(control ? control.result.requestIds : [])],
      ...(a.status === "INCONCLUSIVE" ? { reason: a.observed } : {}),
      ...(approved ? {} : { basis: "draft-flow" as const }),
    });
  }

  const steps = runs.map((x) => x.result);
  for (const st of steps) if (st.status === "NOT_TESTED" && !st.reason) st.reason = "not executed";
  // A value extracted by a step that later failed its denied post-pass is not exported.
  for (const r of runs) if (r.result.status !== "PASS") for (const n of Object.keys(r.step.extract ?? {})) chain.exports.delete(n);
  const status = chain.blocked ? "NOT_TESTED" : flowStatus(steps);
  const reasons = [...new Set(steps.filter((x) => x.status !== "PASS").map((x) => `${x.id} ${x.status}${x.reason ? `: ${x.reason}` : ""}`))];
  return {
    id: doc.header.id,
    title: doc.header.title,
    story: doc.header.story,
    file: doc.file,
    declaredLevel: doc.header.level,
    level: cls.level,
    levelReasons: cls.levelReasons,
    executability: cls.executability,
    review: { status: doc.header.review.status, ...(doc.header.review.approved_by ? { approvedBy: doc.header.review.approved_by } : {}), ...(doc.header.review.approved_at ? { approvedAt: doc.header.review.approved_at } : {}), hashValid: approved },
    contentSha256: flowHash(doc),
    status,
    reasons,
    steps,
    findings: [],
    manualReplay: doc.steps.filter((s) => stepTransport(s) !== "direct-http").map(manualLine),
  };
}

/**
 * Executes flows in dependency order (ties by id); each selected flow runs once, so a shared
 * dependency in a diamond runs once under the one run Budget. A dependent of a flow that is not PASS
 * is NOT_TESTED with "dependency <id> is <status>", never FAIL or PASS (SPEC-0.1.3 §5.5).
 */
/** `extraImports`: per-flow values that are not exported by any flow (login credentials for login flows, kept in memory). */
export async function runFlows(docs: FlowDoc[], ctx: FlowContext, extraImports: Map<string, Map<string, string>> = new Map()): Promise<FlowsOutcome> {
  const checks: CheckResult[] = [];
  const budget: { exhausted?: string } = {};
  const flows: FlowResult[] = [];
  const done = new Map<string, { status: FlowStatus; exports: Map<string, string> }>();
  for (const d of topoOrder(docs)) {
    let blocked: string | undefined;
    for (const id of d.header.requires) {
      const r = done.get(id);
      if (!r) { blocked = `dependency ${id} is not selected (drafts need --include-drafts; production runs approved flows only)`; break; }
      if (r.status !== "PASS") { blocked = `dependency ${id} is ${r.status}`; break; }
    }
    const imports = new Map<string, string>();
    if (!blocked) {
      for (const [name, imp] of Object.entries(d.header.imports)) {
        const v = done.get(imp.flow)!.exports.get(imp.var);
        if (v === undefined) { blocked = `dependency ${imp.flow} did not export ${imp.var} from a PASS step`; break; }
        imports.set(name, v);
      }
    }
    for (const [k, v] of extraImports.get(d.header.id) ?? []) imports.set(k, v);
    const chain: ChainState = { ...(blocked ? { blocked } : {}), imports, exports: new Map() };
    const res = await runDoc(d, ctx, budget, checks, chain);
    if (blocked) res.reasons = [blocked];
    flows.push(res);
    done.set(d.header.id, { status: res.status, exports: chain.exports });
  }
  return { flows, checks, incomplete: budget.exhausted ? [budget.exhausted] : [] };
}

/**
 * `console: "silent"` (SPEC-0.1.3 §6.4-A): a step during which the page wrote to the console fails the
 * functional assertion `console_silent` with the count. It is a functional FAIL only; a security
 * finding needs sensitive content (NSC-INFO-006). Without a JS runtime the assertion is NOT_TESTED.
 */
export function applyConsoleSilent(flows: FlowResult[], docs: FlowDoc[], perStep: Map<string, number> | undefined): void {
  for (const f of flows) {
    const doc = docs.find((d) => d.header.id === f.id);
    if (doc?.header.console !== "silent") continue;
    for (const st of f.steps) {
      if (st.status === "NOT_TESTED" || st.status === "ERROR") continue;
      if (!perStep) { st.assertions.push({ kind: "console_silent", status: "NOT_TESTED", expected: "no console output", observed: "no JS runtime (http engine)" }); continue; }
      const n = perStep.get(st.key) ?? 0;
      st.assertions.push({ kind: "console_silent", status: n ? "FAIL" : "PASS", expected: "no console output", observed: n ? `${n} console message(s)` : "none" });
      st.status = worst(st.assertions.map((a) => a.status));
    }
    f.status = flowStatus(f.steps);
    f.reasons = [...new Set(f.steps.filter((x) => x.status !== "PASS").map((x) => `${x.id} ${x.status}${x.reason ? `: ${x.reason}` : ""}`))];
  }
}

export function functionalResult(flows: FlowResult[]): "PASS" | "FAIL" | "INCOMPLETE" {
  if (flows.some((f) => f.status === "FAIL")) return "FAIL";
  if (!flows.length || flows.some((f) => f.status !== "PASS")) return "INCOMPLETE";
  return "PASS";
}

export type { CheckStatus };
