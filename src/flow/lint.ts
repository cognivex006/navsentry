/**
 * Manifest-aware flow lint (spec §5.10). Zero network: scope is checked statically with
 * ScopeGate; the runtime check on every request stays authoritative.
 */
import type { Manifest } from "../config.js";
import { SECURITY_HEADERS } from "../contract.js";
import { Redactor } from "../redact.js";
import { ScopeGate } from "../scope.js";
import { classify, flowHash, requestTemplate } from "./classify.js";
import { MUTATION_METHODS, UI_ACTIONS, type FlowDoc, type FlowStep } from "./parse.js";

export const VAR_SENTINEL = "navsentry-var";
const PLACEHOLDER = /^\{\{([a-z][a-zA-Z0-9_]{0,31})\}\}$/;
const RISKY = /^(logout|log-out|signout|sign-out|delete|remove|destroy|reset|revoke|cancel|unsubscribe|approve|confirm)$/i;
const FORBIDDEN_EXPECT_HEADERS = new Set(["set-cookie", "cookie", "authorization", "proxy-authorization", "www-authenticate"]);

export interface LintResult {
  errors: string[];
  warnings: string[];
}

/** Origin a flow runs against. */
export function flowOrigin(doc: FlowDoc, m: Manifest): string | undefined {
  if (doc.header.origin) return m.targets.origins.includes(doc.header.origin.replace(/\/$/, "")) ? doc.header.origin.replace(/\/$/, "") : undefined;
  return m.targets.origins.length === 1 ? m.targets.origins[0] : undefined;
}

/** Path template → concrete path, each placeholder replaced by `value(name)`. */
export function fillPath(path: string, value: (name: string) => string): string {
  return path.split("/").map((seg) => {
    const ph = seg.match(PLACEHOLDER);
    return ph ? encodeURIComponent(value(ph[1] as string)) : seg;
  }).join("/");
}

export function placeholders(s: FlowStep): string[] {
  const out: string[] = [];
  for (const seg of s.request?.path.split("/") ?? []) {
    const ph = seg.match(PLACEHOLDER);
    if (ph) out.push(ph[1] as string);
  }
  for (const v of Object.values(s.request?.query ?? {})) {
    const ph = v.match(PLACEHOLDER);
    if (ph) out.push(ph[1] as string);
  }
  if (s.value) out.push(s.value.var);
  return out;
}

function lintDoc(doc: FlowDoc, m: Manifest, gate: ScopeGate, red: Redactor, E: string[], W: string[]): void {
  const h = doc.header;
  const at = (line: number, ptr: string, msg: string) => E.push(`${doc.file}:${line}: ${ptr}: ${msg}`);
  const warn = (line: number, msg: string) => W.push(`${doc.file}:${line}: ${msg}`);
  const literal = (line: number, ptr: string, s: string | undefined) => {
    if (s !== undefined && red.text(s).outcome.applied) at(line, ptr, "literal looks like a secret or personal data (redaction detector matched); use vars.env");
  };

  const origin = flowOrigin(doc, m);
  if (!origin) at(h.line, "/origin", h.origin ? "origin is not in the manifest targets.origins" : "manifest has several origins; set origin");
  const known = new Set(Object.keys(m.actors));
  for (const a of h.actors) if (!known.has(a)) at(h.line, "/actors", `actor "${a}" is not defined in the manifest`);
  literal(h.line, "/title", h.title);
  literal(h.line, "/story", h.story);
  for (const [n, v] of Object.entries(h.vars)) if ("value" in v) literal(h.line, `/vars/${n}/value`, v.value);
  const check = (line: number, ptr: string, path: string, method: "GET" | "HEAD" | "OPTIONS") => {
    if (!origin) return;
    const d = gate.checkRequest(new URL(path, origin).toString(), method);
    if (!d.allowed) at(line, ptr, `out of scope: ${d.reason}`);
  };
  if (h.login_path) {
    if (!h.login_path.startsWith("/") || /[?#\s\\]|\.\./.test(h.login_path)) at(h.line, "/login_path", "must be a plain path");
    else check(h.line, "/login_path", h.login_path, "GET");
  }

  const defined = new Set([...Object.keys(h.vars), ...Object.keys(h.imports)]);
  for (const n of Object.keys(h.imports)) if (n in h.vars) at(h.line, `/imports/${n}`, "collides with a local variable of the same name");
  const seen = new Set<string>();
  const cls = classify(doc);
  if (h.level !== "auto" && h.level !== cls.level) at(h.line, "/level", `declared ${h.level} but derived ${cls.level}: ${cls.levelReasons.join("; ")}`);
  if (cls.level === "e2e" && doc.steps.some((s) => UI_ACTIONS.has(s.action))) warn(h.line, "E2E flow with UI steps will be INCOMPLETE until the browser transport exists (M1b)");

  for (const s of doc.steps) {
    const L = s.line;
    if (!h.actors.includes(s.actor)) at(L, "/actor", `actor "${s.actor}" is not listed in the flow header actors`);
    if (s.object_owner && (!h.actors.includes(s.object_owner) || s.object_owner === s.actor)) at(L, "/object_owner", "must be another actor listed in the header");
    for (const d of s.depends_on ?? []) if (!seen.has(d)) at(L, "/depends_on", `${d} is not an earlier step`);
    seen.add(s.id);
    literal(L, "/title", s.title);
    if (s.action === "fixture_create") {
      // safe-validate (SPEC-0.2.0 §4.2): the fixture must be declared in the manifest; the id becomes a variable.
      if (m.safety.mode !== "safe-validate") at(L, "/action", "fixture_create needs safety.mode safe-validate");
      else if (!s.fixture || !m.fixtures[s.fixture]) at(L, "/fixture", `fixture "${s.fixture}" is not declared in the manifest fixtures`);
      if (s.as) defined.add(s.as);
      continue;
    }
    const ui = UI_ACTIONS.has(s.action);
    if (ui) {
      if (s.request) at(L, "/request", "UI actions take target, not request");
      if (s.expect) at(L, "/expect", "UI steps carry no expect in format v1");
      if (!s.target) at(L, "/target", "required for UI actions");
      if ((s.action === "fill" || s.action === "select") && !s.value) at(L, "/value", "required for fill/select");
      for (const v of Object.values(s.target ?? {})) literal(L, "/target", v as string);
    } else {
      if (s.target || s.value) at(L, "/target", "http/navigate steps take request, not target/value");
      if (!s.request) { at(L, "/request", "required"); continue; }
      const r = s.request;
      const mutation = MUTATION_METHODS.has(r.method);
      if (mutation) {
        // S13 at lint time: the step must match one declared allowed_mutations entry exactly.
        const fx = s.fixture ? m.fixtures[s.fixture] : undefined;
        if (m.safety.mode !== "safe-validate") at(L, "/request/method", `${r.method} needs safety.mode safe-validate`);
        else if (!fx) at(L, "/fixture", `fixture "${s.fixture}" is not declared in the manifest fixtures`);
        else {
          const tpl = r.path.split("/").map((seg) => (PLACEHOLDER.test(seg) ? "{{id}}" : seg)).join("/");
          const entry = fx.allowed_mutations.find((e) => e.method === r.method && e.path === tpl);
          if (!entry) at(L, "/request", `${r.method} ${tpl} matches no allowed_mutations entry of fixture "${s.fixture}"`);
          else if (origin) {
            const d = gate.checkMutation(new URL(fillPath(r.path, () => "x"), origin).toString(), r.method, entry);
            if (!d.allowed) at(L, "/request/path", `out of scope: ${d.reason}`);
          }
        }
        if (s.follow_redirects) at(L, "/follow_redirects", "mutation steps never follow redirects (SPEC-0.2.0 §3.3)");
        if (s.action !== "http") at(L, "/action", "mutations are http steps");
        if (r.query && Object.keys(r.query).length) at(L, "/request/query", "mutation steps take no query; put values in the body");
      } else if (!m.safety.allowed_methods.includes(r.method)) at(L, "/request/method", `${r.method} is not in the manifest safety.allowed_methods`);
      if (s.fixture && !mutation) at(L, "/fixture", "only on fixture_create and mutation steps");
      if (s.action === "navigate" && r.method !== "GET") at(L, "/request/method", "navigate is always GET");
      if (s.action === "navigate" && r.accept) at(L, "/request/accept", "navigate always accepts HTML");
      if (s.action === "http" && (r.accept as string) === "html") at(L, "/request/accept", "use a navigate step for HTML page loads");
      if (!r.path.startsWith("/") || /[?#\s\\]/.test(r.path) || r.path.includes("..") || /%2e|%2f|%5c|%00/i.test(r.path) || /^[a-z]+:/i.test(r.path)) at(L, "/request/path", "must be a plain path starting with / (no query, .., backslash, whitespace or encoded separators)");
      for (const seg of r.path.split("/")) if (seg.includes("{{") && !PLACEHOLDER.test(seg)) at(L, "/request/path", "a placeholder must fill a whole path segment");
      for (const [k, v] of Object.entries(r.query ?? {})) {
        if (v.includes("{{") && !PLACEHOLDER.test(v)) at(L, `/request/query/${k}`, "a placeholder must be the whole query value");
        else if (!PLACEHOLDER.test(v)) literal(L, `/request/query/${k}`, v);
      }
      for (const seg of r.path.split("/")) if (RISKY.test(seg)) warn(L, `path segment "${seg}" suggests a side effect on GET; confirm with the owner`);
      if (!mutation) check(L, "/request/path", fillPath(r.path, () => VAR_SENTINEL), r.method as "GET");
      const e = s.expect;
      if (!e || !Object.keys(e).length) at(L, "/expect", "an http/navigate step needs at least one expectation");
      if (e) {
        for (const hn of [...(e.headers_present ?? []), ...(e.headers_absent ?? [])]) {
          if (SECURITY_HEADERS.has(hn) || FORBIDDEN_EXPECT_HEADERS.has(hn)) at(L, "/expect", `header "${hn}" is covered by the security checks, not by functional expectations`);
        }
        const bodyAssert = e.json || e.shape || e.text_present || e.text_absent || e.content_type;
        if ((r.method === "HEAD" || r.method === "OPTIONS") && bodyAssert) at(L, "/expect", "HEAD/OPTIONS steps support only status, headers and access");
        if (e.access && r.method === "OPTIONS") at(L, "/expect/access", "access expectations need GET or HEAD");
        if (e.deny_status && e.access !== "denied") at(L, "/expect/deny_status", "only with access: denied");
        if (e.redirect_to) {
          if (s.follow_redirects) at(L, "/expect/redirect_to", "needs follow_redirects: false");
          if (!e.redirect_to.startsWith("/") || /[?#\s\\]|\.\./.test(e.redirect_to)) at(L, "/expect/redirect_to", "must be a plain path");
        }
        for (const j of e.json ?? []) if (typeof j.equals === "string") literal(L, "/expect/json/equals", j.equals);
        for (const t of [...(e.text_present ?? []), ...(e.text_absent ?? [])]) literal(L, "/expect/text", t);
        if (e.access === "denied") {
          const tpl = requestTemplate(s);
          const control = doc.steps.find((o) => o !== s && o.actor !== s.actor && o.expect?.access === "allowed" && requestTemplate(o) === tpl);
          if (!control) at(L, "/expect/access", "a denied step needs a positive control (access: allowed) on the same request by another actor in this flow");
        }
      }
    }
    for (const v of placeholders(s)) if (!defined.has(v)) at(L, "/request", `variable {{${v}}} is used before it is defined`);
    for (const name of Object.keys(s.extract ?? {})) {
      if (defined.has(name)) at(L, `/extract/${name}`, "variable already defined");
      defined.add(name);
    }
  }

  if (h.review.status === "approved" && h.review.content_sha256 && h.review.content_sha256 !== flowHash(doc)) {
    at(h.line, "/review", "flow changed after approval; re-approve with `navsentry flow approve`");
  }
}

export function lintFlows(docs: FlowDoc[], m: Manifest): LintResult {
  const gate = new ScopeGate(m);
  const red = new Redactor();
  const errors: string[] = [];
  const warnings: string[] = [];
  for (const d of docs) lintDoc(d, m, gate, red, errors, warnings);
  lintGraph(docs, m, errors);
  return { errors, warnings };
}

/** Chain graph rules (SPEC-0.1.3 §5.5), all reported before any I/O. */
function lintGraph(docs: FlowDoc[], m: Manifest, E: string[]): void {
  const byId = new Map(docs.map((d) => [d.header.id, d]));
  for (const d of docs) {
    const h = d.header;
    const at = (ptr: string, msg: string) => E.push(`${d.file}:${h.line}: ${ptr}: ${msg}`);
    for (const id of h.requires) {
      if (id === h.id) at("/requires", "a flow cannot require itself");
      else if (!byId.has(id)) at("/requires", `no flow "${id}" in the selected flow root`);
    }
    for (const [name, imp] of Object.entries(h.imports)) {
      const ptr = `/imports/${name}`;
      if (!h.requires.includes(imp.flow)) { at(ptr, `undeclared dependency: add "${imp.flow}" to requires`); continue; }
      const src = byId.get(imp.flow);
      if (!src) continue;
      const producers = src.steps.filter((s) => s.extract && imp.var in s.extract);
      if (!producers.length) { at(ptr, `missing export: flow "${imp.flow}" never extracts "${imp.var}"`); continue; }
      const users = d.steps.filter((s) => placeholders(s).includes(name));
      if (!imp.allowCrossActor) {
        const actors = new Set(producers.map((s) => s.actor));
        const cross = users.filter((s) => !actors.has(s.actor));
        if (cross.length) at(ptr, `value crosses an actor boundary (${[...actors].join(",")} → ${[...new Set(cross.map((s) => s.actor))].join(",")}); declare allow_cross_actor in the reviewed flow if intended`);
      }
      if (!imp.allowCrossOrigin && flowOrigin(src, m) !== flowOrigin(d, m)) at(ptr, "value crosses an origin boundary; declare allow_cross_origin in the reviewed flow if intended");
    }
  }
  // Cycles: depth-first search with colours.
  const state = new Map<string, 1 | 2>();
  const reported = new Set<string>();
  const visit = (id: string, path: string[]): void => {
    const d = byId.get(id);
    if (!d) return;
    if (state.get(id) === 2) return;
    if (state.get(id) === 1) {
      const cyc = [...path.slice(path.indexOf(id)), id];
      const key = [...cyc].sort().join(",");
      if (!reported.has(key)) { reported.add(key); E.push(`${d.file}:${d.header.line}: /requires: dependency cycle ${cyc.join(" → ")}`); }
      return;
    }
    state.set(id, 1);
    for (const r of d.header.requires) if (r !== id) visit(r, [...path, id]);
    state.set(id, 2);
  };
  for (const d of docs) visit(d.header.id, []);
}

/** Topological order (dependencies first, ties by id). Assumes a linted, acyclic graph. */
export function topoOrder(docs: FlowDoc[]): FlowDoc[] {
  const byId = new Map(docs.map((d) => [d.header.id, d]));
  const out: FlowDoc[] = [];
  const done = new Set<string>();
  const visit = (d: FlowDoc, stack: Set<string>) => {
    if (done.has(d.header.id) || stack.has(d.header.id)) return;
    stack.add(d.header.id);
    for (const r of [...d.header.requires].sort()) { const x = byId.get(r); if (x) visit(x, stack); }
    done.add(d.header.id);
    out.push(d);
  };
  for (const d of [...docs].sort((a, b) => a.header.id.localeCompare(b.header.id))) visit(d, new Set());
  return out;
}
