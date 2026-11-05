/**
 * Fixture and auth-endpoint declarations for `safe-validate` (SPEC-0.2.0 §3.2). Mutation permission
 * exists only as these entries: never as a boolean or a method list. Paths are templates whose only
 * placeholder is `{{id}}`; they are checked against the manifest scope after parsing.
 */
import { globToRegExp } from "../scope.js";

export type MutationMethod = "POST" | "PUT" | "PATCH" | "DELETE";

export interface EndpointEntry {
  method: MutationMethod | "GET";
  path: string;
  expect_status?: number[];
  content_type?: string;
  max_body_bytes?: number;
  body?: { json: Record<string, unknown> };
  /** NSC-AC-006 (SPEC-0.2.0 §5.2): where the anti-CSRF token comes from and how it is sent. allowed_mutations only. */
  csrf?: { token_from: { cookie: string }; send_as: { header: string } };
}

export interface FixtureDecl {
  owner_actor: string;
  cleanup_actor: string;
  create: EndpointEntry & { extract: { id: string } };
  exists: EndpointEntry;
  cleanup: EndpointEntry;
  verify_gone?: EndpointEntry;
  allowed_mutations: EndpointEntry[];
  /** NSC-BIZ-001 (SPEC-0.2.0 §5.4): owner-declared rules on the object as `exists` returns it. NavSentry never invents one. */
  invariants: Invariant[];
  forbidden_transitions: Transition[];
}

export type InvariantOp = ">=" | "<=" | "==" | "!=" | "in";
export interface Invariant { name: string; pointer: string; op: InvariantOp; value: unknown }
export interface Transition { name: string; pointer: string; from: string | number | boolean; to: string | number | boolean }

export interface AuthEndpoints {
  login?: EndpointEntry;
  logout?: EndpointEntry;
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const NAME = /^[a-z][a-z0-9_-]{0,31}$/;
const PATH = /^\/(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|\{\{id\}\}|\/)*$/;
const MUTATION: MutationMethod[] = ["POST", "PUT", "PATCH", "DELETE"];
const MAX_BODY_TEMPLATE = 4096;

function keys(o: Obj, allowed: string[], where: string, p: string[]): void {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) p.push(`${where}.${k}: ${k === "csrf" ? "csrf is allowed only on allowed_mutations entries" : "unknown key"}`);
}

function endpoint(v: unknown, where: string, p: string[], o: { methods: (MutationMethod | "GET")[]; placeholder: boolean; status?: boolean; body?: boolean; bodyRules?: boolean; extract?: boolean; csrf?: boolean }): EndpointEntry | undefined {
  if (!isObj(v)) { p.push(`${where}: must be an object`); return undefined; }
  keys(v, ["method", "path", ...(o.status ? ["expect_status"] : []), ...(o.body ? ["body"] : []), ...(o.bodyRules ? ["content_type", "max_body_bytes"] : []), ...(o.extract ? ["extract"] : []), ...(o.csrf ? ["csrf"] : [])], where, p);
  const method = v.method as EndpointEntry["method"];
  if (!o.methods.includes(method)) p.push(`${where}.method: one of ${o.methods.join(", ")}`);
  const path = v.path;
  if (typeof path !== "string" || path.length > 300 || !PATH.test(path) || /\/\.{1,2}(\/|$)/.test(path)) p.push(`${where}.path: an absolute path; letters, digits and URL-safe characters, no "." or ".." segments`);
  else if (path.includes("{{id}}") && !o.placeholder) p.push(`${where}.path: may not contain {{id}}`);
  else if (o.placeholder && path.split("/").some((seg) => seg.includes("{{id}}") && seg !== "{{id}}")) p.push(`${where}.path: {{id}} must be a whole path segment`);
  const e: EndpointEntry = { method, path: path as string };
  if (o.status) {
    const s = v.expect_status;
    if (s === undefined || !Array.isArray(s) || !s.length || s.some((x) => !Number.isInteger(x) || (x as number) < 100 || (x as number) > 599)) p.push(`${where}.expect_status: a non-empty array of HTTP status codes`);
    else e.expect_status = s as number[];
  }
  if (v.body !== undefined) {
    if (!isObj(v.body) || Object.keys(v.body).join() !== "json" || !isObj(v.body.json)) p.push(`${where}.body: {"json": {...}}`);
    else if (JSON.stringify(v.body.json).length > MAX_BODY_TEMPLATE) p.push(`${where}.body: at most ${MAX_BODY_TEMPLATE} bytes`);
    else if (!stringLeaves(v.body.json)) p.push(`${where}.body: leaves must be strings, numbers, booleans or null`);
    else e.body = { json: v.body.json };
  }
  if (o.csrf && v.csrf !== undefined) {
    const c = v.csrf as Record<string, unknown>;
    const tf = isObj(c) ? c.token_from : undefined, sa = isObj(c) ? c.send_as : undefined;
    const NAME_RE = /^[A-Za-z0-9_-]{1,64}$/;
    if (!isObj(c) || Object.keys(c).sort().join() !== "send_as,token_from" || !isObj(tf) || Object.keys(tf).join() !== "cookie" || typeof tf.cookie !== "string" || !NAME_RE.test(tf.cookie) || !isObj(sa) || Object.keys(sa).join() !== "header" || typeof sa.header !== "string" || !NAME_RE.test(sa.header))
      p.push(`${where}.csrf: {"token_from": {"cookie": "<name>"}, "send_as": {"header": "<name>"}}`);
    else e.csrf = { token_from: { cookie: tf.cookie as string }, send_as: { header: (sa.header as string).toLowerCase() } };
  }
  if (o.bodyRules) {
    if (v.content_type !== undefined && (typeof v.content_type !== "string" || !/^[a-z]+\/[a-z0-9.+-]+$/.test(v.content_type))) p.push(`${where}.content_type: a media type such as application/json`);
    else if (!["application/json", "application/x-www-form-urlencoded"].includes((v.content_type as string | undefined) ?? "application/json")) p.push(`${where}.content_type: application/json or application/x-www-form-urlencoded`);
    else e.content_type = (v.content_type as string | undefined) ?? "application/json";
    if (v.max_body_bytes !== undefined && (!Number.isInteger(v.max_body_bytes) || (v.max_body_bytes as number) < 1 || (v.max_body_bytes as number) > 65536)) p.push(`${where}.max_body_bytes: 1–65536`);
    else e.max_body_bytes = (v.max_body_bytes as number | undefined) ?? MAX_BODY_TEMPLATE;
  }
  return e;
}

function stringLeaves(v: unknown, depth = 0): boolean {
  if (depth > 8) return false;
  if (v === null || ["string", "number", "boolean"].includes(typeof v)) return true;
  if (Array.isArray(v)) return v.every((x) => stringLeaves(x, depth + 1));
  if (isObj(v)) return Object.values(v).every((x) => stringLeaves(x, depth + 1));
  return false;
}

export function parseFixtures(raw: unknown, actors: string[], p: string[]): Record<string, FixtureDecl> {
  const out: Record<string, FixtureDecl> = {};
  if (!isObj(raw)) { p.push("fixtures: must be an object"); return out; }
  if (Object.keys(raw).length > 20) p.push("fixtures: at most 20 fixtures");
  for (const [name, f] of Object.entries(raw)) {
    const w = `fixtures.${name}`;
    if (!NAME.test(name)) p.push(`${w}: invalid fixture name`);
    if (!isObj(f)) { p.push(`${w}: must be an object`); continue; }
    keys(f, ["owner_actor", "cleanup_actor", "create", "exists", "cleanup", "verify_gone", "allowed_mutations", "invariants", "forbidden_transitions"], w, p);
    const owner = f.owner_actor;
    if (typeof owner !== "string" || !actors.includes(owner)) p.push(`${w}.owner_actor: must name an actor in actors`);
    const cleanupActor = f.cleanup_actor ?? owner;
    if (typeof cleanupActor !== "string" || !actors.includes(cleanupActor)) p.push(`${w}.cleanup_actor: must name an actor in actors`);
    const create = endpoint(f.create, `${w}.create`, p, { methods: ["POST", "PUT"], placeholder: false, body: true, extract: true });
    let extract: { id: string } | undefined;
    if (isObj(f.create)) {
      const x = f.create.extract;
      if (!isObj(x) || Object.keys(x).join() !== "id" || typeof x.id !== "string" || !/^(\/[^/]{1,64}){1,8}$/.test(x.id)) p.push(`${w}.create.extract: {"id": "<JSON pointer>"}`);
      else extract = { id: x.id };
    }
    const exists = endpoint(f.exists, `${w}.exists`, p, { methods: ["GET"], placeholder: true, status: true });
    const cleanup = endpoint(f.cleanup, `${w}.cleanup`, p, { methods: ["DELETE", "POST"], placeholder: true, status: true });
    const verify = f.verify_gone === undefined ? undefined : endpoint(f.verify_gone, `${w}.verify_gone`, p, { methods: ["GET"], placeholder: true, status: true });
    for (const [k, e] of [["exists", exists], ["cleanup", cleanup], ["verify_gone", verify]] as const) if (e && !e.path.includes("{{id}}")) p.push(`${w}.${k}.path: must contain {{id}}`);
    const muts: EndpointEntry[] = [];
    if (f.allowed_mutations !== undefined) {
      if (!Array.isArray(f.allowed_mutations) || f.allowed_mutations.length > 20) p.push(`${w}.allowed_mutations: an array of at most 20 entries`);
      else f.allowed_mutations.forEach((m, i) => { const e = endpoint(m, `${w}.allowed_mutations[${i}]`, p, { methods: MUTATION, placeholder: true, bodyRules: true, csrf: true }); if (e) muts.push(e); });
    }
    const invariants: Invariant[] = [];
    const POINTER = /^(\/[^/]{1,64}){1,8}$/;
    const NAME_RE = /^[a-z][a-z0-9_-]{0,47}$/;
    const scalar = (v: unknown) => ["string", "number", "boolean"].includes(typeof v);
    if (f.invariants !== undefined) {
      if (!Array.isArray(f.invariants) || f.invariants.length > 20) p.push(`${w}.invariants: an array of at most 20 rules`);
      else f.invariants.forEach((r, i) => {
        const at = `${w}.invariants[${i}]`;
        if (!isObj(r)) { p.push(`${at}: must be an object`); return; }
        keys(r, ["name", "pointer", "op", "value"], at, p);
        const op = r.op as InvariantOp;
        if (typeof r.name !== "string" || !NAME_RE.test(r.name)) p.push(`${at}.name: [a-z0-9_-], max 48`);
        else if (typeof r.pointer !== "string" || !POINTER.test(r.pointer)) p.push(`${at}.pointer: a JSON pointer`);
        else if (![">=", "<=", "==", "!=", "in"].includes(op)) p.push(`${at}.op: >=, <=, ==, != or in`);
        else if ((op === ">=" || op === "<=") && typeof r.value !== "number") p.push(`${at}.value: a number for ${op}`);
        else if (op === "in" && (!Array.isArray(r.value) || !r.value.length || r.value.length > 50 || !r.value.every(scalar))) p.push(`${at}.value: a non-empty array of at most 50 scalars for in`);
        else if ((op === "==" || op === "!=") && !scalar(r.value)) p.push(`${at}.value: a scalar`);
        else invariants.push({ name: r.name, pointer: r.pointer, op, value: r.value });
      });
    }
    const transitions: Transition[] = [];
    if (f.forbidden_transitions !== undefined) {
      if (!Array.isArray(f.forbidden_transitions) || f.forbidden_transitions.length > 20) p.push(`${w}.forbidden_transitions: an array of at most 20 rules`);
      else f.forbidden_transitions.forEach((r, i) => {
        const at = `${w}.forbidden_transitions[${i}]`;
        if (!isObj(r)) { p.push(`${at}: must be an object`); return; }
        keys(r, ["name", "pointer", "from", "to"], at, p);
        if (typeof r.name !== "string" || !NAME_RE.test(r.name)) p.push(`${at}.name: [a-z0-9_-], max 48`);
        else if (typeof r.pointer !== "string" || !POINTER.test(r.pointer)) p.push(`${at}.pointer: a JSON pointer`);
        else if (!scalar(r.from) || !scalar(r.to)) p.push(`${at}.from, to: scalars`);
        else transitions.push({ name: r.name, pointer: r.pointer, from: r.from as string, to: r.to as string });
      });
    }
    if (create && extract && exists && cleanup && typeof owner === "string" && typeof cleanupActor === "string")
      out[name] = { owner_actor: owner, cleanup_actor: cleanupActor, create: { ...create, extract }, exists, cleanup, ...(verify ? { verify_gone: verify } : {}), allowed_mutations: muts, invariants, forbidden_transitions: transitions };
  }
  return out;
}

export function parseAuthEndpoints(raw: unknown, p: string[]): AuthEndpoints {
  if (!isObj(raw)) { p.push("auth_endpoints: must be an object"); return {}; }
  keys(raw, ["login", "logout"], "auth_endpoints", p);
  const out: AuthEndpoints = {};
  for (const k of ["login", "logout"] as const) {
    if (raw[k] === undefined) continue;
    const e = endpoint(raw[k], `auth_endpoints.${k}`, p, { methods: ["POST"], placeholder: false, bodyRules: true });
    if (e) out[k] = e;
  }
  return out;
}

/** Config-time scope check of every declared path (SPEC-0.2.0 §3.2): a violation is a config error, not a skip. */
export function fixtureScopeProblems(fixtures: Record<string, FixtureDecl>, auth: AuthEndpoints, allowed: string[], denied: string[]): string[] {
  const a = allowed.map(globToRegExp), d = denied.map(globToRegExp);
  const p: string[] = [];
  const check = (where: string, path: string) => {
    const sample = path.replace(/\{\{id\}\}/g, "x");
    if (d.some((r) => r.test(sample))) p.push(`${where}.path: matches targets.denied_paths`);
    else if (!a.some((r) => r.test(sample))) p.push(`${where}.path: not in targets.allowed_paths`);
  };
  for (const [n, f] of Object.entries(fixtures)) {
    for (const k of ["create", "exists", "cleanup", "verify_gone"] as const) { const e = f[k]; if (e) check(`fixtures.${n}.${k}`, e.path); }
    f.allowed_mutations.forEach((e, i) => check(`fixtures.${n}.allowed_mutations[${i}]`, e.path));
  }
  for (const k of ["login", "logout"] as const) { const e = auth[k]; if (e) check(`auth_endpoints.${k}`, e.path); }
  return p;
}
