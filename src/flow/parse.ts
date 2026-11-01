/**
 * Flow Markdown v1 parser. Only top-level fenced blocks tagged `navsentry-flow` /
 * `navsentry-step` are read; everything else is narrative and is never interpreted.
 * Validation is strict (unknown keys rejected) and messages never echo values.
 */
import { readdirSync, readFileSync, statSync, lstatSync } from "node:fs";
import { join, relative } from "node:path";
import type { FlowAction } from "../types.js";

export const MAX_FILE_BYTES = 256 * 1024;
export const MAX_BLOCK_BYTES = 64 * 1024;
export const MAX_FLOWS = 200;
export const MAX_STEPS = 50;
export const MAX_VARS = 20;
export const MAX_JSON_ASSERTIONS = 20;
export const MAX_TEXT_MARKERS = 10;
export const MAX_POINTER_DEPTH = 16;

export const UI_ACTIONS: ReadonlySet<FlowAction> = new Set(["click", "fill", "select", "submit", "see", "wait_for"]);
const ACTIONS: FlowAction[] = ["http", "navigate", "click", "fill", "select", "submit", "see", "wait_for"];
const SECRETISH_KEYS = /^(password|passwd|secret|token|api[_-]?key|cookie|authorization)$/i;
const ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;
export const VAR_NAME = /^[a-z][a-zA-Z0-9_]{0,31}$/;
export const FLOW_ID = /^[a-z0-9][a-z0-9-]{1,62}$/;
const STEP_ID = /^S[0-9]{1,3}$/;
const JSON_TYPES = ["string", "number", "boolean", "object", "array", "null"] as const;

export type JsonType = (typeof JSON_TYPES)[number];
export type VarSource = { value: string } | { env: string };
export type Extract = { from: "json"; pointer: string } | { from: "header"; name: string };
export type UiTarget = { role: string; name: string } | { label: string } | { text: string } | { test_id: string };

export interface JsonAssertion {
  pointer: string;
  type?: JsonType;
  equals?: string | number | boolean | null;
  exists?: boolean;
  min_items?: number;
}

export interface Expect {
  status?: number[] | "2xx" | "3xx" | "4xx";
  content_type?: string;
  headers_present?: string[];
  headers_absent?: string[];
  json?: JsonAssertion[];
  shape?: string;
  text_present?: string[];
  text_absent?: string[];
  redirect_to?: string;
  access?: "allowed" | "denied";
  deny_status?: number[];
}

export interface FlowRequest {
  method: "GET" | "HEAD" | "OPTIONS";
  path: string;
  query?: Record<string, string>;
  accept?: "json" | "text" | "any";
}

export interface FlowStep {
  id: string;
  title: string;
  action: FlowAction;
  actor: string;
  request?: FlowRequest;
  target?: UiTarget;
  value?: { var: string };
  follow_redirects: boolean;
  expect?: Expect;
  extract?: Record<string, Extract>;
  object_owner?: string;
  depends_on?: string[];
  /** Raw JSON object as written, used for hashing. */
  raw: Record<string, unknown>;
  line: number;
}

export interface FlowReview {
  status: "draft" | "approved";
  approved_by?: string;
  approved_at?: string;
  reference?: string;
  content_sha256?: string;
}

export interface FlowHeader {
  flow: "1";
  id: string;
  title: string;
  story: string;
  level: "auto" | "integration" | "e2e";
  origin?: string;
  actors: string[];
  tags: string[];
  login_path?: string;
  vars: Record<string, VarSource>;
  review: FlowReview;
  provenance?: { kind: "analyzer" | "agent" | "human"; from_run?: string; sources?: string[]; created_at?: string };
  raw: Record<string, unknown>;
  line: number;
}

export interface FlowDoc {
  /** Path relative to the flows root (forward slashes). */
  file: string;
  header: FlowHeader;
  steps: FlowStep[];
  /** Original text, kept for `flow approve` (which rewrites only the header block). */
  text: string;
  headerBlock: { start: number; end: number };
}

export class FlowError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Invalid flows:\n- ${problems.join("\n- ")}`);
  }
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

interface Ctx {
  file: string;
  line: number;
  p: string[];
}

function err(c: Ctx, ptr: string, msg: string): void {
  c.p.push(`${c.file}:${c.line}: ${ptr || "/"}: ${msg}`);
}

function keys(c: Ctx, o: Obj, allowed: string[], ptr: string): void {
  for (const k of Object.keys(o)) {
    if (allowed.includes(k)) continue;
    if (SECRETISH_KEYS.test(k)) err(c, `${ptr}/${k}`, "plaintext secrets are forbidden; credentials come only from manifest actors");
    else err(c, `${ptr}/${k}`, "unknown key");
  }
}

function str(c: Ctx, v: unknown, ptr: string, max: number, req = false, re?: RegExp): string | undefined {
  if (v === undefined) {
    if (req) err(c, ptr, "required");
    return undefined;
  }
  if (typeof v !== "string" || v.length === 0 || v.length > max) {
    err(c, ptr, `must be a string of 1-${max} characters`);
    return undefined;
  }
  if (re && !re.test(v)) {
    err(c, ptr, "has an invalid format");
    return undefined;
  }
  return v;
}

function strList(c: Ctx, v: unknown, ptr: string, maxItems: number, maxLen: number, re?: RegExp): string[] | undefined {
  if (v === undefined) return undefined;
  if (!Array.isArray(v) || v.length > maxItems) {
    err(c, ptr, `must be an array of at most ${maxItems} strings`);
    return undefined;
  }
  const out: string[] = [];
  v.forEach((x, i) => {
    const s = str(c, x, `${ptr}/${i}`, maxLen, true, re);
    if (s !== undefined) out.push(s);
  });
  return out;
}

function intList(c: Ctx, v: unknown, ptr: string, min: number, max: number): number[] | undefined {
  if (!Array.isArray(v) || v.length === 0 || v.length > 10 || v.some((x) => !Number.isInteger(x) || x < min || x > max)) {
    err(c, ptr, `must be a non-empty array of integers in [${min}, ${max}]`);
    return undefined;
  }
  return v as number[];
}

function parseHeader(c: Ctx, o: Obj): FlowHeader | undefined {
  keys(c, o, ["flow", "id", "title", "story", "level", "origin", "actors", "tags", "login_path", "vars", "review", "provenance"], "");
  if (o.flow !== "1") err(c, "/flow", 'must be "1"');
  const id = str(c, o.id, "/id", 63, true, FLOW_ID);
  const title = str(c, o.title, "/title", 120, true);
  const story = str(c, o.story, "/story", 1000, true);
  const level = o.level ?? "auto";
  if (!["auto", "integration", "e2e"].includes(level as string)) err(c, "/level", "auto | integration | e2e");
  const origin = str(c, o.origin, "/origin", 300);
  const actors = strList(c, o.actors, "/actors", 20, 32, /^[a-z][a-z0-9_-]{0,31}$/);
  if (o.actors === undefined) err(c, "/actors", "required");
  const tags = strList(c, o.tags, "/tags", 10, 32, /^[a-z0-9-]{1,32}$/) ?? [];
  const login_path = str(c, o.login_path, "/login_path", 300);
  const vars: Record<string, VarSource> = {};
  if (o.vars !== undefined) {
    if (!isObj(o.vars) || Object.keys(o.vars).length > MAX_VARS) err(c, "/vars", `must be an object with at most ${MAX_VARS} entries`);
    else
      for (const [name, v] of Object.entries(o.vars)) {
        const ptr = `/vars/${name}`;
        if (!VAR_NAME.test(name)) err(c, ptr, "invalid variable name");
        if (!isObj(v)) { err(c, ptr, "must be an object"); continue; }
        keys(c, v, ["value", "env"], ptr);
        if ((v.value === undefined) === (v.env === undefined)) { err(c, ptr, "needs exactly one of value or env"); continue; }
        if (v.env !== undefined) {
          const e = str(c, v.env, `${ptr}/env`, 64, true, ENV_NAME);
          if (e) vars[name] = { env: e };
        } else {
          const s = str(c, v.value, `${ptr}/value`, 128, true, /^[A-Za-z0-9._~-]+$/);
          if (s) vars[name] = { value: s };
        }
      }
  }
  let review: FlowReview = { status: "draft" };
  if (o.review !== undefined) {
    if (!isObj(o.review)) err(c, "/review", "must be an object");
    else {
      keys(c, o.review, ["status", "approved_by", "approved_at", "reference", "content_sha256"], "/review");
      const st = o.review.status;
      if (st !== "draft" && st !== "approved") err(c, "/review/status", "draft | approved");
      review = { status: st === "approved" ? "approved" : "draft" };
      const by = str(c, o.review.approved_by, "/review/approved_by", 100);
      const at = str(c, o.review.approved_at, "/review/approved_at", 10, false, /^\d{4}-\d{2}-\d{2}$/);
      const ref = str(c, o.review.reference, "/review/reference", 200);
      const h = str(c, o.review.content_sha256, "/review/content_sha256", 64, false, /^[0-9a-f]{64}$/);
      if (by) review.approved_by = by;
      if (at) review.approved_at = at;
      if (ref) review.reference = ref;
      if (h) review.content_sha256 = h;
      if (review.status === "approved" && (!by || !at || !h)) err(c, "/review", "approved flows need approved_by, approved_at and content_sha256 (use `navsentry flow approve`)");
    }
  }
  let provenance: FlowHeader["provenance"];
  if (o.provenance !== undefined) {
    if (!isObj(o.provenance)) err(c, "/provenance", "must be an object");
    else {
      keys(c, o.provenance, ["kind", "from_run", "sources", "created_at"], "/provenance");
      const kind = o.provenance.kind;
      if (!["analyzer", "agent", "human"].includes(kind as string)) err(c, "/provenance/kind", "analyzer | agent | human");
      provenance = { kind: kind as "analyzer" };
      const fr = str(c, o.provenance.from_run, "/provenance/from_run", 64);
      const src = strList(c, o.provenance.sources, "/provenance/sources", 10, 120);
      const ca = str(c, o.provenance.created_at, "/provenance/created_at", 40);
      if (fr) provenance.from_run = fr;
      if (src) provenance.sources = src;
      if (ca) provenance.created_at = ca;
    }
  }
  if (!id || !title || !story || !actors) return undefined;
  return {
    flow: "1", id, title, story, level: level as FlowHeader["level"], actors, tags, vars, review, raw: o, line: c.line,
    ...(origin ? { origin } : {}), ...(login_path ? { login_path } : {}), ...(provenance ? { provenance } : {}),
  };
}

function parseExpect(c: Ctx, v: unknown): Expect | undefined {
  const ptr = "/expect";
  if (!isObj(v)) { err(c, ptr, "must be an object"); return undefined; }
  keys(c, v, ["status", "content_type", "headers_present", "headers_absent", "json", "shape", "text_present", "text_absent", "redirect_to", "access", "deny_status"], ptr);
  const e: Expect = {};
  if (v.status !== undefined) {
    if (typeof v.status === "string") {
      if (["2xx", "3xx", "4xx"].includes(v.status)) e.status = v.status as "2xx";
      else err(c, `${ptr}/status`, "2xx | 3xx | 4xx or an array of codes");
    } else {
      const l = intList(c, v.status, `${ptr}/status`, 100, 599);
      if (l) e.status = l;
    }
  }
  const ct = str(c, v.content_type, `${ptr}/content_type`, 100, false, /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/);
  if (ct) e.content_type = ct;
  const hp = strList(c, v.headers_present, `${ptr}/headers_present`, 20, 64, /^[a-z0-9-]+$/);
  const ha = strList(c, v.headers_absent, `${ptr}/headers_absent`, 20, 64, /^[a-z0-9-]+$/);
  if (hp) e.headers_present = hp;
  if (ha) e.headers_absent = ha;
  if (v.json !== undefined) {
    if (!Array.isArray(v.json) || v.json.length === 0 || v.json.length > MAX_JSON_ASSERTIONS) err(c, `${ptr}/json`, `must be an array of 1-${MAX_JSON_ASSERTIONS} assertions`);
    else {
      e.json = [];
      v.json.forEach((a, i) => {
        const ap = `${ptr}/json/${i}`;
        if (!isObj(a)) { err(c, ap, "must be an object"); return; }
        keys(c, a, ["pointer", "type", "equals", "exists", "min_items"], ap);
        const pointer = str(c, a.pointer, `${ap}/pointer`, 300, true, /^(\/[^/]*)*$/);
        if (pointer && pointer.split("/").length - 1 > MAX_POINTER_DEPTH) err(c, `${ap}/pointer`, `deeper than ${MAX_POINTER_DEPTH}`);
        const ja: JsonAssertion = { pointer: pointer ?? "" };
        if (a.type !== undefined) {
          if (!JSON_TYPES.includes(a.type as JsonType)) err(c, `${ap}/type`, JSON_TYPES.join(" | "));
          else ja.type = a.type as JsonType;
        }
        if (a.equals !== undefined) {
          const q = a.equals;
          if (q !== null && typeof q !== "boolean" && (typeof q !== "number" || !Number.isFinite(q)) && (typeof q !== "string" || q.length > 128)) err(c, `${ap}/equals`, "must be a string (≤128), finite number, boolean or null");
          else ja.equals = q as JsonAssertion["equals"];
        }
        if (a.exists !== undefined) {
          if (typeof a.exists !== "boolean") err(c, `${ap}/exists`, "boolean");
          else ja.exists = a.exists;
        }
        if (a.min_items !== undefined) {
          if (!Number.isInteger(a.min_items) || (a.min_items as number) < 0 || (a.min_items as number) > 1000) err(c, `${ap}/min_items`, "integer in [0, 1000]");
          else ja.min_items = a.min_items as number;
        }
        if (ja.type === undefined && ja.equals === undefined && ja.exists === undefined && ja.min_items === undefined) err(c, ap, "needs type, equals, exists or min_items");
        e.json!.push(ja);
      });
    }
  }
  const shape = str(c, v.shape, `${ptr}/shape`, 16, false, /^[0-9a-f]{16}$/);
  if (shape) e.shape = shape;
  const tp = strList(c, v.text_present, `${ptr}/text_present`, MAX_TEXT_MARKERS, 100);
  const tn = strList(c, v.text_absent, `${ptr}/text_absent`, MAX_TEXT_MARKERS, 100);
  if (tp) e.text_present = tp;
  if (tn) e.text_absent = tn;
  const rt = str(c, v.redirect_to, `${ptr}/redirect_to`, 300);
  if (rt) e.redirect_to = rt;
  if (v.access !== undefined) {
    if (v.access !== "allowed" && v.access !== "denied") err(c, `${ptr}/access`, "allowed | denied");
    else e.access = v.access;
  }
  if (v.deny_status !== undefined) {
    const l = intList(c, v.deny_status, `${ptr}/deny_status`, 300, 499);
    if (l) e.deny_status = l;
  }
  return e;
}

function parseStep(c: Ctx, o: Obj, heading: string | undefined): FlowStep | undefined {
  keys(c, o, ["id", "title", "action", "actor", "request", "target", "value", "follow_redirects", "expect", "extract", "object_owner", "depends_on"], "");
  const id = str(c, o.id, "/id", 4, true, STEP_ID);
  const title = str(c, o.title, "/title", 120) ?? heading ?? id ?? "";
  const action = o.action as FlowAction;
  if (!ACTIONS.includes(action)) err(c, "/action", ACTIONS.join(" | "));
  const actor = str(c, o.actor, "/actor", 32, true, /^[a-z][a-z0-9_-]{0,31}$/);
  const step: Partial<FlowStep> = { title, action, follow_redirects: false, raw: o, line: c.line };
  if (o.request !== undefined) {
    if (!isObj(o.request)) err(c, "/request", "must be an object");
    else {
      keys(c, o.request, ["method", "path", "query", "accept"], "/request");
      const m = o.request.method as FlowRequest["method"];
      if (!["GET", "HEAD", "OPTIONS"].includes(m)) err(c, "/request/method", "only GET, HEAD and OPTIONS are allowed in this release");
      const path = str(c, o.request.path, "/request/path", 500, true);
      const req: FlowRequest = { method: m, path: path ?? "/" };
      if (o.request.query !== undefined) {
        if (!isObj(o.request.query) || Object.keys(o.request.query).length > 20) err(c, "/request/query", "must be an object with at most 20 entries");
        else {
          req.query = {};
          for (const [k, qv] of Object.entries(o.request.query)) {
            if (!/^[A-Za-z0-9._-]{1,64}$/.test(k)) err(c, `/request/query/${k}`, "invalid query key");
            const s = str(c, qv, `/request/query/${k}`, 128, true);
            if (s !== undefined) req.query[k] = s;
          }
        }
      }
      if (o.request.accept !== undefined) {
        if (!["json", "text", "any", "html"].includes(o.request.accept as string)) err(c, "/request/accept", "json | text | any");
        else req.accept = o.request.accept as "json";
      }
      step.request = req;
    }
  }
  if (o.target !== undefined) {
    if (!isObj(o.target)) err(c, "/target", "must be an object");
    else {
      const k = Object.keys(o.target).sort().join(",");
      if (!["name,role", "label", "text", "test_id"].includes(k)) err(c, "/target", "exactly one of {role,name}, {label}, {text}, {test_id}");
      else {
        for (const [tk, tv] of Object.entries(o.target)) str(c, tv, `/target/${tk}`, 120, true);
        step.target = o.target as UiTarget;
      }
    }
  }
  if (o.value !== undefined) {
    if (!isObj(o.value)) err(c, "/value", "must be an object");
    else {
      keys(c, o.value, ["var"], "/value");
      const vn = str(c, o.value.var, "/value/var", 32, true, VAR_NAME);
      if (vn) step.value = { var: vn };
    }
  }
  if (o.follow_redirects !== undefined) {
    if (typeof o.follow_redirects !== "boolean") err(c, "/follow_redirects", "boolean");
    else step.follow_redirects = o.follow_redirects;
  }
  if (o.expect !== undefined) {
    const e = parseExpect(c, o.expect);
    if (e) step.expect = e;
  }
  if (o.extract !== undefined) {
    if (!isObj(o.extract) || Object.keys(o.extract).length > MAX_VARS) err(c, "/extract", "must be an object");
    else {
      step.extract = {};
      for (const [name, x] of Object.entries(o.extract)) {
        const ptr = `/extract/${name}`;
        if (!VAR_NAME.test(name)) err(c, ptr, "invalid variable name");
        if (!isObj(x)) { err(c, ptr, "must be an object"); continue; }
        if (x.from === "json") {
          keys(c, x, ["from", "pointer"], ptr);
          const pt = str(c, x.pointer, `${ptr}/pointer`, 300, true, /^(\/[^/]*)+$/);
          if (pt) step.extract[name] = { from: "json", pointer: pt };
        } else if (x.from === "header") {
          keys(c, x, ["from", "name"], ptr);
          const hn = str(c, x.name, `${ptr}/name`, 64, true, /^[a-z0-9-]+$/);
          if (hn && ["set-cookie", "cookie", "authorization", "proxy-authorization", "www-authenticate"].includes(hn)) err(c, `${ptr}/name`, "credential headers cannot be extracted");
          else if (hn) step.extract[name] = { from: "header", name: hn };
        } else err(c, `${ptr}/from`, "json | header");
      }
    }
  }
  const owner = str(c, o.object_owner, "/object_owner", 32, false, /^[a-z][a-z0-9_-]{0,31}$/);
  if (owner) step.object_owner = owner;
  const dep = strList(c, o.depends_on, "/depends_on", 10, 4, STEP_ID);
  if (dep) step.depends_on = dep;
  if (!id || !actor || !ACTIONS.includes(action)) return undefined;
  return { ...step, id, actor } as FlowStep;
}

const FENCE = /^( {0,3})(`{3,}|~{3,})(.*)$/;

/** Parses one flow file's text. Throws nothing; returns problems. */
export function parseFlowText(text: string, file: string): { doc?: FlowDoc; problems: string[] } {
  const p: string[] = [];
  if (Buffer.byteLength(text, "utf8") > MAX_FILE_BYTES) return { problems: [`${file}:1: file larger than ${MAX_FILE_BYTES} bytes`] };
  if (text.includes("\u0000")) return { problems: [`${file}:1: NUL byte`] };
  const src = text.replace(/^﻿/, "").replace(/\r\n?/g, "\n");
  const lines = src.split("\n");
  let header: FlowHeader | undefined;
  let headerBlock = { start: -1, end: -1 };
  let headerCount = 0;
  const steps: FlowStep[] = [];
  let heading: string | undefined;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    const m = line.match(FENCE);
    if (!m) {
      const h = line.match(/^ {0,3}#{1,6}\s+(.*?)\s*#*\s*$/);
      if (h) heading = (h[1] as string).replace(/[`*_~[\]]/g, "").replace(/\s+/g, " ").trim().slice(0, 120) || undefined;
      else if (/^\s*(?:>\s*|[-*+]\s+|\d+[.)]\s+|\s{4,})\s*(`{3,}|~{3,})\s*navsentry/.test(line)) p.push(`${file}:${i + 1}: navsentry blocks must be top-level (not indented, quoted or in a list)`);
      continue;
    }
    const fence = m[2] as string;
    const info = (m[3] as string).trim().split(/\s+/)[0] ?? "";
    let j = i + 1;
    const body: string[] = [];
    for (; j < lines.length; j++) {
      const cl = (lines[j] as string).match(/^ {0,3}(`{3,}|~{3,})\s*$/);
      if (cl && (cl[1] as string)[0] === fence[0] && (cl[1] as string).length >= fence.length) break;
      body.push(lines[j] as string);
    }
    if (j >= lines.length && info.startsWith("navsentry")) p.push(`${file}:${i + 1}: unclosed ${info} block`);
    const startLine = i + 1;
    i = j;
    if (!info.startsWith("navsentry")) continue;
    const c: Ctx = { file, line: startLine, p };
    if (info !== "navsentry-flow" && info !== "navsentry-step") { err(c, "", `unknown block type "${info.slice(0, 40)}" (navsentry-flow | navsentry-step)`); continue; }
    const content = body.join("\n");
    if (Buffer.byteLength(content, "utf8") > MAX_BLOCK_BYTES) { err(c, "", `block larger than ${MAX_BLOCK_BYTES} bytes`); continue; }
    let data: unknown;
    try {
      data = JSON.parse(content);
    } catch {
      err(c, "", "block is not valid JSON");
      continue;
    }
    if (!isObj(data)) { err(c, "", "block root must be an object"); continue; }
    if (info === "navsentry-flow") {
      headerCount++;
      if (headerCount > 1) { err(c, "", "only one navsentry-flow block is allowed"); continue; }
      if (steps.length) err(c, "", "navsentry-flow must come before the first step");
      header = parseHeader(c, data);
      headerBlock = { start: startLine, end: j + 1 };
    } else {
      if (!headerCount) err(c, "", "navsentry-step before the navsentry-flow block");
      const s = parseStep(c, data, heading);
      if (s) steps.push(s);
    }
  }
  if (!headerCount) p.push(`${file}:1: missing navsentry-flow block`);
  else if (!steps.length && header) p.push(`${file}:1: a flow needs at least one navsentry-step block`);
  if (steps.length > MAX_STEPS) p.push(`${file}:1: more than ${MAX_STEPS} steps`);
  const seen = new Set<string>();
  for (const s of steps) {
    if (seen.has(s.id)) p.push(`${file}:${s.line}: /id: duplicate step id ${s.id}`);
    seen.add(s.id);
  }
  if (p.length || !header) return { problems: p };
  return { doc: { file, header, steps, text: src, headerBlock }, problems: [] };
}

/** Collects *.flow.md files (depth ≤ 3, symlinks not followed), sorted by path. */
export function findFlowFiles(path: string): { root: string; files: string[] } {
  const st = statSync(path);
  if (st.isFile()) return { root: join(path, ".."), files: [path] };
  const out: string[] = [];
  const walk = (dir: string, depth: number) => {
    for (const name of readdirSync(dir).sort()) {
      const full = join(dir, name);
      const l = lstatSync(full);
      if (l.isSymbolicLink()) continue;
      if (l.isDirectory() && depth < 3 && !name.startsWith(".")) walk(full, depth + 1);
      else if (l.isFile() && name.endsWith(".flow.md")) out.push(full);
      if (out.length > MAX_FLOWS) throw new FlowError([`more than ${MAX_FLOWS} flow files under the flows path`]);
    }
  };
  walk(path, 1);
  return { root: path, files: out };
}

export function loadFlowFiles(path: string): { docs: FlowDoc[]; problems: string[] } {
  let found: { root: string; files: string[] };
  try {
    found = findFlowFiles(path);
  } catch (e) {
    if (e instanceof FlowError) return { docs: [], problems: e.problems };
    return { docs: [], problems: [`cannot read flows path: ${(e as NodeJS.ErrnoException).code ?? "error"}`] };
  }
  const docs: FlowDoc[] = [];
  const problems: string[] = [];
  for (const f of found.files) {
    const rel = relative(found.root, f).replace(/\\/g, "/");
    const r = parseFlowText(readFileSync(f, "utf8"), rel);
    problems.push(...r.problems);
    if (r.doc) docs.push(r.doc);
  }
  if (!found.files.length) problems.push("no *.flow.md files found under the flows path");
  const ids = new Map<string, string>();
  for (const d of docs) {
    const prev = ids.get(d.header.id);
    if (prev) problems.push(`${d.file}:${d.header.line}: /id: flow id "${d.header.id}" already used by ${prev}`);
    ids.set(d.header.id, d.file);
  }
  docs.sort((a, b) => a.header.id.localeCompare(b.header.id));
  return { docs, problems };
}
