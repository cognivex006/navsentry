/**
 * OpenAPI JSON → draft integration flows (SPEC-0.1.3 §4.1, first slice). Zero network: the spec is
 * a local file read as untrusted data. Only GET operations without a request body become steps;
 * everything else is listed for safe-validate (M2). Step titles are generated, never copied from
 * the spec, so target-controlled text does not reach the flows. Every flow is a draft.
 */
import type { Manifest } from "../config.js";
import { FLOW_ID } from "../flow/parse.js";
import { ScopeGate } from "../scope.js";

export const MAX_SPEC_BYTES = 5 * 1024 * 1024;
const MAX_STEPS_PER_FLOW = 20;
const METHODS = ["get", "head", "options", "post", "put", "patch", "delete", "trace"] as const;
const RISKY = /^(logout|log-out|signout|sign-out|delete|remove|destroy|reset|revoke|cancel|unsubscribe|approve|confirm)$/i;
const PLAIN_SEG = /^[A-Za-z0-9._~-]+$/;

export class OpenApiError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Cannot import OpenAPI document:\n- ${problems.join("\n- ")}`);
  }
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");

export interface ImportOutput {
  files: Map<string, string>;
  skippedExisting: string[];
  operations: { method: string; path: string; encoded: boolean; note?: string }[];
}

export function parseOpenApiText(text: string): Obj {
  if (Buffer.byteLength(text) > MAX_SPEC_BYTES) throw new OpenApiError([`document larger than ${MAX_SPEC_BYTES} bytes`]);
  let doc: unknown;
  try {
    doc = JSON.parse(text.replace(/^﻿/, ""));
  } catch {
    throw new OpenApiError(["not valid JSON (YAML is not supported: zero runtime dependencies, ADR-0003)"]);
  }
  if (!isObj(doc)) throw new OpenApiError(["root must be an object"]);
  const v3 = typeof doc.openapi === "string" && /^3\./.test(doc.openapi);
  const v2 = doc.swagger === "2.0";
  if (!v3 && !v2) throw new OpenApiError(['needs "openapi": "3.x" or "swagger": "2.0"']);
  if (!isObj(doc.paths)) throw new OpenApiError(["paths: required object"]);
  return doc;
}

/** Resolves a local `#/...` reference; external references are not followed. */
function deref(doc: Obj, v: unknown, depth = 0): Obj | undefined {
  if (!isObj(v)) return undefined;
  if (typeof v.$ref !== "string") return v;
  if (depth > 5 || !v.$ref.startsWith("#/")) return undefined;
  let cur: unknown = doc;
  for (const raw of v.$ref.slice(2).split("/")) {
    const k = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    cur = isObj(cur) ? cur[k] : undefined;
  }
  return deref(doc, cur, depth + 1);
}

function basePath(doc: Obj): string {
  let p = "";
  if (typeof doc.basePath === "string") p = doc.basePath;
  else if (Array.isArray(doc.servers) && isObj(doc.servers[0]) && typeof doc.servers[0].url === "string") {
    try { p = new URL(doc.servers[0].url, "http://openapi.invalid").pathname; } catch { p = ""; }
  }
  p = p.replace(/\/+$/, "");
  return /^(\/[A-Za-z0-9._~-]+)*$/.test(p) ? p : "";
}

const varName = (raw: string) => {
  const s = raw.replace(/[^A-Za-z0-9_]/g, "_").replace(/^[^a-zA-Z]+/, "");
  const v = (s.charAt(0).toLowerCase() + s.slice(1)).slice(0, 32);
  return /^[a-z][a-zA-Z0-9_]{0,31}$/.test(v) ? v : undefined;
};

export function importOpenApi(doc: Obj, m: Manifest, existingIds: Set<string>, now = new Date()): ImportOutput {
  const gate = new ScopeGate(m);
  const origin = m.targets.origins.length === 1 ? m.targets.origins[0]! : undefined;
  const authActor = Object.keys(m.actors).filter((a) => a !== "anonymous").sort()[0];
  const base = basePath(doc);
  const operations: ImportOutput["operations"] = [];
  const groups = new Map<string, { steps: { title: string; step: Obj }[]; actors: Set<string>; vars: Map<string, string> }>();
  const globalSecurity = Array.isArray(doc.security) ? doc.security : [];

  for (const [rawPath, rawItem] of Object.entries(doc.paths as Obj).sort(([a], [b]) => a.localeCompare(b))) {
    const item = deref(doc, rawItem);
    if (!item) continue;
    for (const method of METHODS) {
      const op = deref(doc, item[method]);
      if (!op) continue;
      const full = `${base}${rawPath}`;
      const rec = (encoded: boolean, note?: string) => operations.push({ method: method.toUpperCase(), path: full.slice(0, 300), encoded, ...(note ? { note } : {}) });
      if (method !== "get") { rec(false, method === "head" || method === "options" ? "only GET operations become steps" : "state-changing method: needs safe-validate (M2)"); continue; }
      if (op.requestBody !== undefined) { rec(false, "GET with a request body is not replayed"); continue; }
      // Path template → flow path: {param} becomes {{var}} filling a whole segment.
      const vars = new Map<string, string>();
      let ok = true;
      const segs = full.split("/").map((seg, i) => {
        if (i === 0) return "";
        const ph = /^\{([^{}]{1,64})\}$/.exec(seg);
        if (ph) { const v = varName(ph[1]!); if (!v) { ok = false; return seg; } vars.set(v, ph[1]!); return `{{${v}}}`; }
        if (!PLAIN_SEG.test(seg)) ok = false;
        return seg;
      });
      if (!ok || !full.startsWith("/")) { rec(false, "path is not a plain template (encoded separators, partial placeholders or unusual characters)"); continue; }
      if (segs.some((s) => RISKY.test(s))) { rec(false, "path suggests a side effect on GET; confirm with the owner"); continue; }
      const path = segs.join("/") || "/";
      if (origin && !gate.checkRequest(new URL(path.replace(/\{\{[^}]+\}\}/g, "navsentry-var"), origin).toString(), "GET").allowed) { rec(false, "outside the manifest scope"); continue; }
      // Required query parameters become variables; optional ones are omitted.
      const params = [...(Array.isArray(item.parameters) ? item.parameters : []), ...(Array.isArray(op.parameters) ? op.parameters : [])].map((p) => deref(doc, p)).filter((p): p is Obj => !!p);
      const query: Record<string, string> = {};
      let paramOk = true;
      for (const p of params) {
        if (p.in === "query" && p.required === true && typeof p.name === "string") {
          const v = varName(p.name);
          if (!v || !/^[A-Za-z0-9._~-]{1,64}$/.test(p.name)) { paramOk = false; break; }
          vars.set(v, p.name);
          query[p.name] = `{{${v}}}`;
        }
        if (p.in === "header" && p.required === true) { paramOk = false; break; }
      }
      if (!paramOk) { rec(false, "needs a required header or an unsupported query parameter"); continue; }
      const responses = isObj(op.responses) ? op.responses : {};
      const codes = Object.keys(responses).filter((c) => /^\d{3}$/.test(c)).map(Number);
      const okCode = codes.filter((c) => c >= 200 && c < 300).sort()[0];
      const content = okCode !== undefined ? deref(doc, responses[String(okCode)]) : undefined;
      const types = isObj(content?.content) ? Object.keys(content!.content as Obj) : Array.isArray(op.produces) ? (op.produces as string[]) : Array.isArray(doc.produces) ? (doc.produces as string[]) : [];
      const json = types.some((t) => /^application\/(?:[a-z.+-]*\+)?json/i.test(t));
      const security = Array.isArray(op.security) ? op.security : globalSecurity;
      const needsAuth = security.length > 0 && !security.some((s) => isObj(s) && Object.keys(s).length === 0);
      const tag = Array.isArray(op.tags) && typeof op.tags[0] === "string" ? slug(op.tags[0]) : slug(full.split("/").filter(Boolean)[0] ?? "root");
      const gid = `api-${tag || "root"}`.slice(0, 50).replace(/-+$/, "");
      const g = groups.get(gid) ?? { steps: [], actors: new Set<string>(), vars: new Map<string, string>() };
      for (const [v, n] of vars) g.vars.set(v, n);
      const req = { method: "GET", path, accept: json ? "json" : "any", ...(Object.keys(query).length ? { query } : {}) };
      const status = okCode !== undefined ? [okCode] : "2xx";
      if (needsAuth) {
        if (!authActor) { rec(false, "requires authentication; add an authenticated actor to the manifest"); continue; }
        g.steps.push({ title: `${authActor} reads GET ${path}`, step: { id: "S0", action: "http", actor: authActor, request: req, expect: { status, access: "allowed", ...(json ? { content_type: "application/json" } : {}) } } });
        g.steps.push({ title: `anonymous must be denied GET ${path}`, step: { id: "S0", action: "http", actor: "anonymous", request: req, expect: { access: "denied", ...(codes.includes(401) || codes.includes(403) ? { deny_status: codes.filter((c) => c === 401 || c === 403) } : {}) } } });
        g.actors.add(authActor);
      } else {
        g.steps.push({ title: `anonymous reads GET ${path}`, step: { id: "S0", action: "http", actor: "anonymous", request: req, expect: { status, ...(json ? { content_type: "application/json" } : {}) } } });
      }
      groups.set(gid, g);
      rec(true);
    }
  }

  const files = new Map<string, string>();
  const skippedExisting: string[] = [];
  for (const [gid, g] of [...groups].sort(([a], [b]) => a.localeCompare(b))) {
    // Keep allowed/denied pairs in the same flow (a denied step needs its positive control).
    const units: (typeof g.steps)[] = [];
    for (let i = 0; i < g.steps.length; i++) {
      const s = g.steps[i]!;
      if ((s.step.expect as Obj).access === "allowed" && g.steps[i + 1]) units.push([s, g.steps[++i]!]);
      else units.push([s]);
    }
    const chunks: (typeof g.steps)[] = [];
    for (const u of units) {
      const cur = chunks.at(-1);
      if (!cur || cur.length + u.length > MAX_STEPS_PER_FLOW) chunks.push([...u]);
      else cur.push(...u);
    }
    chunks.forEach((steps, i) => {
      const id = i ? `${gid}-${i + 1}` : gid;
      if (!FLOW_ID.test(id)) return;
      if (existingIds.has(id)) { skippedExisting.push(id); return; }
      const used = new Set(steps.flatMap((s) => JSON.stringify(s.step).match(/\{\{([a-zA-Z0-9_]+)\}\}/g) ?? []).map((x) => x.slice(2, -2)));
      const vars = Object.fromEntries([...used].sort().map((v) => [v, { env: `NAVSENTRY_VAR_${v.replace(/([a-z])([A-Z])/g, "$1_$2").toUpperCase()}`.slice(0, 64) }]));
      const actors = [...new Set(["anonymous", ...steps.map((s) => s.step.actor as string)])].sort();
      const header = { flow: "1", id, title: `API (OpenAPI): ${id.replace(/^api-/, "")}`, story: "Documented read operations respond with their documented status and media type; protected operations deny anonymous callers.", level: "integration", actors, ...(Object.keys(vars).length ? { vars } : {}), review: { status: "draft" }, provenance: { kind: "analyzer", sources: ["openapi"], created_at: now.toISOString() } };
      files.set(`${id}.flow.md`, [
        `# ${header.title}`, "",
        "Draft generated by `navsentry flow import --openapi` from a local OpenAPI document. The document is a contract claim, not observed behaviour: review every step, set the variable values, then approve.", "",
        "```navsentry-flow", JSON.stringify(header, null, 2), "```", "",
        ...steps.flatMap((s, k) => [`## S${k + 1} — ${s.title}`, "", "```navsentry-step", JSON.stringify({ ...s.step, id: `S${k + 1}` }, null, 2), "```", ""]),
      ].join("\n"));
    });
  }
  const encoded = operations.filter((o) => o.encoded).length;
  files.set("IMPORT.md", [
    "# OpenAPI import", "",
    `- Operations: ${operations.length} · encoded as steps: ${encoded} · not encoded: ${operations.length - encoded}`,
    `- Draft flows written: ${files.size} · existing, not modified: ${skippedExisting.length ? skippedExisting.join(", ") : "none"}`,
    "", "> All flows are drafts. Variables are `*_env` references: set them to test values, run `navsentry flow lint`, then approve.", "",
    "| Method | Path | Encoded | Note |", "|---|---|---|---|",
    ...operations.map((o) => `| ${o.method} | \`${o.path.replace(/[`|]/g, "")}\` | ${o.encoded ? "yes" : "no"} | ${o.note ?? ""} |`), "",
  ].join("\n"));
  return { files, skippedExisting, operations };
}
