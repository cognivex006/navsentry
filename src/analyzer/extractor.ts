/**
 * Declarative extractor specs (SPEC-0.1.3 §5.4, owner decision D5). Specs are data interpreted by
 * the shipped analyzer; NavSentry never executes model-generated code. The selector grammar is a
 * small subset (tag, tag[attr], tag[attr=value], descendant combinator, ≤ 8 levels); there are no
 * pseudo-classes, text selectors or user regexes. `value` and text content can never be extracted.
 */
import { createHash } from "node:crypto";
import { closest, type Dom } from "./dom.js";

export const EXTRACT_ATTRS = ["href", "src", "action", "method", "name", "type", "rel", "role", "id"] as const;
export const PREDICATES = ["present", "nonempty", "numeric", "same_origin_url", "matches_path_pattern"] as const;
const SECRETISH = /(password|passwd|secret|token|api[_-]?key|cookie|authorization|session|credential)/i;
const MAX_SPEC_BYTES = 64 * 1024;

export interface Compound { tag: string; attr?: string; value?: string }
export interface ExtractorField { name: string; select: Compound[]; selectText: string; attr: (typeof EXTRACT_ATTRS)[number]; predicate?: (typeof PREDICATES)[number]; max_items: number }
export interface ExtractorSpec { id: string; pathPattern: string; fields: ExtractorField[]; sha256: string }

export class ExtractorError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Invalid extractor spec:\n- ${problems.join("\n- ")}`);
  }
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

/** Parses the selector subset. Anything else (":", ">", "+", "~", ",", "*", text) is rejected. */
export function parseSelector(s: string): Compound[] | undefined {
  if (typeof s !== "string" || s.length > 300) return undefined;
  const parts = s.trim().split(/\s+/);
  if (!parts.length || parts.length > 8) return undefined;
  const out: Compound[] = [];
  for (const p of parts) {
    const m = /^([a-z][a-z0-9-]{0,31})(?:\[([a-z][a-z0-9_-]{0,31})(?:=(?:"([A-Za-z0-9 _./-]{0,64})"|([A-Za-z0-9_./-]{1,64})))?\])?$/.exec(p);
    if (!m) return undefined;
    out.push({ tag: m[1]!, ...(m[2] ? { attr: m[2] } : {}), ...(m[3] !== undefined || m[4] !== undefined ? { value: m[3] ?? m[4]! } : {}) });
  }
  return out;
}

export function parseExtractor(text: string): ExtractorSpec {
  const p: string[] = [];
  if (Buffer.byteLength(text) > MAX_SPEC_BYTES) throw new ExtractorError([`spec larger than ${MAX_SPEC_BYTES} bytes`]);
  let o: unknown;
  try { o = JSON.parse(text); } catch { throw new ExtractorError(["not valid JSON"]); }
  if (!isObj(o)) throw new ExtractorError(["root must be an object"]);
  for (const k of Object.keys(o)) if (!["extractor", "id", "match", "fields"].includes(k)) p.push(`${k}: unknown key`);
  if (o.extractor !== "1") p.push('extractor: must be "1"');
  if (typeof o.id !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(o.id)) p.push("id: ^[a-z0-9][a-z0-9-]{1,62}$");
  const match = isObj(o.match) ? o.match : (p.push("match: required object"), {} as Obj);
  for (const k of Object.keys(match)) if (k !== "path_pattern") p.push(`match.${k}: unknown key`);
  const pathPattern = typeof match.path_pattern === "string" && /^\/[A-Za-z0-9._~{}/-]{0,199}$/.test(match.path_pattern) ? match.path_pattern : (p.push("match.path_pattern: a path pattern such as /product/{id}"), "");
  const fields: ExtractorField[] = [];
  if (!Array.isArray(o.fields) || !o.fields.length || o.fields.length > 20) p.push("fields: 1-20 fields");
  else
    for (const [i, f] of o.fields.entries()) {
      const at = `fields[${i}]`;
      if (!isObj(f)) { p.push(`${at}: must be an object`); continue; }
      for (const k of Object.keys(f)) if (!["name", "select", "attr", "predicate", "max_items"].includes(k)) p.push(`${at}.${k}: unknown key${k === "regex" || k === "pattern" ? " (user regexes are not supported)" : ""}`);
      const name = typeof f.name === "string" && /^[a-z][a-z0-9_]{0,31}$/.test(f.name) ? f.name : (p.push(`${at}.name: ^[a-z][a-z0-9_]{0,31}$`), "");
      if (name && SECRETISH.test(name)) p.push(`${at}.name: names that look like secrets are rejected`);
      const sel = typeof f.select === "string" ? parseSelector(f.select) : undefined;
      if (!sel) p.push(`${at}.select: selector subset only (tag, tag[attr], tag[attr=value], descendant, ≤ 8 levels; no pseudo-classes or text)`);
      if (!EXTRACT_ATTRS.includes(f.attr as never)) p.push(`${at}.attr: one of ${EXTRACT_ATTRS.join(", ")} (value and text content are never extracted)`);
      if (f.predicate !== undefined && !PREDICATES.includes(f.predicate as never)) p.push(`${at}.predicate: one of ${PREDICATES.join(", ")}`);
      const max = typeof f.max_items === "number" && Number.isInteger(f.max_items) && f.max_items >= 1 && f.max_items <= 50 ? f.max_items : (p.push(`${at}.max_items: integer 1-50`), 1);
      if (sel && name) fields.push({ name, select: sel, selectText: f.select as string, attr: f.attr as ExtractorField["attr"], ...(f.predicate ? { predicate: f.predicate as ExtractorField["predicate"] } : {}), max_items: max });
    }
  if (p.length) throw new ExtractorError(p);
  return { id: o.id as string, pathPattern, fields, sha256: createHash("sha256").update(text).digest("hex") };
}

function matches(dom: Dom, idx: number, c: Compound): boolean {
  const n = dom.nodes[idx]!;
  if (n.tag !== c.tag) return false;
  if (c.attr && !n.attrs.has(c.attr)) return false;
  if (c.value !== undefined && n.attrs.get(c.attr!) !== c.value) return false;
  return true;
}

/** Descendant matching: the last compound matches the element, earlier ones match ancestors in order. */
export function select(dom: Dom, sel: Compound[]): number[] {
  const out: number[] = [];
  for (let i = 0; i < dom.nodes.length; i++) {
    if (!matches(dom, i, sel[sel.length - 1]!)) continue;
    let k = sel.length - 2;
    for (let a = dom.nodes[i]!.parent; a >= 0 && k >= 0; a = dom.nodes[a]!.parent) if (matches(dom, a, sel[k]!)) k--;
    if (k < 0) out.push(i);
  }
  return out;
}

export { closest };
