/**
 * Page model (SPEC-0.1.3 §5.2): the only artifact allowed to cross from the analyzer to an agent.
 * Structural, allowlisted fields only: no field values, cookie values, tokens, emails or body text.
 * Free text (title and headings) is opt-in (`analyzer.include_text`), redacted and cut to 120
 * characters. Every URL is a display URL. A model is capped at 64 KiB with omitted counts.
 */
import { pathPattern, scanHtml } from "../spider/html.js";
import type { Redactor } from "../redact.js";
import { closest, parseDom, type Dom } from "./dom.js";
import { select, type ExtractorSpec } from "./extractor.js";

export const MAX_MODEL_BYTES = 64 * 1024;
const INPUT_TYPES = new Set(["text", "email", "password", "search", "tel", "url", "number", "date", "datetime-local", "month", "week", "time", "checkbox", "radio", "file", "hidden", "submit", "button", "reset", "image", "color", "range"]);
const SECRETISH_NAME = /(password|passwd|secret|token|api[_-]?key|csrf|xsrf|session|auth|otp|pin|ssn|card)/i;

export interface PageModel {
  model: "1";
  url: string;
  template: { path_pattern: string; shape_hash: string };
  forms: { action: string; method: string; fields: { name: string; type: string; required: boolean }[] }[];
  links: { href: string; rel?: string; same_template: boolean }[];
  scripts: { inline_count: number; external_origins: string[] };
  security: { csp_meta: boolean; frames: number; frame_origins: string[]; cookies: { secure: boolean; http_only: boolean; same_site?: string }[]; mixed_content: number };
  hashes: { text: string };
  text?: { title?: string; landmarks: string[] };
  extracted?: Record<string, Record<string, string[]>>;
  omitted?: Record<string, number>;
  incomplete?: string;
}

/** Display URL: no fragment or userinfo, query values masked, identifier-like path segments as {id}. */
export function displayUrl(raw: string, base?: string): string | undefined {
  let u: URL;
  try { u = new URL(raw, base); } catch { return undefined; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return `${u.protocol}…`;
  const keys = [...new Set(u.searchParams.keys())].sort();
  return `${u.origin}${pathPattern(u.pathname)}${keys.length ? `?${keys.map((k) => `${encodeURIComponent(k).slice(0, 40)}=[REDACTED]`).join("&")}` : ""}`;
}

/** Structural names are still untrusted: secret-looking or detector-matching names are withheld. */
function safeName(red: Redactor, s: string | undefined): string {
  if (!s) return "";
  const t = s.slice(0, 64);
  if (SECRETISH_NAME.test(t) || red.text(t).outcome.applied || !/^[A-Za-z0-9_.\[\]-]{1,64}$/.test(t)) return "[withheld]";
  return t;
}

export interface BuildOptions {
  includeText: boolean;
  extractors: ExtractorSpec[];
  deadline: number;
  setCookies?: string[];
  /** The body was not captured completely: the model is partial. */
  partial?: string;
}

export function buildPageModel(html: string, pageUrl: string, red: Redactor, o: BuildOptions): PageModel {
  const page = new URL(pageUrl);
  const dom = parseDom(html, o.deadline);
  const pattern = pathPattern(page.pathname);
  const m: PageModel = {
    model: "1",
    url: displayUrl(pageUrl)!,
    template: { path_pattern: pattern, shape_hash: scanHtml(html).shapeHash },
    forms: [],
    links: [],
    scripts: { inline_count: 0, external_origins: [] },
    security: { csp_meta: false, frames: 0, frame_origins: [], cookies: [], mixed_content: 0 },
    hashes: { text: dom.textHash },
  };
  const reasons: string[] = [];
  if (dom.truncated) reasons.push(Date.now() > o.deadline ? "analyzer.timeout_seconds reached" : "node limit reached");
  if (o.partial) reasons.push(o.partial);
  const ext = new Set<string>(), frames = new Set<string>();
  const formIdx = new Map<number, number>();
  for (let i = 0; i < dom.nodes.length; i++) {
    const n = dom.nodes[i]!;
    const a = (k: string) => n.attrs.get(k);
    switch (n.tag) {
      case "form": {
        formIdx.set(i, m.forms.length);
        m.forms.push({ action: displayUrl(a("action") || pageUrl, pageUrl) ?? "[unparseable]", method: (a("method") ?? "get").toUpperCase() === "POST" ? "POST" : "GET", fields: [] });
        break;
      }
      case "input": case "select": case "textarea": {
        const f = closest(dom, i, "form");
        const fi = f >= 0 ? formIdx.get(f) : undefined;
        if (fi === undefined) break;
        const type = n.tag === "input" ? (INPUT_TYPES.has((a("type") ?? "text").toLowerCase()) ? (a("type") ?? "text").toLowerCase() : "other") : n.tag;
        m.forms[fi]!.fields.push({ name: safeName(red, a("name")), type, required: n.attrs.has("required") });
        break;
      }
      case "a": case "area": {
        const href = a("href");
        if (href === undefined) break;
        let same = false;
        try { const u = new URL(href, pageUrl); same = u.origin === page.origin && pathPattern(u.pathname) === pattern; } catch { /* display marks it */ }
        const rel = a("rel");
        m.links.push({ href: displayUrl(href, pageUrl) ?? "[unparseable]", ...(rel ? { rel: rel.toLowerCase().slice(0, 40) } : {}), same_template: same });
        break;
      }
      case "script": {
        const src = a("src");
        if (!src) { m.scripts.inline_count++; break; }
        try { const u = new URL(src, pageUrl); if (u.origin !== page.origin) ext.add(u.origin); if (page.protocol === "https:" && u.protocol === "http:") m.security.mixed_content++; } catch { /* ignored */ }
        break;
      }
      case "iframe": case "frame": {
        m.security.frames++;
        try { const u = new URL(a("src") ?? "about:blank", pageUrl); if (u.protocol.startsWith("http")) frames.add(u.origin); } catch { /* ignored */ }
        break;
      }
      case "meta":
        if ((a("http-equiv") ?? "").toLowerCase() === "content-security-policy") m.security.csp_meta = true;
        break;
      case "img": case "link": case "source": case "video": case "audio": {
        const s = a("src") ?? (n.tag === "link" ? a("href") : undefined);
        if (s && page.protocol === "https:") { try { if (new URL(s, pageUrl).protocol === "http:") m.security.mixed_content++; } catch { /* ignored */ } }
        break;
      }
    }
  }
  m.scripts.external_origins = [...ext].sort().slice(0, 50);
  m.security.frame_origins = [...frames].sort().slice(0, 20);
  m.security.cookies = (o.setCookies ?? []).slice(0, 50).map((c) => {
    const ss = /;\s*samesite=(\w+)/i.exec(c)?.[1];
    return { secure: /;\s*secure\b/i.test(c), http_only: /;\s*httponly\b/i.test(c), ...(ss ? { same_site: ss.toLowerCase() } : {}) };
  });
  if (o.includeText) {
    const cut = (s: string) => red.text(s.trim()).text.slice(0, 120);
    const title = dom.nodes.find((n) => n.tag === "title")?.text;
    m.text = { ...(title ? { title: cut(title) } : {}), landmarks: dom.nodes.filter((n) => /^h[1-3]$/.test(n.tag) && n.text).slice(0, 20).map((n) => cut(n.text!)) };
  }
  const extracted = runExtractors(dom, o.extractors.filter((e) => e.pathPattern === pattern), pageUrl, pattern, red);
  if (Object.keys(extracted).length) m.extracted = extracted;
  if (reasons.length) m.incomplete = reasons.join("; ");
  return cap(m);
}

function runExtractors(dom: Dom, specs: ExtractorSpec[], pageUrl: string, pattern: string, red: Redactor): Record<string, Record<string, string[]>> {
  const out: Record<string, Record<string, string[]>> = {};
  const page = new URL(pageUrl);
  for (const spec of specs) {
    const fields: Record<string, string[]> = {};
    for (const f of spec.fields) {
      const vals: string[] = [];
      for (const idx of select(dom, f.select)) {
        if (vals.length >= f.max_items) break;
        const raw = dom.nodes[idx]!.attrs.get(f.attr);
        const urlish = f.attr === "href" || f.attr === "src" || f.attr === "action";
        let ok = true;
        switch (f.predicate) {
          case "present": ok = raw !== undefined; break;
          case "nonempty": ok = !!raw?.trim(); break;
          case "numeric": ok = raw !== undefined && /^-?\d{1,15}(?:\.\d{1,6})?$/.test(raw.trim()); break;
          case "same_origin_url": try { ok = raw !== undefined && new URL(raw, pageUrl).origin === page.origin; } catch { ok = false; } break;
          case "matches_path_pattern": try { ok = raw !== undefined && pathPattern(new URL(raw, pageUrl).pathname) === pattern; } catch { ok = false; } break;
        }
        if (!ok || raw === undefined) continue;
        // Extracted values pass the Redactor; URLs become display URLs.
        vals.push(urlish ? displayUrl(raw, pageUrl) ?? "[unparseable]" : red.text(raw).text.slice(0, 120));
      }
      fields[f.name] = vals;
    }
    out[spec.id] = fields;
  }
  return out;
}

/** Keeps the model within MAX_MODEL_BYTES, recording how much was omitted. */
function cap(m: PageModel): PageModel {
  const size = () => Buffer.byteLength(JSON.stringify(m));
  const omit = (k: string, n: number) => { if (n) (m.omitted ??= {})[k] = ((m.omitted ?? {})[k] ?? 0) + n; };
  if (m.links.length > 200) { omit("links", m.links.length - 200); m.links = m.links.slice(0, 200); }
  if (m.forms.length > 50) { omit("forms", m.forms.length - 50); m.forms = m.forms.slice(0, 50); }
  for (const f of m.forms) if (f.fields.length > 50) { omit("fields", f.fields.length - 50); f.fields = f.fields.slice(0, 50); }
  while (size() > MAX_MODEL_BYTES && m.links.length) { const n = Math.ceil(m.links.length / 2); omit("links", n); m.links = m.links.slice(0, m.links.length - n); }
  while (size() > MAX_MODEL_BYTES && m.forms.length) { omit("forms", 1); m.forms.pop(); }
  if (size() > MAX_MODEL_BYTES) { delete m.extracted; omit("extracted", 1); }
  return m;
}

/** Strict read-back: unknown fields are rejected; page models are data, never instructions. */
export function validatePageModel(x: unknown): PageModel {
  const ok = (o: unknown, keys: string[]) => !!o && typeof o === "object" && !Array.isArray(o) && Object.keys(o).every((k) => keys.includes(k));
  if (!ok(x, ["model", "url", "template", "forms", "links", "scripts", "security", "hashes", "text", "extracted", "omitted", "incomplete"])) throw new Error("not a page model (unknown fields)");
  const m = x as PageModel;
  if (m.model !== "1" || typeof m.url !== "string" || !ok(m.template, ["path_pattern", "shape_hash"]) || !Array.isArray(m.forms) || !Array.isArray(m.links)) throw new Error("not a page model");
  for (const f of m.forms) if (!ok(f, ["action", "method", "fields"]) || !Array.isArray(f.fields) || !f.fields.every((x) => ok(x, ["name", "type", "required"]))) throw new Error("invalid page model form");
  return m;
}
