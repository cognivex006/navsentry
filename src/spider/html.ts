/**
 * Bounded HTML tag tokenizer (SPEC-0.1.3 §6.2, owner decision D3: pure Node, no parser dependency).
 * It reads tag names and attributes only. Text, script and style bodies are skipped, never kept.
 * It is a grouping and link-extraction aid, never evidence for a finding.
 */
import { createHash } from "node:crypto";

export const MAX_TAGS = 100_000;
const RAW_TEXT = new Set(["script", "style", "textarea", "title", "xmp", "noscript", "template"]);
const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"]);
const ATTR = /([^\s"'=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;

export interface PageScan {
  /** sha256 of the tag skeleton: names and nesting only (no text, ids, classes or attribute values). */
  shapeHash: string;
  /** Raw href values of <a>/<area>, in document order (never fetched here). */
  hrefs: string[];
  base?: string;
  tags: number;
  /** true when MAX_TAGS stopped the scan; the skeleton and links are then partial. */
  truncated: boolean;
}

export function decodeEntities(s: string): string {
  return s.replace(/&(?:#x([0-9a-f]{1,6})|#([0-9]{1,7})|(amp|quot|apos|lt|gt));/gi, (_m, hex: string, dec: string, name: string) => {
    if (hex || dec) {
      const cp = hex ? parseInt(hex, 16) : Number(dec);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : "";
    }
    return ({ amp: "&", quot: '"', apos: "'", lt: "<", gt: ">" } as Record<string, string>)[name.toLowerCase()] ?? "";
  });
}

export function scanHtml(html: string): PageScan {
  const hash = createHash("sha256");
  const hrefs: string[] = [];
  let base: string | undefined;
  let tags = 0;
  let i = 0;
  while (i < html.length) {
    const lt = html.indexOf("<", i);
    if (lt < 0) break;
    if (html.startsWith("<!--", lt)) {
      const end = html.indexOf("-->", lt + 4);
      i = end < 0 ? html.length : end + 3;
      continue;
    }
    if (html[lt + 1] === "!" || html[lt + 1] === "?") {
      const end = html.indexOf(">", lt);
      i = end < 0 ? html.length : end + 1;
      continue;
    }
    const closing = html[lt + 1] === "/";
    const m = /^[A-Za-z][A-Za-z0-9-]*/.exec(html.slice(lt + (closing ? 2 : 1), lt + (closing ? 2 : 1) + 64));
    if (!m) { i = lt + 1; continue; }
    const name = m[0].toLowerCase();
    const end = findTagEnd(html, lt + 1);
    if (end < 0) break;
    if (++tags > MAX_TAGS) return { shapeHash: hash.digest("hex"), hrefs, ...(base ? { base } : {}), tags: MAX_TAGS, truncated: true };
    hash.update(closing ? `</${name}>` : VOID.has(name) ? `<${name}/>` : `<${name}>`);
    i = end + 1;
    if (closing) continue;
    const inner = html.slice(lt + 1 + name.length, end);
    if (name === "a" || name === "area" || (name === "base" && base === undefined)) {
      const href = attr(inner, "href");
      if (href !== undefined) {
        if (name === "base") base = href;
        else hrefs.push(href);
      }
    }
    if (RAW_TEXT.has(name)) {
      // Skip the raw-text body without tokenizing it; the closing tag is hashed on the next pass.
      const close = html.toLowerCase().indexOf(`</${name}`, i);
      i = close < 0 ? html.length : close;
    }
  }
  return { shapeHash: hash.digest("hex"), hrefs, ...(base ? { base } : {}), tags, truncated: false };
}

/** Finds the `>` that ends a tag, ignoring `>` inside quoted attribute values. */
function findTagEnd(s: string, from: number): number {
  let q: string | undefined;
  for (let j = from; j < s.length; j++) {
    const c = s[j];
    if (q) { if (c === q) q = undefined; }
    else if (c === '"' || c === "'") q = c;
    else if (c === ">") return j;
  }
  return -1;
}

function attr(inner: string, want: string): string | undefined {
  ATTR.lastIndex = 0;
  for (let m = ATTR.exec(inner); m; m = ATTR.exec(inner)) {
    if (m[1]!.toLowerCase() === want) return decodeEntities((m[2] ?? m[3] ?? m[4] ?? "").trim());
  }
  return undefined;
}

// ───────────────────────── URL patterns ─────────────────────────

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** True for path segments that identify an object rather than a template. */
export function isIdSegment(seg: string): boolean {
  if (/^\d+$/.test(seg)) return true;
  if (UUID.test(seg)) return true;
  if (/^[0-9a-f]{16,}$/i.test(seg)) return true; // hash-like
  if (seg.length >= 20 && /\d/.test(seg) && /[A-Za-z]/.test(seg) && /^[A-Za-z0-9_-]+$/.test(seg) && !seg.includes("-")) return true; // opaque token-like ids
  if (seg.length >= 24 && /^[a-z0-9]+(?:-[a-z0-9]+){3,}$/i.test(seg)) return true; // long slug
  return false;
}

/** `/product/1234/reviews` → `/product/{id}/reviews`. */
export function pathPattern(pathname: string): string {
  return pathname.split("/").map((s) => (s && isIdSegment(decodeURIComponentSafe(s)) ? "{id}" : s)).join("/");
}

function decodeURIComponentSafe(s: string): string {
  try { return decodeURIComponent(s); } catch { return s; }
}

/** Grouping key: (origin, actor, path_pattern, sorted query-key set). Actors are never merged. */
export function groupKey(u: URL, actor: string): string {
  const keys = [...new Set([...u.searchParams.keys()])].sort();
  return `${u.origin}\n${actor}\n${pathPattern(u.pathname)}\n${keys.join("&")}`;
}

/** URL identity for dedupe: query values kept in memory, fragment dropped. */
export function urlIdentity(u: URL): string {
  const c = new URL(u.toString());
  c.hash = "";
  return c.toString();
}
