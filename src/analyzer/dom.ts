/**
 * Bounded element tree for the page-model analyzer (SPEC-0.1.3 §5, owner decision D3: pure Node,
 * no parser dependency). It keeps element names, attributes (bounded) and nesting. Text is kept
 * only for <title> and h1–h3 (used solely when `analyzer.include_text` is set) and is otherwise only
 * hashed. Script and style bodies are skipped. Limits make every document bounded in time and memory.
 */
import { createHash } from "node:crypto";
import { decodeEntities } from "../spider/html.js";

export const MAX_NODES = 50_000;
const MAX_ATTR_LEN = 2048;
const RAW_TEXT = new Set(["script", "style", "textarea", "xmp", "noscript", "template"]);
const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr", "param", "keygen"]);
const KEEP_TEXT = new Set(["title", "h1", "h2", "h3"]);
const ATTR = /([^\s"'=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;

export interface Node {
  tag: string;
  attrs: Map<string, string>;
  parent: number;
  /** Text of title / h1–h3 only (bounded); never other text. */
  text?: string;
}

export interface Dom {
  nodes: Node[];
  /** sha256 of all visible text (high-entropy whole-page digest, never per value). */
  textHash: string;
  truncated: boolean;
}

export function parseDom(html: string, deadline = Number.POSITIVE_INFINITY): Dom {
  const nodes: Node[] = [];
  const stack: number[] = [];
  const text = createHash("sha256");
  let truncated = false;
  let i = 0;
  const top = () => (stack.length ? stack[stack.length - 1]! : -1);
  const addText = (s: string) => {
    if (!s.trim()) return;
    const t = decodeEntities(s).replace(/\s+/g, " ");
    text.update(t);
    for (let k = stack.length - 1; k >= 0; k--) {
      const n = nodes[stack[k]!]!;
      if (KEEP_TEXT.has(n.tag)) { n.text = `${n.text ?? ""}${t}`.slice(0, 512); break; }
    }
  };
  while (i < html.length) {
    if ((nodes.length & 1023) === 0 && Date.now() > deadline) { truncated = true; break; }
    const lt = html.indexOf("<", i);
    if (lt < 0) { addText(html.slice(i)); break; }
    if (lt > i) addText(html.slice(i, lt));
    if (html.startsWith("<!--", lt)) { const e = html.indexOf("-->", lt + 4); i = e < 0 ? html.length : e + 3; continue; }
    if (html[lt + 1] === "!" || html[lt + 1] === "?") { const e = html.indexOf(">", lt); i = e < 0 ? html.length : e + 1; continue; }
    const closing = html[lt + 1] === "/";
    const m = /^[A-Za-z][A-Za-z0-9-]*/.exec(html.slice(lt + (closing ? 2 : 1), lt + (closing ? 2 : 1) + 64));
    if (!m) { addText("<"); i = lt + 1; continue; }
    const tag = m[0].toLowerCase();
    const end = tagEnd(html, lt + 1);
    if (end < 0) break;
    i = end + 1;
    if (closing) {
      const at = stack.map((n) => nodes[n]!.tag).lastIndexOf(tag);
      if (at >= 0) stack.length = at;
      continue;
    }
    if (nodes.length >= MAX_NODES) { truncated = true; break; }
    const attrs = new Map<string, string>();
    const inner = html.slice(lt + 1 + tag.length, html[end - 1] === "/" ? end - 1 : end);
    ATTR.lastIndex = 0;
    for (let a = ATTR.exec(inner); a && attrs.size < 64; a = ATTR.exec(inner)) {
      const k = a[1]!.toLowerCase();
      if (!attrs.has(k)) attrs.set(k, decodeEntities((a[2] ?? a[3] ?? a[4] ?? "").slice(0, MAX_ATTR_LEN)));
    }
    // Implicit closes for the common cases, so siblings do not nest forever.
    if ((tag === "p" || tag === "li" || tag === "option" || tag === "tr" || tag === "td" || tag === "th") && top() >= 0 && nodes[top()]!.tag === tag) stack.pop();
    nodes.push({ tag, attrs, parent: top() });
    const idx = nodes.length - 1;
    if (VOID.has(tag) || html[end - 1] === "/") continue;
    if (RAW_TEXT.has(tag)) {
      const close = html.toLowerCase().indexOf(`</${tag}`, i);
      i = close < 0 ? html.length : close;
      continue;
    }
    stack.push(idx);
  }
  return { nodes, textHash: text.digest("hex"), truncated };
}

function tagEnd(s: string, from: number): number {
  let q: string | undefined;
  for (let j = from; j < s.length; j++) {
    const c = s[j];
    if (q) { if (c === q) q = undefined; }
    else if (c === '"' || c === "'") q = c;
    else if (c === ">") return j;
  }
  return -1;
}

/** Index of the nearest ancestor (or self) with `tag`, or -1. */
export function closest(dom: Dom, idx: number, tag: string): number {
  for (let k = idx; k >= 0; k = dom.nodes[k]!.parent) if (dom.nodes[k]!.tag === tag) return k;
  return -1;
}
