/**
 * Functions that Playwright serializes and runs inside the page (visual driver, SPEC-0.3.0 §5).
 * They must be self-contained: no imports or closures. The project has no DOM types, so page
 * globals are declared locally as untyped.
 */
import type { ElementInfo, PageSnapshot, SnapshotElement } from "./playwright.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
declare const document: any;
declare const getComputedStyle: any;
declare const innerHeight: number;
declare const innerWidth: number;
declare const location: any;

/**
 * Runs in the page. It labels visible interactive elements with data-nsref and returns role, accessible
 * name, tag and position. It never returns a field value. Page scripts can tamper with what it sees, so
 * the result is target data, never instructions.
 */
export function snapshotInPage(max: number): PageSnapshot {
  for (const old of Array.from(document.querySelectorAll("[data-nsref]")) as any[]) old.removeAttribute("data-nsref");
  const sel = "a[href],button,input,select,textarea,summary,[role=button],[role=link],[role=tab],[role=menuitem],[role=checkbox],[role=radio],[role=combobox],[contenteditable=true]";
  const out: SnapshotElement[] = [];
  let n = 0;
  let truncated = false;
  for (const el of Array.from(document.querySelectorAll(sel)) as any[]) {
    const r = el.getBoundingClientRect();
    const st = getComputedStyle(el);
    if (r.width <= 0 || r.height <= 0 || st.visibility === "hidden" || st.display === "none") continue;
    if (out.length >= max) { truncated = true; break; }
    const ref = "e" + ++n;
    el.setAttribute("data-nsref", ref);
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute("type") ?? "").toLowerCase();
    const role = el.getAttribute("role") ?? (tag === "a" ? "link" : tag === "button" || type === "submit" || type === "button" ? "button" : tag === "select" ? "combobox" : tag === "textarea" ? "textbox" : tag === "input" ? (type === "checkbox" ? "checkbox" : type === "radio" ? "radio" : "textbox") : tag);
    let name = el.getAttribute("aria-label") ?? "";
    const labels = (el as any).labels;
    if (!name && labels && labels.length) name = labels[0]!.innerText;
    if (!name && tag !== "input" && tag !== "textarea" && tag !== "select") name = el.innerText ?? "";
    if (!name) name = el.getAttribute("placeholder") ?? el.getAttribute("title") ?? el.getAttribute("alt") ?? el.getAttribute("name") ?? "";
    const v = (el as any).value;
    const item: SnapshotElement = { ref, role, name: name.replace(/\s+/g, " ").trim().slice(0, 80), tag, password: type === "password", x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2), inViewport: r.bottom > 0 && r.right > 0 && r.top < innerHeight && r.left < innerWidth };
    if (type) item.type = type;
    if (tag === "a") item.href = (el as any).href;
    if (typeof v === "string" && tag !== "button" && tag !== "a") item.hasValue = v !== "";
    out.push(item);
  }
  return { url: location.href, title: document.title.slice(0, 120), elements: out, truncated };
}

/** Runs in the page: role, name and editability of one element (by ref or at a point). No value. */
export function describeInPage(a: { ref?: string; x?: number; y?: number }): ElementInfo | null {
  const el = (a.ref ? document.querySelector(`[data-nsref="${a.ref}"]`) : document.elementFromPoint(a.x ?? -1, a.y ?? -1)) as any | null;
  const target = (el?.closest("a[href],button,input,select,textarea,summary,[role]") as any | null) ?? el;
  if (!target) return null;
  const tag = target.tagName.toLowerCase();
  const type = (target.getAttribute("type") ?? "").toLowerCase();
  const role = target.getAttribute("role") ?? (tag === "a" ? "link" : tag === "button" || type === "submit" ? "button" : tag === "input" || tag === "textarea" ? "textbox" : tag === "select" ? "combobox" : tag);
  let name = target.getAttribute("aria-label") ?? "";
  const labels = (target as any).labels;
  if (!name && labels && labels.length) name = labels[0]!.innerText;
  if (!name && tag !== "input" && tag !== "textarea") name = target.innerText ?? "";
  if (!name) name = target.getAttribute("placeholder") ?? target.getAttribute("name") ?? "";
  const textual = ["", "text", "search", "email", "url", "tel", "number", "password"].includes(type);
  const info: ElementInfo = { role, name: name.replace(/\s+/g, " ").trim().slice(0, 80), tag, password: type === "password", editable: (tag === "input" && textual) || tag === "textarea" || target.isContentEditable };
  if (type) info.type = type;
  return info;
}


/**
 * Init script for the headed visual driver: reports trusted clicks (a person's, or the agent's own, which the
 * session tells apart by timing) with the role and accessible name of the nearest interactive element. It runs
 * before page scripts, keeps the binding in its closure and removes it from `window`, so later page code cannot
 * call it. Role and name are page data. Never reads field values.
 */
export function humanWatchScript(binding: string): string {
  return `(() => {
  const b = window[${JSON.stringify(binding)}];
  try { delete window[${JSON.stringify(binding)}]; } catch (e) {}
  if (typeof b !== "function") return;
  const sel = "a[href],button,input,select,textarea,summary,[role=button],[role=link],[role=tab],[role=menuitem],[role=checkbox],[role=radio],[role=combobox]";
  addEventListener("click", (ev) => {
    if (!ev.isTrusted) return;
    const t = ev.target && ev.target.closest ? ev.target.closest(sel) : null;
    if (!t) { b({ role: "", name: "" }); return; }
    const tag = t.tagName.toLowerCase();
    const type = (t.getAttribute("type") || "").toLowerCase();
    const role = t.getAttribute("role") || (tag === "a" ? "link" : tag === "button" || type === "submit" || type === "button" ? "button" : tag === "select" ? "combobox" : tag === "input" || tag === "textarea" ? "textbox" : tag);
    let name = t.getAttribute("aria-label") || "";
    if (!name && t.labels && t.labels.length) name = t.labels[0].innerText || "";
    if (!name && tag !== "input" && tag !== "textarea" && tag !== "select") name = t.innerText || "";
    b({ role, name: String(name).replace(/\\s+/g, " ").trim().slice(0, 120) });
  }, true);
})();`;
}

/** Runs in the page: names of cookies readable through document.cookie. Values are cut off here and never returned. */
export function cookieNamesInPage(max: number): string[] {
  const raw = String(document.cookie ?? "");
  if (!raw) return [];
  return raw.split(";").map((p: string) => p.split("=")[0]!.trim().slice(0, 80)).filter((n: string) => n).slice(0, max);
}

/**
 * Init script: reports CSP violations (directive, blocked origin, disposition) through a binding it keeps in its
 * closure and removes from `window`, like humanWatchScript. Only the origin of a blocked URL is sent.
 */
export function cspWatchScript(binding: string): string {
  return `(() => {
  const b = window[${JSON.stringify(binding)}];
  try { delete window[${JSON.stringify(binding)}]; } catch (e) {}
  if (typeof b !== "function") return;
  let n = 0;
  addEventListener("securitypolicyviolation", (ev) => {
    if (++n > 50) return;
    let blocked = String(ev.blockedURI || "");
    try { if (/^https?:/.test(blocked)) blocked = new URL(blocked).origin; } catch (e) { blocked = ""; }
    b({ directive: String(ev.effectiveDirective || ev.violatedDirective || ""), blocked, disposition: String(ev.disposition || "") });
  }, true);
})();`;
}
