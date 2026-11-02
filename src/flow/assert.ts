/**
 * Functional expectations over an in-memory response (spec §5.6). Results are value-free:
 * they report codes, media types, JSON types and matched/differs, never response values.
 */
import { jsonShapeHash } from "../contract.js";
import type { Exchange } from "../transports/types.js";
import type { AssertionResult, CheckStatus } from "../types.js";
import type { Expect } from "./parse.js";

const mediaType = (ex: Exchange) => (ex.raw?.headers["content-type"]?.[0] ?? "").split(";")[0]!.trim().toLowerCase();

export function jsonType(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

/** RFC 6901 JSON Pointer. Returns { found:false } when any token is missing. */
export function resolvePointer(doc: unknown, pointer: string): { found: boolean; value?: unknown } {
  if (pointer === "") return { found: true, value: doc };
  let cur: unknown = doc;
  for (const raw of pointer.slice(1).split("/")) {
    const tok = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(cur)) {
      if (!/^(0|[1-9][0-9]*)$/.test(tok) || Number(tok) >= cur.length) return { found: false };
      cur = cur[Number(tok)];
    } else if (cur && typeof cur === "object" && Object.prototype.hasOwnProperty.call(cur, tok)) {
      cur = (cur as Record<string, unknown>)[tok];
    } else return { found: false };
  }
  return { found: true, value: cur };
}

export function statusMatches(status: number, exp: NonNullable<Expect["status"]>): boolean {
  if (typeof exp === "string") return Math.floor(status / 100) === Number(exp[0]);
  return exp.includes(status);
}

const r = (kind: AssertionResult["kind"], ok: boolean | "inconclusive", expected: string, observed: string): AssertionResult => ({
  kind,
  status: (ok === "inconclusive" ? "INCONCLUSIVE" : ok ? "PASS" : "FAIL") as CheckStatus,
  expected,
  observed,
});

/** Evaluates every expectation except `access: denied`, which needs positive controls (post-pass). */
export function evaluate(e: Expect, ex: Exchange, origin: string): AssertionResult[] {
  const out: AssertionResult[] = [];
  const raw = ex.raw!;
  if (e.status) out.push(r("status", statusMatches(raw.status, e.status), `status ${Array.isArray(e.status) ? e.status.join("|") : e.status}`, `status ${raw.status}`));
  if (e.access === "allowed") out.push(r("access", raw.status >= 200 && raw.status < 300, "allowed (2xx)", `status ${raw.status}`));
  if (e.content_type) out.push(r("content_type", mediaType(ex) === e.content_type, e.content_type, mediaType(ex) || "none"));
  for (const h of e.headers_present ?? []) out.push(r("header_present", h in raw.headers, `${h} present`, h in raw.headers ? "present" : "absent"));
  for (const h of e.headers_absent ?? []) out.push(r("header_absent", !(h in raw.headers), `${h} absent`, h in raw.headers ? "present" : "absent"));
  // A body that was not captured completely never supports PASS or FAIL (SPEC-0.1.3 §6.5-A).
  const partial = raw.capture && (raw.capture.status !== "complete" || raw.capture.retainedBytes < raw.capture.decodedBytes);
  if (partial && (e.json || e.shape || e.text_present || e.text_absent)) {
    const why = `body ${raw.capture!.status}, ${raw.capture!.retainedBytes} of ${raw.capture!.decodedBytes} bytes retained`;
    for (const j of e.json ?? []) out.push(r("json", "inconclusive", `${j.pointer || "/"}`, why));
    if (e.shape) out.push(r("shape", "inconclusive", `JSON shape ${e.shape}`, why));
    (e.text_present ?? []).forEach((_, i) => out.push(r("text_present", "inconclusive", `marker ${i + 1} present`, why)));
    (e.text_absent ?? []).forEach((_, i) => out.push(r("text_absent", "inconclusive", `marker ${i + 1} absent`, why)));
  } else if (e.json || e.shape) {
    let parsed: unknown;
    let ok = true;
    try {
      parsed = JSON.parse(raw.body.toString("utf8"));
    } catch {
      ok = false;
    }
    for (const j of e.json ?? []) {
      const exp = [j.type && `type ${j.type}`, j.exists !== undefined && (j.exists ? "exists" : "absent"), j.equals !== undefined && "equals expected literal", j.min_items !== undefined && `≥${j.min_items} items`].filter(Boolean).join(", ");
      const label = `${j.pointer || "/"}: ${exp}`;
      if (!ok) { out.push(r("json", false, label, "body is not JSON")); continue; }
      const p = resolvePointer(parsed, j.pointer);
      if (j.exists === false) { out.push(r("json", !p.found, label, p.found ? "present" : "absent")); continue; }
      if (!p.found) { out.push(r("json", false, label, "absent")); continue; }
      const t = jsonType(p.value);
      const fails: string[] = [];
      if (j.type && t !== j.type) fails.push(`type ${t}`);
      if (j.equals !== undefined && p.value !== j.equals) fails.push("differs (value withheld)");
      if (j.min_items !== undefined && (!Array.isArray(p.value) || p.value.length < j.min_items)) fails.push(Array.isArray(p.value) ? `${p.value.length} items` : `type ${t}`);
      out.push(r("json", fails.length === 0, label, fails.length ? fails.join(", ") : `present, type ${t}${j.equals !== undefined ? ", matched" : ""}`));
    }
    if (e.shape) {
      const h = ok ? jsonShapeHash(raw.body.toString("utf8")) : undefined;
      out.push(r("shape", h === e.shape, `JSON shape ${e.shape}`, h === e.shape ? "matched" : h ? "differs" : "body is not JSON"));
    }
  }
  if (!partial && (e.text_present || e.text_absent)) {
    const body = raw.body.toString("utf8");
    (e.text_present ?? []).forEach((t, i) => out.push(r("text_present", body.includes(t), `marker ${i + 1} present`, body.includes(t) ? "present" : "absent")));
    (e.text_absent ?? []).forEach((t, i) => out.push(r("text_absent", !body.includes(t), `marker ${i + 1} absent`, body.includes(t) ? "present" : "absent")));
  }
  if (e.redirect_to) {
    let observed = "not a redirect";
    let ok = false;
    if (raw.status >= 300 && raw.status < 400 && raw.redirectLocation) {
      const u = new URL(raw.redirectLocation);
      ok = u.origin === origin && u.pathname === e.redirect_to;
      observed = u.origin === origin ? `redirect to ${u.pathname}` : "redirect to another origin";
    }
    out.push(r("redirect_to", ok, `redirect to ${e.redirect_to}`, observed));
  }
  return out;
}

const RANK: Record<CheckStatus, number> = { FAIL: 5, ERROR: 4, INCONCLUSIVE: 3, PASS: 2, NOT_TESTED: 1 };

export function worst(statuses: CheckStatus[]): CheckStatus {
  return statuses.reduce<CheckStatus>((a, b) => (RANK[b] > RANK[a] ? b : a), "PASS");
}
