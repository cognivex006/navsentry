/**
 * Response-contract fingerprints. Used by `navsentry compare` to prove a security fix did
 * not change what legitimate callers receive (status, content type, header set, JSON shape).
 */
import { createHash } from "node:crypto";
import type { ResponseContract } from "./types.js";

/** Headers whose values or presence legitimately vary between runs or are security-only. */
const VOLATILE = new Set(["date", "age", "etag", "last-modified", "expires", "set-cookie", "content-length", "x-request-id", "x-correlation-id", "traceparent", "server-timing", "keep-alive", "connection", "transfer-encoding", "vary", "via", "x-cache", "cf-ray"]);

/** Security headers are expected to change during remediation; tracked separately, not as contract drift. */
export const SECURITY_HEADERS = new Set(["strict-transport-security", "content-security-policy", "content-security-policy-report-only", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy", "cross-origin-embedder-policy", "cache-control", "pragma", "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]);

function skeleton(v: unknown, depth = 0): unknown {
  if (depth > 12) return "…";
  if (Array.isArray(v)) {
    // Union of element skeletons so array length / ordering does not cause drift.
    const set = new Map<string, unknown>();
    for (const e of v.slice(0, 50)) {
      const s = skeleton(e, depth + 1);
      set.set(JSON.stringify(s), s);
    }
    return ["array", [...set.keys()].sort()];
  }
  if (v === null) return "null";
  if (typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v as object).sort()) o[k] = skeleton((v as Record<string, unknown>)[k], depth + 1);
    return o;
  }
  return typeof v;
}

export function jsonShapeHash(body: string): string | undefined {
  try {
    return createHash("sha256").update(JSON.stringify(skeleton(JSON.parse(body)))).digest("hex").slice(0, 16);
  } catch {
    return undefined;
  }
}

function bucket(n: number): string {
  if (n === 0) return "0";
  const e = Math.floor(Math.log2(n));
  return `2^${e}`;
}

export function buildContract(status: number, headers: Record<string, string[]>, body: Buffer): ResponseContract {
  const contentType = (headers["content-type"]?.[0] ?? "").split(";")[0]!.trim().toLowerCase();
  const headerNames = Object.keys(headers)
    .map((h) => h.toLowerCase())
    .filter((h) => !VOLATILE.has(h) && !SECURITY_HEADERS.has(h))
    .sort();
  const c: ResponseContract = { status, contentType, headerNames, bodyLengthBucket: bucket(body.length) };
  if (/json/.test(contentType)) {
    const h = jsonShapeHash(body.toString("utf8"));
    if (h) c.jsonShapeHash = h;
  }
  return c;
}
