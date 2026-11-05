/**
 * Library-native HTTP transport (node:http / node:https). Zero dependencies.
 * - Scope is checked before the request and again at connect time via a custom `lookup`,
 *   so a hostname that re-resolves to a private/metadata address is refused (DNS rebinding).
 * - Redirects are never followed here; the runner re-checks scope for each hop.
 * - Bodies are streamed: every byte is counted and hashed, a bounded prefix is retained, and
 *   the capture records whether it is complete, truncated (budget) or aborted (early close).
 *   Nothing raw leaves this module except the in-memory RawResponse.
 */
import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import http from "node:http";
import https from "node:https";
import { createHash, randomUUID } from "node:crypto";
import { closeSync, openSync, writeSync } from "node:fs";
import { buildContract } from "../contract.js";
import { CAPTURE_DEFAULTS } from "../config.js";
import type { Budget, ByteBudget } from "../budget.js";
import type { Redactor } from "../redact.js";
import type { ScopeGate } from "../scope.js";
import type { CaptureInfo, TransportStatus } from "../types.js";
import type { ExecutionAdapter, Exchange, HttpRequestSpec, TransportCapabilities } from "./types.js";

export interface CaptureOptions {
  /** Decoded bytes read per response before the capture is `truncated`. */
  maxResponseBytes: number;
  /** Prefix kept in memory for checks. */
  memoryBufferBytes: number;
  /** Shared run-level byte budget. */
  bytes?: ByteBudget;
}

export const DEFAULT_CAPTURE: CaptureOptions = { maxResponseBytes: CAPTURE_DEFAULTS.max_response_bytes, memoryBufferBytes: CAPTURE_DEFAULTS.memory_buffer_bytes };
export const USER_AGENT = "NavSentry/0.1 (+authorized-security-test)";

export class ScopeDenied extends Error {}

export const DIRECT_HTTP_CAPABILITIES: TransportCapabilities = {
    id: "direct-http",
    mode: "http",
    supportsAuthentication: true,
    supportsDOM: false,
    supportsJSRuntime: false,
    supportsNetworkCapture: true,
    supportsCookies: true,
    supportsFileUpload: false,
    sideEffectClasses: ["none", "read"],
    cost: 1,
    timeoutMs: 15000,
    trustLevel: "in-process",
    evidenceFormats: ["http-exchange"],
    platforms: "all",
    unenforceableChannels: [],
};

export class DirectHttpAdapter implements ExecutionAdapter {
  readonly capabilities = DIRECT_HTTP_CAPABILITIES;

  constructor(
    private readonly gate: ScopeGate,
    private readonly budget: Budget,
    private readonly redactor: Redactor,
    private readonly onDenied: (url: string, method: string, reason: string) => void = () => {},
    private readonly capture: CaptureOptions = DEFAULT_CAPTURE,
  ) {}

  async probe(): Promise<TransportStatus> {
    return { id: this.capabilities.id, available: true, usable: true, reason: "built-in node:http/https", version: process.versions.node };
  }

  private guardedLookup = (hostname: string, options: unknown, cb: (...a: unknown[]) => void): void => {
    const opts = (typeof options === "object" && options !== null ? options : {}) as { all?: boolean; family?: number };
    dnsLookup(hostname, { all: true, family: opts.family ?? 0 }, (err, addresses: LookupAddress[]) => {
      if (err) return cb(err);
      for (const a of addresses) {
        const d = this.gate.checkResolvedAddress(hostname, a.address);
        if (!d.allowed) return cb(new ScopeDenied(d.reason));
      }
      if (opts.all) return cb(null, addresses);
      const first = addresses[0];
      if (!first) return cb(new Error("no address"));
      cb(null, first.address, first.family);
    });
  };

  async send(spec: HttpRequestSpec): Promise<Exchange> {
    if (spec.body && !spec.mutation) throw new ScopeDenied("a request body is allowed only on a declared mutation");
    const decision = spec.mutation ? this.gate.checkMutation(spec.url, spec.method, spec.mutation) : this.gate.checkRequest(spec.url, spec.method);
    if (!decision.allowed) {
      this.onDenied(spec.displayUrl ? templateUrl(this.redactor.url(spec.displayUrl)) : this.redactor.url(spec.url), spec.method, decision.reason);
      throw new ScopeDenied(decision.reason);
    }
    await this.budget.acquire(spec.fromReserve === true);
    const id = randomUUID();
    const started = Date.now();
    const u = new URL(spec.url);
    const headers: Record<string, string> = { "user-agent": USER_AGENT, accept: "*/*", "accept-encoding": "identity", ...lower(spec.headers ?? {}), ...(spec.body ? { "content-type": spec.body.contentType, "content-length": String(spec.body.data.length) } : {}) };
    const redactedReqHeaders = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, this.redactor.headerValue(k, v)]));
    const base = {
      id,
      transport: this.capabilities.id,
      actor: spec.actor,
      method: spec.method,
      url: spec.displayUrl ? templateUrl(this.redactor.url(spec.displayUrl)) : this.redactor.url(spec.url),
      requestHeaders: redactedReqHeaders,
      startedAt: new Date(started).toISOString(),
      ...(spec.flow ? { flow: spec.flow } : {}),
      ...(spec.body ? { requestBodySha256: createHash("sha256").update(spec.body.data).digest("hex") } : {}),
    };
    const mod = u.protocol === "https:" ? https : http;
    const lim = this.capture;
    try {
      const raw = await new Promise<{ status: number; headers: Record<string, string[]>; body: Buffer; capture: CaptureInfo }>((resolve, reject) => {
        const signal = this.budget.signal;
        if (signal.aborted) return reject(new Error("authorization window ended"));
        const req = mod.request(
          u,
          { method: spec.method, headers, lookup: this.guardedLookup as never, timeout: this.capabilities.timeoutMs, agent: false },
          (res) => {
            // Streamed capture: count and hash every byte, retain a bounded prefix, stop at budgets.
            // Nothing here trusts Content-Length; limits apply to observed bytes.
            const chunks: Buffer[] = [];
            const hash = createHash("sha256");
            const keepMax = Math.min(spec.retainBytes ?? lim.memoryBufferBytes, lim.memoryBufferBytes);
            let decoded = 0, retained = 0;
            let fd: number | undefined;
            try {
              if (spec.spool) fd = openSync(spec.spool.path, "wx", 0o600);
            } catch {
              fd = undefined;
            }
            let stop: { status: "truncated" | "aborted"; reason: string } | undefined;
            const halt = (s: NonNullable<typeof stop>) => { stop ??= s; res.destroy(); };
            res.on("data", (c: Buffer) => {
              if (stop) return;
              const room = lim.maxResponseBytes - decoded;
              const part = c.length > room ? c.subarray(0, Math.max(0, room)) : c;
              decoded += part.length;
              hash.update(part);
              if (retained < keepMax) {
                const keep = part.subarray(0, keepMax - retained);
                chunks.push(keep);
                retained += keep.length;
              }
              if (spec.spool) {
                spec.spool.budget.used += part.length;
                if (spec.spool.budget.used > spec.spool.budget.max) return halt({ status: "truncated", reason: `spool exceeded capture.max_work_bytes (${spec.spool.budget.max})` });
                try {
                  if (fd === undefined) throw new Error("spool unavailable");
                  writeSync(fd, part);
                } catch (e) {
                  return halt({ status: "aborted", reason: `spool write failed (${(e as NodeJS.ErrnoException).code ?? "error"})` });
                }
              }
              if (lim.bytes && !lim.bytes.take(c.length, part.length)) return halt({ status: "truncated", reason: "run byte budget exhausted" });
              if (c.length > room) halt({ status: "truncated", reason: `response exceeded capture.max_response_bytes (${lim.maxResponseBytes})` });
            });
            let settled = false;
            const done = (ended: boolean) => {
              if (settled) return;
              settled = true;
              signal.removeEventListener("abort", onAbort);
              if (fd !== undefined) { try { closeSync(fd); } catch { /* reported by the reader */ } fd = undefined; }
              const hdrs: Record<string, string[]> = {};
              for (let i = 0; i < res.rawHeaders.length; i += 2) {
                const k = (res.rawHeaders[i] as string).toLowerCase();
                (hdrs[k] ??= []).push(res.rawHeaders[i + 1] as string);
              }
              const enc = hdrs["content-encoding"]?.[0]?.trim().toLowerCase();
              const st = stop ?? (ended ? undefined : { status: "aborted" as const, reason: "connection closed before the body ended" });
              const capture: CaptureInfo = {
                status: st?.status ?? "complete",
                ...(st ? { reason: st.reason } : {}),
                wireBytes: res.socket?.bytesRead ?? decoded,
                decodedBytes: decoded,
                retainedBytes: retained,
                sha256: hash.digest("hex"),
                ...(enc && enc !== "identity" ? { encoding: enc } : {}),
              };
              resolve({ status: res.statusCode ?? 0, headers: hdrs, body: Buffer.concat(chunks, retained), capture });
            };
            res.on("end", () => done(true));
            res.on("close", () => done(res.complete));
            res.on("error", (e) => { if (stop) done(false); else reject(e); });
          },
        );
        const onAbort = () => req.destroy(new Error("authorization window ended"));
        signal.addEventListener("abort", onAbort, { once: true });
        req.on("timeout", () => req.destroy(new Error("request timeout")));
        req.on("error", (e) => { signal.removeEventListener("abort", onAbort); reject(e); });
        req.end(spec.body?.data);
      });
      const ct = raw.headers["content-type"]?.[0] ?? "";
      const body = spec.noExcerpt ? { outcome: { applied: false, count: 0, kinds: ["withheld:asset"], safe: true } } as ReturnType<Redactor["body"]> : this.redactor.body(raw.body, ct);
      const responseHeaders = Object.fromEntries(Object.entries(raw.headers).map(([k, vs]) => [k, vs.map((v) => this.redactor.headerValue(k, v))]));
      const loc = raw.headers["location"]?.[0];
      return {
        record: {
          ...base,
          durationMs: Date.now() - started,
          status: raw.status,
          responseHeaders,
          ...(body.excerpt !== undefined ? { bodyExcerpt: body.excerpt } : {}),
          bodyBytes: raw.capture.decodedBytes,
          contract: buildContract(raw.status, raw.headers, raw.body),
          redaction: body.outcome,
          capture: raw.capture,
        },
        raw: { ...raw, finalUrl: spec.url, ...(loc ? { redirectLocation: new URL(loc, u).toString() } : {}) },
      };
    } catch (e) {
      if (e instanceof ScopeDenied) this.onDenied(base.url, spec.method, e.message);
      return {
        record: { ...base, durationMs: Date.now() - started, error: e instanceof ScopeDenied ? `scope denied at connect: ${e.message}` : safeError(e), redaction: { applied: false, count: 0, kinds: [], safe: true } },
      };
    }
  }
}

/** Restores {{name}} placeholders that URL serialization percent-encoded. */
export function templateUrl(u: string): string {
  return u.replace(/%7B%7B([A-Za-z0-9_]+)%7D%7D/gi, "{{$1}}");
}

function lower(h: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]));
}

/** Error text without echoing request data. */
export function safeError(e: unknown): string {
  const err = e as NodeJS.ErrnoException;
  if (err?.code) return `network error: ${err.code}`;
  if (err?.message === "request timeout") return "network error: timeout";
  if (err?.message === "authorization window ended") return "cancelled: authorization window ended";
  return "network error";
}
