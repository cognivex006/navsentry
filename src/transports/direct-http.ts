/**
 * Library-native HTTP transport (node:http / node:https). Zero dependencies.
 * - Scope is checked before the request and again at connect time via a custom `lookup`,
 *   so a hostname that re-resolves to a private/metadata address is refused (DNS rebinding).
 * - Redirects are never followed here; the runner re-checks scope for each hop.
 * - Bodies are bounded; nothing raw leaves this module except the in-memory RawResponse.
 */
import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import http from "node:http";
import https from "node:https";
import { randomUUID } from "node:crypto";
import { buildContract } from "../contract.js";
import type { Budget } from "../budget.js";
import type { Redactor } from "../redact.js";
import type { ScopeGate } from "../scope.js";
import type { TransportStatus } from "../types.js";
import type { ExecutionAdapter, Exchange, HttpRequestSpec, TransportCapabilities } from "./types.js";

export const MAX_BODY_BYTES = 1024 * 1024;
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
    const decision = this.gate.checkRequest(spec.url, spec.method);
    if (!decision.allowed) {
      this.onDenied(this.redactor.url(spec.url), spec.method, decision.reason);
      throw new ScopeDenied(decision.reason);
    }
    await this.budget.acquire();
    const id = randomUUID();
    const started = Date.now();
    const u = new URL(spec.url);
    const headers: Record<string, string> = { "user-agent": USER_AGENT, accept: "*/*", "accept-encoding": "identity", ...lower(spec.headers ?? {}) };
    const redactedReqHeaders = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, this.redactor.headerValue(k, v)]));
    const base = {
      id,
      transport: this.capabilities.id,
      actor: spec.actor,
      method: spec.method,
      url: this.redactor.url(spec.url),
      requestHeaders: redactedReqHeaders,
      startedAt: new Date(started).toISOString(),
    };
    const mod = u.protocol === "https:" ? https : http;
    try {
      const raw = await new Promise<{ status: number; headers: Record<string, string[]>; body: Buffer }>((resolve, reject) => {
        const req = mod.request(
          u,
          { method: spec.method, headers, lookup: this.guardedLookup as never, timeout: this.capabilities.timeoutMs, agent: false },
          (res) => {
            const chunks: Buffer[] = [];
            let size = 0;
            res.on("data", (c: Buffer) => {
              size += c.length;
              if (size <= MAX_BODY_BYTES) chunks.push(c);
              else res.destroy();
            });
            const done = () => {
              const hdrs: Record<string, string[]> = {};
              for (let i = 0; i < res.rawHeaders.length; i += 2) {
                const k = (res.rawHeaders[i] as string).toLowerCase();
                (hdrs[k] ??= []).push(res.rawHeaders[i + 1] as string);
              }
              resolve({ status: res.statusCode ?? 0, headers: hdrs, body: Buffer.concat(chunks) });
            };
            res.on("end", done);
            res.on("close", done);
            res.on("error", reject);
          },
        );
        req.on("timeout", () => req.destroy(new Error("request timeout")));
        req.on("error", reject);
        req.end();
      });
      const ct = raw.headers["content-type"]?.[0] ?? "";
      const body = this.redactor.body(raw.body, ct);
      const responseHeaders = Object.fromEntries(Object.entries(raw.headers).map(([k, vs]) => [k, vs.map((v) => this.redactor.headerValue(k, v))]));
      const loc = raw.headers["location"]?.[0];
      return {
        record: {
          ...base,
          durationMs: Date.now() - started,
          status: raw.status,
          responseHeaders,
          ...(body.excerpt !== undefined ? { bodyExcerpt: body.excerpt } : {}),
          bodyBytes: raw.body.length,
          contract: buildContract(raw.status, raw.headers, raw.body),
          redaction: body.outcome,
        },
        raw: { ...raw, ...(loc ? { redirectLocation: new URL(loc, u).toString() } : {}) },
      };
    } catch (e) {
      if (e instanceof ScopeDenied) this.onDenied(this.redactor.url(spec.url), spec.method, e.message);
      return {
        record: { ...base, durationMs: Date.now() - started, error: e instanceof ScopeDenied ? `scope denied at connect: ${e.message}` : safeError(e), redaction: { applied: false, count: 0, kinds: [], safe: true } },
      };
    }
  }
}

function lower(h: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), v]));
}

/** Error text without echoing request data. */
export function safeError(e: unknown): string {
  const err = e as NodeJS.ErrnoException;
  if (err?.code) return `network error: ${err.code}`;
  if (err?.message === "request timeout") return "network error: timeout";
  return "network error";
}
