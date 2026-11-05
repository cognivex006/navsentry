import type { CaptureInfo, HttpMethod, ObservedRequest, TransportStatus } from "../types.js";

export type SideEffectClass = "none" | "read" | "state-change";
export type TrustLevel = "in-process" | "vetted-executable" | "external-provider";
export type EvidenceFormat = "http-exchange" | "dom-snapshot" | "screenshot" | "console" | "network-log";

/** Declared, static capabilities of a transport. Availability is probed separately. */
export interface TransportCapabilities {
  id: string;
  mode: "http" | "browser" | "cli-http" | "visual" | "proxy-passive";
  supportsAuthentication: boolean;
  supportsDOM: boolean;
  supportsJSRuntime: boolean;
  supportsNetworkCapture: boolean;
  supportsCookies: boolean;
  supportsFileUpload: boolean;
  sideEffectClasses: SideEffectClass[];
  /** Relative cost/risk rank; the router prefers the lowest that satisfies a check. */
  cost: number;
  timeoutMs: number;
  trustLevel: TrustLevel;
  evidenceFormats: EvidenceFormat[];
  platforms: NodeJS.Platform[] | "all";
  /** Channels this transport cannot constrain; documented, never claimed secure. */
  unenforceableChannels: string[];
}

export interface HttpRequestSpec {
  method: HttpMethod;
  url: string;
  headers?: Record<string, string>;
  actor: string;
  /** URL to record instead of `url` (flow template form, e.g. /api/orders/{{orderA}}). */
  displayUrl?: string;
  /** Flow step that issued the request. */
  flow?: { id: string; step: string; deniedProbe?: true };
  /** Record no body excerpt (static assets: raw content never reaches artifacts, S8). */
  noExcerpt?: true;
  /** Bytes kept in memory for checks; defaults to capture.memory_buffer_bytes. */
  retainBytes?: number;
  /**
   * Streams every captured body byte into this file (created exclusively, mode 0600) inside the
   * run's work directory. `budget` is the shared on-disk spool budget (capture.max_work_bytes).
   */
  spool?: { path: string; budget: { used: number; max: number } };
  /**
   * safe-validate only (SPEC-0.2.0 §3.3): the declared entry this non-observe request must match;
   * the adapter then checks `ScopeGate.checkMutation` instead of `checkRequest`.
   */
  mutation?: { method: string; path: string };
  /** Request body (mutations only). Its sha256 is recorded, never its content. */
  body?: { contentType: string; data: Buffer };
  /** Cleanup request: draws a slot held by `Budget.reserve`. */
  fromReserve?: true;
}

/** In-memory raw response. Never persisted; only the redacted ObservedRequest is. */
export interface RawResponse {
  status: number;
  headers: Record<string, string[]>;
  /** The retained prefix of the body (≤ capture.memory_buffer_bytes); see `capture`. */
  body: Buffer;
  capture?: CaptureInfo;
  /** The URL this exchange requested (raw, in memory only). */
  finalUrl?: string;
  /** Location of a redirect that was NOT followed (scope re-check happens in the runner). */
  redirectLocation?: string;
}

export interface Exchange {
  record: ObservedRequest;
  raw?: RawResponse;
}

export interface ExecutionAdapter {
  readonly capabilities: TransportCapabilities;
  probe(): Promise<TransportStatus>;
  /** Present only on adapters that can execute HTTP exchanges in this release. */
  send?(spec: HttpRequestSpec): Promise<Exchange>;
}
