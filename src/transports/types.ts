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
}

/** In-memory raw response. Never persisted; only the redacted ObservedRequest is. */
export interface RawResponse {
  status: number;
  headers: Record<string, string[]>;
  /** The retained prefix of the body (≤ capture.memory_buffer_bytes); see `capture`. */
  body: Buffer;
  capture?: CaptureInfo;
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
