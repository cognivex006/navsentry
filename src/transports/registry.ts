/**
 * Transport capability router. Selects the lowest-cost USABLE adapter whose declared
 * capabilities satisfy a requirement. An unavailable adapter is never substituted silently:
 * the caller gets `undefined` plus the reasons, and the check becomes NOT_TESTED.
 */
import type { TransportStatus } from "../types.js";
import { DIRECT_HTTP_CAPABILITIES } from "./direct-http.js";
import { CurlCliAdapter, PlaywrightBrowserAdapter, PowerShellHttpAdapter, VisualComputerUseAdapter, ZapPassiveAdapter } from "./optional.js";
import type { ExecutionAdapter, TransportCapabilities } from "./types.js";

/** Probe-only instances (direct-http is constructed per run with its scope gate). */
export function allAdapters(): ExecutionAdapter[] {
  return [
    { capabilities: DIRECT_HTTP_CAPABILITIES, probe: async () => ({ id: "direct-http", available: true, usable: true, reason: "built-in node:http/https", version: process.versions.node }) },
    new PlaywrightBrowserAdapter(),
    new CurlCliAdapter(),
    new PowerShellHttpAdapter(),
    new VisualComputerUseAdapter(),
    new ZapPassiveAdapter(),
  ];
}

export interface Requirement {
  needsDOM?: boolean;
  needsJSRuntime?: boolean;
  needsCookies?: boolean;
  allowedTransports: string[];
}

export interface RouteDecision {
  selected?: string;
  rejected: { id: string; reason: string }[];
}

export function route(req: Requirement, adapters: { capabilities: TransportCapabilities; status: TransportStatus }[]): RouteDecision {
  const rejected: RouteDecision["rejected"] = [];
  const candidates = adapters
    .filter((a) => {
      const c = a.capabilities;
      if (!req.allowedTransports.includes(c.id)) return rejected.push({ id: c.id, reason: "not in manifest transports.order" }), false;
      if (!a.status.usable) return rejected.push({ id: c.id, reason: a.status.reason }), false;
      if (req.needsDOM && !c.supportsDOM) return rejected.push({ id: c.id, reason: "no DOM support" }), false;
      if (req.needsJSRuntime && !c.supportsJSRuntime) return rejected.push({ id: c.id, reason: "no JS runtime" }), false;
      if (req.needsCookies && !c.supportsCookies) return rejected.push({ id: c.id, reason: "no cookie support" }), false;
      return true;
    })
    .sort((a, b) => a.capabilities.cost - b.capabilities.cost);
  return { ...(candidates[0] ? { selected: candidates[0].capabilities.id } : {}), rejected };
}
