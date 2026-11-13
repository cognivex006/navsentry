/**
 * Optional transports. Each reports honest availability; none is ever mocked as live.
 * direct-http executes requests by default; curl-cli and powershell-http execute them with `--transport`
 * (M3, src/transports/cli-http.ts). The others are probed (doctor/integrations).
 */
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import type { HttpMethod, TransportStatus } from "../types.js";
import type { ExecutionAdapter, TransportCapabilities } from "./types.js";
import { probePlaywright } from "./playwright.js";

const base = (id: string, mode: TransportCapabilities["mode"], cost: number, extra: Partial<TransportCapabilities>): TransportCapabilities => ({
  id,
  mode,
  supportsAuthentication: false,
  supportsDOM: false,
  supportsJSRuntime: false,
  supportsNetworkCapture: false,
  supportsCookies: false,
  supportsFileUpload: false,
  sideEffectClasses: ["none", "read"],
  cost,
  timeoutMs: 15000,
  trustLevel: "vetted-executable",
  evidenceFormats: ["http-exchange"],
  platforms: "all",
  unenforceableChannels: [],
  ...extra,
});

/** Minimal environment for child processes: no proxies, no credentials, no config injection. */
export function scrubbedEnv(): NodeJS.ProcessEnv {
  const keep = ["SystemRoot", "WINDIR", "PATHEXT", "TEMP", "TMP"];
  const env: NodeJS.ProcessEnv = { PATH: process.platform === "win32" ? `${process.env.SystemRoot ?? "C:\\Windows"}\\System32` : "/usr/bin:/bin" };
  for (const k of keep) if (process.env[k]) env[k] = process.env[k];
  return env;
}

function runVersion(file: string, args: string[]): Promise<string | undefined> {
  return new Promise((resolve) => {
    execFile(file, args, { shell: false, timeout: 5000, env: scrubbedEnv(), windowsHide: true }, (err, stdout) => {
      resolve(err ? undefined : String(stdout).split(/\r?\n/)[0]?.trim());
    });
  });
}

/** Executables are only taken from fixed system locations, never from an arbitrary PATH entry. */
export const TRUSTED_CURL = process.platform === "win32" ? [`${process.env.SystemRoot ?? "C:\\Windows"}\\System32\\curl.exe`] : ["/usr/bin/curl", "/bin/curl"];
export const TRUSTED_PWSH = process.platform === "win32"
  ? ["C:\\Program Files\\PowerShell\\7\\pwsh.exe", `${process.env.SystemRoot ?? "C:\\Windows"}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`]
  : ["/usr/bin/pwsh", "/opt/microsoft/powershell/7/pwsh"];

const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

export function assertSafeHeader(name: string, value: string): void {
  if (!HEADER_NAME.test(name)) throw new Error("invalid header name");
  if (/[\r\n\0]/.test(value)) throw new Error("header value contains CR/LF/NUL");
}

abstract class ProbedCli implements ExecutionAdapter {
  abstract readonly capabilities: TransportCapabilities;
  protected abstract candidates: string[];
  protected abstract versionArgs: string[];
  async probe(): Promise<TransportStatus> {
    const file = this.candidates.find((c) => existsSync(c));
    if (!file) return { id: this.capabilities.id, available: false, usable: false, reason: "executable not found in trusted system locations" };
    const version = await runVersion(file, this.versionArgs);
    if (!version) return { id: this.capabilities.id, available: false, usable: false, reason: "executable present but version probe failed" };
    return { id: this.capabilities.id, available: true, usable: true, reason: "fixed system path; `--transport` sends observe requests pinned to the ScopeGate-checked address (M3)", version };
  }
}

export class CurlCliAdapter extends ProbedCli {
  readonly capabilities = base("curl-cli", "cli-http", 2, { supportsAuthentication: true, supportsCookies: true });
  protected candidates = TRUSTED_CURL;
  protected versionArgs = ["-q", "--version"];
}

export class PowerShellHttpAdapter extends ProbedCli {
  readonly capabilities = base("powershell-http", "cli-http", 3, { supportsAuthentication: true, supportsCookies: true, platforms: ["win32", "linux", "darwin"] });
  protected candidates = TRUSTED_PWSH;
  protected versionArgs = ["-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"];
}

export class PlaywrightBrowserAdapter implements ExecutionAdapter {
  readonly capabilities = base("playwright-browser", "browser", 5, {
    supportsAuthentication: true,
    supportsDOM: true,
    supportsJSRuntime: true,
    supportsNetworkCapture: true,
    supportsCookies: true,
    trustLevel: "in-process",
    evidenceFormats: ["dom-snapshot", "console", "network-log", "screenshot"],
    // Every routed request is fulfilled through ScopeGate/Budget; these channels are disabled, not enforced (ADR-0008).
    unenforceableChannels: ["WebSocket (disabled: closed before connecting)", "service workers (disabled: blocked per context)", "browser-internal traffic (disabled by launch flags and a dead proxy, not by ScopeGate)"],
  });
  async probe(): Promise<TransportStatus> {
    return { id: this.capabilities.id, ...probePlaywright() };
  }
}

export class VisualComputerUseAdapter implements ExecutionAdapter {
  // NavSentry owns the browser (ADR-0009); the host agent only sees screenshots and sends coordinates.
  readonly capabilities = base("visual-computer-use", "visual", 9, { trustLevel: "in-process", supportsDOM: true, supportsJSRuntime: true, supportsCookies: true, evidenceFormats: ["screenshot", "network-log"], unenforceableChannels: ["WebSocket (disabled: closed before connecting)", "service workers (disabled: blocked per context)", "browser-internal traffic (disabled by launch flags and a dead proxy, not by ScopeGate)", "screenshots leave NavSentry through the host agent (owner consent: transports.visual_computer_use)"] });
  async probe(): Promise<TransportStatus> {
    // The visual driver (ADR-0009) runs on the playwright engine; NavSentry calls no visual provider itself.
    const p = probePlaywright();
    return { id: this.capabilities.id, available: p.available, usable: p.usable, reason: p.usable ? "visual driver over playwright-browser: `navsentry browse` (development; needs transports.visual_computer_use: true)" : `visual driver needs the playwright engine: ${p.reason}`, ...(p.version ? { version: p.version } : {}) };
  }
}

export class ZapPassiveAdapter implements ExecutionAdapter {
  readonly capabilities = base("zap-passive", "proxy-passive", 6, { evidenceFormats: ["network-log"] });
  async probe(): Promise<TransportStatus> {
    return { id: this.capabilities.id, available: false, usable: false, reason: "phase-2 integration; not implemented" };
  }
}
