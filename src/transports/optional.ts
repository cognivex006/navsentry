/**
 * Optional transports. Each reports honest availability; none is ever mocked as live.
 * In v0.1 only `direct-http` executes requests. The others are probed (doctor/integrations)
 * and their safety-critical argument builders are implemented and unit-tested ahead of M3.
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

/**
 * Builds curl argv (no shell). `-q` MUST be first so ~/.curlrc cannot inject options;
 * redirects are disabled so the runner re-checks scope per hop.
 */
export function buildCurlArgv(method: HttpMethod, url: string, headers: Record<string, string>): string[] {
  const u = new URL(url);
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("scheme not allowed");
  const argv = ["-q", "--silent", "--show-error", "--include", "--proto", "=http,https", "--max-redirs", "0", "--max-time", "15", "--max-filesize", "1048576", "--noproxy", "*", "-X", method];
  for (const [k, v] of Object.entries(headers)) {
    assertSafeHeader(k, v);
    argv.push("-H", `${k}: ${v}`);
  }
  argv.push("--", u.toString());
  return argv;
}

/**
 * PowerShell parameters are passed as data via a fixed script and -EncodedCommand-free argv;
 * user values never become script text. MaximumRedirection 0 keeps scope checks per hop.
 */
export const PWSH_FIXED_SCRIPT =
  "param([string]$Method,[string]$Uri,[string]$HeadersJson) $ErrorActionPreference='Stop'; $h=@{}; (ConvertFrom-Json $HeadersJson).psobject.properties | ForEach-Object { $h[$_.Name]=[string]$_.Value }; $r=Invoke-WebRequest -UseBasicParsing -Method $Method -Uri $Uri -Headers $h -MaximumRedirection 0 -TimeoutSec 15 -NoProxy -SkipHttpErrorCheck; [pscustomobject]@{status=[int]$r.StatusCode; headers=$r.Headers} | ConvertTo-Json -Depth 4 -Compress";

export function buildPwshArgv(method: HttpMethod, url: string, headers: Record<string, string>): string[] {
  const u = new URL(url);
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("scheme not allowed");
  for (const [k, v] of Object.entries(headers)) assertSafeHeader(k, v);
  return ["-NoProfile", "-NonInteractive", "-Command", `& { ${PWSH_FIXED_SCRIPT} }`, "-Method", method, "-Uri", u.toString(), "-HeadersJson", JSON.stringify(headers)];
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
    return { id: this.capabilities.id, available: true, usable: false, reason: "detected; request execution is scheduled for milestone M3 (argv builder implemented and tested)", version };
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
  readonly capabilities = base("visual-computer-use", "visual", 9, { trustLevel: "external-provider", evidenceFormats: ["screenshot"], unenforceableChannels: ["everything rendered by the provider's own browser"] });
  async probe(): Promise<TransportStatus> {
    return { id: this.capabilities.id, available: false, usable: false, reason: "no visual provider configured; interface only (provider terms must be reviewed before integration)" };
  }
}

export class ZapPassiveAdapter implements ExecutionAdapter {
  readonly capabilities = base("zap-passive", "proxy-passive", 6, { evidenceFormats: ["network-log"] });
  async probe(): Promise<TransportStatus> {
    return { id: this.capabilities.id, available: false, usable: false, reason: "phase-2 integration; not implemented" };
  }
}
