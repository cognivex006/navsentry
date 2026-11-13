/**
 * M3 CLI transports (SPEC-0.4.0 D2; governance: curl / PowerShell APPROVED_WITH_CONDITIONS 2026-11-13).
 *
 * The same request a direct-http run would send, made by curl or PowerShell instead, so findings can be
 * compared across transports. Conditions, all enforced here:
 * - Executables come only from fixed system paths (TRUSTED_CURL / TRUSTED_PWSH), never PATH or a shell.
 * - ScopeGate checks the request, then NavSentry resolves the host itself and checks every address
 *   (`checkResolvedAddress`). The process is pinned to that address, so it cannot re-resolve to another
 *   one (DNS rebinding): curl through `--resolve`, PowerShell by connecting to the IP with the Host header.
 * - PowerShell cannot pin an https connection without breaking certificate checks, so https is refused there.
 * - The Budget is acquired before the process starts. No proxy, no redirects, http/https only, observe
 *   methods only (no request body). The child gets a scrubbed environment.
 * - Values reach curl as argv entries and PowerShell as JSON on stdin; the PowerShell script is fixed text.
 */
import { spawn } from "node:child_process";
import { lookup as dnsLookup } from "node:dns/promises";
import { createHash, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { isIP } from "node:net";
import { buildContract } from "../contract.js";
import type { Budget } from "../budget.js";
import type { Redactor } from "../redact.js";
import type { ScopeGate } from "../scope.js";
import type { CaptureInfo, HttpMethod, TransportStatus } from "../types.js";
import { DEFAULT_CAPTURE, ScopeDenied, USER_AGENT, templateUrl, type CaptureOptions } from "./direct-http.js";
import { TRUSTED_CURL, TRUSTED_PWSH, assertSafeHeader, scrubbedEnv } from "./optional.js";
import type { ExecutionAdapter, Exchange, HttpRequestSpec, TransportCapabilities } from "./types.js";

export type CliKind = "curl-cli" | "powershell-http";
const OBSERVE: ReadonlySet<string> = new Set(["GET", "HEAD", "OPTIONS"]);
const TIMEOUT_S = 15;

/** curl argv, pinned to `ip`. `-q` first so ~/.curlrc cannot add options. */
export function buildPinnedCurlArgv(method: HttpMethod, url: string, ip: string, headers: Record<string, string>, maxBytes: number): string[] {
  const u = new URL(url);
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("scheme not allowed");
  const port = u.port || (u.protocol === "https:" ? "443" : "80");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const argv = ["-q", "--silent", "--show-error", "--include", "--http1.1", "--proto", "=http,https", "--max-redirs", "0", "--max-time", String(TIMEOUT_S), "--max-filesize", String(maxBytes), "--noproxy", "*", "--resolve", `${host}:${port}:${ip.includes(":") ? `[${ip}]` : ip}`];
  argv.push(...(method === "HEAD" ? ["--head"] : ["-X", method]));
  for (const [k, v] of Object.entries(headers)) {
    assertSafeHeader(k, v);
    argv.push("-H", `${k}: ${v}`);
  }
  argv.push("--", u.toString());
  return argv;
}

/** Fixed PowerShell script (5.1 and 7): reads its parameters as JSON from stdin, never as script text. */
export const PWSH_PINNED_SCRIPT = String.raw`$ErrorActionPreference='Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
Add-Type -AssemblyName System.Net.Http
$u = [Uri]$p.uri
$h = New-Object System.Net.Http.HttpClientHandler
$h.UseProxy = $false; $h.AllowAutoRedirect = $false; $h.UseCookies = $false
$h.AutomaticDecompression = [System.Net.DecompressionMethods]::None
$c = New-Object System.Net.Http.HttpClient($h)
$c.Timeout = [TimeSpan]::FromSeconds([int]$p.timeout)
$b = New-Object System.UriBuilder($u)
if ($p.ip.Contains(':')) { $b.Host = '[' + $p.ip + ']' } else { $b.Host = $p.ip }
$rq = New-Object System.Net.Http.HttpRequestMessage((New-Object System.Net.Http.HttpMethod([string]$p.method)), $b.Uri)
$rq.Headers.Host = $u.Authority
foreach ($x in $p.headers.psobject.properties) { [void]$rq.Headers.TryAddWithoutValidation($x.Name, [string]$x.Value) }
$r = $c.SendAsync($rq, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
$s = $r.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
$ms = New-Object System.IO.MemoryStream
$buf = New-Object byte[] 65536
$t = $false
while (($n = $s.Read($buf, 0, $buf.Length)) -gt 0) {
  if ($ms.Length + $n -gt [int64]$p.max) { $ms.Write($buf, 0, [int]([int64]$p.max - $ms.Length)); $t = $true; break }
  $ms.Write($buf, 0, $n)
}
$hs = New-Object System.Collections.ArrayList
foreach ($x in $r.Headers) { foreach ($v in $x.Value) { [void]$hs.Add(@{ k = $x.Key; v = $v }) } }
foreach ($x in $r.Content.Headers) { foreach ($v in $x.Value) { [void]$hs.Add(@{ k = $x.Key; v = $v }) } }
$o = @{ status = [int]$r.StatusCode; headers = $hs.ToArray(); body = [Convert]::ToBase64String($ms.ToArray()); truncated = $t }
[Console]::Out.Write((ConvertTo-Json -InputObject $o -Depth 4 -Compress))`;

export function pwshArgv(): string[] {
  return ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", Buffer.from(PWSH_PINNED_SCRIPT, "utf16le").toString("base64")];
}

interface Parsed { status: number; headers: Record<string, string[]>; body: Buffer; truncated: boolean }

/** Parses curl --include output: skips 1xx blocks, then status line, headers and body. */
export function parseCurlOutput(out: Buffer, truncated: boolean): Parsed {
  let rest = out;
  for (;;) {
    const end = rest.indexOf("\r\n\r\n");
    if (end < 0) throw new Error("curl output has no header block");
    const head = rest.subarray(0, end).toString("latin1").split("\r\n");
    const m = /^HTTP\/[\d.]+ (\d{3})/.exec(head[0] ?? "");
    if (!m) throw new Error("curl output has no status line");
    const status = Number(m[1]);
    rest = rest.subarray(end + 4);
    if (status >= 100 && status < 200) continue;
    const headers: Record<string, string[]> = {};
    for (const line of head.slice(1)) {
      const i = line.indexOf(":");
      if (i > 0) (headers[line.slice(0, i).trim().toLowerCase()] ??= []).push(line.slice(i + 1).trim());
    }
    return { status, headers, body: rest, truncated };
  }
}

export function parsePwshOutput(out: Buffer): Parsed {
  const j = JSON.parse(out.toString("utf8")) as { status: number; headers: { k: string; v: string }[] | { k: string; v: string }; body: string; truncated: boolean };
  const list = Array.isArray(j.headers) ? j.headers : j.headers ? [j.headers] : [];
  const headers: Record<string, string[]> = {};
  for (const h of list) (headers[String(h.k).toLowerCase()] ??= []).push(String(h.v));
  return { status: j.status, headers, body: Buffer.from(j.body ?? "", "base64"), truncated: j.truncated === true };
}

function run(file: string, argv: string[], stdin: string | undefined, maxOut: number, signal: AbortSignal): Promise<{ out: Buffer; code: number | null; overflow: boolean; err: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(file, argv, { shell: false, windowsHide: true, env: scrubbedEnv(), stdio: ["pipe", "pipe", "pipe"] });
    const chunks: Buffer[] = [];
    let size = 0, overflow = false, err = "";
    const timer = setTimeout(() => child.kill(), (TIMEOUT_S + 10) * 1000);
    const onAbort = () => child.kill();
    signal.addEventListener("abort", onAbort, { once: true });
    child.stdout.on("data", (c: Buffer) => {
      if (overflow) return;
      if (size + c.length > maxOut) { chunks.push(c.subarray(0, maxOut - size)); size = maxOut; overflow = true; child.kill(); return; }
      chunks.push(c);
      size += c.length;
    });
    child.stderr.on("data", (c: Buffer) => { if (err.length < 500) err += c.toString("utf8"); });
    child.on("error", (e) => { clearTimeout(timer); signal.removeEventListener("abort", onAbort); reject(e); });
    child.on("close", (code) => { clearTimeout(timer); signal.removeEventListener("abort", onAbort); resolve({ out: Buffer.concat(chunks, size), code, overflow, err }); });
    child.stdin.end(stdin ?? "");
  });
}

const capabilities = (id: CliKind, cost: number): TransportCapabilities => ({
  id, mode: "cli-http", supportsAuthentication: true, supportsDOM: false, supportsJSRuntime: false, supportsNetworkCapture: true, supportsCookies: true, supportsFileUpload: false,
  sideEffectClasses: ["none", "read"], cost, timeoutMs: TIMEOUT_S * 1000, trustLevel: "vetted-executable", evidenceFormats: ["http-exchange"], platforms: "all",
  unenforceableChannels: id === "powershell-http" ? ["https (refused: the connection cannot be pinned to the checked address)"] : [],
});

export function findExecutable(kind: CliKind): string | undefined {
  return (kind === "curl-cli" ? TRUSTED_CURL : TRUSTED_PWSH).find((c) => existsSync(c));
}

/**
 * Preconditions for `--transport curl-cli|powershell-http` (SPEC-0.4.0 D2). Returns the executable or the reason
 * the run is refused; a flag never overrides the manifest, and nothing is substituted silently.
 */
export function cliTransportCheck(kind: string, order: string[], mode: string): { file: string } | { refused: string } {
  if (kind !== "curl-cli" && kind !== "powershell-http") return { refused: "--transport must be curl-cli or powershell-http" };
  if (!order.includes(kind)) return { refused: `${kind} is not in the manifest's transports.order; a flag never overrides manifest policy` };
  if (mode !== "observe") return { refused: `${kind} runs observe mode only (no request bodies)` };
  const file = findExecutable(kind);
  return file ? { file } : { refused: `${kind}: executable not found in trusted system locations` };
}

export class CliHttpAdapter implements ExecutionAdapter {
  readonly capabilities: TransportCapabilities;

  constructor(
    private readonly kind: CliKind,
    private readonly file: string,
    private readonly gate: ScopeGate,
    private readonly budget: Budget,
    private readonly redactor: Redactor,
    private readonly onDenied: (url: string, method: string, reason: string) => void = () => {},
    private readonly capture: CaptureOptions = DEFAULT_CAPTURE,
  ) {
    this.capabilities = capabilities(kind, kind === "curl-cli" ? 2 : 3);
  }

  async probe(): Promise<TransportStatus> {
    return { id: this.kind, available: true, usable: true, reason: `${this.kind} at a fixed system path; pinned to the ScopeGate-checked address` };
  }

  private deny(display: string, method: string, reason: string): never {
    this.onDenied(display, method, reason);
    throw new ScopeDenied(reason);
  }

  async send(spec: HttpRequestSpec): Promise<Exchange> {
    const display = spec.displayUrl ? templateUrl(this.redactor.url(spec.displayUrl)) : this.redactor.url(spec.url);
    if (spec.body || spec.mutation || !OBSERVE.has(spec.method)) this.deny(display, spec.method, `${this.kind} runs observe requests only (GET, HEAD, OPTIONS without a body)`);
    const decision = this.gate.checkRequest(spec.url, spec.method);
    if (!decision.allowed) this.deny(display, spec.method, decision.reason);
    const u = new URL(spec.url);
    if (this.kind === "powershell-http" && u.protocol === "https:") this.deny(display, spec.method, "powershell-http refuses https: the connection cannot be pinned to the checked address without breaking certificate validation");
    await this.budget.acquire(spec.fromReserve === true);
    const id = randomUUID();
    const started = Date.now();
    const headers: Record<string, string> = { "user-agent": USER_AGENT, accept: "*/*", "accept-encoding": "identity", connection: "close", ...Object.fromEntries(Object.entries(spec.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v])) };
    const base = {
      id, transport: this.kind, actor: spec.actor, method: spec.method, url: display,
      requestHeaders: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, this.redactor.headerValue(k, v)])),
      startedAt: new Date(started).toISOString(),
      ...(spec.flow ? { flow: spec.flow } : {}),
    };
    try {
      if (this.budget.signal.aborted) throw new Error("authorization window ended");
      // Resolve here and check every address; the process is pinned to the first one (connect-time check).
      const host = u.hostname.replace(/^\[|\]$/g, "");
      const addrs = isIP(host) ? [{ address: host }] : await dnsLookup(host, { all: true });
      if (!addrs.length) throw new Error("no address");
      for (const a of addrs) { const d = this.gate.checkResolvedAddress(host, a.address); if (!d.allowed) throw new ScopeDenied(d.reason); }
      const ip = addrs[0]!.address;
      const max = this.capture.maxResponseBytes;
      let parsed: Parsed;
      if (this.kind === "curl-cli") {
        const r = await run(this.file, buildPinnedCurlArgv(spec.method, spec.url, ip, headers, max), undefined, max + 64 * 1024, this.budget.signal);
        if (r.code !== 0 && !r.overflow) throw new Error(`curl exit ${r.code ?? "killed"}`);
        parsed = parseCurlOutput(r.out, r.overflow);
      } else {
        for (const [k, v] of Object.entries(headers)) assertSafeHeader(k, v);
        const input = JSON.stringify({ method: spec.method, uri: u.toString(), ip, headers, max, timeout: TIMEOUT_S });
        // Base64 inflates the body by 4/3; allow for it plus the JSON envelope.
        const r = await run(this.file, pwshArgv(), input, Math.ceil(max * 1.4) + 256 * 1024, this.budget.signal);
        if (r.code !== 0 || r.overflow) throw new Error(`powershell exit ${r.code ?? "killed"}`);
        parsed = parsePwshOutput(r.out);
      }
      const keep = Math.min(spec.retainBytes ?? this.capture.memoryBufferBytes, this.capture.memoryBufferBytes);
      const body = parsed.body.subarray(0, keep);
      if (this.capture.bytes && !this.capture.bytes.take(parsed.body.length, parsed.body.length)) parsed.truncated = true;
      const enc = parsed.headers["content-encoding"]?.[0]?.trim().toLowerCase();
      const capture: CaptureInfo = {
        status: parsed.truncated ? "truncated" : "complete",
        ...(parsed.truncated ? { reason: `response exceeded capture.max_response_bytes (${max})` } : {}),
        wireBytes: parsed.body.length, decodedBytes: parsed.body.length, retainedBytes: body.length,
        sha256: createHash("sha256").update(parsed.body).digest("hex"),
        ...(enc && enc !== "identity" ? { encoding: enc } : {}),
      };
      const ct = parsed.headers["content-type"]?.[0] ?? "";
      const red = spec.noExcerpt ? { outcome: { applied: false, count: 0, kinds: ["withheld:asset"], safe: true } } as ReturnType<Redactor["body"]> : this.redactor.body(body, ct);
      const loc = parsed.headers["location"]?.[0];
      return {
        record: {
          ...base, durationMs: Date.now() - started, status: parsed.status,
          responseHeaders: Object.fromEntries(Object.entries(parsed.headers).map(([k, vs]) => [k, vs.map((v) => this.redactor.headerValue(k, v))])),
          ...(red.excerpt !== undefined ? { bodyExcerpt: red.excerpt } : {}),
          bodyBytes: parsed.body.length, contract: buildContract(parsed.status, parsed.headers, body), redaction: red.outcome, capture,
        },
        raw: { status: parsed.status, headers: parsed.headers, body, capture, finalUrl: spec.url, ...(loc ? { redirectLocation: new URL(loc, u).toString() } : {}) },
      };
    } catch (e) {
      if (e instanceof ScopeDenied) this.onDenied(display, spec.method, e.message);
      const msg = e instanceof ScopeDenied ? `scope denied at connect: ${e.message}` : e instanceof Error && /^(curl|powershell) exit|authorization window|no address|output has/.test(e.message) ? `${this.kind} error: ${e.message}` : `${this.kind} error: ${(e as NodeJS.ErrnoException)?.code ?? "failed"}`;
      return { record: { ...base, durationMs: Date.now() - started, error: msg, redaction: { applied: false, count: 0, kinds: [], safe: true } } };
    }
  }
}
