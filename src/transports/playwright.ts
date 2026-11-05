/**
 * Playwright browser engine (M1b, development profile only).
 *
 * S1 design (docs/adr/0008-playwright-engine-s1.md): the browser never opens a network
 * connection of its own. Every request it makes is intercepted by `context.route('**')` and is
 * either fulfilled from NavSentry's direct-http transport (ScopeGate before the request, the
 * connect-time DNS check, the shared Budget) or aborted. As defence in depth the browser is
 * launched against a dead proxy with all host resolution disabled, so a request that escaped
 * routing would fail instead of reaching the network. WebSocket is closed before any connection
 * and service workers are blocked. Nothing here ever calls `route.continue()`.
 */
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import type { Exchange } from "./types.js";
import type { UiTarget } from "../flow/parse.js";

/** Minimal structural types of the playwright-core API used here (it is an optional peer). */
interface PwRequest { postDataBuffer(): Buffer | null; url(): string; method(): string; headers(): Record<string, string>; resourceType(): string; isNavigationRequest(): boolean; frame(): { parentFrame(): unknown } }
interface PwRoute { request(): PwRequest; fulfill(o: { status: number; headers: Record<string, string>; body: Buffer }): Promise<void>; abort(code?: string): Promise<void> }
interface PwWebSocketRoute { url(): string; close(o?: { code?: number; reason?: string }): Promise<void> }
interface PwMouse { click(x: number, y: number): Promise<void>; wheel(dx: number, dy: number): Promise<void> }
interface PwLocator { first(): PwLocator; fill(v: string, o: { timeout: number }): Promise<void>; selectOption(v: string, o: { timeout: number }): Promise<unknown>; click(o: { timeout: number }): Promise<void>; waitFor(o: { state: "visible"; timeout: number }): Promise<void>; isVisible(): Promise<boolean> }
interface PwConsoleMessage { type(): string; text(): string; location(): { url: string; lineNumber: number } }
interface PwPage {
  goto(url: string, o: { timeout: number; waitUntil: "load" }): Promise<{ status(): number } | null>;
  waitForLoadState(s: "load" | "networkidle", o: { timeout: number }): Promise<void>;
  getByRole(role: string, o: { name: string; exact: true }): PwLocator;
  getByLabel(t: string, o: { exact: true }): PwLocator;
  getByText(t: string, o: { exact: true }): PwLocator;
  getByTestId(t: string): PwLocator;
  on(ev: "console", fn: (m: PwConsoleMessage) => void): void;
  on(ev: "popup", fn: (p: PwPage) => void): void;
  on(ev: "pageerror", fn: (e: Error) => void): void;
  close(): Promise<void>;
  mouse: PwMouse;
  screenshot(o: { path: string; type: "png"; fullPage: false }): Promise<unknown>;
  url(): string;
  waitForEvent(ev: "framenavigated", o: { timeout: number }): Promise<unknown>;
}
interface PwContext {
  route(p: string, fn: (r: PwRoute) => Promise<void>): Promise<void>;
  routeWebSocket(p: string, fn: (ws: PwWebSocketRoute) => Promise<void>): Promise<void>;
  newPage(): Promise<PwPage>;
  close(): Promise<void>;
  cookies(urls?: string[]): Promise<{ name: string; value: string }[]>;
}
interface PwBrowser { newContext(o: Record<string, unknown>): Promise<PwContext>; close(): Promise<void> }
interface PwChromium { executablePath(): string; launch(o: Record<string, unknown>): Promise<PwBrowser> }

export const PLAYWRIGHT_VERSION = "1.64.1";
const ACTION_TIMEOUT_MS = 10_000;
/** Fixed viewport so screenshot pixel coordinates are click coordinates (visual driver). */
export const VIEWPORT = { width: 1280, height: 800 } as const;

/** Launch flags that leave the browser without a usable network path of its own (defence in depth). */
export const ISOLATION_ARGS = [
  "--proxy-server=http://127.0.0.1:9",
  "--proxy-bypass-list=<-loopback>",
  "--host-resolver-rules=MAP * ~NOTFOUND",
  "--disable-background-networking",
  "--disable-component-update",
  "--disable-domain-reliability",
  "--disable-sync",
  "--no-pings",
  "--dns-prefetch-disable",
  "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
  "--disable-features=NetworkPrediction,OptimizationHints,MediaRouter,DialMediaRouteProvider",
];

/** Response headers the browser must not see from a fulfilled, already-decoded body. */
const DROP_RESPONSE = new Set(["content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive"]);
/** Request headers the browser may forward to direct-http; everything else is dropped. */
const KEEP_REQUEST = new Set(["accept", "accept-language", "cookie", "referer", "user-agent", "if-none-match", "if-modified-since"]);

export interface BrowserRequest {
  method: string;
  url: string;
  actor: string;
  headers: Record<string, string>;
  resourceType: string;
  /** A main-frame document load (the page a step's expectations are evaluated against). */
  mainDocument: boolean;
}

const OBSERVE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export interface ConsoleEvent { actor: string; type: string; text: string; sourceUrl: string; line?: number }

export interface BrowserEngineOptions {
  /** Sends through ScopeGate → Budget → direct-http. Returns undefined when scope denied it. */
  send(req: BrowserRequest): Promise<Exchange | undefined>;
  /** Records a request the engine refused before sending (WebSocket, non-observe method…). */
  onDenied(url: string, method: string, reason: string): void;
  onConsole?(e: ConsoleEvent): void;
  /**
   * safe-validate only (SPEC-0.2.0 §3.3): decides a non-observe browser request. The runner matches a declared
   * entry with `checkMutation`, checks the content type and body size, and sends it through direct-http.
   * Without this hook every non-observe request is refused (observe engine, visual driver).
   */
  mutate?(req: BrowserRequest & { body: Buffer; contentType: string }): Promise<Exchange | undefined>;
}

/** Browser builds come from the process's PLAYWRIGHT_BROWSERS_PATH (read once by playwright-core at load). */
function loadChromium(): PwChromium {
  const req = createRequire(import.meta.url);
  return (req("playwright-core") as { chromium: PwChromium }).chromium;
}

/** Availability without launching anything: package version pinned and the headless shell installed. */
export type PlaywrightProbe = { available: boolean; usable: boolean; reason: string; version?: string };
export function probePlaywright(): { available: boolean; usable: boolean; reason: string; version?: string } {
  let version: string;
  try {
    version = (createRequire(import.meta.url)("playwright-core/package.json") as { version: string }).version;
  } catch {
    return { available: false, usable: false, reason: "optional package 'playwright-core' is not installed (NavSentry never installs it automatically)" };
  }
  if (version !== PLAYWRIGHT_VERSION) return { available: true, usable: false, reason: `playwright-core ${version} is not the governance-approved ${PLAYWRIGHT_VERSION}`, version };
  let exe: string;
  try {
    exe = headlessShellPath(loadChromium());
  } catch (e) {
    return { available: true, usable: false, reason: `browser path unresolved: ${(e as Error).message}`, version };
  }
  if (!existsSync(exe)) return { available: true, usable: false, reason: "Chromium headless shell is not installed; run `npx playwright-core install --only-shell chromium` (NavSentry never downloads it)", version };
  return { available: true, usable: true, reason: "playwright-core with Chromium headless shell; every request is fulfilled through ScopeGate and Budget (S1)", version };
}

/** The approved build is the headless shell; the full and branded builds are not used. */
function headlessShellPath(ch: PwChromium): string {
  return ch.executablePath().replace(/chromium-(\d+)([\\/])chrome-(win64|win|linux64|linux|mac-arm64|mac-x64|mac)[\\/][^\\/]+$/i, (_m, n: string, sep: string, plat: string) => {
    const exe = plat.startsWith("win") ? "chrome-headless-shell.exe" : "chrome-headless-shell";
    return `chromium_headless_shell-${n}${sep}chrome-headless-shell-${plat.replace(/^win$/, "win64").replace(/^linux$/, "linux64")}${sep}${exe}`;
  });
}

function locate(page: PwPage, t: UiTarget): PwLocator {
  if ("role" in t) return page.getByRole(t.role, { name: t.name, exact: true }).first();
  if ("label" in t) return page.getByLabel(t.label, { exact: true }).first();
  if ("text" in t) return page.getByText(t.text, { exact: true }).first();
  return page.getByTestId(t.test_id).first();
}

export class BrowserEngine {
  private contexts = new Map<string, { ctx: PwContext; page: PwPage }>();
  private constructor(private readonly browser: PwBrowser, private readonly opts: BrowserEngineOptions, private readonly actorHeaders: Map<string, Record<string, string>>) {}

  static async open(opts: BrowserEngineOptions, actorHeaders: Map<string, Record<string, string>>): Promise<BrowserEngine> {
    const ch = loadChromium();
    // headless: true selects the Chromium headless shell, the only approved build.
    const browser = await ch.launch({ headless: true, args: ISOLATION_ARGS, env: {}, handleSIGINT: false, handleSIGTERM: false });
    return new BrowserEngine(browser, opts, actorHeaders);
  }

  /** One isolated context per actor: cookies and storage never cross actors. */
  private async session(actor: string): Promise<{ ctx: PwContext; page: PwPage }> {
    const have = this.contexts.get(actor);
    if (have) return have;
    const ctx = await this.browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: 1, serviceWorkers: "block", acceptDownloads: false, bypassCSP: false, ignoreHTTPSErrors: false, javaScriptEnabled: true });
    await ctx.routeWebSocket("**", async (ws) => {
      this.opts.onDenied(ws.url(), "GET", "WebSocket is disabled in the playwright engine (S1: frames after the upgrade cannot be checked)");
      await ws.close({ code: 1008, reason: "blocked by NavSentry" });
    });
    await ctx.route("**", (r) => this.handle(r, actor));
    const page = await ctx.newPage();
    const watch = (p: PwPage) => {
      p.on("console", (m) => { const l = m.location(); this.opts.onConsole?.({ actor, type: m.type(), text: m.text(), sourceUrl: l.url, ...(l.lineNumber ? { line: l.lineNumber } : {}) }); });
      p.on("pageerror", (e) => this.opts.onConsole?.({ actor, type: "pageerror", text: String(e.stack ?? e.message), sourceUrl: "" }));
    };
    watch(page);
    page.on("popup", watch);
    const s = { ctx, page };
    this.contexts.set(actor, s);
    return s;
  }

  private async handle(route: PwRoute, actor: string): Promise<void> {
    const rq = route.request();
    const url = rq.url();
    let u: URL;
    try { u = new URL(url); } catch { await route.abort("blockedbyclient"); return; }
    if (u.protocol !== "http:" && u.protocol !== "https:") { await route.abort("blockedbyclient"); return; }
    const observe = OBSERVE_METHODS.has(rq.method());
    if (!observe && !this.opts.mutate) {
      // The browser would send a body NavSentry cannot vet; observe mode sends no state-changing request.
      this.opts.onDenied(url, rq.method(), "state-changing browser request refused (observe engine)");
      await route.abort("blockedbyclient");
      return;
    }
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(rq.headers())) if (KEEP_REQUEST.has(k.toLowerCase())) headers[k.toLowerCase()] = v;
    Object.assign(headers, this.actorHeaders.get(actor) ?? {});
    let ex: Exchange | undefined;
    try {
      const base = { method: rq.method(), url, actor, headers, resourceType: rq.resourceType(), mainDocument: rq.isNavigationRequest() && rq.frame().parentFrame() === null };
      ex = observe ? await this.opts.send(base) : await this.opts.mutate!({ ...base, body: rq.postDataBuffer() ?? Buffer.alloc(0), contentType: rq.headers()["content-type"] ?? "" });
    } catch {
      // The caller records the reason (budget, transport error); the page just sees a failed load.
      await route.abort("failed");
      return;
    }
    if (!ex) { await route.abort("blockedbyclient"); return; }
    const raw = ex.raw;
    if (ex.record.error || !raw) { await route.abort("failed"); return; }
    if (raw.capture && (raw.capture.status !== "complete" || raw.capture.encoding)) {
      // A partial body would be rendered as if it were the page: refuse instead of guessing.
      await route.abort("failed");
      return;
    }
    const out: Record<string, string> = {};
    for (const [k, vs] of Object.entries(raw.headers)) if (!DROP_RESPONSE.has(k)) out[k] = vs.join(k === "set-cookie" ? "\n" : ", ");
    await route.fulfill({ status: raw.status, headers: out, body: raw.body });
  }

  async navigate(actor: string, url: string): Promise<{ status?: number; error?: string }> {
    const { page } = await this.session(actor);
    try {
      const r = await page.goto(url, { timeout: ACTION_TIMEOUT_MS, waitUntil: "load" });
      return r ? { status: r.status() } : { error: "navigation produced no response" };
    } catch (e) {
      return { error: `navigation failed: ${firstLine(e)}` };
    }
  }

  /** Session cookies the actor's context holds for an origin (browser login, SPEC-0.2.0 §4.3). Values stay in memory. */
  async cookies(actor: string, origin: string): Promise<{ name: string; value: string }[]> {
    const s = this.contexts.get(actor);
    return s ? s.ctx.cookies([origin]) : [];
  }

  /**
   * click | see | wait_for, and in safe-validate fill | select | submit. Returns whether the expectation held;
   * errors are reported, not thrown. A filled value is never returned or logged.
   */
  async act(actor: string, action: "click" | "see" | "wait_for" | "fill" | "select" | "submit", target: UiTarget, value?: string): Promise<{ ok: boolean; observed: string; error?: string }> {
    const s = this.contexts.get(actor);
    if (!s) return { ok: false, observed: "no page loaded for this actor", error: "a navigate step must run first" };
    const loc = locate(s.page, target);
    try {
      if (action === "fill") { await loc.fill(value ?? "", { timeout: ACTION_TIMEOUT_MS }); return { ok: true, observed: "filled (value not shown)" }; }
      if (action === "select") { await loc.selectOption(value ?? "", { timeout: ACTION_TIMEOUT_MS }); return { ok: true, observed: "selected (value not shown)" }; }
      if (action === "submit") {
        await loc.click({ timeout: ACTION_TIMEOUT_MS });
        // A submit may be a navigation or a fetch: wait until the page's requests have settled.
        await s.page.waitForLoadState("networkidle", { timeout: ACTION_TIMEOUT_MS }).catch(() => undefined);
        return { ok: true, observed: "submitted" };
      }
      if (action === "click") {
        await loc.click({ timeout: ACTION_TIMEOUT_MS });
        await s.page.waitForLoadState("load", { timeout: ACTION_TIMEOUT_MS });
        return { ok: true, observed: "clicked" };
      }
      await loc.waitFor({ state: "visible", timeout: action === "see" ? 2_000 : ACTION_TIMEOUT_MS });
      return { ok: true, observed: "visible" };
    } catch (e) {
      const msg = firstLine(e);
      if (/timeout/i.test(msg)) return { ok: false, observed: action === "click" ? "element not clickable before timeout" : "not visible before timeout" };
      return { ok: false, observed: "action failed", error: msg };
    }
  }

  /** Visual driver: a PNG of the viewport, written only to the given path (inside the run's work directory). */
  async screenshot(actor: string, path: string): Promise<{ url: string } | { error: string }> {
    const s = this.contexts.get(actor);
    if (!s) return { error: "no page loaded for this actor" };
    try {
      await s.page.screenshot({ path, type: "png", fullPage: false });
      return { url: s.page.url() };
    } catch (e) {
      return { error: `screenshot failed: ${firstLine(e)}` };
    }
  }

  /** Visual driver: a click at viewport coordinates. Any request it causes still goes through route(). */
  async clickAt(actor: string, x: number, y: number): Promise<{ url: string } | { error: string }> {
    const s = this.contexts.get(actor);
    if (!s) return { error: "no page loaded for this actor" };
    if (!(Number.isInteger(x) && Number.isInteger(y) && x >= 0 && y >= 0 && x < VIEWPORT.width && y < VIEWPORT.height)) return { error: `coordinates must be integers inside the ${VIEWPORT.width}x${VIEWPORT.height} viewport` };
    try {
      // A click may start a navigation asynchronously; give it a moment to begin, then wait for the load.
      const nav = s.page.waitForEvent("framenavigated", { timeout: 1_000 }).catch(() => undefined);
      await s.page.mouse.click(x, y);
      await nav;
      await s.page.waitForLoadState("load", { timeout: ACTION_TIMEOUT_MS }).catch(() => undefined);
      return { url: s.page.url() };
    } catch (e) {
      return { error: `click failed: ${firstLine(e)}` };
    }
  }

  async scroll(actor: string, dx: number, dy: number): Promise<{ url: string } | { error: string }> {
    const s = this.contexts.get(actor);
    if (!s) return { error: "no page loaded for this actor" };
    if (!(Number.isInteger(dx) && Number.isInteger(dy) && Math.abs(dx) <= 10_000 && Math.abs(dy) <= 10_000)) return { error: "scroll deltas must be integers within ±10000" };
    try {
      await s.page.mouse.wheel(dx, dy);
      return { url: s.page.url() };
    } catch (e) {
      return { error: `scroll failed: ${firstLine(e)}` };
    }
  }

  async close(): Promise<void> {
    for (const s of this.contexts.values()) await s.ctx.close().catch(() => undefined);
    this.contexts.clear();
    await this.browser.close().catch(() => undefined);
  }
}

export function firstLine(e: unknown): string {
  return String((e as Error)?.message ?? e).split(/\r?\n/)[0]!.slice(0, 200);
}
