/**
 * Disposable fixture API for safe-validate tests (SPEC-0.2.0 §9). Synthetic ids only; binds to
 * 127.0.0.1. `secure` behaves correctly; the other modes inject one cleanup or create failure each
 * while keeping the same routes and response contract for legitimate callers.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";

/** `vulnerable`: no ownership check on PATCH (AC-003), no CSRF check on cancel (AC-006), logout keeps the session (AUTH-002). */
export type FixtureMode = "secure" | "vulnerable" | "create-reset" | "create-truncated" | "bad-id" | "delete-500" | "stays" | "patch-redirect";

/** Synthetic test credentials (not secrets). */
export const FIXTURE_LOGIN = { user: "alice", password: "pw-correct-horse-battery", presetCookie: "sid=preset-session-cookie-0001" } as const;

const LOGIN_PAGE = `<!doctype html><title>Login</title><h1>Login</h1>
<label>Username <input id="u"></label><label>Password <input id="p" type="password"></label>
<button id="go">Sign in</button><p id="out"></p>
<script>document.getElementById("go").onclick = async () => {
  try { const r = await fetch("/api/session", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ user: u.value, password: p.value }) });
    out.textContent = r.ok ? "Signed in" : "Login refused"; } catch { out.textContent = "Login blocked"; } };</script>`;

const PROBE_PAGE = `<!doctype html><title>Probe</title><h1>Probe</h1>
<button onclick="go('declared','/api/echo','application/json')">Declared</button>
<button onclick="go('undeclared','/api/undeclared','application/json')">Undeclared</button>
<button onclick="go('redirected','/api/echo-redirect','application/json')">Redirected</button>
<button onclick="go('wrongtype','/api/echo','text/plain')">Wrong type</button>
<form method="post" action="/api/undeclared-form"><input name="a" value="1"><button>Form post</button></form>
<ul id="out"></ul>
<script>async function go(n, u, t) { let v; try { const r = await fetch(u, { method: "POST", headers: { "content-type": t }, body: JSON.stringify({ a: 1 }) }); v = n + ":" + r.status; } catch { v = n + ":blocked"; }
  const li = document.createElement("li"); li.textContent = v; out.appendChild(li); }</script>`;

export interface FixtureServer {
  origin: string;
  /** Every request seen: "METHOD /path". */
  log: string[];
  objects: Set<string>;
  /** Resolves the next time a GET /api/hold arrives; the response waits for `release()`. */
  held(): Promise<void>;
  release(): void;
  close(): Promise<void>;
}

export async function startFixtureServer(mode: FixtureMode = "secure"): Promise<FixtureServer> {
  const log: string[] = [];
  const objects = new Set<string>();
  let n = 0;
  let onHeld: (() => void) | undefined;
  let pendingHold: http.ServerResponse | undefined;
  const sessions = new Set<string>([FIXTURE_LOGIN.presetCookie.split("=")[1]!]);
  const owners = new Map<string, string>();
  let selfOrigin = "";
  const cookieOf = (h: string | undefined, name: string) => new RegExp(`(?:^|;\\s*)${name}=([^;]+)`).exec(h ?? "")?.[1];
  const ADMIN = new Set(["Bearer sv-fixture-admin"]);
  const json = (res: http.ServerResponse, status: number, body: object) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  const server = http.createServer((q, res) => {
    const path = new URL(q.url ?? "/", "http://x").pathname;
    log.push(`${q.method} ${path}`);
    const chunks: Buffer[] = [];
    q.on("data", (c: Buffer) => chunks.push(c));
    q.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const html = (h: string) => res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(h);
      if (path === "/ui/login") return html(LOGIN_PAGE);
      if (path === "/ui/probe") return html(PROBE_PAGE);
      if (path === "/ui/autopost") return html("<!doctype html><title>Auto</title><h1>Auto</h1><script>fetch(\"/api/echo\", { method: \"POST\", headers: { \"content-type\": \"application/json\" }, body: \"{}\" }).catch(() => {});</script>");
      if (q.method === "POST" && path === "/api/session") {
        let c: { user?: string; password?: string } = {};
        try { c = JSON.parse(body); } catch { /* refused below */ }
        if (c.user !== FIXTURE_LOGIN.user || c.password !== FIXTURE_LOGIN.password) return json(res, 401, { error: "bad credentials" });
        const sid = `sess-${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
        sessions.add(sid);
        const csrf = `csrf-${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
        return res.writeHead(200, { "content-type": "application/json", "set-cookie": [`sid=${sid}; Path=/; HttpOnly`, `csrf_token=${csrf}; Path=/`] }).end(JSON.stringify({ ok: true }));
      }
      if (q.method === "POST" && path === "/api/session/logout") {
        const sid = cookieOf(q.headers.cookie, "sid");
        if (sid && mode !== "vulnerable") sessions.delete(sid);
        return json(res, 200, { ok: true });
      }
      if (path === "/api/me") {
        const sid = cookieOf(q.headers.cookie, "sid");
        return sid && sessions.has(sid) ? json(res, 200, { user: "alice" }) : json(res, 401, { error: "no session" });
      }
      if (q.method === "POST" && path === "/api/echo") return json(res, 200, { ok: true });
      if (q.method === "POST" && path === "/api/echo-redirect") return res.writeHead(307, { location: "/api/undeclared" }).end();
      if (q.method === "POST" && path === "/api/test-fixtures/orders") {
        if (mode === "create-reset") { objects.add(`o${++n}`); q.socket.destroy(); return; }
        const id = mode === "bad-id" ? ".." : `o${++n}`;
        objects.add(id);
        owners.set(id, q.headers.authorization ?? cookieOf(q.headers.cookie, "sid") ?? "");
        if (mode === "create-truncated") { res.writeHead(201, { "content-type": "application/json", "content-length": "200" }); res.write(`{"id":"${id}"`); setTimeout(() => res.socket?.destroy(), 20); return; }
        return json(res, 201, { id });
      }
      const m = path.match(/^\/api\/orders\/([^/]+)$/);
      if (m && q.method === "GET") return objects.has(m[1]!) ? json(res, 200, { id: m[1], note: "x" }) : json(res, 404, { error: "not found" });
      if (m && q.method === "PATCH") {
        if (mode === "patch-redirect") return res.writeHead(307, { location: "/api/undeclared" }).end();
        const who = q.headers.authorization ?? cookieOf(q.headers.cookie, "sid") ?? "";
        if (mode !== "vulnerable" && objects.has(m[1]!) && owners.get(m[1]!) !== who && !ADMIN.has(who)) return json(res, 403, { error: "forbidden" });
        return objects.has(m[1]!) ? json(res, 200, { id: m[1], note: "x" }) : json(res, 404, { error: "not found" });
      }
      const cancel = path.match(/^\/api\/orders\/([^/]+)\/cancel$/);
      if (cancel && q.method === "POST") {
        const sid = cookieOf(q.headers.cookie, "sid");
        if (!sid || !sessions.has(sid)) return json(res, 401, { error: "no session" });
        const token = cookieOf(q.headers.cookie, "csrf_token");
        const origin = q.headers.origin;
        if (mode !== "vulnerable" && (!token || q.headers["x-csrf-token"] !== token || (origin !== undefined && origin !== selfOrigin))) return json(res, 403, { error: "csrf" });
        return objects.has(cancel[1]!) ? json(res, 200, { id: cancel[1], status: "cancelled" }) : json(res, 404, { error: "not found" });
      }
      const d = path.match(/^\/api\/test-fixtures\/orders\/([^/]+)$/);
      if (d && q.method === "DELETE") {
        if (mode === "delete-500") return json(res, 500, { error: "refused" });
        if (mode !== "stays") objects.delete(d[1]!);
        return res.writeHead(204).end();
      }
      if (path === "/api/hold") { pendingHold = res; onHeld?.(); return; }
      if (path === "/api/ok") return json(res, 200, { ok: true });
      json(res, 404, { error: "not found" });
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  selfOrigin = `http://127.0.0.1:${port}`;
  return {
    origin: `http://127.0.0.1:${port}`,
    log,
    objects,
    held: () => new Promise<void>((r) => { onHeld = r; }),
    release: () => { if (pendingHold) json(pendingHold, 200, { ok: true }); pendingHold = undefined; },
    close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }),
  };
}
