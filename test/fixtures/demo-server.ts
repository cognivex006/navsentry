/**
 * Local disposable demo app with intentional, bounded defects ("vulnerable") and the same
 * routes correctly hardened ("secure"). The secure variant keeps the exact response contract
 * (status, content type, JSON shape) so `compare` can prove fixes do not break legitimate callers.
 * All data is synthetic. Binds to 127.0.0.1 only.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";

export type DemoMode = "vulnerable" | "secure";

/** Synthetic, checksum-valid Thai national ID used only in tests (not a real person). */
export const SYNTHETIC_NATIONAL_ID = "1101700207366";

/** Synthetic bearer values for fixture actors (test-only, not secrets). */
export const FIXTURE_TOKENS = { reader_a: "Bearer fixture-reader-a-token", reader_b: "Bearer fixture-reader-b-token", admin: "Bearer fixture-admin-token" } as const;
const TOKEN_ACTOR: Record<string, string> = { [FIXTURE_TOKENS.reader_a]: "reader-a", [FIXTURE_TOKENS.reader_b]: "reader-b", [FIXTURE_TOKENS.admin]: "admin" };
const ORDERS: Record<string, { owner: string; total: number }> = { "o-a-1": { owner: "reader-a", total: 120 }, "o-b-1": { owner: "reader-b", total: 80 } };

function actorOf(h: string | undefined): string | undefined {
  return h ? TOKEN_ACTOR[h] : undefined;
}

function json(res: http.ServerResponse, status: number, body: object): void {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }).end(JSON.stringify(body));
}

function b64url(o: object): string {
  return Buffer.from(JSON.stringify(o)).toString("base64url");
}

export function startDemo(mode: DemoMode, port = 0): Promise<{ origin: string; hits: () => number; close: () => Promise<void> }> {
  let count = 0;
  const vuln = mode === "vulnerable";
  const server = http.createServer((req, res) => {
    count++;
    const url = new URL(req.url ?? "/", "http://demo");
    const common: Record<string, string> = vuln
      ? { server: "Apache/2.4.29 (Ubuntu)", "x-powered-by": "PHP/7.2.1" }
      : { "x-content-type-options": "nosniff", "content-security-policy": "default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'", "referrer-policy": "no-referrer" };
    const origin = req.headers.origin;
    if (vuln && origin) Object.assign(common, { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" });
    for (const [k, v] of Object.entries(common)) res.setHeader(k, v);

    if (req.method === "OPTIONS") {
      res.setHeader("allow", vuln ? "GET, POST, OPTIONS, TRACE" : "GET, OPTIONS");
      res.writeHead(204).end();
      return;
    }
    switch (url.pathname) {
      case "/":
        res.setHeader("set-cookie", vuln ? "SESSIONID=abc123def456; Path=/" : "SESSIONID=abc123def456; Path=/; HttpOnly; SameSite=Lax");
        if (!vuln) res.setHeader("cache-control", "no-store");
        res.writeHead(200, { "content-type": vuln ? "text/html" : "text/html; charset=utf-8" });
        res.end("<!doctype html><title>Demo</title><h1>Demo app</h1>");
        return;
      case "/api/profile": {
        res.setHeader("cache-control", vuln ? "public, max-age=600" : "no-store");
        res.writeHead(200, { "content-type": "application/json" });
        const masked = `x-xxxx-xxxxx-${SYNTHETIC_NATIONAL_ID.slice(10, 12)}-${SYNTHETIC_NATIONAL_ID.slice(12)}`;
        res.end(JSON.stringify({ name: "Test User", email: vuln ? "dev.team@internal.example" : "", nationalId: vuln ? SYNTHETIC_NATIONAL_ID : masked, node: vuln ? "10.20.30.40" : "api" }));
        return;
      }
      case "/api/error":
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ success: false, code: "E500", message: vuln ? "java.lang.NullPointerException\n\tat com.demo.Svc.load(Svc.java:42)" : "Internal error, reference 7f3a" }));
        return;
      case "/api/token": {
        const claims = vuln ? { sub: "u1" } : { sub: "u1", iss: "demo", aud: "demo-api", iat: 1700000000, exp: 1700000900 };
        const jwt = `${b64url({ alg: vuln ? "none" : "HS256", typ: "JWT" })}.${b64url(claims)}.${vuln ? "" : "c2lnbmF0dXJl"}`;
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ token: jwt }));
        return;
      }
      case "/go-out":
        res.writeHead(302, { location: "http://evil.example/steal" }).end();
        return;
      case "/go-in":
        res.writeHead(302, { location: "/" }).end();
        return;
      case "/api/me": {
        // Missing authentication (NSC-AC-002) in the vulnerable variant.
        const who = actorOf(req.headers.authorization);
        if (!who && !vuln) return json(res, 401, { error: "unauthorized" });
        return json(res, 200, { id: who ?? "reader-a", role: who === "admin" ? "admin" : "reader" });
      }
      case "/api/orders": {
        const who = actorOf(req.headers.authorization);
        if (!who) return json(res, 401, { error: "unauthorized" });
        return json(res, 200, { items: Object.entries(ORDERS).filter(([, o]) => o.owner === who).map(([id, o]) => ({ id, total: o.total })) });
      }
      case "/api/admin/stats": {
        // Missing function-level authorization (NSC-AC-007) in the vulnerable variant.
        const who = actorOf(req.headers.authorization);
        if (!who) return json(res, 401, { error: "unauthorized" });
        if (who !== "admin" && !vuln) return json(res, 403, { error: "forbidden" });
        return json(res, 200, { users: 3, orders: 2 });
      }
      case "/api/hostile-ids":
        // NavSentry safety fixture (not a target defect): values a flow must refuse to put in a URL.
        return json(res, 200, { traversal: "../admin", encoded: "%2e%2e", long: "x".repeat(300), absolute: "http://evil.example/x", ok: "o-a-1" });
      case "/app/profile": {
        const who = actorOf(req.headers.authorization);
        if (!who && !vuln) { res.writeHead(302, { location: "/login" }).end(); return; }
        if (!vuln) res.setHeader("cache-control", "no-store");
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end("<!doctype html><title>Profile</title><h1>Profile</h1><a href=\"/app/orders\">Orders</a>");
        return;
      }
      case "/login":
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end("<!doctype html><title>Login</title><h1>Sign in</h1>");
        return;
      default: {
        const m = url.pathname.match(/^\/api\/orders\/([a-z0-9-]+)$/);
        if (m) {
          // IDOR / BOLA (NSC-AC-003) in the vulnerable variant: no ownership check.
          const who = actorOf(req.headers.authorization);
          const o = ORDERS[m[1] as string];
          if (!who) return json(res, 401, { error: "unauthorized" });
          if (!o || (o.owner !== who && !vuln)) return json(res, 404, { error: "not found" });
          return json(res, 200, { id: m[1], total: o.total, status: "paid" });
        }
        res.writeHead(404, { "content-type": "text/plain; charset=utf-8" }).end("not found");
      }
    }
  });
  return new Promise((resolve) => {
    server.listen(port, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({ origin: `http://127.0.0.1:${port}`, hits: () => count, close: () => new Promise<void>((r) => server.close(() => r())) });
    });
  });
}
