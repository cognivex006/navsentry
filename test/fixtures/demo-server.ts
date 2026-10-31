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
      default:
        res.writeHead(404, { "content-type": "text/plain; charset=utf-8" }).end("not found");
    }
  });
  return new Promise((resolve) => {
    server.listen(port, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({ origin: `http://127.0.0.1:${port}`, hits: () => count, close: () => new Promise<void>((r) => server.close(() => r())) });
    });
  });
}
