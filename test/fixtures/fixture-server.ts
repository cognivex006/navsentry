/**
 * Disposable fixture API for safe-validate tests (SPEC-0.2.0 §9). Synthetic ids only; binds to
 * 127.0.0.1. `secure` behaves correctly; the other modes inject one cleanup or create failure each
 * while keeping the same routes and response contract for legitimate callers.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";

export type FixtureMode = "secure" | "create-reset" | "create-truncated" | "bad-id" | "delete-500" | "stays" | "patch-redirect";

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
  const json = (res: http.ServerResponse, status: number, body: object) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  const server = http.createServer((q, res) => {
    const path = new URL(q.url ?? "/", "http://x").pathname;
    log.push(`${q.method} ${path}`);
    q.resume();
    q.on("end", () => {
      if (q.method === "POST" && path === "/api/test-fixtures/orders") {
        if (mode === "create-reset") { objects.add(`o${++n}`); q.socket.destroy(); return; }
        const id = mode === "bad-id" ? ".." : `o${++n}`;
        objects.add(id);
        if (mode === "create-truncated") { res.writeHead(201, { "content-type": "application/json", "content-length": "200" }); res.write(`{"id":"${id}"`); setTimeout(() => res.socket?.destroy(), 20); return; }
        return json(res, 201, { id });
      }
      const m = path.match(/^\/api\/orders\/([^/]+)$/);
      if (m && q.method === "GET") return objects.has(m[1]!) ? json(res, 200, { id: m[1], note: "x" }) : json(res, 404, { error: "not found" });
      if (m && q.method === "PATCH") {
        if (mode === "patch-redirect") return res.writeHead(307, { location: "/api/undeclared" }).end();
        return objects.has(m[1]!) ? json(res, 200, { id: m[1], note: "x" }) : json(res, 404, { error: "not found" });
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
  return {
    origin: `http://127.0.0.1:${port}`,
    log,
    objects,
    held: () => new Promise<void>((r) => { onHeld = r; }),
    release: () => { if (pendingHold) json(pendingHold, 200, { ok: true }); pendingHold = undefined; },
    close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }),
  };
}
