/**
 * Browser engine fixture (M1b, SPEC-0.1.3 §6.3 / S1). An in-scope app whose page tries every
 * channel S1 cares about — an off-scope image and fetch, a WebSocket, a service worker and a
 * state-changing POST — plus a separate off-scope "canary" origin that counts any hit it gets.
 * Binds to 127.0.0.1 only; all content is synthetic.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";

export interface BrowserFixture {
  origin: string;
  canary: string;
  /** Requests the app received, as "METHOD /path". */
  hits: string[];
  canaryHits: () => number;
  upgrades: () => number;
  close(): Promise<void>;
}

/** Synthetic actor credential that /ui/leak logs to the console (0.1.3-k); test-only, not a secret. */
export const CONSOLE_TEST_TOKEN = "fixture-console-reader-token-0001";

function listen(server: http.Server): Promise<string> {
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(server.address() as AddressInfo).port}`)));
}

export async function startBrowserFixture(): Promise<BrowserFixture> {
  let canaryCount = 0;
  let upgrades = 0;
  const hits: string[] = [];
  const canaryServer = http.createServer((_req, res) => { canaryCount++; res.writeHead(200, { "content-type": "image/png" }).end(); });
  canaryServer.on("upgrade", (_req, socket) => { canaryCount++; socket.destroy(); });
  const canary = await listen(canaryServer);

  const html = (res: http.ServerResponse, body: string) => res.writeHead(200, { "content-type": "text/html; charset=utf-8", "x-content-type-options": "nosniff" }).end(`<!doctype html><html lang="en">${body}</html>`);
  const app = http.createServer((req, res) => {
    const path = new URL(req.url ?? "/", "http://x").pathname;
    hits.push(`${req.method} ${path}`);
    switch (path) {
      case "/ui/":
        res.setHeader("set-cookie", "fixture_session=s1; Path=/; HttpOnly; SameSite=Lax");
        return html(res, `<title>Shop</title><h1>Shop</h1><a href="/ui/next">Next page</a><button data-testid="go" type="button">Go</button><img alt="" src="${canary}/pixel.png"><script src="/ui/app.js"></script>`);
      case "/ui/app.js": {
        const ws = `ws://${req.headers.host}/ws`;
        res.writeHead(200, { "content-type": "text/javascript" }).end(
          `fetch(${JSON.stringify(`${canary}/beacon`)}).catch(()=>{});` +
          `try{new WebSocket(${JSON.stringify(ws)})}catch(e){}` +
          `if(navigator.serviceWorker)navigator.serviceWorker.register("/ui/sw.js").catch(()=>{});` +
          `fetch("/ui/form",{method:"POST",body:"x=1"}).catch(()=>{});` +
          `console.log("ready");`);
        return;
      }
      case "/ui/sw.js":
        res.writeHead(200, { "content-type": "text/javascript" }).end("self.addEventListener('fetch',()=>{});");
        return;
      case "/ui/next":
        return html(res, `<title>Second</title><h2>Second</h2><p>${req.headers.cookie?.includes("fixture_session=s1") ? "Signed cookie seen" : "No cookie"}</p>`);
      case "/ui/leak":
        return html(res, `<title>Leak</title><h1>Leak</h1><script>console.log("debug token ${CONSOLE_TEST_TOKEN}")</script>`);
      case "/ui/quiet":
        return html(res, "<title>Quiet</title><h1>Quiet</h1>");
      case "/ui/noisy":
        return html(res, `<title>Noisy</title><h1>Noisy</h1><script>console.log("loaded widget 3")</script>`);
      default:
        res.writeHead(404, { "content-type": "text/plain" }).end("not found");
    }
  });
  app.on("upgrade", (_req, socket) => { upgrades++; socket.destroy(); });
  const origin = await listen(app);
  return {
    origin,
    canary,
    hits,
    canaryHits: () => canaryCount,
    upgrades: () => upgrades,
    close: async () => {
      await new Promise<void>((r) => app.close(() => r()));
      await new Promise<void>((r) => canaryServer.close(() => r()));
    },
  };
}
