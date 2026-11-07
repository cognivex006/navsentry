/**
 * Demo v2 (SPEC-0.3.0 §8): the demo app plus a small linked website, so page, spider, the
 * visual driver and flows have something to explore. One origin; the variant is chosen at
 * start, so a before/after compare sees only real changes. Synthetic data, 127.0.0.1 only.
 */
import { startDemo, type DemoMode, type DemoPages } from "./demo-server.js";

const PRODUCTS: Record<string, { name: string; price: number }> = {
  "1": { name: "Rice cooker", price: 1290 },
  "2": { name: "Desk lamp", price: 590 },
  "3": { name: "Water bottle", price: 250 },
};

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function layout(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(title)} · NavSentry demo shop</title>
<style>body{font-family:system-ui,sans-serif;margin:0;color:#1d2433}header{background:#1d4ed8;color:#fff;padding:12px 24px}
nav a{color:#fff;margin-right:18px;text-decoration:none;font-size:18px}main{padding:24px}a.card{display:block;border:1px solid #ccd;border-radius:8px;padding:12px;margin:8px 0;max-width:420px;color:#1d2433;text-decoration:none}
label{display:block;margin:8px 0}input{font-size:16px;padding:6px}button{font-size:16px;padding:6px 14px}</style></head>
<body><header><nav><a href="/">Home</a><a href="/products">Products</a><a href="/search">Search</a><a href="/about">About</a><a href="/app/profile">My profile</a><a href="/login">Sign in</a></nav></header>
<main><h1>${esc(title)}</h1>${body}</main></body></html>`;
}

export const demoPages: DemoPages = (url, vulnerable) => {
  const p = url.pathname;
  if (p === "/") return layout("Demo shop", `<p>A small synthetic shop for trying NavSentry. Nothing here is real.</p>
<a class="card" href="/products">Browse products</a><a class="card" href="/search">Search the catalog</a><a class="card" href="/login">Sign in</a>`);
  if (p === "/products") return layout("Products", Object.entries(PRODUCTS).map(([id, x]) => `<a class="card" href="/products/${id}">${esc(x.name)} — ${x.price} THB</a>`).join(""));
  const m = p.match(/^\/products\/([0-9]+)$/);
  if (m) {
    const x = PRODUCTS[m[1] as string];
    return x ? layout(x.name, `<p>Price: ${x.price} THB</p><p><a href="/products">Back to products</a></p>`) : undefined;
  }
  if (p === "/about") return layout("About", `<p>Demo app for NavSentry. Vulnerable and secure variants keep the same pages.</p><p><a href="/">Home</a></p>`);
  if (p === "/search") {
    const q = url.searchParams.get("q") ?? "";
    const hits = Object.entries(PRODUCTS).filter(([, x]) => q && x.name.toLowerCase().includes(q.toLowerCase()));
    // The vulnerable variant reflects the query without encoding (NSC-INJ-004 observation only).
    const shown = vulnerable ? q : esc(q);
    return layout("Search", `<form method="get" action="/search"><label>Product name <input name="q" value="${esc(q)}"></label><button type="submit">Search</button></form>
${q ? `<p>Results for ${shown}: ${hits.length}</p>${hits.map(([id, x]) => `<a class="card" href="/products/${id}">${esc(x.name)}</a>`).join("")}` : ""}`);
  }
  if (p === "/login") return layout("Sign in", `<form method="post" action="/login"><label>Username <input name="username" autocomplete="username"></label>
<label>Password <input type="password" name="password" autocomplete="current-password"></label><button type="submit">Sign in</button></form>`);
  return undefined;
};

export function startDemoSite(mode: DemoMode, port = 0) {
  return startDemo(mode, port, demoPages);
}
