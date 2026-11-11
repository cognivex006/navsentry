/**
 * Headed visual driver (SPEC-0.3.0 §5; still PENDING_REVIEW in governance): human-event capture and the full-build probe.
 * The capture is the same in headless and headed Chromium, so it is tested headless with synthetic
 * responses: no socket is opened. A real headed window can only be verified once governance approves the full build.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { BrowserEngine, HEADED_BROWSER_APPROVED, probePlaywright, type HumanEvent } from "../src/transports/playwright.js";
import type { Exchange } from "../src/transports/types.js";

const probe = probePlaywright();
const skip = probe.usable ? false : `playwright engine unavailable: ${probe.reason}`;
const ORIGIN = "http://127.0.0.1:9";

const PAGES: Record<string, string> = {
  "/": `<!doctype html><title>t</title><button style="position:absolute;left:40px;top:40px;width:120px;height:40px">Buy now</button>
<a href="/next" style="position:absolute;left:40px;top:120px">Next page</a>
<script>try { window.__navsentryHuman && window.__navsentryHuman({ role: "button", name: "forged" }); } catch (e) {}
document.title = typeof window.__navsentryHuman;</script>`,
  "/next": `<!doctype html><title>next</title><p>ok</p>`,
};

function fake(url: string): Exchange {
  const body = PAGES[new URL(url).pathname];
  return {
    record: { id: url, method: "GET", url, actor: "anonymous" } as unknown as Exchange["record"],
    raw: { status: body ? 200 : 404, headers: { "content-type": ["text/html; charset=utf-8"] }, body: Buffer.from(body ?? "") },
  };
}

test("headed stays refused in code; its probe asks for the full build, not the shell", () => {
  assert.equal(HEADED_BROWSER_APPROVED, false, "flip only with a dated APPROVED governance entry");
  const p = probePlaywright({ headed: true });
  if (p.available && p.version === "1.64.1" && !p.usable) assert.match(p.reason, /install chromium/);
  if (p.usable) assert.match(p.reason, /full Chromium build/);
});

test("trusted clicks and main-frame navigations reach onHuman; page code cannot call the binding", { skip }, async () => {
  const events: HumanEvent[] = [];
  const e = await BrowserEngine.open({ send: async (q) => fake(q.url), onDenied: () => undefined, onHuman: (ev) => events.push(ev) }, new Map());
  try {
    assert.equal((await e.navigate("anonymous", `${ORIGIN}/`)).status, 200);
    const snap = await e.snapshot("anonymous");
    assert.ok(!("error" in snap));
    assert.equal(snap.title, "undefined", "the binding is gone before page scripts run");
    const buy = snap.elements.find((x) => x.name === "Buy now")!;
    await e.clickAt("anonymous", buy.x, buy.y);
    const next = snap.elements.find((x) => x.name === "Next page")!;
    await e.clickAt("anonymous", next.x, next.y);
    await new Promise((r) => setTimeout(r, 500));
    assert.ok(!events.some((x) => x.kind === "click" && x.name === "forged"), "a page script could not forge an event");
    assert.ok(events.some((x) => x.kind === "click" && x.role === "button" && x.name === "Buy now"));
    assert.ok(events.some((x) => x.kind === "click" && x.role === "link" && x.name === "Next page"));
    assert.ok(events.some((x) => x.kind === "navigate" && x.url === `${ORIGIN}/next`));
  } finally {
    await e.close();
  }
});
