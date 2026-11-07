/**
 * NavSentry Recorder service worker. It keeps the recording in chrome.storage.local, takes a
 * screenshot of the visible tab after each step, and injects the content script only into pages
 * of an origin the person imported from their NavSentry manifest and granted access to.
 *
 * It sends no network requests of its own: there is no request, socket, event-stream or
 * beacon anywhere in the extension, and the extension CSP sets connect-src 'none'. The person's
 * own browsing is theirs; NavSentry's safety guarantees start when the flow is replayed.
 */
const MAX_STEPS = 200;

/** Every read-modify-write of the recording runs one at a time, so fast clicks never lose a step. */
let queue = Promise.resolve();
const serial = (fn) => (queue = queue.then(fn, fn));

const get = async (k, d) => (await chrome.storage.local.get(k))[k] ?? d;
const set = (o) => chrome.storage.local.set(o);

/** Origin + path, with query keys but never query values (they may hold personal data). */
export function displayUrl(raw) {
  const u = new URL(raw);
  const keys = [...new URLSearchParams(u.search).keys()];
  return u.origin + u.pathname + (keys.length ? "?" + keys.map((k) => `${encodeURIComponent(k)}=`).join("&") : "");
}

async function allowedOrigin(url) {
  let o;
  try { o = new URL(url).origin; } catch { return false; }
  const allowed = await get("allowedOrigins", []);
  if (!allowed.includes(o)) return false;
  return chrome.permissions.contains({ origins: [`${o}/*`] });
}

async function shot(windowId) {
  try {
    return await chrome.tabs.captureVisibleTab(windowId, { format: "jpeg", quality: 60 });
  } catch {
    return null;
  }
}

async function addStep(step, windowId, withScreenshot) {
  const rec = await get("rec", null);
  if (!rec || !rec.active) return;
  if (rec.steps.length >= MAX_STEPS) { rec.active = false; rec.stoppedReason = `step limit ${MAX_STEPS} reached`; await set({ rec }); return; }
  const n = rec.steps.length + 1;
  const s = { n, at: new Date().toISOString(), ...step };
  if (withScreenshot) {
    // Let the page react to the action before the screenshot.
    await new Promise((r) => setTimeout(r, 400));
    const img = await shot(windowId);
    if (img) { await set({ [`shot_${rec.id}_${n}`]: img }); s.shot = true; }
  } else s.withheld = true;
  rec.steps.push(s);
  await set({ rec });
}

async function inject(tabId) {
  try {
    await chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] });
  } catch {
    // Not injectable (for example a browser page); nothing is recorded there.
  }
}

async function start(tab) {
  if (!(await allowedOrigin(tab.url))) return { ok: false, error: "This page's origin is not in scope. Import your NavSentry manifest in the options page and grant access to the origin." };
  const old = await get("rec", null);
  if (old) await clearShots(old);
  const rec = { id: crypto.randomUUID(), active: true, tabId: tab.id, windowId: tab.windowId, origin: new URL(tab.url).origin, createdAt: new Date().toISOString(), steps: [], lastUrl: tab.url, inScope: true };
  await set({ rec });
  await addStep({ type: "navigate", url: displayUrl(tab.url) }, tab.windowId, true);
  await inject(tab.id);
  return { ok: true };
}

async function clearShots(rec) {
  const keys = rec.steps.filter((s) => s.shot).map((s) => `shot_${rec.id}_${s.n}`);
  if (keys.length) await chrome.storage.local.remove(keys);
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  serial(async () => {
    if (msg?.ns === "navsentry-rec") {
      // From the content script: only the recording tab counts.
      const rec = await get("rec", null);
      if (!rec?.active || !rec.inScope || sender.tab?.id !== rec.tabId) return reply({ ok: false });
      if (!["click", "change", "submit"].includes(msg.type)) return reply({ ok: false });
      const t = msg.target && typeof msg.target === "object" ? msg.target : undefined;
      const target = t ? { role: String(t.role || "").slice(0, 40), name: String(t.name || "").slice(0, 120), tag: String(t.tag || "").slice(0, 20), password: t.password === true, ...(t.type ? { type: String(t.type).slice(0, 20) } : {}), ...(t.label ? { label: String(t.label).slice(0, 120) } : {}) } : undefined;
      // A password field is never photographed.
      await addStep({ type: msg.type, ...(target ? { target } : {}) }, rec.windowId, !(target?.password));
      return reply({ ok: true });
    }
    if (msg?.cmd === "start") {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      return reply(tab ? await start(tab) : { ok: false, error: "no active tab" });
    }
    if (msg?.cmd === "stop") {
      const rec = await get("rec", null);
      if (rec) { rec.active = false; await set({ rec }); }
      return reply({ ok: true });
    }
    if (msg?.cmd === "clear") {
      const rec = await get("rec", null);
      if (rec) await clearShots(rec);
      await chrome.storage.local.remove("rec");
      return reply({ ok: true });
    }
    return reply({ ok: false, error: "unknown message" });
  });
  return true;
});

chrome.tabs.onUpdated.addListener((tabId, info, tab) => serial(async () => {
  if (info.status !== "complete" || !tab.url) return;
  const rec = await get("rec", null);
  if (!rec?.active || tabId !== rec.tabId || tab.url === rec.lastUrl) return;
  rec.lastUrl = tab.url;
  const ok = (await allowedOrigin(tab.url)) && new URL(tab.url).origin === rec.origin;
  if (!ok) {
    // Out of scope: record the fact without the address or a screenshot, and pause until the person comes back.
    if (rec.inScope) { rec.inScope = false; await set({ rec }); await addStep({ type: "left-scope" }, rec.windowId, false); }
    return;
  }
  const back = !rec.inScope;
  rec.inScope = true;
  await set({ rec });
  if (back) await addStep({ type: "navigate", url: displayUrl(tab.url) }, rec.windowId, true);
  await inject(tabId);
}));
