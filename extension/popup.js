/**
 * Popup: start/stop, review the steps (delete one, mark where the flow ends, add a note for the
 * agent), and save the recording as a .navrec.zip through the browser's download dialog.
 * No network: the archive is built here and handed to chrome.downloads as a local blob URL.
 */
import { zipStored } from "./zip.js";

const $ = (id) => document.getElementById(id);
const get = async (k, d) => (await chrome.storage.local.get(k))[k] ?? d;
const msg = (t) => { $("msg").textContent = t; };

const LABEL = { navigate: "Open page", click: "Click", change: "Fill", submit: "Submit", "left-scope": "Left the scope (not recorded)" };

const KIND = { navigate: "page", click: "click", change: "field", submit: "submit", "left-scope": "paused" };

/** The active tab's origin and whether it is in the imported scope. */
async function tabScope() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  let origin = "";
  try { origin = tab?.url ? new URL(tab.url).origin : ""; } catch { origin = ""; }
  const allowed = await get("allowedOrigins", []);
  return { origin, allowed, inScope: !!origin && allowed.includes(origin) };
}

async function renderScope(rec) {
  const sc = await tabScope();
  const badge = $("scope-badge");
  $("origin").textContent = sc.origin || "no web page in this tab";
  if (!sc.allowed.length) {
    badge.textContent = "no scope"; badge.className = "badge warn";
    $("scope-help").textContent = "Import your navsentry.json in Scope settings first. Only its targets.origins are read.";
  } else if (sc.inScope) {
    badge.textContent = "in scope ✓"; badge.className = "badge ok";
    $("scope-help").textContent = rec?.active ? "Recording this origin. Other origins are never recorded." : "You can record this origin.";
  } else {
    badge.textContent = "not in scope"; badge.className = "badge bad";
    $("scope-help").textContent = `In scope: ${sc.allowed.join(", ")}. Open one of those to record.`;
  }
  return sc;
}

async function render() {
  const rec = await get("rec", null);
  const sc = await renderScope(rec);
  const kept = (rec?.steps ?? []).filter((s) => !s.removed).length;
  $("status").textContent = rec ? (rec.active ? `● recording · ${rec.steps.length}` : `stopped · ${kept} step(s)`) : "idle";
  $("status").className = `pill ${rec?.active ? "on" : ""}`;
  // Buttons say what is possible right now.
  $("record").disabled = !!rec?.active || !sc.inScope;
  $("stop").disabled = !rec?.active;
  $("save").disabled = !rec || rec.active || kept === 0;
  $("clear").disabled = !rec || rec.active;
  $("empty").hidden = !!rec?.steps.length;
  const last = await get("lastSaved", null);
  $("next").hidden = !last;
  if (last) $("next-cmd").textContent = `navsentry flow from-recording --input "${last}" --out navsentry/flows/drafts`;
  const ol = $("steps");
  ol.replaceChildren();
  let shown = 0;
  for (const s of rec?.steps ?? []) {
    const li = document.createElement("li");
    li.className = `step${s.removed ? " removed" : ""}${s.end ? " end" : ""}`;
    const head = document.createElement("div");
    head.className = "step-head";
    const num = document.createElement("span");
    num.className = "num";
    num.textContent = s.removed ? "–" : String(++shown);
    const kind = document.createElement("span");
    kind.className = "kind";
    kind.textContent = KIND[s.type] ?? s.type;
    const title = document.createElement("span");
    title.className = "title";
    const what = s.type === "navigate" ? s.url : s.target ? `${s.target.role} “${s.target.label || s.target.name}”` : "";
    // Page text is shown as text, never as markup.
    title.textContent = `${LABEL[s.type] ?? s.type} ${what}`;
    head.append(num, kind, title);
    li.append(head);
    if (s.shot) {
      const img = document.createElement("img");
      img.alt = `screenshot of step ${shown}`;
      img.src = (await chrome.storage.local.get(`shot_${rec.id}_${s.n}`))[`shot_${rec.id}_${s.n}`] ?? "";
      li.append(img);
    } else if (s.withheld && s.type !== "left-scope") {
      const p = document.createElement("div");
      p.className = "withheld";
      p.textContent = `🔒 no screenshot (${s.withheldReason ?? "password field"})`;
      li.append(p);
    }
    const tools = document.createElement("div");
    tools.className = "tools";
    const del = document.createElement("button");
    del.type = "button";
    del.className = "quiet";
    del.textContent = s.removed ? "Keep" : "Delete";
    del.disabled = !!rec.active;
    del.onclick = () => edit(s.n, (x) => { x.removed = !x.removed; });
    const end = document.createElement("label");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = !!s.end;
    cb.disabled = !!rec.active;
    cb.onchange = () => edit(s.n, (x, all) => { for (const y of all) y.end = false; x.end = cb.checked; });
    end.append(cb, " flow ends here");
    const note = document.createElement("input");
    note.placeholder = "note for the reviewer, e.g. order list is shown";
    note.maxLength = 200;
    note.value = s.note ?? "";
    note.onchange = () => edit(s.n, (x) => { x.note = note.value.trim().slice(0, 200) || undefined; });
    tools.append(del, end, note);
    li.append(tools);
    ol.append(li);
  }
}

async function edit(n, fn) {
  const rec = await get("rec", null);
  const s = rec?.steps.find((x) => x.n === n);
  if (!s) return;
  fn(s, rec.steps);
  await chrome.storage.local.set({ rec });
  await render();
}

async function sha256(bytes) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function dataUrlBytes(u) {
  const b64 = u.slice(u.indexOf(",") + 1);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function save() {
  const rec = await get("rec", null);
  if (!rec?.steps.length) return msg("Nothing recorded yet.");
  if (rec.active) return msg("Stop the recording first.");
  const files = [];
  const hashes = {};
  const steps = [];
  for (const s of rec.steps) {
    if (s.removed) continue;
    const out = { n: steps.length + 1, type: s.type, at: s.at };
    if (s.url) out.url = s.url;
    if (s.target) out.target = s.target;
    if (s.note) out.note = s.note;
    if (s.end) out.end = true;
    if (s.withheld) { out.withheld = true; if (s.withheldReason) out.withheldReason = String(s.withheldReason).slice(0, 60); }
    if (s.shot) {
      const url = (await chrome.storage.local.get(`shot_${rec.id}_${s.n}`))[`shot_${rec.id}_${s.n}`];
      if (url) {
        const name = `shots/${String(out.n).padStart(4, "0")}.jpg`;
        const data = dataUrlBytes(url);
        files.push({ name, data });
        hashes[name] = await sha256(data);
        out.screenshot = name;
      }
    }
    steps.push(out);
    if (s.end) break;
  }
  const recording = { kind: "navsentry-recording", schemaVersion: 1, createdAt: rec.createdAt, origin: rec.origin, recorder: `navsentry-recorder/${chrome.runtime.getManifest().version}`, steps, files: hashes };
  files.unshift({ name: "recording.json", data: new TextEncoder().encode(JSON.stringify(recording, null, 2)) });
  const blob = new Blob([zipStored(files)], { type: "application/zip" });
  const url = URL.createObjectURL(blob);
  const host = new URL(rec.origin).hostname.replace(/[^a-z0-9.-]/gi, "-");
  try {
    const id = await chrome.downloads.download({ url, filename: `navsentry-${host}-${rec.createdAt.slice(0, 10)}.navrec.zip`, saveAs: true });
    // Wait for the download to finish (or be cancelled) before offering the command for its path.
    const done = await new Promise((resolve) => {
      const check = async () => { const [it] = await chrome.downloads.search({ id }); if (!it || it.state !== "in_progress") { chrome.downloads.onChanged.removeListener(on); resolve(it); } };
      const on = (d) => { if (d.id === id && d.state) void check(); };
      chrome.downloads.onChanged.addListener(on);
      void check();
    });
    if (!done || done.state !== "complete" || !done.filename) { await chrome.storage.local.remove("lastSaved"); msg("Not saved (the download was cancelled or failed)."); await render(); return; }
    // The path stays in this browser's extension storage only, to show the next command.
    await chrome.storage.local.set({ lastSaved: done.filename });
    msg(`Saved ${steps.length} step(s). Run the command below in your project folder.`);
    await render();
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }
}

$("record").onclick = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return msg("No page open.");
  const origin = new URL(tab.url).origin;
  const allowed = await get("allowedOrigins", []);
  if (!allowed.includes(origin)) return msg(`${origin} is not in scope. Import your NavSentry manifest in Scope settings first.`);
  // Access is requested per origin, from this click (a user gesture), never for all sites.
  if (!(await chrome.permissions.request({ origins: [`${origin}/*`] }))) return msg("Access to this origin was not granted.");
  const r = await chrome.runtime.sendMessage({ cmd: "start" });
  if (r?.ok) await chrome.storage.local.remove("lastSaved");
  msg(r?.ok ? "Recording. Use the site as a user would, then press Stop." : r?.error ?? "Could not start.");
  await render();
};
$("stop").onclick = async () => { await chrome.runtime.sendMessage({ cmd: "stop" }); msg("Stopped. Review the steps, then Save."); await render(); };
$("clear").onclick = async () => {
  if (!confirm("Delete this recording and its screenshots from the browser?")) return;
  await chrome.runtime.sendMessage({ cmd: "clear" });
  await chrome.storage.local.remove("lastSaved");
  msg("Cleared.");
  await render();
};
$("copy").onclick = async () => {
  try { await navigator.clipboard.writeText($("next-cmd").textContent); msg("Command copied."); } catch { msg("Select the command and copy it."); }
};
$("save").onclick = () => void save();
chrome.storage.onChanged.addListener(() => void render());
void render();
