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

async function render() {
  const rec = await get("rec", null);
  $("status").textContent = rec ? (rec.active ? "recording" : `stopped · ${rec.steps.length} steps`) : "idle";
  $("status").className = `pill ${rec?.active ? "on" : ""}`;
  const ol = $("steps");
  ol.replaceChildren();
  for (const s of rec?.steps ?? []) {
    const li = document.createElement("li");
    if (s.removed) li.className = "removed";
    const title = document.createElement("div");
    title.className = "title";
    const what = s.type === "navigate" ? s.url : s.target ? `${s.target.role} “${s.target.label || s.target.name}”` : "";
    title.textContent = `${LABEL[s.type] ?? s.type} ${what}`;
    li.append(title);
    if (s.shot) {
      const img = document.createElement("img");
      img.alt = `screenshot ${s.n}`;
      img.src = (await chrome.storage.local.get(`shot_${rec.id}_${s.n}`))[`shot_${rec.id}_${s.n}`] ?? "";
      li.append(img);
    } else if (s.withheld && s.type !== "left-scope") {
      const p = document.createElement("div");
      p.className = "withheld";
      p.textContent = "screenshot withheld (password field)";
      li.append(p);
    }
    const tools = document.createElement("div");
    tools.className = "tools";
    const del = document.createElement("button");
    del.type = "button";
    del.textContent = s.removed ? "Keep" : "Delete";
    del.onclick = () => edit(s.n, (x) => { x.removed = !x.removed; });
    const end = document.createElement("label");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = !!s.end;
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
    if (s.withheld) out.withheld = true;
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
    await chrome.downloads.download({ url, filename: `navsentry-${host}-${rec.createdAt.slice(0, 10)}.navrec.zip`, saveAs: true });
    msg("Saved. Import it with: navsentry flow from-recording --input <file> --out navsentry/flows/drafts");
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }
}

$("record").onclick = async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return msg("No page open.");
  const origin = new URL(tab.url).origin;
  const allowed = await get("allowedOrigins", []);
  if (!allowed.includes(origin)) return msg(`${origin} is not in scope. Import your NavSentry manifest in Scope first.`);
  // Access is requested per origin, from this click (a user gesture), never for all sites.
  if (!(await chrome.permissions.request({ origins: [`${origin}/*`] }))) return msg("Access to this origin was not granted.");
  const r = await chrome.runtime.sendMessage({ cmd: "start" });
  msg(r?.ok ? "Recording. Use the site, then press Stop." : r?.error ?? "Could not start.");
  await render();
};
$("stop").onclick = async () => { await chrome.runtime.sendMessage({ cmd: "stop" }); msg("Stopped. Review the steps, then Save."); await render(); };
$("clear").onclick = async () => { await chrome.runtime.sendMessage({ cmd: "clear" }); msg("Cleared."); await render(); };
$("save").onclick = () => void save();
chrome.storage.onChanged.addListener(() => void render());
void render();
