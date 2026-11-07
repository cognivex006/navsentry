/** Options: import targets.origins from a NavSentry manifest. Only bare http(s) origins are kept. */
const $ = (id) => document.getElementById(id);

/** Returns the bare origin, or undefined for anything with a path, credentials, wildcard or other scheme. */
export function bareOrigin(raw) {
  if (typeof raw !== "string" || raw.includes("*")) return undefined;
  let u;
  try { u = new URL(raw); } catch { return undefined; }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username || u.password || (u.pathname !== "/" && u.pathname !== "") || u.search || u.hash) return undefined;
  return u.origin;
}

async function render() {
  const list = (await chrome.storage.local.get("allowedOrigins")).allowedOrigins ?? [];
  const ul = $("origins");
  ul.replaceChildren();
  if (!list.length) { const li = document.createElement("li"); li.textContent = "None yet."; ul.append(li); }
  for (const o of list) {
    const li = document.createElement("li");
    const granted = await chrome.permissions.contains({ origins: [`${o}/*`] });
    li.textContent = `${o} — ${granted ? "access granted" : "access asked on Record"}`;
    ul.append(li);
  }
}

$("file").onchange = async () => {
  const f = $("file").files?.[0];
  if (!f) return;
  if (f.size > 1024 * 1024) { $("msg").textContent = "That file is too large for a manifest."; return; }
  let j;
  try { j = JSON.parse(await f.text()); } catch { $("msg").textContent = "Not a JSON file."; return; }
  const raw = Array.isArray(j?.targets?.origins) ? j.targets.origins : [];
  const origins = [...new Set(raw.map(bareOrigin).filter(Boolean))].slice(0, 20);
  if (!origins.length) { $("msg").textContent = "No valid origins in targets.origins."; return; }
  if (j?.authorization?.acknowledged !== true) { $("msg").textContent = "The manifest does not acknowledge authorization; nothing was imported."; return; }
  await chrome.storage.local.set({ allowedOrigins: origins });
  $("msg").textContent = `Imported ${origins.length} origin(s).`;
  await render();
};

void render();
