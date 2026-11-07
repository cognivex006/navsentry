/**
 * NavSentry Recorder content script. Injected only into tabs of an in-scope origin while recording.
 * It reports what the person did (click, change, submit) with the element's role, accessible name,
 * tag and type. It never reads or sends a field value, and it sends nothing over the network: it
 * only messages the extension's own service worker.
 */
(() => {
  if (window.__navsentryRecorder) return;
  window.__navsentryRecorder = true;

  const INTERACTIVE = "a[href],button,input,select,textarea,summary,[role=button],[role=link],[role=tab],[role=menuitem],[role=checkbox],[role=radio],[role=combobox]";
  const TEXTUAL = new Set(["", "text", "search", "email", "url", "tel", "number", "password"]);

  const clean = (s) => String(s || "").replace(/\s+/g, " ").trim().slice(0, 120);

  function roleOf(el) {
    const explicit = el.getAttribute("role");
    if (explicit) return explicit;
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (tag === "a") return "link";
    if (tag === "button" || type === "submit" || type === "button") return "button";
    if (tag === "select") return "combobox";
    if (tag === "textarea") return "textbox";
    if (tag === "input") return type === "checkbox" ? "checkbox" : type === "radio" ? "radio" : "textbox";
    return tag;
  }

  function labelOf(el) {
    if (el.labels && el.labels.length) return clean(el.labels[0].innerText);
    return clean(el.getAttribute("aria-label") || el.getAttribute("placeholder") || el.getAttribute("name"));
  }

  function nameOf(el) {
    const tag = el.tagName.toLowerCase();
    const aria = el.getAttribute("aria-label");
    if (aria) return clean(aria);
    if (tag === "input" || tag === "textarea" || tag === "select") return labelOf(el);
    return clean(el.innerText || el.getAttribute("title") || el.getAttribute("alt"));
  }

  function describe(el) {
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute("type") || "").toLowerCase();
    const d = { role: roleOf(el), name: nameOf(el), tag, password: type === "password" };
    if (type) d.type = type;
    if (tag === "input" || tag === "textarea" || tag === "select") d.label = labelOf(el);
    return d;
  }

  const isTextField = (el) => (el.tagName === "INPUT" && TEXTUAL.has((el.getAttribute("type") || "").toLowerCase())) || el.tagName === "TEXTAREA";

  function send(type, el) {
    try {
      chrome.runtime.sendMessage({ ns: "navsentry-rec", type, target: el ? describe(el) : undefined });
    } catch {
      // The extension was reloaded; the page keeps working.
    }
  }

  document.addEventListener("click", (e) => {
    if (!e.isTrusted || !(e.target instanceof Element)) return;
    const el = e.target.closest(INTERACTIVE) || e.target;
    // Clicking into a text field only focuses it; the change event records the fill.
    if (isTextField(el)) return;
    // A submit button is recorded by the submit event, with the button as target.
    if (el.matches("button[type=submit],input[type=submit],button:not([type])") && el.form) return;
    send("click", el);
  }, true);

  document.addEventListener("change", (e) => {
    if (!e.isTrusted || !(e.target instanceof Element)) return;
    const el = e.target;
    if (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT") send("change", el);
  }, true);

  document.addEventListener("submit", (e) => {
    if (!e.isTrusted) return;
    send("submit", e.submitter || e.target);
  }, true);
})();
