/**
 * REPORT.html (SPEC-0.3.0 §4.3): one offline file built from the same Markdown as REPORT.md, so
 * the two never disagree. Everything from the run is target data, so all text is HTML-escaped
 * before any markup is added. A Content-Security-Policy with hashes allows only the embedded
 * style and script: no network, fonts or images. "Export Markdown" downloads the embedded
 * REPORT.md; "Print / PDF" uses the browser's print dialog.
 */
import { createHash } from "node:crypto";

const escHtml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

const STATUS = /(?<![-\w])(PASS|FAIL|FAILED|INCONCLUSIVE|NOT_TESTED|ERROR|IMMEDIATE|CAUTION|PLANNED|OPTIONAL|INFO|VALIDATED|SUSPECTED|NEEDS_REVIEW|DISMISSED|COMPLETE|PARTIAL|FINDINGS|NO_FINDINGS_IN_TESTED_SCOPE|INCOMPLETE|IMPROVED_NO_DRIFT|IMPROVED_WITH_DRIFT|REGRESSED|FUNCTIONAL_REGRESSION|NO_CHANGE|DRIFT_ONLY|critical|high|medium|low)(?![-\w])/g;

/** Inline Markdown on already-split text: `code`, **bold**, status words. Input is raw; output is safe HTML. */
function inline(raw: string): string {
  const parts = raw.split(/(`[^`]+`)/g);
  return parts.map((p) => {
    if (p.length > 1 && p.startsWith("`") && p.endsWith("`")) return `<code>${escHtml(p.slice(1, -1))}</code>`;
    let h = escHtml(p);
    h = h.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    h = h.replace(STATUS, (m) => `<span class="st st-${m.toLowerCase()}">${m}</span>`);
    h = h.replace(/<strong>(critical|high|medium|low|info)<\/strong>/g, (_m, v: string) => `<strong class="st st-${v}">${v}</strong>`);
    return h;
  }).join("");
}

function cells(line: string): string[] {
  const body = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  const out: string[] = [];
  let cur = "";
  for (let i = 0; i < body.length; i++) {
    if (body[i] === "\\" && body[i + 1] === "|") { cur += "|"; i++; continue; }
    if (body[i] === "|") { out.push(cur.trim()); cur = ""; continue; }
    cur += body[i];
  }
  out.push(cur.trim());
  return out;
}

const LEVEL_OF: Record<string, string> = { "🔴": "IMMEDIATE", "🟠": "CAUTION", "🟡": "PLANNED", "🔵": "OPTIONAL", "⚪": "INFO" };

/** Converts the subset of Markdown that NavSentry's renderers emit. */
export function markdownToHtml(md: string): string {
  const lines = md.split(/\r?\n/);
  const out: string[] = [];
  let inSection = false, inGroup = false, inList = 0, para: string[] = [];
  const flushPara = () => { if (para.length) { out.push(`<p>${inline(para.join(" "))}</p>`); para = []; } };
  const closeList = () => { while (inList > 0) { out.push("</ul>"); inList--; } };
  const closeGroup = () => { if (inGroup) { out.push("</div>"); inGroup = false; } };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const fm = line.match(/^(\s*)(`{3,})(\w*)\s*$/);
    if (fm) {
      flushPara();
      const indent = fm[1]!.length, ticks = fm[2]!, lang = fm[3]!;
      const code: string[] = [];
      for (i++; i < lines.length; i++) {
        const l = lines[i]!;
        if (l.trim() === ticks) break;
        code.push(l.startsWith(" ".repeat(indent)) ? l.slice(indent) : l.trimStart());
      }
      out.push(`<pre class="code"${lang ? ` data-lang="${escHtml(lang)}"` : ""}><code>${escHtml(code.join("\n"))}</code></pre>`);
      continue;
    }
    const h = line.match(/^(#{1,4}) (.*)$/);
    if (h) {
      flushPara(); closeList();
      const n = h[1]!.length, text = h[2]!;
      if (n === 1) { out.push(`<h1>${inline(text)}</h1>`); continue; }
      if (n === 2) {
        closeGroup();
        if (inSection) out.push("</div></details>");
        out.push(`<details open class="section"><summary><h2>${inline(text)}</h2></summary><div class="body">`);
        inSection = true;
        continue;
      }
      if (n === 3) {
        closeGroup();
        const lv = LEVEL_OF[[...text][0] ?? ""];
        if (lv) { out.push(`<div class="group" data-level="${lv}">`); inGroup = true; }
        out.push(`<h3${lv ? ` class="lv lv-${lv.toLowerCase()}"` : ""}>${inline(text)}</h3>`);
        continue;
      }
      const lv = LEVEL_OF[[...text][0] ?? ""];
      out.push(`<h4${lv ? ` class="card lv-${lv.toLowerCase()}"` : ""}>${inline(text)}</h4>`);
      continue;
    }
    if (/^\s*\|/.test(line)) {
      flushPara(); closeList();
      const rows: string[][] = [];
      for (; i < lines.length && /^\s*\|/.test(lines[i]!); i++) rows.push(cells(lines[i]!));
      i--;
      const [head, sep, ...body] = rows;
      const hasHead = sep && sep.every((c) => /^:?-{3,}:?$/.test(c));
      out.push("<div class=\"tw\"><table>");
      if (hasHead) out.push(`<thead><tr>${head!.map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead>`);
      out.push("<tbody>", ...(hasHead ? body : rows).map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`), "</tbody></table></div>");
      continue;
    }
    const li = line.match(/^(\s*)- (.*)$/);
    if (li) {
      flushPara();
      const depth = Math.floor(li[1]!.length / 2) + 1;
      while (inList < depth) { out.push("<ul>"); inList++; }
      while (inList > depth) { out.push("</ul>"); inList--; }
      out.push(`<li>${inline(li[2]!)}</li>`);
      continue;
    }
    if (line.startsWith("> ")) { flushPara(); closeList(); out.push(`<blockquote>${inline(line.slice(2))}</blockquote>`); continue; }
    if (!line.trim()) { flushPara(); if (!/^\s+/.test(lines[i + 1] ?? "")) closeList(); continue; }
    if (inList && /^\s+/.test(line)) { out.push(`<div class="li-text">${inline(line.trim())}</div>`); continue; }
    closeList();
    para.push(line.trim());
  }
  flushPara(); closeList(); closeGroup();
  if (inSection) out.push("</div></details>");
  return out.join("\n");
}

const CSS = `:root{--fg:#1d2433;--muted:#5b6475;--line:#d9dee7;--bg:#f6f7f9;--card:#fff;--red:#b42318;--red-bg:#fde8e7;--green:#067647;--green-bg:#e3f6ec;--amber:#b54708;--amber-bg:#fef0c7;--yellow:#8a6a00;--yellow-bg:#fff7d1;--blue:#175cd3;--blue-bg:#e5efff;--grey:#475467;--grey-bg:#eef0f3}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--fg);background:var(--bg)}
.bar{position:sticky;top:0;z-index:2;display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:10px 24px;background:#1d2433;color:#fff}
.bar strong{margin-right:auto}.bar button{font:inherit;border:1px solid #fff4;background:#ffffff14;color:#fff;border-radius:6px;padding:4px 10px;cursor:pointer}.bar button[aria-pressed=false]{opacity:.45}
main{max-width:1180px;margin:0 auto;padding:18px 24px 60px}h1{font-size:24px}
details.section{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:14px 0;padding:0 16px}
summary{cursor:pointer;list-style:none}summary h2{display:inline-block;font-size:19px;margin:12px 0}summary::before{content:"▸ ";color:var(--muted)}details[open]>summary::before{content:"▾ "}
h3{font-size:17px;margin:18px 0 6px}h4.card{font-size:16px;margin:16px 0 8px;padding:8px 12px;border-left:5px solid var(--grey);background:var(--grey-bg);border-radius:6px}
.lv-immediate{border-color:var(--red)!important;background:var(--red-bg)!important}.lv-caution{border-color:var(--amber)!important;background:var(--amber-bg)!important}
.lv-planned{border-color:var(--yellow)!important;background:var(--yellow-bg)!important}.lv-optional{border-color:var(--blue)!important;background:var(--blue-bg)!important}.lv-info{border-color:var(--grey)!important}
h3.lv{padding:6px 12px;border-radius:6px;border-left:5px solid}
.tw{overflow-x:auto}table{border-collapse:collapse;margin:8px 0;font-size:14px}th,td{border:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}th{background:var(--grey-bg)}
code{font:13px ui-monospace,Consolas,monospace;background:var(--grey-bg);padding:1px 4px;border-radius:4px;word-break:break-word}
pre.code{background:#101828;color:#e4e7ec;padding:10px 12px;border-radius:8px;overflow-x:auto}pre.code code{background:none;color:inherit;padding:0}
blockquote{margin:8px 0;padding:8px 12px;border-left:4px solid var(--amber);background:var(--amber-bg);border-radius:4px}
.st{display:inline-block;padding:0 6px;border-radius:4px;font-weight:600;font-size:12.5px;letter-spacing:.2px}
.st-pass,.st-complete,.st-improved_no_drift,.st-no_findings_in_tested_scope,.st-validated{color:var(--green);background:var(--green-bg)}
.st-fail,.st-failed,.st-immediate,.st-critical,.st-high,.st-regressed,.st-functional_regression,.st-findings{color:var(--red);background:var(--red-bg)}
.st-inconclusive,.st-caution,.st-medium,.st-partial,.st-suspected,.st-improved_with_drift,.st-drift_only,.st-needs_review,.st-incomplete{color:var(--amber);background:var(--amber-bg)}
.st-planned,.st-low{color:var(--yellow);background:var(--yellow-bg)}.st-optional{color:var(--blue);background:var(--blue-bg)}
.st-not_tested,.st-info,.st-error,.st-dismissed,.st-no_change{color:var(--grey);background:var(--grey-bg)}.st-error{color:var(--red)}
.li-text{margin-left:4px}.hidden{display:none}
@media print{.bar{display:none}body{background:#fff}details.section{border:none;padding:0}summary::before{content:""}pre.code{white-space:pre-wrap;background:#f2f4f7;color:#101828}}`;

const JS = `(function(){var md=JSON.parse(document.getElementById("report-md").textContent);
document.getElementById("export-md").addEventListener("click",function(){var a=document.createElement("a");a.href=URL.createObjectURL(new Blob([md],{type:"text/markdown"}));a.download="REPORT.md";a.click();setTimeout(function(){URL.revokeObjectURL(a.href)},1000)});
document.getElementById("print").addEventListener("click",function(){window.print()});
window.addEventListener("beforeprint",function(){document.querySelectorAll("details").forEach(function(d){d.open=true})});
document.querySelectorAll("button[data-level]").forEach(function(b){b.addEventListener("click",function(){var on=b.getAttribute("aria-pressed")!=="true";b.setAttribute("aria-pressed",on?"true":"false");
document.querySelectorAll('.group[data-level="'+b.dataset.level+'"]').forEach(function(g){g.classList.toggle("hidden",!on)})})});})();`;

const sha = (s: string) => `'sha256-${createHash("sha256").update(s, "utf8").digest("base64")}'`;

export function renderHtml(markdown: string, title: string, lang: "en" | "th" = "en"): string {
  const levels = ["IMMEDIATE", "CAUTION", "PLANNED", "OPTIONAL", "INFO"];
  const data = JSON.stringify(markdown).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
  const csp = `default-src 'none'; style-src ${sha(CSS)}; script-src ${sha(JS)}; img-src 'none'; base-uri 'none'; form-action 'none'`;
  return `<!doctype html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escHtml(title)}</title>
<style>${CSS}</style>
</head>
<body>
<div class="bar"><strong>NavSentry</strong>${levels.map((l) => `<button type="button" data-level="${l}" aria-pressed="true">${l}</button>`).join("")}<button type="button" id="export-md">Export Markdown</button><button type="button" id="print">Print / PDF</button></div>
<main>
${markdownToHtml(markdown)}
</main>
<script type="application/json" id="report-md">${data}</script>
<script>${JS}</script>
</body>
</html>
`;
}
