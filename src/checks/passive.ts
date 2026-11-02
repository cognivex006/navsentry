/**
 * Deterministic passive checks over one observed HTTP exchange. Checks read the raw
 * in-memory response but only ever emit redacted, value-free observations.
 */
import { isThaiNationalId, luhn } from "../redact.js";
import type { Exchange } from "../transports/types.js";
import type { CheckResult, CheckStatus } from "../types.js";

export interface CheckContext {
  /** Actor that made the request (anything but "anonymous" counts as authenticated). */
  actor: string;
}

const h1 = (ex: Exchange, name: string): string | undefined => ex.raw?.headers[name]?.[0];
const hAll = (ex: Exchange, name: string): string[] => ex.raw?.headers[name] ?? [];

function result(ruleId: string, ex: Exchange, status: CheckStatus, summary: string, observations: string[] = [], reason?: string): CheckResult {
  return { ruleId, status, target: `${ex.record.method} ${ex.record.url}`, transport: ex.record.transport, summary, observations, requestIds: [ex.record.id], ...(reason ? { reason } : {}) };
}

const isHtml = (ex: Exchange) => /text\/html|application\/xhtml/i.test(h1(ex, "content-type") ?? "");
const isHttps = (ex: Exchange) => ex.record.url.startsWith("https:");
const hasBody = (ex: Exchange) => (ex.raw?.body.length ?? 0) > 0;
const isRedirect = (ex: Exchange) => (ex.raw?.status ?? 0) >= 300 && (ex.raw?.status ?? 0) < 400;

export function checkHsts(ex: Exchange): CheckResult {
  const id = "NSC-CONF-001";
  if (!isHttps(ex)) return result(id, ex, "NOT_TESTED", "HSTS applies to HTTPS responses only", [], "plain HTTP target");
  const v = h1(ex, "strict-transport-security");
  if (!v) return result(id, ex, "FAIL", "Strict-Transport-Security header missing", ["header absent"]);
  const m = v.match(/max-age\s*=\s*"?(\d+)"?/i);
  const age = m ? Number(m[1]) : NaN;
  if (!Number.isFinite(age)) return result(id, ex, "FAIL", "HSTS header has no valid max-age", [`value: ${v.slice(0, 120)}`]);
  if (age < 15552000) return result(id, ex, "FAIL", `HSTS max-age ${age} is below 15552000 (180 days)`, [`max-age=${age}`]);
  return result(id, ex, "PASS", `HSTS max-age=${age}`, [/includesubdomains/i.test(v) ? "includeSubDomains" : "no includeSubDomains"]);
}

export function parseCsp(v: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of v.split(";")) {
    const [name, ...vals] = part.trim().split(/\s+/);
    if (name && !out.has(name.toLowerCase())) out.set(name.toLowerCase(), vals);
  }
  return out;
}

export function checkCsp(ex: Exchange): CheckResult {
  const id = "NSC-CONF-002";
  if (!isHtml(ex) || isRedirect(ex)) return result(id, ex, "NOT_TESTED", "CSP is evaluated on HTML documents only", [], "not an HTML document");
  const v = h1(ex, "content-security-policy");
  if (!v) {
    const ro = h1(ex, "content-security-policy-report-only");
    return result(id, ex, "FAIL", ro ? "Only Content-Security-Policy-Report-Only present (not enforcing)" : "Content-Security-Policy header missing", [ro ? "report-only policy present" : "header absent"]);
  }
  const csp = parseCsp(v);
  const script = csp.get("script-src") ?? csp.get("default-src");
  const problems: string[] = [];
  if (!script) problems.push("no script-src/default-src directive");
  else {
    const hasNonceOrHash = script.some((s) => /^'(nonce-|sha(256|384|512)-)/i.test(s));
    if (script.includes("'unsafe-inline'") && !hasNonceOrHash) problems.push("script 'unsafe-inline' without nonce/hash");
    if (script.includes("'unsafe-eval'")) problems.push("script 'unsafe-eval'");
    if (script.some((s) => s === "*" || s === "http:" || s === "https:" || s === "data:")) problems.push("wildcard/scheme script source");
  }
  const obj = csp.get("object-src") ?? csp.get("default-src");
  if (!obj || !obj.includes("'none'")) problems.push("object-src not 'none'");
  if (problems.length) return result(id, ex, "FAIL", `CSP present but weak: ${problems.join(", ")}`, problems);
  return result(id, ex, "PASS", "Enforcing CSP without unsafe script sources");
}

export function checkFraming(ex: Exchange): CheckResult {
  const id = "NSC-CONF-003";
  if (!isHtml(ex) || isRedirect(ex)) return result(id, ex, "NOT_TESTED", "Framing protection is evaluated on HTML documents only", [], "not an HTML document");
  const xfo = (h1(ex, "x-frame-options") ?? "").trim().toUpperCase();
  const fa = parseCsp(h1(ex, "content-security-policy") ?? "").get("frame-ancestors");
  if (fa && !fa.includes("*")) return result(id, ex, "PASS", `CSP frame-ancestors ${fa.join(" ")}`);
  if (xfo === "DENY" || xfo === "SAMEORIGIN") return result(id, ex, "PASS", `X-Frame-Options ${xfo}`);
  return result(id, ex, "FAIL", "No frame-ancestors or valid X-Frame-Options", [fa ? "frame-ancestors allows *" : "frame-ancestors absent", xfo ? `X-Frame-Options=${xfo} (invalid)` : "X-Frame-Options absent"]);
}

export function checkContentType(ex: Exchange): CheckResult {
  const id = "NSC-CONF-004";
  if (!hasBody(ex)) return result(id, ex, "NOT_TESTED", "No response body", [], "empty body");
  const ct = h1(ex, "content-type");
  const nosniff = (h1(ex, "x-content-type-options") ?? "").trim().toLowerCase() === "nosniff";
  const problems: string[] = [];
  if (!ct) problems.push("Content-Type missing");
  else if (/^text\//i.test(ct) && !/charset=/i.test(ct)) problems.push("text response without charset");
  if (!nosniff) problems.push("X-Content-Type-Options: nosniff missing");
  return problems.length ? result(id, ex, "FAIL", problems.join("; "), problems) : result(id, ex, "PASS", "Explicit Content-Type and nosniff");
}

export function checkCache(ex: Exchange, ctx: CheckContext): CheckResult {
  const id = "NSC-CONF-007";
  const sensitive = ctx.actor !== "anonymous" || hAll(ex, "set-cookie").length > 0;
  if (!sensitive || !hasBody(ex)) return result(id, ex, "NOT_TESTED", "Response is neither authenticated nor session-setting", [], "not sensitive");
  const cc = (h1(ex, "cache-control") ?? "").toLowerCase();
  if (/no-store/.test(cc) || (/private/.test(cc) && /no-cache|max-age=0/.test(cc))) return result(id, ex, "PASS", `Cache-Control: ${cc}`);
  return result(id, ex, "FAIL", "Sensitive response is cacheable", [cc ? `Cache-Control: ${cc}` : "Cache-Control absent"]);
}

const VERSION_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime"];

export function checkVersionDisclosure(ex: Exchange): CheckResult {
  const id = "NSC-INFO-001";
  if (!ex.raw) return result(id, ex, "ERROR", "No response", [], ex.record.error);
  const hits: string[] = [];
  for (const name of VERSION_HEADERS) {
    for (const v of hAll(ex, name)) {
      if (name.startsWith("x-aspnet") || /\d+(\.\d+)+/.test(v)) hits.push(`${name}: ${v.slice(0, 80)}`);
    }
  }
  if (isHtml(ex) && ex.raw.status >= 400) {
    const body = ex.raw.body.toString("utf8", 0, 65536);
    const m = body.match(/(Apache|nginx|Microsoft-IIS|Apache Tomcat|Jetty|Kestrel|Express)[/ ]v?\d+(\.\d+)+/i);
    if (m) hits.push(`error page: ${m[0].slice(0, 60)}`);
  }
  return hits.length ? result(id, ex, "FAIL", "Product version disclosed", hits) : result(id, ex, "PASS", "No version numbers in headers or error page");
}

const ERROR_SIGNATURES: [string, RegExp][] = [
  ["Java stack trace", /\bat [a-z_$][\w$]*(\.[\w$]+)+\([\w$]+\.java:\d+\)/i],
  [".NET stack trace", /\bat [\w.`<>]+\(.*\) in .+:line \d+/i],
  ["ASP.NET error page", /Server Error in '.*' Application|<title>Runtime Error<\/title>|System\.Web\.HttpException/i],
  ["Python traceback", /Traceback \(most recent call last\):/],
  ["Node.js stack trace", /\n\s+at .+ \((\/|[A-Z]:\\).+:\d+:\d+\)/],
  ["Go panic", /goroutine \d+ \[running\]:/],
  ["PHP error", /(Fatal error|Warning|Parse error): .+ in .+ on line \d+/],
  ["SQL error message", /(SQLSTATE\[|ORA-\d{5}|Microsoft OLE DB Provider for SQL Server|You have an error in your SQL syntax|PG::|SqlException)/i],
  ["Exception class name", /\b(java\.lang\.|System\.)[A-Z]\w*Exception\b/],
];

export function checkErrorDisclosure(ex: Exchange): CheckResult {
  const id = "NSC-ERR-001";
  if (!ex.raw) return result(id, ex, "ERROR", "No response", [], ex.record.error);
  if (!hasBody(ex)) return result(id, ex, "PASS", "No body");
  const body = ex.raw.body.toString("utf8", 0, 262144);
  const hits = ERROR_SIGNATURES.filter(([, re]) => re.test(body)).map(([n]) => n);
  return hits.length ? result(id, ex, "FAIL", `Internal error details exposed (HTTP ${ex.raw.status})`, hits) : result(id, ex, "PASS", "No stack trace or internal error signature");
}

const PRIVATE_IP = /\b(10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b/g;

function headerText(ex: Exchange): string {
  return Object.entries(ex.raw?.headers ?? {}).map(([k, vs]) => vs.map((v) => `${k}: ${v}`).join("\n")).join("\n");
}

export function checkInternalIp(ex: Exchange): CheckResult {
  const id = "NSC-INFO-003";
  if (!ex.raw) return result(id, ex, "ERROR", "No response", [], ex.record.error);
  const inHeaders = (headerText(ex).match(PRIVATE_IP) ?? []).length;
  const inBody = (ex.raw.body.toString("utf8", 0, 262144).match(PRIVATE_IP) ?? []).length;
  if (inHeaders + inBody === 0) return result(id, ex, "PASS", "No private IP literals");
  return result(id, ex, "FAIL", "Private IP address literals disclosed", [`headers: ${inHeaders} match(es)`, `body: ${inBody} match(es)`, "values masked"]);
}

const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

export function checkEmail(ex: Exchange): CheckResult {
  const id = "NSC-INFO-004";
  if (!ex.raw) return result(id, ex, "ERROR", "No response", [], ex.record.error);
  const hits = (ex.raw.body.toString("utf8", 0, 262144).match(EMAIL) ?? []).filter((e) => !/\.(png|jpe?g|gif|svg|webp|css|js)$/i.test(e));
  if (!hits.length) return result(id, ex, "PASS", "No email addresses");
  const domains = [...new Set(hits.map((e) => e.split("@")[1]?.toLowerCase().replace(/^[^.]+\./, "*.")))].slice(0, 5);
  return result(id, ex, "FAIL", `${hits.length} email address(es) in response`, [`count: ${hits.length}`, `domain shapes: ${domains.join(", ")}`, "addresses masked"]);
}

export function checkPii(ex: Exchange): CheckResult {
  const id = "NSC-PRIV-001";
  if (!ex.raw) return result(id, ex, "ERROR", "No response", [], ex.record.error);
  const body = ex.raw.body.toString("utf8", 0, 1048576);
  const ids = (body.match(/(?<![\d.])\d[- ]?\d{4}[- ]?\d{5}[- ]?\d{2}[- ]?\d(?![\d.])/g) ?? []).filter(isThaiNationalId).length;
  const cards = (body.match(/(?<![\d.])(?:\d[ -]?){13,19}(?![\d.])/g) ?? []).filter((m) => /^[3-6]/.test(m) && luhn(m)).length;
  if (ids + cards === 0) return result(id, ex, "PASS", "No checksum-valid national ID or card numbers");
  return result(id, ex, "FAIL", "Checksum-valid personal identifiers in response", [`thai-national-id (mod-11 valid): ${ids}`, `card-number (Luhn valid): ${cards}`, "values never stored"]);
}

const SENSITIVE_PARAM = /^(pass(word)?|pwd|secret|token|access_?token|id_?token|refresh_?token|api_?key|apikey|session(id)?|jsessionid|auth|otp|pin|card(no|number)?|citizen_?id|national_?id|id_?card|ssn)$/i;

export function checkSensitiveUrl(ex: Exchange, rawUrl: string): CheckResult {
  const id = "NSC-PRIV-002";
  const urls = [rawUrl, ...(ex.raw?.redirectLocation ? [ex.raw.redirectLocation] : [])];
  const names = new Set<string>();
  for (const u of urls) {
    try {
      for (const k of new URL(u).searchParams.keys()) if (SENSITIVE_PARAM.test(k)) names.add(k);
    } catch {
      /* ignore malformed redirect */
    }
  }
  return names.size ? result(id, ex, "FAIL", "Sensitive parameter names carried in URL", [...names].map((n) => `param: ${n} (value redacted)`)) : result(id, ex, "PASS", "No sensitive parameter names in URL or redirect");
}

export interface ParsedCookie {
  name: string;
  attrs: Map<string, string>;
}

export function parseSetCookie(v: string): ParsedCookie {
  const [pair, ...rest] = v.split(";");
  const name = (pair ?? "").split("=")[0]!.trim();
  const attrs = new Map<string, string>();
  for (const a of rest) {
    const [k, ...vv] = a.trim().split("=");
    if (k) attrs.set(k.toLowerCase(), vv.join("=").trim());
  }
  return { name, attrs };
}

const SESSIONISH = /(sess|sid|auth|token|jwt|login|identity|asp\.net|aspxauth|connect\.sid|remember)/i;

export function checkCookies(ex: Exchange): CheckResult[] {
  const cookies = hAll(ex, "set-cookie").map(parseSetCookie).filter((c) => c.name);
  const ids = ["NSC-SESS-001", "NSC-SESS-002", "NSC-SESS-003"];
  if (!cookies.length) return ids.map((id) => result(id, ex, "NOT_TESTED", "No Set-Cookie in response", [], "no cookies"));
  const secure: string[] = [], httpOnly: string[] = [], sameSite: string[] = [];
  for (const c of cookies) {
    const deleting = c.attrs.get("max-age") === "0" || /1970/.test(c.attrs.get("expires") ?? "");
    if (deleting) continue;
    if (isHttps(ex) && !c.attrs.has("secure")) secure.push(`${c.name}: Secure missing`);
    if (c.name.startsWith("__Host-") && (!c.attrs.has("secure") || c.attrs.has("domain") || c.attrs.get("path") !== "/")) secure.push(`${c.name}: __Host- prefix rules violated`);
    if (SESSIONISH.test(c.name) && !c.attrs.has("httponly")) httpOnly.push(`${c.name}: HttpOnly missing on session-like cookie`);
    const ss = c.attrs.get("samesite")?.toLowerCase();
    if (!ss) sameSite.push(`${c.name}: SameSite missing`);
    else if (!["lax", "strict", "none"].includes(ss)) sameSite.push(`${c.name}: invalid SameSite=${ss}`);
    else if (ss === "none" && !c.attrs.has("secure")) sameSite.push(`${c.name}: SameSite=None without Secure (contradictory)`);
  }
  const mk = (id: string, list: string[], ok: string, bad: string) =>
    id === "NSC-SESS-001" && !isHttps(ex) && !list.length
      ? result(id, ex, "NOT_TESTED", "Secure flag evaluated on HTTPS responses only", [], "plain HTTP target")
      : list.length ? result(id, ex, "FAIL", bad, list) : result(id, ex, "PASS", ok, cookies.map((c) => `cookie: ${c.name}`));
  return [
    mk("NSC-SESS-001", secure, "All cookies Secure", "Cookie(s) without Secure"),
    mk("NSC-SESS-002", httpOnly, "Session-like cookies are HttpOnly", "Session-like cookie(s) readable by JavaScript"),
    mk("NSC-SESS-003", sameSite, "SameSite set consistently", "SameSite missing or contradictory"),
  ];
}

const JWT_RE = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;

function b64json(s: string): Record<string, unknown> | undefined {
  try {
    const v = JSON.parse(Buffer.from(s, "base64url").toString("utf8"));
    return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

export function checkJwt(ex: Exchange): CheckResult {
  const id = "NSC-SESS-004";
  if (!ex.raw) return result(id, ex, "ERROR", "No response", [], ex.record.error);
  const text = `${headerText(ex)}\n${ex.raw.body.toString("utf8", 0, 262144)}`;
  const tokens = [...new Set(text.match(JWT_RE) ?? [])].slice(0, 10);
  if (!tokens.length) return result(id, ex, "NOT_TESTED", "No JWT observed in response", [], "no token");
  const problems: string[] = [];
  tokens.forEach((t, i) => {
    const [h, p] = t.split(".");
    const header = b64json(h ?? ""), payload = b64json(p ?? "");
    if (!header || !payload) return;
    const alg = String(header.alg ?? "");
    if (!alg || alg.toLowerCase() === "none") problems.push(`token#${i + 1}: alg=${alg || "missing"}`);
    for (const claim of ["exp", "iss", "aud"]) if (!(claim in payload)) problems.push(`token#${i + 1}: ${claim} claim missing`);
    if (typeof payload.exp === "number" && typeof payload.iat === "number" && payload.exp - payload.iat > 86400) problems.push(`token#${i + 1}: lifetime > 24h`);
  });
  return problems.length ? result(id, ex, "FAIL", "JWT missing protection claims or weak alg", problems) : result(id, ex, "PASS", `${tokens.length} JWT(s) carry alg/exp/iss/aud`);
}

export function checkHttpsRedirect(ex: Exchange): CheckResult {
  const id = "NSC-CRYPT-006";
  if (isHttps(ex)) return result(id, ex, "NOT_TESTED", "Target is already HTTPS", [], "https target");
  if (!ex.raw) return result(id, ex, "ERROR", "No response", [], ex.record.error);
  const loc = ex.raw.redirectLocation;
  if (isRedirect(ex) && loc?.startsWith("https:")) return result(id, ex, "PASS", `Redirects to HTTPS (${ex.raw.status})`);
  return result(id, ex, "FAIL", `Plain HTTP serves content (HTTP ${ex.raw.status}) without HTTPS redirect`, [loc ? `Location scheme: ${new URL(loc).protocol}` : "no redirect"]);
}

export function checkCors(ex: Exchange, probeOrigin: string): CheckResult {
  const id = "NSC-AC-004";
  if (!ex.raw) return result(id, ex, "ERROR", "No response", [], ex.record.error);
  const acao = h1(ex, "access-control-allow-origin");
  const acac = (h1(ex, "access-control-allow-credentials") ?? "").toLowerCase() === "true";
  if (!acao) return result(id, ex, "PASS", "Untrusted origin not granted CORS access");
  if (acao === probeOrigin || acao === "null") return result(id, ex, "FAIL", `Untrusted Origin reflected${acac ? " WITH credentials" : ""}`, [`ACAO reflects probe origin`, `credentials=${acac}`]);
  if (acao === "*" && acac) return result(id, ex, "FAIL", "Wildcard origin with credentials", ["ACAO=*", "credentials=true"]);
  if (acao === "*") return result(id, ex, "INCONCLUSIVE", "Wildcard CORS without credentials (acceptable for public data only)", ["ACAO=*"], "needs owner confirmation that data is public");
  return result(id, ex, "PASS", "CORS allowlist does not include the probe origin", ["ACAO=fixed origin"]);
}

const DANGEROUS_METHODS = ["TRACE", "TRACK", "CONNECT", "DEBUG"];

export function checkMethods(ex: Exchange): CheckResult {
  const id = "NSC-CONF-006";
  if (!ex.raw) return result(id, ex, "ERROR", "No response", [], ex.record.error);
  const allow = [...hAll(ex, "allow"), ...hAll(ex, "access-control-allow-methods")].join(",").toUpperCase().split(/\s*,\s*/).filter(Boolean);
  if (!allow.length) return result(id, ex, ex.raw.status < 500 ? "PASS" : "INCONCLUSIVE", `OPTIONS returned ${ex.raw.status} without method advertisement`);
  const bad = allow.filter((m) => DANGEROUS_METHODS.includes(m));
  return bad.length ? result(id, ex, "FAIL", `Dangerous methods advertised: ${bad.join(", ")}`, [`advertised: ${[...new Set(allow)].join(", ")}`]) : result(id, ex, "PASS", `Advertised: ${[...new Set(allow)].join(", ")}`);
}

/**
 * NSC-AC-008 open-redirect observation (SPEC-0.1.3 §4.2). Looks only at query parameters already
 * present in the requested URL (seed or crawled link) and never injects a value. Emits nothing
 * when no parameter value looks like a URL or path.
 */
export function checkOpenRedirect(ex: Exchange, rawUrl: string): CheckResult[] {
  const id = "NSC-AC-008";
  let req: URL;
  try { req = new URL(rawUrl); } catch { return []; }
  const params = [...req.searchParams.entries()].filter(([, v]) => /^(https?:)?\/\//i.test(v) || /^\/[^/\\]/.test(v));
  if (!params.length || !ex.raw) return [];
  const loc = ex.raw.redirectLocation;
  if (!isRedirect(ex) || !loc) return [result(id, ex, "PASS", "URL-like parameter did not cause a redirect", [`parameters: ${params.map(([k]) => k).join(", ")}`])];
  const target = new URL(loc);
  const reflected = params.filter(([, v]) => {
    try { return new URL(v, req).toString() === target.toString(); } catch { return false; }
  });
  if (reflected.length && target.origin !== req.origin) {
    return [result(id, ex, "FAIL", `Redirect target taken from parameter ${reflected.map(([k]) => k).join(", ")} leaves the origin`, [`status ${ex.raw.status}`, "Location origin differs from the request origin", "parameter value equals the redirect target"])];
  }
  return [result(id, ex, "PASS", reflected.length ? "Parameter-driven redirect stays on the same origin" : "Redirect target is not taken from a parameter", [`parameters: ${params.map(([k]) => k).join(", ")}`])];
}
