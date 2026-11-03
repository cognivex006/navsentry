/**
 * Static asset scan (SPEC-0.1.3 §6.4-B/C): inventory from fetched HTML, fixed exposure probes,
 * source maps, streamed detection from an owned spool file, a facts-only cache and cost accounting.
 * Every request goes through the runner's send (ScopeGate → Budget). Local-first, model-last: only
 * `client-findings.json` (masked, capped) is meant for an agent.
 */
import { createHash } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Manifest } from "../config.js";
import { REDACTION_POLICY_VERSION, type Redactor } from "../redact.js";
import type { ScopeGate } from "../scope.js";
import type { Exchange, HttpRequestSpec } from "../transports/types.js";
import type { AssetScanResult, CheckResult, ClientFinding } from "../types.js";
import { scanHtml } from "../spider/html.js";
import { DETECTOR_VERSION, LiteralScanner, StreamScanner, exposureMatch, type ExposureFormat, type Fact } from "./detect.js";

export const MAX_ASSETS = 200;
export const MAX_CLIENT_FINDINGS = 200;
const RETAIN = 64 * 1024;
const SKIP_EXT = /\.(?:png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|ogg|wav|pdf|zip)$/i;
const SKIP_TYPE = /^(?:image|font|audio|video)\//i;

/** Fixed exposure probes (no fuzzing). `/manifest.json` is public by design and never probed. */
export const EXPOSURE_PROBES: { path: string; format: ExposureFormat | "inventory" }[] = [
  { path: "/.env", format: "dotenv" },
  { path: "/.git/HEAD", format: "git-head" },
  { path: "/config.js", format: "js-config" },
  { path: "/env.js", format: "js-config" },
  { path: "/__ENV.js", format: "js-config" },
  { path: "/asset-manifest.json", format: "inventory" },
];

export interface AssetContext {
  manifest: Manifest;
  gate: ScopeGate;
  redactor: Redactor;
  /** Pages already fetched by page/spider (HTML is read from their retained bodies). */
  pages: Exchange[];
  actors: { name: string; headers: Record<string, string> }[];
  /** Known test tokens and in-scope credentials: exact matches are deterministic evidence. */
  literals: string[];
  send(spec: HttpRequestSpec): Promise<Exchange | undefined>;
  workDir?: string;
  cacheDir?: string;
  disabled: Set<string>;
  now?: () => Date;
}

interface Scanned {
  ex?: Exchange;
  facts: Fact[];
  dropped: number;
  literalHits: number;
  complete: boolean;
  reason?: string;
  cached: boolean;
  sourceMappingUrl?: string;
}

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const preview = (f: Fact) => `[${f.marker ?? f.kind},len=${f.len}]`;

export async function scanAssets(ctx: AssetContext): Promise<{ checks: CheckResult[]; result: AssetScanResult; clientFindings: ClientFinding[]; incomplete: string[] }> {
  const m = ctx.manifest;
  const checks: CheckResult[] = [];
  const incomplete: string[] = [];
  const findings: ClientFinding[] = [];
  const result: AssetScanResult = { engine: "node-detector", detectorVersion: DETECTOR_VERSION, assets: [], probes: [], maps: [], skipped: [], clientFindings: { entries: 0, truncated: 0 }, libraryAdvisories: "NOT_TESTED: client library matching needs reviewed advisory records from an approved source (SPEC-0.1.3 §6.6-A)" };
  const cost = { bytesScannedLocally: 0, cacheEligible: 0, cacheHits: 0 };
  const spoolBudget = { used: 0, max: m.capture.max_work_bytes };
  let spoolN = 0;
  if (!ctx.workDir) {
    incomplete.push("static assets NOT_TESTED: no work directory for spooling (run through the CLI)");
    return { checks, result: { ...result, cost: { ...cost, agentVisibleBytes: 0, hitRatio: null } }, clientFindings: [], incomplete };
  }
  const spoolDir = join(ctx.workDir, "spool");
  mkdirSync(spoolDir, { recursive: true, mode: 0o700 });
  const target = (ex: Exchange) => `${ex.record.method} ${ex.record.url}`;
  const check = (ruleId: string, ex: Exchange | undefined, url: string, status: CheckResult["status"], summary: string, observations: string[] = [], extra: Partial<CheckResult> = {}): void => {
    if (ctx.disabled.has(ruleId)) return;
    checks.push({ ruleId, status, target: ex ? target(ex) : `GET ${ctx.redactor.url(url)}`, transport: "direct-http", summary, observations, requestIds: ex ? [ex.record.id] : [], ...extra });
  };
  const addFinding = (caseId: string, ex: Exchange, f: Fact | undefined, label: string) => {
    const asset = ex.record.url;
    const prev = findings.find((x) => x.caseId === caseId && x.asset === asset && x.preview === label);
    if (prev) { prev.count++; return; }
    if (findings.length >= MAX_CLIENT_FINDINGS) { result.clientFindings.truncated++; return; }
    findings.push({ caseId, asset, position: f ? `${f.line}:${f.col}` : "-", preview: label, count: 1, contentHash: (ex.record.capture?.sha256 ?? "").slice(0, 12) });
  };

  /** Fetches into an owned spool file and scans it (or reuses cached facts for identical content). */
  const fetchScan = async (url: string, actor: AssetContext["actors"][number], method: "GET" = "GET"): Promise<Scanned> => {
    const path = join(spoolDir, `${++spoolN}.bin`);
    const ex = await ctx.send({ method, url, actor: actor.name, headers: { ...actor.headers, accept: "*/*" }, retainBytes: RETAIN, noExcerpt: true, spool: { path, budget: spoolBudget } });
    const out: Scanned = { facts: [], dropped: 0, literalHits: 0, complete: false, cached: false, ...(ex ? { ex } : {}) };
    try {
      if (!ex || ex.record.error || !ex.raw) { out.reason = ex?.record.error ?? "denied by scope"; return out; }
      const c = ex.raw.capture!;
      const ct = ex.raw.headers["content-type"]?.[0] ?? "";
      if (SKIP_TYPE.test(ct)) { out.reason = `skipped by content type ${ct.split(";")[0]}`; return out; }
      out.complete = c.status === "complete" && !c.encoding;
      if (!out.complete) out.reason = c.encoding ? `content-encoding ${c.encoding} not decoded` : `capture ${c.status}: ${c.reason ?? ""}`;
      const key = sha(`${c.sha256}|${DETECTOR_VERSION}|${REDACTION_POLICY_VERSION}`);
      const cached = out.complete ? cacheGet(ctx, key) : undefined;
      if (out.complete) cost.cacheEligible++;
      const lit = new LiteralScanner(ctx.literals);
      const det = cached ? undefined : new StreamScanner();
      if (existsSync(path) && (det || ctx.literals.length)) {
        for await (const chunk of createReadStream(path, { highWaterMark: 1024 * 1024 }) as AsyncIterable<Buffer>) {
          cost.bytesScannedLocally += chunk.length;
          lit.feed(chunk);
          det?.feed(chunk);
        }
      }
      out.literalHits = lit.matches;
      if (cached) { cost.cacheHits++; out.cached = true; out.facts = cached.facts; out.dropped = cached.dropped; if (cached.sourceMappingUrl) out.sourceMappingUrl = cached.sourceMappingUrl; }
      else if (det) {
        const r = det.end();
        out.facts = r.facts;
        out.dropped = r.dropped;
        if (r.sourceMappingUrl) out.sourceMappingUrl = r.sourceMappingUrl;
        // Only complete captures are cache-eligible; partial input is never a reusable clean scan.
        if (out.complete) cachePut(ctx, key, { facts: r.facts, dropped: r.dropped, ...(r.sourceMappingUrl ? { sourceMappingUrl: r.sourceMappingUrl } : {}) });
      }
      return out;
    } finally {
      try { unlinkSync(path); } catch { /* not created */ }
    }
  };

  // ── Inventory from fetched HTML (scripts, stylesheets, preloads) ──
  const queue: { url: string; actor: AssetContext["actors"][number]; from: string }[] = [];
  const seen = new Set<string>();
  const offer = (raw: string, base: string, actorName: string, from: string) => {
    let u: URL;
    try { u = new URL(raw, base); } catch { return; }
    if (u.protocol !== "http:" && u.protocol !== "https:") return;
    u.hash = "";
    const id = `${actorName}\n${u}`;
    if (seen.has(id)) return;
    seen.add(id);
    if (SKIP_EXT.test(u.pathname)) { result.skipped.push({ url: ctx.redactor.url(u.toString()), reason: "media or font (skipped by type)" }); return; }
    const d = ctx.gate.checkRequest(u.toString(), "GET");
    if (!d.allowed) { result.skipped.push({ url: ctx.redactor.url(u.toString()), reason: `out of scope: ${d.reason}` }); return; }
    const actor = ctx.actors.find((a) => a.name === actorName);
    if (actor) queue.push({ url: u.toString(), actor, from });
  };
  for (const p of ctx.pages) {
    if (!p.raw || p.record.error || !/text\/html|application\/xhtml/i.test(p.raw.headers["content-type"]?.[0] ?? "")) continue;
    const page = scanHtml(p.raw.body.toString("utf8"));
    const base = page.base ? safeUrl(page.base, p.raw.finalUrl ?? "") ?? p.raw.finalUrl : p.raw.finalUrl;
    if (!base) continue;
    for (const a of page.assets) offer(a, base, p.record.actor, "html");
  }

  // ── Exposure probes (fixed list, once per origin, as anonymous) ──
  const anon = ctx.actors.find((a) => a.name === "anonymous")!;
  if (!ctx.disabled.has("NSC-CONF-009")) {
    for (const origin of m.targets.origins) {
      for (const probe of EXPOSURE_PROBES) {
        const url = new URL(probe.path, origin).toString();
        const d = ctx.gate.checkRequest(url, "HEAD");
        if (!d.allowed) {
          result.probes.push({ origin, path: probe.path, result: "NOT_TESTED", detail: `outside scope: ${d.reason}` });
          if (probe.format !== "inventory") check("NSC-CONF-009", undefined, url, "NOT_TESTED", `${probe.path} not probed`, [], { reason: `path outside allowed scope: ${d.reason}` });
          continue;
        }
        const head = await ctx.send({ method: "HEAD", url, actor: "anonymous", headers: { ...anon.headers }, retainBytes: 0 });
        const hs = head?.raw?.status;
        if (!head || head.record.error || hs === undefined) {
          result.probes.push({ origin, path: probe.path, result: "ERROR", detail: head?.record.error ?? "no response" });
          if (probe.format !== "inventory") check("NSC-CONF-009", head, url, "ERROR", `${probe.path} probe failed`, [], { reason: head?.record.error ?? "no response" });
          continue;
        }
        if (!((hs >= 200 && hs < 300) || hs === 405)) {
          result.probes.push({ origin, path: probe.path, result: "PASS", detail: `HEAD ${hs}` });
          if (probe.format !== "inventory") check("NSC-CONF-009", head, url, "PASS", `${probe.path} not served (HEAD ${hs})`);
          continue;
        }
        const get = await ctx.send({ method: "GET", url, actor: "anonymous", headers: { ...anon.headers }, retainBytes: RETAIN, noExcerpt: true });
        if (!get?.raw || get.record.error) {
          result.probes.push({ origin, path: probe.path, result: "ERROR", detail: get?.record.error ?? "no response" });
          continue;
        }
        const body = get.raw.body.toString("utf8");
        const status = get.raw.status;
        if (probe.format === "inventory") {
          result.probes.push({ origin, path: probe.path, result: "INVENTORY", detail: `GET ${status}` });
          if (status >= 200 && status < 300) for (const ref of manifestRefs(body)) offer(ref, url, "anonymous", "asset-manifest");
          continue;
        }
        if (status < 200 || status >= 300) {
          result.probes.push({ origin, path: probe.path, result: "PASS", detail: `GET ${status}` });
          check("NSC-CONF-009", get, url, "PASS", `${probe.path} not served (GET ${status})`);
          continue;
        }
        const x = exposureMatch(probe.format, body);
        if (x.match) {
          const obs = [`actor anonymous (public exposure)`, `format ${probe.format} matched`, ...(x.keys.length ? [`key names: ${x.keys.join(", ")}`] : []), "values withheld"];
          result.probes.push({ origin, path: probe.path, result: "FAIL", detail: `format ${probe.format} matched` });
          check("NSC-CONF-009", get, url, "FAIL", `${probe.path} is publicly reachable and matches the ${probe.format} format`, obs, { lifecycle: "VALIDATED" });
          addFinding("NSC-CONF-009", get, undefined, `[${probe.format},keys=${x.keys.length}]`);
        } else {
          result.probes.push({ origin, path: probe.path, result: "PASS", detail: `GET ${status}, format not matched (for example an SPA fallback page)` });
          check("NSC-CONF-009", get, url, "PASS", `${probe.path} returns ${status} but does not match the ${probe.format} format`, ["no finding: a 200 page that is not the file is not an exposure"]);
        }
      }
    }
  }

  // ── Assets: fetch once per request identity, scan, then source maps ──
  const mapsTried = new Set<string>();
  for (let i = 0; i < queue.length; i++) {
    if (result.assets.length >= MAX_ASSETS) { incomplete.push(`static assets: more than ${MAX_ASSETS} assets; the rest were not scanned`); break; }
    const { url, actor, from } = queue[i]!;
    const isMap = from === "map";
    const s = await fetchScan(url, actor);
    const ex = s.ex;
    const status = ex?.raw?.status;
    const entry = { url: ctx.redactor.url(url), actor: actor.name, kind: isMap ? "source-map" : from === "asset-manifest" ? "asset (manifest)" : "asset", status: status ?? 0, bytes: ex?.record.capture?.decodedBytes ?? 0, complete: s.complete, cached: s.cached, facts: s.facts.length, ...(s.reason ? { reason: s.reason } : {}) };
    if (isMap) result.maps.push(entry);
    else result.assets.push(entry);
    if (!ex?.raw || ex.record.error) { if (!isMap) check("NSC-INFO-007", ex, url, "ERROR", "asset fetch failed", [], { reason: s.reason ?? "no response" }); continue; }
    const ok = status! >= 200 && status! < 300;
    if (isMap) { mapVerdict(ctx, s, url, actor.name, ok, check, addFinding); continue; }
    if (!ok) continue;
    if (s.dropped) incomplete.push(`static assets: ${s.dropped} fact(s) beyond the per-asset limit were counted, not kept (${ctx.redactor.url(url)})`);
    assetVerdicts(ctx, s, url, check, addFinding);
    // Source maps: comment, SourceMap / X-SourceMap header, else one `<bundle>.map` sibling probe.
    if (!/\.(?:js|mjs|css)$/i.test(new URL(url).pathname) && !s.sourceMappingUrl) continue;
    const hdr = ex.raw.headers["sourcemap"]?.[0] ?? ex.raw.headers["x-sourcemap"]?.[0];
    const ref = s.sourceMappingUrl && !/^(?:data|file):/i.test(s.sourceMappingUrl) ? s.sourceMappingUrl : hdr;
    const mapUrl = safeUrl(ref ?? `${new URL(url).pathname.split("/").pop()}.map`, url);
    if (!mapUrl || mapsTried.has(`${actor.name}\n${mapUrl}`)) continue;
    mapsTried.add(`${actor.name}\n${mapUrl}`);
    const d = ctx.gate.checkRequest(mapUrl, "GET");
    if (!d.allowed) { result.skipped.push({ url: ctx.redactor.url(mapUrl), reason: `source map out of scope: ${d.reason}` }); continue; }
    queue.push({ url: mapUrl, actor, from: "map" });
  }

  const hitRatio = cost.cacheEligible ? cost.cacheHits / cost.cacheEligible : null;
  result.cost = { ...cost, agentVisibleBytes: 0, hitRatio };
  result.clientFindings.entries = findings.length;
  return { checks, result, clientFindings: findings, incomplete };
}

function assetVerdicts(ctx: AssetContext, s: Scanned, url: string, check: (...a: Parameters<CheckFn>) => void, addFinding: AddFn): void {
  const ex = s.ex!;
  const secrets = s.facts.filter((f) => f.detector === "STA-SECRET");
  const internal = s.facts.filter((f) => f.detector === "STA-INTERNAL");
  const dev = s.facts.filter((f) => f.detector === "STA-DEVBUILD" || f.kind === "sourcemap-file-url");
  const where = (fs: Fact[]) => fs.slice(0, 5).map((f) => `${preview(f)} at ${f.line}:${f.col}`);
  const incompleteReason = s.complete ? undefined : s.reason ?? "incomplete capture";
  // NSC-INFO-007: an exact known-token match is deterministic (VALIDATED); a format match is SUSPECTED.
  if (s.literalHits) {
    check("NSC-INFO-007", ex, url, "FAIL", "Client asset contains a known test token or in-scope credential", [`exact match with ${s.literalHits} known value(s)`, "values withheld"], { lifecycle: "VALIDATED" });
    addFinding("NSC-INFO-007", ex, undefined, `[known-token,matches=${s.literalHits}]`);
  }
  if (secrets.length) {
    check("NSC-INFO-007", ex, url, "FAIL", `Client asset contains ${secrets.length} secret-shaped value(s)`, [...where(secrets), "a format match does not prove the key is live; NavSentry never calls the provider"], { lifecycle: "SUSPECTED" });
    for (const f of secrets) addFinding("NSC-INFO-007", ex, f, preview(f));
  }
  if (!s.literalHits && !secrets.length) check("NSC-INFO-007", ex, url, incompleteReason ? "INCONCLUSIVE" : "PASS", incompleteReason ? "asset not scanned completely" : "no secret-shaped values in the asset", [], incompleteReason ? { reason: incompleteReason } : {});
  if (internal.length) {
    check("NSC-INFO-003", ex, url, "FAIL", `Client asset references ${internal.length} internal host(s) or address(es)`, where(internal));
    for (const f of internal) addFinding("NSC-INFO-003", ex, f, preview(f));
  } else check("NSC-INFO-003", ex, url, incompleteReason ? "INCONCLUSIVE" : "PASS", incompleteReason ? "asset not scanned completely" : "no internal hosts in the asset", [], incompleteReason ? { reason: incompleteReason } : {});
  if (dev.length) {
    if (ctx.manifest.profile === "production") {
      check("NSC-CONF-005", ex, url, "FAIL", "Production bundle contains development-server client code", where(dev), { lifecycle: "SUSPECTED" });
      for (const f of dev) addFinding("NSC-CONF-005", ex, f, preview(f));
    } else check("NSC-CONF-005", ex, url, "NOT_TESTED", "development build markers observed", where(dev), { reason: "development profile: observation only" });
  }
}

function mapVerdict(ctx: AssetContext, s: Scanned, url: string, actor: string, ok: boolean, check: (...a: Parameters<CheckFn>) => void, addFinding: AddFn): void {
  const ex = s.ex!;
  if (!ok) { check("NSC-INFO-008", ex, url, "PASS", `source map not served (${ex.raw!.status})`); return; }
  const ct = ex.raw!.headers["content-type"]?.[0] ?? "";
  if (/text\/html/i.test(ct)) { check("NSC-INFO-008", ex, url, "PASS", "the map URL returns an HTML page, not a source map"); return; }
  const withContent = s.facts.some((f) => f.kind === "sources-content");
  if (!withContent) { check("NSC-INFO-008", ex, url, s.complete ? "PASS" : "INCONCLUSIVE", s.complete ? "source map is served without sourcesContent" : "source map not scanned completely", [], s.complete ? {} : { reason: s.reason ?? "incomplete" }); return; }
  if (ctx.manifest.profile !== "production") { check("NSC-INFO-008", ex, url, "NOT_TESTED", "source map with sourcesContent is reachable", [`actor ${actor}`], { reason: "development profile: observation only" }); return; }
  const anonymous = actor === "anonymous";
  check("NSC-INFO-008", ex, url, "FAIL", anonymous ? "Source map with sourcesContent is publicly reachable" : "Source map with sourcesContent is reachable by an authenticated actor (authenticated-only exposure)", [`actor ${actor}`, anonymous ? "public exposure" : "authenticated-only exposure", "sourcesContent is not empty"], { lifecycle: anonymous ? "VALIDATED" : "SUSPECTED" });
  addFinding("NSC-INFO-008", ex, undefined, `[sources-content,actor=${anonymous ? "anonymous" : "authenticated"}]`);
}

type CheckFn = (ruleId: string, ex: Exchange | undefined, url: string, status: CheckResult["status"], summary: string, observations?: string[], extra?: Partial<CheckResult>) => void;
type AddFn = (caseId: string, ex: Exchange, f: Fact | undefined, label: string) => void;

function safeUrl(ref: string, base: string): string | undefined {
  try { const u = new URL(ref, base); u.hash = ""; return u.protocol === "http:" || u.protocol === "https:" ? u.toString() : undefined; } catch { return undefined; }
}

/** String values of an asset manifest that name scripts, styles or maps (inventory only). */
function manifestRefs(body: string): string[] {
  let doc: unknown;
  try { doc = JSON.parse(body); } catch { return []; }
  const out: string[] = [];
  const walk = (v: unknown, depth: number) => {
    if (depth > 4 || out.length >= MAX_ASSETS) return;
    if (typeof v === "string") { if (/\.(?:m?js|css)(?:\?|$)/i.test(v) && v.length < 500) out.push(v); }
    else if (Array.isArray(v)) v.forEach((x) => walk(x, depth + 1));
    else if (v && typeof v === "object") Object.values(v).forEach((x) => walk(x, depth + 1));
  };
  walk(doc, 0);
  return out;
}

// ───────────────────────── Facts cache (§6.4-C) ─────────────────────────

interface CacheEntry { v: 1; createdAt: string; facts: Fact[]; dropped: number; sourceMappingUrl?: string }

function cacheGet(ctx: AssetContext, key: string): CacheEntry | undefined {
  const days = ctx.manifest.capture.cache_max_age_days;
  if (!ctx.cacheDir || days === 0) return undefined;
  const p = join(ctx.cacheDir, `${key}.json`);
  try {
    const st = statSync(p);
    if (!st.isFile() || st.size > 1024 * 1024) return undefined;
    const e = JSON.parse(readFileSync(p, "utf8")) as CacheEntry;
    const age = (ctx.now?.() ?? new Date()).getTime() - Date.parse(e.createdAt);
    if (e.v !== 1 || !Array.isArray(e.facts) || !(age >= 0 && age < days * 86_400_000)) return undefined;
    return e;
  } catch {
    return undefined;
  }
}

function cachePut(ctx: AssetContext, key: string, e: Omit<CacheEntry, "v" | "createdAt">): void {
  if (!ctx.cacheDir || ctx.manifest.capture.cache_max_age_days === 0) return;
  try {
    mkdirSync(ctx.cacheDir, { recursive: true, mode: 0o700 });
    const p = join(ctx.cacheDir, `${key}.json`);
    const tmp = `${p}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ v: 1, createdAt: (ctx.now?.() ?? new Date()).toISOString(), ...e }), { mode: 0o600 });
    renameSync(tmp, p);
  } catch {
    /* the cache is an optimisation; a failed write only costs a rescan */
  }
}
