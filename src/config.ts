/**
 * Manifest loading and strict validation. Manifests are JSON in v0.1 (zero runtime
 * dependencies, see docs/adr/0003-zero-runtime-dependencies.md). Unknown keys are
 * rejected so a typo can never silently widen scope.
 */
import { readFileSync } from "node:fs";
import { fixtureScopeProblems, parseAuthEndpoints, parseFixtures, type AuthEndpoints, type FixtureDecl } from "./fixtures/config.js";
import type { HttpMethod, SafetyMode } from "./types.js";

export interface PrivateNetworkApproval {
  host: string;
  approved_by: string;
  reason: string;
}

export interface ActorConfig {
  username_env?: string;
  password_env?: string;
  /** Env var holding a full header value, e.g. a test bearer token. Never the value itself. */
  authorization_header_env?: string;
  /** Env var holding a full Cookie header for a cookie-session actor (development profile only; SPEC-0.2.0 §4.3, S17). */
  cookie_env?: string;
  /** safe-validate login (SPEC-0.2.0 §4.3): over http to auth_endpoints.login, or through a referenced browser flow. */
  login?: { http: "login"; body: { json: Record<string, unknown> } } | { flow: string };
}

/** Derived from `environment` (SPEC-0.1.3 §4); staging is production-like (owner decision D4). */
export type Profile = "development" | "production";

export function profileOf(environment: Manifest["environment"]): Profile {
  return environment === "local" || environment === "dev" ? "development" : "production";
}

export interface CaptureLimits {
  max_response_bytes: number;
  max_run_bytes: number;
  max_wire_bytes: number;
  max_work_bytes: number;
  memory_buffer_bytes: number;
  max_console_messages: number;
  max_console_bytes: number;
  cache_max_age_days: number;
}

export interface Manifest {
  version: "1";
  project: string;
  environment: "local" | "dev" | "staging" | "production";
  profile: Profile;
  authorization: { acknowledged: boolean; owner: string; reference?: string; expires_at?: string; not_before?: string; allow_live_tokens: boolean };
  targets: { origins: string[]; allowed_paths: string[]; denied_paths: string[]; seed_paths: string[] };
  network: { allow_private: PrivateNetworkApproval[] };
  safety: {
    mode: SafetyMode;
    max_pages: number;
    max_requests: number;
    max_requests_per_second: number;
    max_duration_seconds: number;
    concurrency: number;
    allow_mutations: boolean;
    allowed_methods: HttpMethod[];
    max_depth: number;
    representatives_per_pattern: number;
    max_frontier: number;
    /** safe-validate: non-observe requests per run, including login and logout (SPEC-0.2.0 §3.2). */
    max_mutations: number;
    /** safe-validate: creates stop when less than this remains before the earlier deadline (§6.1). */
    cleanup_window_seconds: number;
  };
  capture: CaptureLimits;
  analyzer: { timeout_seconds: number; include_text: boolean };
  workspace: { ignore: string[] };
  transports: { order: string[]; visual_computer_use: boolean };
  actors: Record<string, ActorConfig>;
  checks: { disabled: string[] };
  report: { language: "en" | "th"; formats: ("json" | "markdown" | "sarif")[]; evidence: "redacted-only" | "none" };
  /** safe-validate only (SPEC-0.2.0 §3.2); empty otherwise. */
  fixtures: Record<string, FixtureDecl>;
  auth_endpoints: AuthEndpoints;
}

export class ConfigError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Invalid manifest:\n- ${problems.join("\n- ")}`);
  }
}

type Obj = Record<string, unknown>;
const ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;
const KNOWN_TRANSPORTS = ["direct-http", "playwright-browser", "curl-cli", "powershell-http", "visual-computer-use", "zap-passive"];
const SECRETISH_KEYS = /^(password|passwd|secret|token|api[_-]?key|cookie|authorization)$/i;

function isObj(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function checkKeys(o: Obj, allowed: string[], where: string, p: string[]): void {
  for (const k of Object.keys(o)) {
    if (!allowed.includes(k)) {
      if (SECRETISH_KEYS.test(k)) p.push(`${where}.${k}: plaintext secrets are forbidden; use an *_env reference`);
      else p.push(`${where}.${k}: unknown key`);
    }
  }
}

function strArr(v: unknown, where: string, p: string[], def: string[] = []): string[] {
  if (v === undefined) return def;
  if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
    p.push(`${where}: must be an array of strings`);
    return def;
  }
  return v as string[];
}

function num(v: unknown, where: string, p: string[], def: number, min: number, max: number): number {
  if (v === undefined) return def;
  if (typeof v !== "number" || !Number.isFinite(v) || v < min || v > max) {
    p.push(`${where}: must be a number in [${min}, ${max}]`);
    return def;
  }
  return v;
}

const KiB = 1024, MiB = 1024 * KiB, GiB = 1024 * MiB;

/** Profile defaults, applied before parsing (SPEC-0.1.3 §3.2; owner decisions D2, D6, D9). */
export const PROFILE_DEFAULTS: Record<Profile, { max_requests: number; max_requests_per_second: number; max_depth: number; representatives_per_pattern: number; max_frontier: number }> = {
  development: { max_requests: 200, max_requests_per_second: 2, max_depth: 4, representatives_per_pattern: 3, max_frontier: 5000 },
  production: { max_requests: 100, max_requests_per_second: 1, max_depth: 2, representatives_per_pattern: 2, max_frontier: 1000 },
};

export const CAPTURE_DEFAULTS: CaptureLimits = {
  max_response_bytes: 256 * MiB,
  max_run_bytes: 2 * GiB,
  max_wire_bytes: 2 * GiB,
  max_work_bytes: 2 * GiB,
  memory_buffer_bytes: 8 * MiB,
  max_console_messages: 10_000,
  max_console_bytes: 16 * MiB,
  cache_max_age_days: 30,
};

function int(v: unknown, where: string, p: string[], def: number, min: number, max: number): number {
  if (v !== undefined && (typeof v !== "number" || !Number.isSafeInteger(v))) {
    p.push(`${where}: must be an integer in [${min}, ${max}]`);
    return def;
  }
  return num(v, where, p, def, min, max);
}

/** Relative glob without traversal, absolute, drive or UNC forms. */
function safeGlob(g: string): boolean {
  return g.length > 0 && g.length <= 200 && !/^[\\/]/.test(g) && !/^[A-Za-z]:/.test(g) && !g.split(/[\\/]/).includes("..") && !/[\0\r\n]/.test(g);
}

export function normalizeOrigin(raw: string): string | undefined {
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:" && u.protocol !== "http:") return undefined;
    if (u.username || u.password || u.search || u.hash || (u.pathname !== "/" && u.pathname !== "")) return undefined;
    return u.origin;
  } catch {
    return undefined;
  }
}

function section(input: Obj, key: string, p: string[]): Obj {
  const v = input[key];
  if (v === undefined) return {};
  if (!isObj(v)) { p.push(`${key}: must be an object`); return {}; }
  return v;
}

export function parseManifest(input: unknown): Manifest {
  const p: string[] = [];
  if (!isObj(input)) throw new ConfigError(["manifest root must be an object"]);
  checkKeys(input, ["version", "project", "environment", "authorization", "targets", "network", "safety", "transports", "actors", "checks", "report", "capture", "analyzer", "workspace", "fixtures", "auth_endpoints"], "$", p);

  if (input.version !== "1") p.push('version: must be "1"');
  const project = typeof input.project === "string" && /^[a-z0-9][a-z0-9._-]{0,63}$/i.test(input.project) ? input.project : (p.push("project: required, [A-Za-z0-9._-], max 64"), "invalid");
  const envs = ["local", "dev", "staging", "production"] as const;
  const environment = envs.includes(input.environment as never) ? (input.environment as Manifest["environment"]) : (p.push(`environment: one of ${envs.join(", ")}`), "staging");

  const profile = profileOf(environment);
  const auth = isObj(input.authorization) ? input.authorization : (p.push("authorization: required object"), {} as Obj);
  checkKeys(auth, ["acknowledged", "owner", "reference", "expires_at", "not_before", "allow_live_tokens"], "authorization", p);
  if (auth.acknowledged !== true) p.push("authorization.acknowledged: must be true (you must own or be explicitly authorized to test every target)");
  if (typeof auth.owner !== "string" || auth.owner.trim() === "") p.push("authorization.owner: required");
  if (auth.expires_at !== undefined) {
    const t = typeof auth.expires_at === "string" ? Date.parse(auth.expires_at) : NaN;
    if (Number.isNaN(t)) p.push("authorization.expires_at: must be an ISO date");
    else if (t < Date.now()) p.push("authorization.expires_at: authorization has expired");
  }
  if (auth.reference !== undefined && (typeof auth.reference !== "string" || auth.reference.trim().length < 1 || auth.reference.length > 100)) p.push("authorization.reference: string of 1-100 characters");
  if (auth.not_before !== undefined) {
    const nb = typeof auth.not_before === "string" ? Date.parse(auth.not_before) : NaN;
    if (Number.isNaN(nb)) p.push("authorization.not_before: must be an ISO date");
    else if (typeof auth.expires_at === "string" && !(nb < Date.parse(auth.expires_at))) p.push("authorization.not_before: must be before expires_at");
  }
  if (auth.allow_live_tokens !== undefined && typeof auth.allow_live_tokens !== "boolean") p.push("authorization.allow_live_tokens: boolean");
  if (profile === "production") {
    const migrate = envs.includes(input.environment as never)
      ? `(environment "${environment}" uses the production profile since 0.1.3; see CHANGELOG migration notes)`
      : "(an unrecognized environment is treated as production; use local or dev for the development profile)";
    if (typeof auth.reference !== "string") p.push(`authorization.reference: required for the production profile ${migrate}`);
    else if (/[./:]/.test(auth.reference)) p.push("authorization.reference: may not contain '.', '/' or ':' in the production profile (no hostnames or URLs)");
    if (auth.expires_at === undefined) p.push(`authorization.expires_at: required for the production profile ${migrate}`);
  }

  const tg = isObj(input.targets) ? input.targets : (p.push("targets: required object"), {} as Obj);
  checkKeys(tg, ["origins", "allowed_paths", "denied_paths", "seed_paths"], "targets", p);
  const rawOrigins = strArr(tg.origins, "targets.origins", p);
  if (rawOrigins.length === 0) p.push("targets.origins: at least one origin is required");
  const origins: string[] = [];
  for (const o of rawOrigins) {
    if (o.includes("*")) { p.push(`targets.origins: "${o}" contains "*"; wildcard origins are not supported`); continue; }
    const n = normalizeOrigin(o);
    if (!n) p.push(`targets.origins: "${o}" is not a bare http(s) origin (no path, query, credentials)`);
    else origins.push(n);
  }
  const allowed_paths = strArr(tg.allowed_paths, "targets.allowed_paths", p, ["/**"]);
  const denied_paths = strArr(tg.denied_paths, "targets.denied_paths", p);
  const seed_paths = strArr(tg.seed_paths, "targets.seed_paths", p, ["/"]);
  for (const s of [...allowed_paths, ...denied_paths, ...seed_paths]) {
    if (!s.startsWith("/") || /[\s\\]/.test(s) || s.includes("..")) p.push(`targets: path pattern "${s}" must start with "/" and contain no whitespace, backslash or ".."`);
  }

  const net = isObj(input.network) ? input.network : {};
  checkKeys(net, ["allow_private"], "network", p);
  const allow_private: PrivateNetworkApproval[] = [];
  if (net.allow_private !== undefined) {
    if (!Array.isArray(net.allow_private)) p.push("network.allow_private: must be an array");
    else
      for (const [i, a] of net.allow_private.entries()) {
        if (!isObj(a) || typeof a.host !== "string" || typeof a.approved_by !== "string" || typeof a.reason !== "string" || !a.approved_by.trim() || !a.reason.trim()) {
          p.push(`network.allow_private[${i}]: requires host, approved_by and reason`);
        } else {
          checkKeys(a, ["host", "approved_by", "reason"], `network.allow_private[${i}]`, p);
          allow_private.push({ host: a.host.toLowerCase(), approved_by: a.approved_by, reason: a.reason });
        }
      }
  }

  const sf = isObj(input.safety) ? input.safety : {};
  checkKeys(sf, ["mode", "max_pages", "max_requests", "max_requests_per_second", "max_duration_seconds", "concurrency", "allow_mutations", "allowed_methods", "max_depth", "representatives_per_pattern", "max_frontier", "max_mutations", "cleanup_window_seconds"], "safety", p);
  const mode = (sf.mode ?? "observe") as SafetyMode;
  if (!["observe", "safe-validate", "active-approved"].includes(mode)) p.push("safety.mode: observe | safe-validate");
  if (mode === "active-approved") p.push("safety.mode: active-approved is not available in this release (see docs/DEV-PLAN.md)");
  // By profile, not by name: staging (and an unrecognized environment) is the production profile too.
  if (profile === "production" && mode !== "observe") p.push(`safety.mode: the production profile (environment "${environment}") is limited to observe mode`);
  if (sf.allow_mutations !== undefined && sf.allow_mutations !== false) p.push("safety.allow_mutations: mutations are not supported in this release");
  const allowed_methods = strArr(sf.allowed_methods, "safety.allowed_methods", p, ["GET", "HEAD", "OPTIONS"]) as HttpMethod[];
  for (const m of allowed_methods) if (!["GET", "HEAD", "OPTIONS"].includes(m)) p.push(`safety.allowed_methods: ${m} is not a safe method; only GET, HEAD, OPTIONS are allowed in this release`);

  const tr = isObj(input.transports) ? input.transports : {};
  checkKeys(tr, ["order", "visual_computer_use"], "transports", p);
  const order = strArr(tr.order, "transports.order", p, ["direct-http"]);
  for (const t of order) if (!KNOWN_TRANSPORTS.includes(t)) p.push(`transports.order: unknown transport "${t}"`);
  if (tr.visual_computer_use !== undefined && typeof tr.visual_computer_use !== "boolean") p.push("transports.visual_computer_use: boolean");

  const actors: Record<string, ActorConfig> = { anonymous: {} };
  if (input.actors !== undefined) {
    if (!isObj(input.actors)) p.push("actors: must be an object");
    else
      for (const [name, a] of Object.entries(input.actors)) {
        if (!/^[a-z][a-z0-9_-]{0,31}$/.test(name)) p.push(`actors.${name}: invalid actor name`);
        if (!isObj(a)) { p.push(`actors.${name}: must be an object`); continue; }
        checkKeys(a, ["username_env", "password_env", "authorization_header_env", "cookie_env", "login"], `actors.${name}`, p);
        for (const k of ["username_env", "password_env", "authorization_header_env", "cookie_env"] as const) {
          const v = a[k];
          if (v !== undefined && (typeof v !== "string" || !ENV_NAME.test(v))) p.push(`actors.${name}.${k}: must be an UPPER_SNAKE env var name`);
        }
        const kinds = ["authorization_header_env", "cookie_env", "login"].filter((k) => a[k] !== undefined);
        if (kinds.length > 1) p.push(`actors.${name}: use one of authorization_header_env, cookie_env or login`);
        if (a.cookie_env !== undefined && profile === "production") p.push(`actors.${name}.cookie_env: refused in the production profile (live session cookies, S17)`);
        if (a.login !== undefined) {
          const l = a.login;
          if (!isObj(l)) p.push(`actors.${name}.login: must be an object`);
          else if ("flow" in l) {
            checkKeys(l, ["flow"], `actors.${name}.login`, p);
            if (typeof l.flow !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(l.flow)) p.push(`actors.${name}.login.flow: a flow id`);
          } else {
            checkKeys(l, ["http", "body"], `actors.${name}.login`, p);
            if (l.http !== "login") p.push(`actors.${name}.login.http: must be "login" (the auth_endpoints entry)`);
            const b = l.body;
            if (!isObj(b) || Object.keys(b).join() !== "json" || !isObj(b.json)) p.push(`actors.${name}.login.body: {"json": {...}}`);
            else {
              const leaves = JSON.stringify(b.json).match(/{{[^}]*}}/g) ?? [];
              if (leaves.some((x) => x !== "{{username}}" && x !== "{{password}}")) p.push(`actors.${name}.login.body: only {{username}} and {{password}} placeholders`);
              if (JSON.stringify(b.json).length > 4096) p.push(`actors.${name}.login.body: at most 4096 bytes`);
            }
          }
          if (!a.username_env || !a.password_env) p.push(`actors.${name}.login: needs username_env and password_env`);
        }
        actors[name] = a as ActorConfig;
      }
  }

  const ck = isObj(input.checks) ? input.checks : {};
  checkKeys(ck, ["disabled"], "checks", p);
  const disabled = strArr(ck.disabled, "checks.disabled", p);

  const rp = isObj(input.report) ? input.report : {};
  checkKeys(rp, ["language", "formats", "evidence"], "report", p);
  const language = (rp.language ?? "en") as "en" | "th";
  if (!["en", "th"].includes(language)) p.push("report.language: en | th");
  const formats = strArr(rp.formats, "report.formats", p, ["json", "markdown", "sarif"]) as Manifest["report"]["formats"];
  for (const f of formats) if (!["json", "markdown", "sarif"].includes(f)) p.push(`report.formats: unsupported "${f}"`);
  const evidence = (rp.evidence ?? "redacted-only") as Manifest["report"]["evidence"];
  if (!["redacted-only", "none"].includes(evidence)) p.push("report.evidence: redacted-only | none");

  const pd = PROFILE_DEFAULTS[profile];
  const limits = {
    max_pages: num(sf.max_pages, "safety.max_pages", p, 30, 1, 500),
    max_requests: num(sf.max_requests, "safety.max_requests", p, pd.max_requests, 1, 5000),
    max_requests_per_second: num(sf.max_requests_per_second, "safety.max_requests_per_second", p, pd.max_requests_per_second, 0.1, 20),
    max_duration_seconds: num(sf.max_duration_seconds, "safety.max_duration_seconds", p, 600, 5, 7200),
    concurrency: num(sf.concurrency, "safety.concurrency", p, 1, 1, 4),
    max_depth: int(sf.max_depth, "safety.max_depth", p, pd.max_depth, 1, 10),
    representatives_per_pattern: int(sf.representatives_per_pattern, "safety.representatives_per_pattern", p, pd.representatives_per_pattern, 1, 10),
    max_frontier: int(sf.max_frontier, "safety.max_frontier", p, pd.max_frontier, 10, 100_000),
    max_mutations: int(sf.max_mutations, "safety.max_mutations", p, 20, 1, 200),
    cleanup_window_seconds: int(sf.cleanup_window_seconds, "safety.cleanup_window_seconds", p, 30, 10, 300),
  };

  const cp = section(input, "capture", p);
  checkKeys(cp, Object.keys(CAPTURE_DEFAULTS), "capture", p);
  const big = Number.MAX_SAFE_INTEGER;
  const resp = int(cp.max_response_bytes, "capture.max_response_bytes", p, CAPTURE_DEFAULTS.max_response_bytes, 64 * KiB, big);
  const runB = int(cp.max_run_bytes, "capture.max_run_bytes", p, Math.max(CAPTURE_DEFAULTS.max_run_bytes, resp), resp, big);
  const capture: CaptureLimits = {
    max_response_bytes: resp,
    max_run_bytes: runB,
    max_wire_bytes: int(cp.max_wire_bytes, "capture.max_wire_bytes", p, CAPTURE_DEFAULTS.max_wire_bytes, MiB, big),
    max_work_bytes: int(cp.max_work_bytes, "capture.max_work_bytes", p, Math.max(CAPTURE_DEFAULTS.max_work_bytes, resp), resp, big),
    memory_buffer_bytes: int(cp.memory_buffer_bytes, "capture.memory_buffer_bytes", p, Math.min(CAPTURE_DEFAULTS.memory_buffer_bytes, resp), 64 * KiB, Math.min(256 * MiB, resp)),
    max_console_messages: int(cp.max_console_messages, "capture.max_console_messages", p, CAPTURE_DEFAULTS.max_console_messages, 1, 1_000_000),
    max_console_bytes: int(cp.max_console_bytes, "capture.max_console_bytes", p, Math.min(CAPTURE_DEFAULTS.max_console_bytes, runB), 64 * KiB, runB),
    cache_max_age_days: int(cp.cache_max_age_days, "capture.cache_max_age_days", p, CAPTURE_DEFAULTS.cache_max_age_days, 0, 365),
  };

  const an = section(input, "analyzer", p);
  checkKeys(an, ["timeout_seconds", "include_text"], "analyzer", p);
  if (an.include_text !== undefined && typeof an.include_text !== "boolean") p.push("analyzer.include_text: boolean");
  const analyzer = { timeout_seconds: int(an.timeout_seconds, "analyzer.timeout_seconds", p, Math.min(120, limits.max_duration_seconds), 1, 3600), include_text: an.include_text === true };
  if (an.timeout_seconds !== undefined && analyzer.timeout_seconds > limits.max_duration_seconds) p.push("analyzer.timeout_seconds: must not exceed safety.max_duration_seconds");

  const ws = section(input, "workspace", p);
  checkKeys(ws, ["ignore"], "workspace", p);
  const ignore = strArr(ws.ignore, "workspace.ignore", p);
  if (ignore.length > 50) p.push("workspace.ignore: at most 50 globs");
  for (const g of ignore) if (!safeGlob(g)) p.push(`workspace.ignore: "${g}" must be a relative glob without "..", absolute, drive or UNC paths`);

  // safe-validate declarations (SPEC-0.2.0): only with that mode and the development profile.
  let fixtures: Record<string, FixtureDecl> = {};
  let auth_endpoints: AuthEndpoints = {};
  if (input.fixtures !== undefined || input.auth_endpoints !== undefined) {
    if (mode !== "safe-validate" || profile !== "development") p.push("fixtures, auth_endpoints: need safety.mode safe-validate and the development profile (environment local or dev)");
    else {
      if (input.fixtures !== undefined) fixtures = parseFixtures(input.fixtures, Object.keys(actors), p);
      if (input.auth_endpoints !== undefined) auth_endpoints = parseAuthEndpoints(input.auth_endpoints, p);
      p.push(...fixtureScopeProblems(fixtures, auth_endpoints, allowed_paths, denied_paths));
    }
  }
  for (const [name, a] of Object.entries(actors)) {
    if (!a.login) continue;
    if (mode !== "safe-validate" || profile !== "development") p.push(`actors.${name}.login: needs safety.mode safe-validate and the development profile`);
    else if (!auth_endpoints.login) p.push(`actors.${name}.login: declare auth_endpoints.login`);
  }
  if (p.length) throw new ConfigError(p);
  return {
    version: "1",
    project,
    environment,
    profile,
    authorization: {
      acknowledged: true,
      owner: auth.owner as string,
      ...(typeof auth.reference === "string" ? { reference: auth.reference } : {}),
      ...(typeof auth.expires_at === "string" ? { expires_at: auth.expires_at } : {}),
      ...(typeof auth.not_before === "string" ? { not_before: auth.not_before } : {}),
      allow_live_tokens: auth.allow_live_tokens === true,
    },
    targets: { origins, allowed_paths, denied_paths, seed_paths },
    network: { allow_private },
    safety: {
      mode,
      ...limits,
      allow_mutations: false,
      allowed_methods,
    },
    capture,
    analyzer,
    workspace: { ignore },
    transports: { order, visual_computer_use: tr.visual_computer_use === true },
    actors,
    checks: { disabled },
    fixtures,
    auth_endpoints,
    report: { language, formats, evidence },
  };
}

export function loadManifest(path: string): Manifest {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (e) {
    throw new ConfigError([`cannot read manifest: ${(e as NodeJS.ErrnoException).code ?? "error"}`]);
  }
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new ConfigError(["manifest is not valid JSON (YAML support is planned, see docs/DEV-PLAN.md)"]);
  }
  return parseManifest(data);
}

/** Throws when `now` is outside [not_before, expires_at]. Called before any network activity. */
export function assertAuthorizationWindow(m: Manifest, now: Date = new Date()): void {
  const t = now.getTime();
  if (m.authorization.not_before && t < Date.parse(m.authorization.not_before)) throw new ConfigError([`authorization.not_before: the authorization window has not started (${m.authorization.not_before})`]);
  if (m.authorization.expires_at && t >= Date.parse(m.authorization.expires_at)) throw new ConfigError([`authorization.expires_at: the authorization window has ended (${m.authorization.expires_at})`]);
}

/** Public live-key prefixes. In the production profile a credential carrying one is refused unless allowed. */
const LIVE_TOKEN = /\b(sk_live_|rk_live_|pk_live_|xox[bpa]-|ghp_|github_pat_|AKIA)/;

export function assertNoLiveTokens(m: Manifest, values: string[]): void {
  if (m.profile !== "production" || m.authorization.allow_live_tokens) return;
  if (values.some((v) => LIVE_TOKEN.test(v))) throw new ConfigError(["actors: a credential with a live-key prefix was refused for the production profile; use a test token or set authorization.allow_live_tokens: true"]);
}
