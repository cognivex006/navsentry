/**
 * Manifest loading and strict validation. Manifests are JSON in v0.1 (zero runtime
 * dependencies, see docs/adr/0003-zero-runtime-dependencies.md). Unknown keys are
 * rejected so a typo can never silently widen scope.
 */
import { readFileSync } from "node:fs";
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
}

export interface Manifest {
  version: "1";
  project: string;
  environment: "local" | "dev" | "staging" | "production";
  authorization: { acknowledged: boolean; owner: string; reference?: string; expires_at?: string };
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
  };
  transports: { order: string[]; visual_computer_use: boolean };
  actors: Record<string, ActorConfig>;
  checks: { disabled: string[] };
  report: { language: "en" | "th"; formats: ("json" | "markdown" | "sarif")[]; evidence: "redacted-only" | "none" };
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

export function parseManifest(input: unknown): Manifest {
  const p: string[] = [];
  if (!isObj(input)) throw new ConfigError(["manifest root must be an object"]);
  checkKeys(input, ["version", "project", "environment", "authorization", "targets", "network", "safety", "transports", "actors", "checks", "report"], "$", p);

  if (input.version !== "1") p.push('version: must be "1"');
  const project = typeof input.project === "string" && /^[a-z0-9][a-z0-9._-]{0,63}$/i.test(input.project) ? input.project : (p.push("project: required, [A-Za-z0-9._-], max 64"), "invalid");
  const envs = ["local", "dev", "staging", "production"] as const;
  const environment = envs.includes(input.environment as never) ? (input.environment as Manifest["environment"]) : (p.push(`environment: one of ${envs.join(", ")}`), "staging");

  const auth = isObj(input.authorization) ? input.authorization : (p.push("authorization: required object"), {} as Obj);
  checkKeys(auth, ["acknowledged", "owner", "reference", "expires_at"], "authorization", p);
  if (auth.acknowledged !== true) p.push("authorization.acknowledged: must be true (you must own or be explicitly authorized to test every target)");
  if (typeof auth.owner !== "string" || auth.owner.trim() === "") p.push("authorization.owner: required");
  if (auth.expires_at !== undefined) {
    const t = typeof auth.expires_at === "string" ? Date.parse(auth.expires_at) : NaN;
    if (Number.isNaN(t)) p.push("authorization.expires_at: must be an ISO date");
    else if (t < Date.now()) p.push("authorization.expires_at: authorization has expired");
  }

  const tg = isObj(input.targets) ? input.targets : (p.push("targets: required object"), {} as Obj);
  checkKeys(tg, ["origins", "allowed_paths", "denied_paths", "seed_paths"], "targets", p);
  const rawOrigins = strArr(tg.origins, "targets.origins", p);
  if (rawOrigins.length === 0) p.push("targets.origins: at least one origin is required");
  const origins: string[] = [];
  for (const o of rawOrigins) {
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
  checkKeys(sf, ["mode", "max_pages", "max_requests", "max_requests_per_second", "max_duration_seconds", "concurrency", "allow_mutations", "allowed_methods"], "safety", p);
  const mode = (sf.mode ?? "observe") as SafetyMode;
  if (!["observe", "safe-validate", "active-approved"].includes(mode)) p.push("safety.mode: observe | safe-validate");
  if (mode === "active-approved") p.push("safety.mode: active-approved is not available in this release (see docs/DEV-PLAN.md)");
  if (environment === "production" && mode !== "observe") p.push("safety.mode: production targets are limited to observe mode");
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
        checkKeys(a, ["username_env", "password_env", "authorization_header_env"], `actors.${name}`, p);
        for (const k of ["username_env", "password_env", "authorization_header_env"] as const) {
          const v = a[k];
          if (v !== undefined && (typeof v !== "string" || !ENV_NAME.test(v))) p.push(`actors.${name}.${k}: must be an UPPER_SNAKE env var name`);
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

  const limits = {
    max_pages: num(sf.max_pages, "safety.max_pages", p, 30, 1, 500),
    max_requests: num(sf.max_requests, "safety.max_requests", p, 200, 1, 5000),
    max_requests_per_second: num(sf.max_requests_per_second, "safety.max_requests_per_second", p, 2, 0.1, 20),
    max_duration_seconds: num(sf.max_duration_seconds, "safety.max_duration_seconds", p, 600, 5, 7200),
    concurrency: num(sf.concurrency, "safety.concurrency", p, 1, 1, 4),
  };

  if (p.length) throw new ConfigError(p);
  return {
    version: "1",
    project,
    environment,
    authorization: { acknowledged: true, owner: auth.owner as string, ...(typeof auth.reference === "string" ? { reference: auth.reference } : {}), ...(typeof auth.expires_at === "string" ? { expires_at: auth.expires_at } : {}) },
    targets: { origins, allowed_paths, denied_paths, seed_paths },
    network: { allow_private },
    safety: {
      mode,
      ...limits,
      allow_mutations: false,
      allowed_methods,
    },
    transports: { order, visual_computer_use: tr.visual_computer_use === true },
    actors,
    checks: { disabled },
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
