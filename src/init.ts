/**
 * `navsentry init <url>` (SPEC-0.3.0 §3.1): writes a starter manifest after the person at the
 * terminal confirms authorization. The questions are asked on a TTY only, so an agent cannot
 * answer them on the user's behalf. The result is validated with the normal manifest parser
 * and never overwrites an existing file.
 */
import { isIP } from "node:net";
import { existsSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";
import { parseManifest, profileOf, type Manifest } from "./config.js";
import { classifyAddress } from "./scope.js";

export const DEFAULT_MANIFEST = "navsentry.json";

export type InitEnvironment = Manifest["environment"];
export const INIT_ENVIRONMENTS: InitEnvironment[] = ["local", "dev", "staging", "production"];

export class InitError extends Error {}

export interface InitAnswers {
  url: string;
  environment: InitEnvironment;
  owner: string;
  /** Required for staging and production (production profile). */
  reference?: string;
  /** ISO date, required for staging and production. */
  expiresAt?: string;
  /** The person confirmed that NavSentry may connect to this loopback or private host. */
  allowPrivate?: boolean;
  language?: "en" | "th";
}

export interface ParsedTarget {
  origin: string;
  host: string;
  seedPath: string;
  /** Non-public label (loopback, private…) when the host is a literal address or localhost. */
  privateLabel?: string;
}

/** Parses the init URL. Only http(s), no credentials; metadata addresses are refused outright. */
export function parseTarget(raw: string): ParsedTarget {
  let u: URL;
  try { u = new URL(raw); } catch { throw new InitError("the URL must be absolute, for example https://app.example.test/"); }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new InitError("only http and https URLs are supported");
  if (u.username || u.password) throw new InitError("the URL may not contain credentials");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  let privateLabel: string | undefined;
  if (host === "localhost" || host.endsWith(".localhost")) privateLabel = "loopback";
  else if (isIP(host)) {
    const label = classifyAddress(host);
    if (label === "cloud metadata") throw new InitError("cloud metadata addresses are never allowed as targets");
    privateLabel = label;
  }
  const seedPath = u.pathname && u.pathname.startsWith("/") ? u.pathname : "/";
  return { origin: u.origin, host, seedPath, ...(privateLabel ? { privateLabel } : {}) };
}

/** Suggested environment: development for local addresses, staging (observe, production profile) otherwise. */
export function suggestEnvironment(t: ParsedTarget): InitEnvironment {
  return t.privateLabel ? "local" : "staging";
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "my-web";

/**
 * Warns when a public host gets the development profile: development allows safe-validate (writes
 * with cleanup) and the browser engine, which is meant for hosts the owner runs locally or in dev.
 */
export function environmentWarning(t: ParsedTarget, environment: InitEnvironment): string | undefined {
  if (t.privateLabel || profileOf(environment) !== "development") return undefined;
  return `Warning: ${t.host} is not a loopback or private address, but environment ${environment} uses the development profile, which allows safe-validate writes and the browser engine. Use staging or production for a shared or public host.`;
}

/**
 * True when `file` would be written inside a NavSentry source checkout. The repository is public,
 * so a manifest naming a real target must not land there by accident.
 */
export function insideNavSentryCheckout(file: string, root: string): boolean {
  const r = resolve(root);
  const f = resolve(file);
  const rel = relative(r, f);
  return !rel.startsWith("..") && !isAbsolute(rel) && existsSync(join(r, ".git"));
}

/** Builds the manifest object and validates it with the normal parser (throws ConfigError). */
export function buildInitManifest(a: InitAnswers): Record<string, unknown> {
  const t = parseTarget(a.url);
  const owner = a.owner.trim();
  if (!owner) throw new InitError("an owner (person or team responsible for the target) is required");
  if (t.privateLabel && !a.allowPrivate) throw new InitError(`${t.host} is a ${t.privateLabel} address; NavSentry connects to it only with your explicit approval`);
  const production = profileOf(a.environment) === "production";
  const authorization: Record<string, unknown> = { acknowledged: true, owner };
  if (production) {
    if (!a.reference?.trim()) throw new InitError(`environment ${a.environment} uses the production profile and needs an authorization reference (ticket or approval ID)`);
    if (!a.expiresAt?.trim()) throw new InitError(`environment ${a.environment} uses the production profile and needs an authorization expiry date`);
    authorization.reference = a.reference.trim();
    authorization.expires_at = a.expiresAt.trim();
  }
  const manifest: Record<string, unknown> = {
    version: "1",
    project: slug(t.host),
    environment: a.environment,
    authorization,
    targets: { origins: [t.origin], allowed_paths: ["/**"], denied_paths: [], seed_paths: [t.seedPath] },
    ...(t.privateLabel ? { network: { allow_private: [{ host: t.host, approved_by: owner, reason: "approved at navsentry init" }] } } : {}),
    safety: { mode: "observe" },
    // The approved headless shell is offered only on the development profile (scan refuses it on production).
    transports: { order: production ? ["direct-http"] : ["direct-http", "playwright-browser"], visual_computer_use: false },
    checks: { disabled: [] },
    report: { language: a.language ?? "en", formats: ["json", "markdown", "sarif"], evidence: "redacted-only" },
  };
  parseManifest(manifest);
  return manifest;
}

export interface Prompter {
  ask(question: string): Promise<string>;
  say(line: string): void;
}

const yes = (s: string) => /^(y|yes|ใช่)$/i.test(s.trim());

/** Runs the interactive questions. Every refusal throws InitError; nothing is written here. */
export async function askInit(p: Prompter, url: string, opts: { environment?: InitEnvironment; language?: "en" | "th" } = {}): Promise<InitAnswers> {
  const t = parseTarget(url);
  let environment = opts.environment;
  if (!environment) {
    const def = suggestEnvironment(t);
    const e = (await p.ask(`Environment [local/dev/staging/production] (${def}): `)).trim() || def;
    if (!INIT_ENVIRONMENTS.includes(e as InitEnvironment)) throw new InitError(`environment must be one of ${INIT_ENVIRONMENTS.join(", ")}`);
    environment = e as InitEnvironment;
  }
  p.say(`Target: ${t.origin} (environment ${environment}, ${profileOf(environment)} profile)`);
  const warning = environmentWarning(t, environment);
  if (warning) {
    p.say(warning);
    if (!yes(await p.ask(`Keep environment ${environment} for ${t.host}? (yes/no): `))) throw new InitError("environment not confirmed; nothing was written. Run again with --environment staging or production");
  }
  if (!yes(await p.ask(`Do you own ${t.origin} or have written authorization to test it? (yes/no): `))) throw new InitError("authorization not confirmed; nothing was written");
  const owner = (await p.ask("Owner (person or team responsible for the target): ")).trim();
  if (!owner) throw new InitError("an owner is required; nothing was written");
  const a: InitAnswers = { url, environment, owner, ...(opts.language ? { language: opts.language } : {}) };
  if (profileOf(environment) === "production") {
    a.reference = (await p.ask("Authorization reference (ticket or approval ID, no URLs): ")).trim();
    a.expiresAt = (await p.ask("Authorization expires on (YYYY-MM-DD): ")).trim();
  }
  if (t.privateLabel) {
    if (!yes(await p.ask(`${t.host} is a ${t.privateLabel} address. Allow NavSentry to connect to it? (yes/no): `))) throw new InitError("private address not approved; nothing was written");
    a.allowPrivate = true;
  }
  return a;
}
