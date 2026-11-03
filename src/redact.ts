/**
 * Redaction applied BEFORE anything is persisted. If a body cannot be shown to be safe
 * (binary, oversized, undecodable) it is withheld and the outcome is marked unsafe.
 */
import type { RedactionOutcome } from "./types.js";

export const MAX_EXCERPT_CHARS = 2048;
/** Bump when redaction rules change; it invalidates cached asset facts (SPEC-0.1.3 §6.4-C). */
export const REDACTION_POLICY_VERSION = "1";

const SENSITIVE_HEADERS = new Set(["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token"]);

interface Pattern {
  kind: string;
  re: RegExp;
  replace: (m: string, ...groups: string[]) => string;
  validate?: (m: string) => boolean;
}

/** Thai national ID checksum (13 digits, mod-11). Reduces false positives on long numbers. */
export function isThaiNationalId(raw: string): boolean {
  const d = raw.replace(/\D/g, "");
  if (d.length !== 13) return false;
  let sum = 0;
  for (let i = 0; i < 12; i++) sum += Number(d[i]) * (13 - i);
  return (11 - (sum % 11)) % 10 === Number(d[12]);
}

export function luhn(raw: string): boolean {
  const d = raw.replace(/\D/g, "");
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = Number(d[d.length - 1 - i]);
    if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return sum % 10 === 0;
}

/**
 * Secret shapes shared by the Redactor and the static asset detectors (SPEC-0.1.3 §6.4: one
 * definition of each secret shape). `marker` is a fixed public provider label, never value data.
 */
export const SECRET_SHAPES: { kind: string; marker?: string; re: RegExp }[] = [
  { kind: "jwt", marker: "jwt", re: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g },
  { kind: "private-key", marker: "private-key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { kind: "provider-key", marker: "aws-access-key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { kind: "provider-key", marker: "stripe-live-key", re: /\b[sr]k_live_[0-9A-Za-z]{16,}\b/g },
  { kind: "provider-key", marker: "stripe-test-key", re: /\b[sr]k_test_[0-9A-Za-z]{16,}\b/g },
  { kind: "provider-key", marker: "github-token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/g },
  { kind: "provider-key", marker: "slack-token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g },
  { kind: "provider-key", marker: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
];

const PROVIDER_PATTERNS: Pattern[] = SECRET_SHAPES.filter((x) => x.kind === "provider-key").map((x) => ({ kind: `provider-key`, re: x.re, replace: () => `[REDACTED:${x.marker}]` }));

const PATTERNS: Pattern[] = [
  ...PROVIDER_PATTERNS,
  { kind: "jwt", re: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g, replace: () => "[REDACTED:jwt]" },
  { kind: "bearer", re: /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, replace: (_m, s) => `${s} [REDACTED]` },
  { kind: "private-key", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, replace: () => "[REDACTED:private-key]" },
  { kind: "secret-assignment", re: /("?(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)"?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,&}]+)/gi, replace: (_m, k) => `${k}"[REDACTED]"` },
  { kind: "email", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, replace: () => "[REDACTED:email]" },
  { kind: "thai-national-id", re: /\b\d{1}[- ]?\d{4}[- ]?\d{5}[- ]?\d{2}[- ]?\d{1}\b/g, replace: () => "[REDACTED:national-id]", validate: isThaiNationalId },
  { kind: "private-ip", re: /\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b/g, replace: () => "[REDACTED:private-ip]" },
  { kind: "card-number", re: /\b(?:\d[ -]?){13,19}\b/g, replace: () => "[REDACTED:card]", validate: luhn },
];

export class Redactor {
  private readonly literals: string[];
  private readonly preserve: Set<string>;

  /**
   * `literals`: exact secret values known to the run (e.g. resolved env credentials).
   * `preserve`: in-scope target hostnames that stay readable even if they are private IPs.
   */
  constructor(literals: string[] = [], preserve: string[] = []) {
    this.literals = literals.filter((s) => s.length >= 4).sort((a, b) => b.length - a.length);
    this.preserve = new Set(preserve);
  }

  text(input: string): { text: string; outcome: RedactionOutcome } {
    let out = input;
    let count = 0;
    const kinds = new Set<string>();
    for (const lit of this.literals) {
      if (out.includes(lit)) {
        const parts = out.split(lit);
        count += parts.length - 1;
        kinds.add("known-secret");
        out = parts.join("[REDACTED:known-secret]");
      }
    }
    for (const p of PATTERNS) {
      out = out.replace(p.re, (m: string, ...rest: unknown[]) => {
        if (p.validate && !p.validate(m)) return m;
        if (p.kind === "private-ip" && this.preserve.has(m)) return m;
        count++;
        kinds.add(p.kind);
        return p.replace(m, ...(rest.filter((x) => typeof x === "string") as string[]));
      });
    }
    return { text: out, outcome: { applied: count > 0, count, kinds: [...kinds].sort(), safe: true } };
  }

  /** Bounded body excerpt. Binary / non-text content is withheld (safe:false). */
  body(buf: Buffer, contentType: string): { excerpt?: string; outcome: RedactionOutcome } {
    const textual = /^(text\/|application\/(json|xml|javascript|problem\+json|x-www-form-urlencoded)|[^;]*\+(json|xml))/i.test(contentType) || contentType === "";
    if (!textual) return { outcome: { applied: false, count: 0, kinds: ["withheld:non-text"], safe: false } };
    const decoded = buf.subarray(0, MAX_EXCERPT_CHARS * 4).toString("utf8");
    if (decoded.includes("\u0000")) return { outcome: { applied: false, count: 0, kinds: ["withheld:binary"], safe: false } };
    const { text, outcome } = this.text(decoded.slice(0, MAX_EXCERPT_CHARS));
    return { excerpt: text, outcome };
  }

  headerValue(name: string, value: string): string {
    const n = name.toLowerCase();
    if (n === "set-cookie") {
      // Keep the cookie name and attributes (needed for cookie checks); drop the value.
      const [pair, ...attrs] = value.split(";");
      const eq = (pair ?? "").indexOf("=");
      const cname = eq >= 0 ? (pair as string).slice(0, eq).trim() : (pair ?? "").trim();
      return [`${cname}=[REDACTED]`, ...attrs.map((a) => a.trim())].join("; ");
    }
    if (SENSITIVE_HEADERS.has(n)) return "[REDACTED]";
    return this.text(value).text;
  }

  url(raw: string): string {
    try {
      const u = new URL(raw);
      for (const k of [...u.searchParams.keys()]) u.searchParams.set(k, "[REDACTED]");
      u.username = "";
      u.password = "";
      return this.text(u.toString()).text.replace(/%5BREDACTED%5D/g, "[REDACTED]");
    } catch {
      return "[REDACTED:unparseable-url]";
    }
  }
}
