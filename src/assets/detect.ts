/**
 * Static asset detectors (SPEC-0.1.3 §6.4-B, engine `node-detector`). They run over a stream of
 * chunks with a bounded overlap, so a value split across a chunk boundary is still found, and they
 * keep only redacted facts: kind, position and length. Never a value, prefix or hash of a value.
 */
import { SECRET_SHAPES } from "../redact.js";

/** Bump when a detector changes; it invalidates cached facts. */
export const DETECTOR_VERSION = "3";
/** Longest match a detector reports; the overlap window is this long. */
export const MAX_MATCH = 4096;

export type FactKind =
  | "secret" | "private-key" | "secret-assignment" | "internal-host" | "private-ip"
  | "dev-server-client" | "sourcemap-url" | "sourcemap-file-url" | "sources-content"
  | "console-override" | "debug-toggle" | "library-banner";

export interface Fact {
  /** Detector label (internal). */
  detector: "STA-SECRET" | "STA-INTERNAL" | "STA-DEVBUILD" | "STA-SOURCEMAP" | "STA-HIDDENLOG" | "STA-LIBVULN";
  kind: FactKind;
  /** Public provider marker from the detector definition, e.g. "aws-access-key". */
  marker?: string;
  line: number;
  col: number;
  len: number;
  /** STA-LIBVULN only: public library identity from its licence banner (a version, never a secret). */
  library?: { ecosystem: "npm"; name: string; version: string };
}

interface Rule {
  detector: Fact["detector"];
  kind: FactKind;
  re: RegExp;
  marker?: string;
  validate?: (m: string) => boolean;
  /**
   * Fast prefilter for rules whose precise pattern starts with an open character class: only
   * candidate spans around a prefilter hit (`span` chars each side) get the precise check (§6.4-C).
   */
  pre?: RegExp;
  span?: number;
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  const f = new Map<string, number>();
  for (const c of s) f.set(c, (f.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of f.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

const ASSIGN_VALUE = /[:=]\s*["'`]([^"'`\s]{8,512})["'`]/;

const RULES: Rule[] = [
  ...SECRET_SHAPES.map((s): Rule => ({ detector: "STA-SECRET", kind: s.kind === "private-key" ? "private-key" : "secret", re: s.re, marker: s.marker })),
  // High-entropy literal next to a secret-looking key name. Public client IDs are usually low-entropy or unprefixed.
  {
    detector: "STA-SECRET", kind: "secret-assignment",
    pre: /secret|token|passw(?:or)?d|api[_-]?key|private[_-]?key/gi, span: 64,
    re: /["']?\b[A-Za-z0-9_]{0,40}(?:secret|token|passw(?:or)?d|api[_-]?key|private[_-]?key)[A-Za-z0-9_]{0,40}["']?\s*[:=]\s*["'`][^"'`\s]{8,512}["'`]/gi,
    validate: (m) => { const v = ASSIGN_VALUE.exec(m)?.[1] ?? ""; return v.length >= 12 && entropy(v) >= 3.5 && !/^(?:x+|\*+|your[-_]|<|\$\{|process\.env)/i.test(v); },
  },
  { detector: "STA-INTERNAL", kind: "private-ip", re: /\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g },
  {
    detector: "STA-INTERNAL", kind: "internal-host",
    pre: /\.(?:internal|corp|intranet|lan)\b|localhost:\d|(?:staging|stg|uat|preprod)[.-]/gi, span: 260,
    re: /\b[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,6}\.(?:internal|corp|intranet|lan)\b|\blocalhost:\d{2,5}\b|\b(?:staging|stg|uat|preprod)[.-][a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63}){0,6}\.[a-z]{2,}\b/gi,
  },
  { detector: "STA-DEVBUILD", kind: "dev-server-client", re: /webpack-dev-server|\[HMR\] |\/@vite\/client|__webpack_hmr/g },
  // Logging that is only hidden, not removed (SPEC-0.1.3 §6.4-A). Observations; toggles are never set (S9).
  { detector: "STA-HIDDENLOG", kind: "console-override", re: /\bconsole\.(?:log|debug|info|warn|error)\s*=\s*(?:function\s*\w*\s*\(\s*\)\s*\{\s*\}|\(\s*\)\s*=>\s*(?:\{\s*\}|void 0|undefined|null|0))/g },
  { detector: "STA-HIDDENLOG", kind: "debug-toggle", re: /[?&]debug=(?:1|true)\b|localStorage\.(?:getItem|setItem)\(\s*["'`](?:debug|DEBUG|loglevel|logLevel)["'`]/g },
  // Client library licence banners (SPEC-0.1.3 §6.4-B STA-LIBVULN). Only the banner comment form counts, so a
  // plugin's "requires jQuery v1.7" is not mistaken for the bundled library.
  { detector: "STA-LIBVULN", kind: "library-banner", re: /\/\*!\s*jQuery v\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?\b|^\s*\*\s*jQuery JavaScript Library v\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?\b/gm },
  { detector: "STA-SOURCEMAP", kind: "sourcemap-file-url", re: /[#@] sourceMappingURL=file:\/\/[^\s'"]+/g },
  { detector: "STA-SOURCEMAP", kind: "sources-content", re: /"sourcesContent"\s*:\s*\[\s*"/g },
];

const SOURCEMAP_URL = /[#@] sourceMappingURL=([^\s'"*]+)/g;

export interface ScanOutput {
  facts: Fact[];
  /** Value of the last `sourceMappingURL` comment (a URL reference, not a secret). */
  sourceMappingUrl?: string;
  bytes: number;
  /** Facts beyond MAX_FACTS are counted, not kept. */
  dropped: number;
}

export const MAX_FACTS = 500;

/** Chunked scanner: `feed` chunks in order, then `end`. Memory is bounded by chunk + MAX_MATCH. */
export class StreamScanner {
  private tail = "";
  /** Offset (in the decoded string stream) where `tail` starts. */
  private tailStart = 0;
  private line = 1;
  private lineStart = 0;
  /** Absolute end offset up to which matches are settled. */
  private doneUpTo = -1;
  private out: ScanOutput = { facts: [], bytes: 0, dropped: 0 };
  private readonly decoder = new TextDecoder("utf-8", { fatal: false });

  feed(chunk: Uint8Array): void {
    this.out.bytes += chunk.length;
    this.scan(this.decoder.decode(chunk, { stream: true }), false);
  }

  end(): ScanOutput {
    this.scan(this.decoder.decode(), true);
    return this.out;
  }

  private scan(text: string, final: boolean): void {
    const win = this.tail + text;
    const base = this.tailStart;
    const lines = lineIndex(win);
    for (const r of RULES) {
      for (const m of matches(r, win)) {
        const endRel = m.index + m[0].length;
        // Ended where the previous call already decided (reported, or deferred only at its very end).
        if (base + endRel <= this.doneUpTo) continue;
        // Touches the window end: it may continue in the next chunk, so wait (the tail keeps it).
        if (!final && endRel === win.length && win.length - m.index <= MAX_MATCH) continue;
        if (m[0].length > MAX_MATCH || (r.validate && !r.validate(m[0]))) continue;
        const version = r.detector === "STA-LIBVULN" ? /v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)/.exec(m[0])?.[1] : undefined;
        this.add({ detector: r.detector, kind: r.kind, ...(r.marker ? { marker: r.marker } : {}), ...this.pos(lines, base, m.index), len: m[0].length, ...(version ? { library: { ecosystem: "npm" as const, name: "jquery", version } } : {}) });
      }
    }
    SOURCEMAP_URL.lastIndex = 0;
    for (let m = SOURCEMAP_URL.exec(win); m; m = SOURCEMAP_URL.exec(win)) this.out.sourceMappingUrl = m[1]!.slice(0, 2048);
    const keep = final ? 0 : Math.min(MAX_MATCH, win.length);
    const cut = win.length - keep;
    for (const i of lines) if (i < cut) { this.line++; this.lineStart = base + i + 1; }
    this.tail = win.slice(cut);
    this.tailStart = base + cut;
    // Matches ending at the window end were deferred, so only offsets before it are settled.
    this.doneUpTo = final ? Number.MAX_SAFE_INTEGER : base + win.length - 1;
  }

  private pos(lines: number[], base: number, rel: number): { line: number; col: number } {
    // Lines before the tail are already counted; count tail/new-text newlines before `rel`.
    let line = this.line, ls = this.lineStart;
    for (const i of lines) { if (i >= rel) break; if (base + i + 1 > this.lineStart) { line++; ls = base + i + 1; } }
    return { line, col: base + rel - ls + 1 };
  }

  private add(f: Fact): void {
    if (this.out.facts.some((x) => x.kind === f.kind && x.line === f.line && x.col === f.col)) return;
    if (this.out.facts.length >= MAX_FACTS) { this.out.dropped++; return; }
    this.out.facts.push(f);
  }
}

/**
 * Exact search for known test tokens and in-scope secrets over a chunk stream. Runs on every
 * fetch, never cached (SPEC-0.1.3 §6.4-C). Returns how many literals matched, not which.
 */
export class LiteralScanner {
  private tail = Buffer.alloc(0);
  private readonly needles: Buffer[];
  private readonly found = new Set<number>();
  private readonly keep: number;

  constructor(literals: string[]) {
    this.needles = literals.filter((l) => l.length >= 8).map((l) => Buffer.from(l, "utf8"));
    this.keep = Math.max(0, ...this.needles.map((n) => n.length - 1));
  }

  feed(chunk: Buffer): void {
    if (!this.needles.length) return;
    const win = Buffer.concat([this.tail, chunk]);
    this.needles.forEach((n, i) => { if (!this.found.has(i) && win.indexOf(n) >= 0) this.found.add(i); });
    this.tail = win.subarray(Math.max(0, win.length - this.keep));
  }

  get matches(): number {
    return this.found.size;
  }
}

// ───────────────────────── Exposure file formats ─────────────────────────

/** Keys public by design in common build tools; never treated as secrets. */
const PUBLIC_PREFIX = /^(?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_|GATSBY_)/;
const NONPUBLIC_KEY = /["']?\b([A-Z0-9_]*(?:SECRET|PRIVATE|PASSWORD|PASSWD|TOKEN|API_KEY|ACCESS_KEY)[A-Z0-9_]*)\b["']?\s*[:=]\s*["']?([^"'\s,;}]{6,})/g;

export type ExposureFormat = "git-head" | "dotenv" | "js-config";

/** Format check for exposure probes. HTML (an SPA fallback) never matches. Returns key names only. */
export function exposureMatch(format: ExposureFormat, body: string): { match: boolean; keys: string[]; lines?: number } {
  if (/^\s*<(?:!doctype|html|head|body)/i.test(body)) return { match: false, keys: [] };
  if (format === "git-head") return { match: /^(?:ref: refs\/[^\s]+|[0-9a-f]{40})\s*$/.test(body.trim()), keys: [] };
  if (format === "dotenv") {
    const lines = body.split(/\r?\n/).filter((l) => /^(?:export\s+)?[A-Z][A-Z0-9_]*=/.test(l));
    return { match: lines.length > 0, keys: lines.map((l) => l.replace(/^export\s+/, "").split("=")[0]!).slice(0, 50), lines: lines.length };
  }
  const keys: string[] = [];
  NONPUBLIC_KEY.lastIndex = 0;
  for (let m = NONPUBLIC_KEY.exec(body); m; m = NONPUBLIC_KEY.exec(body)) if (!PUBLIC_PREFIX.test(m[1]!) && !/^(?:x+|\*+|null|undefined|true|false)$/i.test(m[2]!)) keys.push(m[1]!);
  return { match: keys.length > 0, keys: [...new Set(keys)].slice(0, 50) };
}

function lineIndex(s: string): number[] {
  const out: number[] = [];
  for (let i = s.indexOf("\n"); i >= 0; i = s.indexOf("\n", i + 1)) out.push(i);
  return out;
}

/** All matches of a rule in `s`, using the prefilter when the rule has one. Indices are into `s`. */
function* matches(r: Rule, s: string): Generator<RegExpExecArray> {
  if (!r.pre) {
    r.re.lastIndex = 0;
    for (let m = r.re.exec(s); m; m = r.re.exec(s)) yield m;
    return;
  }
  const span = r.span ?? 128;
  let scannedTo = -1;
  r.pre.lastIndex = 0;
  for (let p = r.pre.exec(s); p; p = r.pre.exec(s)) {
    const from = Math.max(scannedTo, p.index - span, 0);
    const to = Math.min(s.length, p.index + p[0].length + span + 600);
    if (to <= from) continue;
    const slice = s.slice(from, to);
    r.re.lastIndex = 0;
    for (let m = r.re.exec(slice); m; m = r.re.exec(slice)) {
      // A match cut by the slice end is rechecked from a later slice; only full matches count.
      if (m.index + m[0].length === slice.length && to < s.length) break;
      m.index += from;
      yield m;
    }
    scannedTo = Math.max(from, to - span - 600);
    r.pre.lastIndex = Math.max(r.pre.lastIndex, p.index + 1);
  }
}
