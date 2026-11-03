/**
 * Runtime console detectors (SPEC-0.1.3 §6.4-A, milestone 0.1.3-k). Raw console text lives only in
 * memory for the duration of the run and is never persisted (S8): each bounded message is inspected
 * on arrival, before any normalising or deduplication, and only value-free facts are kept: the case,
 * the source file:line, a masked preview `[<kind>,len=<n>]` and a template hash.
 */
import { createHash } from "node:crypto";
import { Redactor } from "../redact.js";

export type ConsoleDetector = "CON-SECRET" | "CON-PII" | "CON-TRACE" | "CON-ECHO" | "CON-DEBUG";

export interface ConsoleFact {
  detector: ConsoleDetector;
  caseId: string;
  /** Exact match with a known in-scope value: a deterministic assertion (VALIDATED). */
  exact: boolean;
  kind: string;
  level: string;
  /** Display URL of the script that logged it, plus ":line" when known. */
  source: string;
  preview: string;
  /** Template hash: the message with every value-like token replaced, so it carries no value. */
  template: string;
  flow?: string;
  step?: string;
}

export interface ConsoleSummary {
  messages: number;
  bytes: number;
  /** Messages not inspected because a capture limit was reached; coverage is then incomplete. */
  dropped: number;
  facts: ConsoleFact[];
  /** Messages per flow step, for `console: "silent"`. */
  perStep: Map<string, number>;
}

const KIND_CASE: Record<string, { detector: ConsoleDetector; caseId: string }> = {
  "known-secret": { detector: "CON-SECRET", caseId: "NSC-INFO-006" },
  "provider-key": { detector: "CON-SECRET", caseId: "NSC-INFO-006" },
  jwt: { detector: "CON-SECRET", caseId: "NSC-INFO-006" },
  bearer: { detector: "CON-SECRET", caseId: "NSC-INFO-006" },
  "private-key": { detector: "CON-SECRET", caseId: "NSC-INFO-006" },
  "secret-assignment": { detector: "CON-ECHO", caseId: "NSC-INFO-006" },
  email: { detector: "CON-PII", caseId: "NSC-INFO-004" },
  "thai-national-id": { detector: "CON-PII", caseId: "NSC-PRIV-001" },
  "private-ip": { detector: "CON-TRACE", caseId: "NSC-INFO-003" },
};

const STACK = /\n\s+at\s+\S.*:\d+:\d+|(?:^|[\s(])(?:[A-Za-z]:\\|\/(?:home|Users|var|srv|opt|usr)\/)[^\s:)]+/;
const DEV_RUNTIME = /\[HMR\]|\[vite\] connect|webpack-dev-server|Download the React DevTools|You are running Vue in development mode|development build/i;
const MAX_FACTS = 200;

/** Replaces every value-like token so the template identifies a message shape, never a value. */
export function templateOf(text: string): string {
  const shape = text.slice(0, 2048).replace(/[A-Za-z0-9+/_=.-]{6,}|\d+/g, "#");
  return createHash("sha256").update(shape).digest("hex").slice(0, 12);
}

export class ConsoleInspector {
  private readonly redactor: Redactor;
  readonly summary: ConsoleSummary = { messages: 0, bytes: 0, dropped: 0, facts: [], perStep: new Map() };

  constructor(literals: string[], private readonly maxMessages: number, private readonly maxBytes: number, private readonly displayUrl: (u: string) => string) {
    this.redactor = new Redactor(literals);
  }

  inspect(e: { type: string; text: string; sourceUrl: string; line?: number; flow?: string; step?: string }): void {
    const s = this.summary;
    const size = Buffer.byteLength(e.text, "utf8");
    if (s.messages >= this.maxMessages || s.bytes + size > this.maxBytes) { s.dropped++; return; }
    s.messages++;
    s.bytes += size;
    if (e.flow && e.step) { const k = `${e.flow}/${e.step}`; s.perStep.set(k, (s.perStep.get(k) ?? 0) + 1); }
    const template = templateOf(e.text);
    const source = `${e.sourceUrl ? this.displayUrl(e.sourceUrl) : "-"}${e.line ? `:${e.line}` : ""}`;
    const at = { level: e.type, source, template, ...(e.flow ? { flow: e.flow } : {}), ...(e.step ? { step: e.step } : {}) };
    const { outcome } = this.redactor.text(e.text);
    for (const kind of outcome.kinds) {
      const c = KIND_CASE[kind];
      if (c) this.add({ ...c, exact: kind === "known-secret", kind, preview: `[${kind},len=${e.text.length}]`, ...at });
    }
    if (STACK.test(e.text)) this.add({ detector: "CON-TRACE", caseId: "NSC-ERR-001", exact: false, kind: "stack-trace", preview: `[stack-trace,len=${e.text.length}]`, ...at });
    if (DEV_RUNTIME.test(e.text)) this.add({ detector: "CON-DEBUG", caseId: "NSC-CONF-005", exact: false, kind: "dev-runtime", preview: `[dev-runtime,len=${e.text.length}]`, ...at });
  }

  private add(f: ConsoleFact): void {
    if (this.summary.facts.some((x) => x.caseId === f.caseId && x.kind === f.kind && x.template === f.template && x.source === f.source && x.exact === f.exact)) return;
    if (this.summary.facts.length >= MAX_FACTS) { this.summary.dropped++; return; }
    this.summary.facts.push(f);
  }
}
