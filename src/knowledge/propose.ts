/**
 * Knowledge update proposals (SPEC-0.1.3 §6.6-D). Local and offline: proposals are validated against
 * a strict schema, deduplicated by a stable ID, and written atomically under a lock to
 * `.navsentry/knowledge/proposals/<id>.md` plus `INDEX.md`. Source URLs are validated, never fetched.
 * Proposals are persistent artifacts and never cleanup targets.
 */
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, openSync, closeSync, readFileSync, readdirSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Redactor } from "../redact.js";
import { canonicalJson, type AdvisoryRecord, type Snapshot } from "./model.js";

export const PROPOSAL_KINDS = ["new", "change", "withdraw", "alias", "research-needed", "conflict", "stale"] as const;
export type ProposalKind = (typeof PROPOSAL_KINDS)[number];
const ECOSYSTEMS = ["runtime", "server", "npm", "composer", "os-package"] as const;

export interface Proposal {
  kind: ProposalKind;
  product: { ecosystem: AdvisoryRecord["product"]["ecosystem"]; name: string };
  recordId?: string;
  identifiers?: { cve?: string[]; advisory?: string[]; aliases?: string[] };
  alias?: string;
  affected?: { introduced?: string; fixed?: string; lastAffected?: string }[];
  summary: string;
  sources: { url: string; published?: string; updated?: string }[];
  confidence: "high" | "medium" | "low";
  missing?: string[];
}

export class ProposalError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Invalid knowledge proposal:\n- ${problems.join("\n- ")}`);
  }
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const NAME = /^[a-z0-9][a-z0-9._@/-]{0,99}$/;
const CVE = /^CVE-\d{4}-\d{4,7}$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const VERSION = /^[0-9A-Za-z.+-]{1,40}$/;

/** Rejects text that looks like a target identifier, secret or personal data (§6.6-D: reusable knowledge carries none). */
function clean(where: string, s: string, p: string[], forbidden: RegExp[]): string {
  const red = new Redactor();
  if (red.text(s).outcome.applied) p.push(`${where}: looks like a secret, address or personal data; use generic wording`);
  if (forbidden.some((re) => re.test(s))) p.push(`${where}: contains a target identifier (manifest origin or host); proposals must stay generic`);
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(s)) p.push(`${where}: control characters are not allowed`);
  return s;
}

export function parseProposal(input: unknown, forbidden: RegExp[] = []): Proposal {
  const p: string[] = [];
  if (!isObj(input)) throw new ProposalError(["proposal must be a JSON object"]);
  for (const k of Object.keys(input)) if (!["kind", "product", "recordId", "identifiers", "alias", "affected", "summary", "sources", "confidence", "missing"].includes(k)) p.push(`${k}: unknown key`);
  const kind = input.kind as ProposalKind;
  if (!PROPOSAL_KINDS.includes(kind)) p.push(`kind: one of ${PROPOSAL_KINDS.join(", ")}`);
  const prod = isObj(input.product) ? input.product : (p.push("product: required object"), {} as Obj);
  for (const k of Object.keys(prod)) if (!["ecosystem", "name"].includes(k)) p.push(`product.${k}: unknown key`);
  if (!ECOSYSTEMS.includes(prod.ecosystem as never)) p.push(`product.ecosystem: one of ${ECOSYSTEMS.join(", ")}`);
  if (typeof prod.name !== "string" || !NAME.test(prod.name)) p.push("product.name: lower-case package or product name");
  const out: Proposal = { kind, product: { ecosystem: prod.ecosystem as Proposal["product"]["ecosystem"], name: String(prod.name ?? "") }, summary: "", sources: [], confidence: "low" };
  if (input.recordId !== undefined) {
    if (typeof input.recordId !== "string" || !/^[A-Z0-9-]{3,40}$/.test(input.recordId)) p.push("recordId: upper-case record ID");
    else out.recordId = input.recordId;
  }
  if ((kind === "change" || kind === "withdraw" || kind === "stale") && !out.recordId) p.push(`recordId: required for kind ${kind}`);
  if (input.identifiers !== undefined) {
    if (!isObj(input.identifiers)) p.push("identifiers: must be an object");
    else {
      const ids: NonNullable<Proposal["identifiers"]> = {};
      for (const [k, v] of Object.entries(input.identifiers)) {
        if (!["cve", "advisory", "aliases"].includes(k)) { p.push(`identifiers.${k}: unknown key`); continue; }
        if (!Array.isArray(v) || v.length > 20 || v.some((x) => typeof x !== "string" || x.length > 60)) { p.push(`identifiers.${k}: up to 20 strings`); continue; }
        if (k === "cve") for (const x of v as string[]) if (!CVE.test(x)) p.push(`identifiers.cve: "${x.slice(0, 20)}" is not a CVE ID`);
        ids[k as "cve"] = [...new Set(v as string[])].sort();
      }
      out.identifiers = ids;
    }
  }
  if (input.alias !== undefined) {
    if (typeof input.alias !== "string" || !/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,59}$/.test(input.alias)) p.push("alias: 1-60 characters, letters, digits, space, . _ -");
    else out.alias = input.alias;
  }
  if (kind === "alias" && !out.alias) p.push("alias: required for kind alias");
  if (input.affected !== undefined) {
    if (!Array.isArray(input.affected) || input.affected.length > 20) p.push("affected: up to 20 ranges");
    else
      out.affected = input.affected.map((r, i) => {
        if (!isObj(r)) { p.push(`affected[${i}]: must be an object`); return {}; }
        const g: NonNullable<Proposal["affected"]>[number] = {};
        for (const [k, v] of Object.entries(r)) {
          if (!["introduced", "fixed", "lastAffected"].includes(k)) p.push(`affected[${i}].${k}: unknown key`);
          else if (typeof v !== "string" || !VERSION.test(v)) p.push(`affected[${i}].${k}: version string`);
          else g[k as "fixed"] = v;
        }
        return g;
      });
  }
  if (typeof input.summary !== "string" || !input.summary.trim() || input.summary.length > 500) p.push("summary: 1-500 characters");
  else out.summary = clean("summary", input.summary.trim(), p, forbidden);
  if (!Array.isArray(input.sources) || input.sources.length > 10) p.push("sources: array of up to 10 sources");
  else {
    for (const [i, src] of input.sources.entries()) {
      if (!isObj(src) || typeof src.url !== "string") { p.push(`sources[${i}].url: required`); continue; }
      for (const k of Object.keys(src)) if (!["url", "published", "updated"].includes(k)) p.push(`sources[${i}].${k}: unknown key`);
      let u: URL | undefined;
      try { u = new URL(src.url); } catch { /* reported below */ }
      if (!u || u.protocol !== "https:" || u.username || u.password || src.url.length > 300) { p.push(`sources[${i}].url: must be an https URL without credentials (it is never fetched)`); continue; }
      if (forbidden.some((re) => re.test(u!.hostname))) p.push(`sources[${i}].url: points to a target host; use primary advisory sources`);
      for (const d of ["published", "updated"] as const) if (src[d] !== undefined && (typeof src[d] !== "string" || !DATE.test(src[d] as string))) p.push(`sources[${i}].${d}: YYYY-MM-DD`);
      out.sources.push({ url: u.toString(), ...(src.published ? { published: src.published as string } : {}), ...(src.updated ? { updated: src.updated as string } : {}) });
    }
    if (!out.sources.length && kind !== "research-needed" && kind !== "stale") p.push("sources: primary sources are required except for research-needed and stale proposals");
  }
  if (!["high", "medium", "low"].includes(input.confidence as string)) p.push("confidence: high | medium | low");
  else out.confidence = input.confidence as Proposal["confidence"];
  if (input.missing !== undefined) {
    if (!Array.isArray(input.missing) || input.missing.length > 20 || input.missing.some((x) => typeof x !== "string" || x.length > 200)) p.push("missing: up to 20 strings");
    else out.missing = (input.missing as string[]).map((x, i) => clean(`missing[${i}]`, x, p, forbidden));
  }
  if (p.length) throw new ProposalError(p);
  return out;
}

/** Stable identity: advisory and product identity; unresolved aliases get provisional IDs. */
export function proposalId(x: Proposal): string {
  const key = canonicalJson({ kind: x.kind === "research-needed" || x.kind === "stale" ? x.kind : "advisory", eco: x.product.ecosystem, name: x.product.name, record: x.recordId ?? null, ids: x.identifiers?.cve ?? x.identifiers?.advisory ?? null, alias: x.alias ?? null });
  return `KBP-${createHash("sha256").update(key).digest("hex").slice(0, 16)}`;
}

const contentHash = (x: Proposal) => createHash("sha256").update(canonicalJson(x)).digest("hex");

export interface ProposeOutcome {
  id: string;
  status: "new" | "unchanged" | "revised";
  revision: number;
  file: string;
}

const LOCK_STALE_MS = 30_000;

function withLock<T>(dir: string, fn: () => T): T {
  const lock = join(dir, ".lock");
  for (let i = 0; i < 200; i++) {
    try {
      closeSync(openSync(lock, "wx", 0o600));
      try { return fn(); } finally { try { unlinkSync(lock); } catch { /* already gone */ } }
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      // A lock left by a killed writer is taken over after it is clearly stale.
      try { if (Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS) unlinkSync(lock); } catch { /* raced */ }
      const until = Date.now() + 10;
      while (Date.now() < until) { /* brief spin; proposals are small and rare */ }
    }
  }
  throw new ProposalError(["knowledge proposals are locked by another process; try again"]);
}

function atomicWrite(path: string, content: string): void {
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  writeFileSync(tmp, content, { mode: 0o600 });
  renameSync(tmp, path);
}

interface Meta { id: string; revision: number; contentSha256: string; history: { revision: number; contentSha256: string; at: string }[]; proposal: Proposal; createdAt: string; updatedAt: string }

const META_RE = /<!-- navsentry-proposal ([A-Za-z0-9+/=]+) -->/;

function readMeta(file: string): Meta | undefined {
  try {
    const m = META_RE.exec(readFileSync(file, "utf8"));
    return m ? (JSON.parse(Buffer.from(m[1]!, "base64").toString("utf8")) as Meta) : undefined;
  } catch {
    return undefined;
  }
}

/** Validated, deduplicated, atomic, locked write. Identical research creates no new revision. */
export function propose(root: string, x: Proposal, snapshot: Snapshot, now = new Date()): ProposeOutcome {
  const dir = join(root, ".navsentry", "knowledge", "proposals");
  for (const part of [join(root, ".navsentry"), join(root, ".navsentry", "knowledge"), dir]) {
    const st = lstatSync(part, { throwIfNoEntry: false });
    if (st?.isSymbolicLink()) throw new ProposalError([`linked path refused: ${part}`]);
  }
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!existsSync(join(root, ".navsentry", ".gitignore"))) writeFileSync(join(root, ".navsentry", ".gitignore"), "*\n");
  return withLock(dir, () => {
    // Recover from interrupted writes: leftover temp files never become proposals.
    for (const n of readdirSync(dir)) if (n.endsWith(".tmp")) { try { unlinkSync(join(dir, n)); } catch { /* in use */ } }
    const id = proposalId(x);
    const file = join(dir, `${id}.md`);
    const hash = contentHash(x);
    const prev = existsSync(file) ? readMeta(file) : undefined;
    if (prev && prev.contentSha256 === hash) return { id, status: "unchanged", revision: prev.revision, file };
    const at = now.toISOString();
    const meta: Meta = prev
      ? { ...prev, revision: prev.revision + 1, contentSha256: hash, proposal: x, updatedAt: at, history: [...prev.history, { revision: prev.revision, contentSha256: prev.contentSha256, at: prev.updatedAt }] }
      : { id, revision: 1, contentSha256: hash, history: [], proposal: x, createdAt: at, updatedAt: at };
    atomicWrite(file, renderProposal(meta, snapshot));
    atomicWrite(join(dir, "INDEX.md"), renderIndex(dir));
    return { id, status: prev ? "revised" : "new", revision: meta.revision, file };
  });
}

/** Escapes Markdown and HTML so advisory text stays data. */
export function mdEscape(s: string): string {
  return s.replace(/[\\`*_{}[\]()#+!|<>&~]/g, (c) => `\\${c}`).replace(/\r?\n/g, " ");
}

function renderProposal(m: Meta, snap: Snapshot): string {
  const x = m.proposal;
  const current = x.recordId ? snap.records.find((r) => r.id === x.recordId) : undefined;
  const diff: string[] = [];
  if (current) {
    if (x.affected) diff.push(`- affected ranges: ${mdEscape(JSON.stringify(current.affected))} → ${mdEscape(JSON.stringify(x.affected))}`);
    if (x.identifiers?.cve) diff.push(`- CVE: ${current.identifiers.cve.join(", ") || "—"} → ${x.identifiers.cve.join(", ")}`);
    if (x.kind === "withdraw") diff.push(`- state: ${current.state} → withdrawn`);
  }
  const lines = [
    `# Knowledge proposal ${m.id} (revision ${m.revision})`,
    "",
    "> Proposal only. Not part of the packaged snapshot until a maintainer verifies the sources, adds fixture tests and passes review. Text below is untrusted data.",
    "",
    "| Field | Value |", "|---|---|",
    `| Kind | ${x.kind} |`,
    `| Product | ${x.product.ecosystem} / \`${mdEscape(x.product.name)}\` |`,
    `| Record | ${x.recordId ?? "new"} |`,
    `| CVE / advisory / aliases | ${[...(x.identifiers?.cve ?? []), ...(x.identifiers?.advisory ?? []), ...(x.identifiers?.aliases ?? [])].map(mdEscape).join(", ") || "—"} |`,
    `| Alias | ${x.alias ? `${mdEscape(x.alias)} (unresolved until verified)` : "—"} |`,
    `| Affected | ${x.affected?.length ? x.affected.map((g) => mdEscape(`${g.introduced ?? "*"} ≤ v < ${g.fixed ?? (g.lastAffected ? `≤ ${g.lastAffected}` : "?")}`)).join("; ") : "unknown"} |`,
    `| Confidence | ${x.confidence} |`,
    `| Affected cases | ${current?.nsc ?? (x.product.ecosystem === "npm" ? "NSC-SUPPLY-002" : "NSC-SUPPLY-001")} |`,
    `| Governance | advisory source not approved for automatic import; manual verification required |`,
    "",
    "## Summary", "", mdEscape(x.summary), "",
    "## Sources (never fetched by NavSentry)", "",
    ...(x.sources.length ? x.sources.map((s) => `- <${s.url.replace(/[<>]/g, "")}>${s.published ? ` · published ${s.published}` : ""}${s.updated ? ` · updated ${s.updated}` : ""}`) : ["- none (research needed)"]),
    "",
    "## Field diff against the current record", "", ...(diff.length ? diff : ["- no current record"]), "",
    "## Missing facts and work needed", "", ...(x.missing?.length ? x.missing.map((s) => `- ${mdEscape(s)}`) : ["- none listed"]), "- detector and fixture tests for the affected case", "",
    "## History", "", ...(m.history.length ? m.history.map((h) => `- revision ${h.revision} (${h.at}) superseded`) : ["- first revision"]), "",
    `<!-- navsentry-proposal ${Buffer.from(JSON.stringify(m)).toString("base64")} -->`, "",
  ];
  return lines.join("\n");
}

function renderIndex(dir: string): string {
  const rows = readdirSync(dir).filter((n) => /^KBP-[0-9a-f]{16}\.md$/.test(n)).sort().map((n) => readMeta(join(dir, n))).filter((m): m is Meta => !!m);
  return [
    "# Knowledge proposals", "",
    "Local, persistent proposals. Never cleaned automatically; promotion is a reviewed maintainer change.", "",
    "| ID | Rev | Kind | Product | Identifiers | Confidence | Updated |", "|---|---|---|---|---|---|---|",
    ...rows.map((m) => `| [${m.id}](${m.id}.md) | ${m.revision} | ${m.proposal.kind} | ${m.proposal.product.ecosystem}/${mdEscape(m.proposal.product.name)} | ${mdEscape([...(m.proposal.identifiers?.cve ?? []), ...(m.proposal.alias ? [m.proposal.alias] : [])].join(", ")) || "—"} | ${m.proposal.confidence} | ${m.updatedAt.slice(0, 10)} |`),
    "",
  ].join("\n");
}
