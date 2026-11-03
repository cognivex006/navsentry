/**
 * Vulnerability knowledge base (SPEC-0.1.3 §6.6). Offline, typed data; zero network. Advisory text is
 * untrusted data: it is rendered escaped and never becomes a command, payload or check activation (S12).
 */
import { createHash } from "node:crypto";

/** Applicability of one record to one piece of product evidence (separate from check/finding statuses). */
export type Applicability = "affected" | "not-affected" | "unknown" | "not-applicable";
/** Knowledge record state (separate from check/finding statuses). */
export type RecordState = "candidate" | "reviewed" | "needs-review" | "superseded" | "withdrawn";

export interface VersionRange {
  /** Inclusive lower bound; absent = from the first version. */
  introduced?: string;
  /** Exclusive upper bound (first fixed version). */
  fixed?: string;
  /** Inclusive upper bound when no fix exists. */
  lastAffected?: string;
}

export interface AdvisoryRecord {
  id: string;
  revision: number;
  supersedes?: string;
  state: RecordState;
  /** Exact identity: runtime vs bundled dependency, upstream vs distribution package. */
  product: { ecosystem: "runtime" | "server" | "npm" | "composer" | "os-package"; name: string; component?: string; packaging: "upstream" | "distribution" | "bundled" };
  identifiers: { cve: string[]; advisory: string[]; aliases: string[] };
  versionScheme: "semver" | "unknown";
  affected: VersionRange[];
  exclusions?: string[];
  preconditions: string[];
  surface: string[];
  severity?: { source: string; score?: number; vector?: string; scoringVersion?: string };
  safeEvidence: string;
  nsc: "NSC-SUPPLY-001" | "NSC-SUPPLY-002";
  detector?: string;
  /** Why the detector is unavailable, when it is. */
  capability: string;
  fix: string;
  regressionGuard: string;
  sources: { url: string; published?: string; updated?: string }[];
  verifiedAt: string;
  nextReviewAt: string;
  digest?: string;
  /** Synthetic records exist only in tests and fixtures. */
  synthetic?: true;
}

export interface AliasEntry {
  alias: string;
  status: "verified" | "unresolved";
  /** Record IDs this alias may refer to; for unresolved aliases these are candidates only. */
  candidates: string[];
}

export interface Snapshot {
  version: string;
  generatedAt: string;
  records: AdvisoryRecord[];
  aliases: AliasEntry[];
}

export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson((v as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

export function snapshotHash(s: Snapshot): string {
  return createHash("sha256").update(canonicalJson({ version: s.version, records: s.records, aliases: s.aliases })).digest("hex");
}

export interface SnapshotStatus {
  version: string;
  sha256: string;
  generatedAt: string;
  records: number;
  reviewed: number;
  /** Records past their next-review date. */
  stale: number;
  /** Oldest verification date among reviewed records, if any. */
  verifiedAt?: string;
  note: string;
}

export function snapshotStatus(s: Snapshot, now = new Date()): SnapshotStatus {
  const live = s.records.filter((r) => r.state !== "superseded" && r.state !== "withdrawn");
  const verified = live.map((r) => r.verifiedAt).sort();
  return {
    version: s.version,
    sha256: snapshotHash(s),
    generatedAt: s.generatedAt,
    records: s.records.length,
    reviewed: live.filter((r) => r.state === "reviewed").length,
    stale: live.filter((r) => Date.parse(r.nextReviewAt) < now.getTime()).length,
    ...(verified[0] ? { verifiedAt: verified[0] } : {}),
    note: "Offline snapshot: it cannot prove that no newer advisory exists. Zero matches never means no vulnerabilities.",
  };
}

// ───────────────────────── Versions ─────────────────────────

interface SemVer { nums: number[]; pre: string[] }

export function parseSemver(v: string): SemVer | undefined {
  const m = /^v?(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(?:-([0-9A-Za-z.-]{1,64}))?(?:\+[0-9A-Za-z.-]{1,64})?$/.exec(v.trim());
  if (!m) return undefined;
  return { nums: [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0)], pre: m[4] ? m[4].split(".") : [] };
}

export function compareSemver(a: SemVer, b: SemVer): number {
  for (let i = 0; i < 3; i++) if (a.nums[i] !== b.nums[i]) return a.nums[i]! < b.nums[i]! ? -1 : 1;
  if (!a.pre.length || !b.pre.length) return a.pre.length === b.pre.length ? 0 : a.pre.length ? -1 : 1;
  for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i++) {
    const x = a.pre[i], y = b.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny && Number(x) !== Number(y)) return Number(x) < Number(y) ? -1 : 1;
    if (nx !== ny) return nx ? -1 : 1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

export interface ProductEvidence {
  ecosystem: AdvisoryRecord["product"]["ecosystem"];
  name: string;
  version?: string;
  /** Where the evidence came from; an HTTP banner is weak evidence. */
  provenance: "http-banner" | "lockfile" | "manifest" | "installed";
  /** A distribution packaging hint (for example "(Ubuntu)"): backports may apply. */
  distribution?: string;
}

export interface Match {
  record: AdvisoryRecord;
  applicability: Applicability;
  caveats: string[];
}

/** Explicit matching (§6.6-C3): unsupported schemes and unknown or partial versions give `unknown`, never an assumed range. */
export function applicability(r: AdvisoryRecord, e: ProductEvidence): Match {
  const caveats: string[] = [];
  if (r.product.ecosystem !== e.ecosystem || r.product.name !== e.name) return { record: r, applicability: "not-applicable", caveats };
  if (r.state === "withdrawn" || r.state === "superseded") return { record: r, applicability: "not-applicable", caveats: [`record ${r.state}`] };
  if (e.provenance === "http-banner") caveats.push("version from an HTTP banner: weak evidence that may be stale or altered");
  if (r.preconditions.length) caveats.push(`preconditions not verified: ${r.preconditions.join("; ")}`);
  if (!e.version) return { record: r, applicability: "unknown", caveats: [...caveats, "version not observed"] };
  if (r.versionScheme !== "semver") return { record: r, applicability: "unknown", caveats: [...caveats, "unsupported version scheme"] };
  const v = parseSemver(e.version);
  if (!v || !/^\d+\.\d+\.\d+/.test(e.version.replace(/^v/, ""))) return { record: r, applicability: "unknown", caveats: [...caveats, "incomplete or unparseable version"] };
  if (e.distribution || r.product.packaging === "distribution") return { record: r, applicability: "unknown", caveats: [...caveats, `distribution package${e.distribution ? ` (${e.distribution})` : ""}: vendor backports may fix this without a version change`] };
  if (v.pre.length) caveats.push("prerelease version: ranges are compared by semver precedence");
  if (r.exclusions?.includes(e.version)) return { record: r, applicability: "not-affected", caveats: [...caveats, "explicitly excluded version"] };
  const inRange = r.affected.some((g) => {
    const lo = g.introduced ? parseSemver(g.introduced) : undefined;
    const fx = g.fixed ? parseSemver(g.fixed) : undefined;
    const la = g.lastAffected ? parseSemver(g.lastAffected) : undefined;
    if ((g.introduced && !lo) || (g.fixed && !fx) || (g.lastAffected && !la)) return false;
    if (lo && compareSemver(v, lo) < 0) return false;
    if (fx && compareSemver(v, fx) >= 0) return false;
    if (la && compareSemver(v, la) > 0) return false;
    return !!(lo || fx || la);
  });
  return { record: r, applicability: inRange ? "affected" : "not-affected", caveats };
}

export interface LookupQuery {
  product?: string;
  ecosystem?: ProductEvidence["ecosystem"];
  version?: string;
  /** CVE, advisory ID or alias. */
  id?: string;
}

export interface LookupResult {
  matches: Match[];
  /** Unresolved alias: candidates only, research needed; never the nearest-sounding record. */
  research?: { alias: string; candidates: string[]; reason: string };
}

const MAX_RESULTS = 50;

/** Bounded local search by product, version, advisory ID or alias. */
export function lookup(s: Snapshot, q: LookupQuery): LookupResult {
  const live = s.records.filter((r) => r.state !== "superseded");
  if (q.id) {
    const id = q.id.trim();
    const idU = id.toUpperCase();
    const direct = live.filter((r) => r.id === id || r.identifiers.cve.includes(idU) || r.identifiers.advisory.includes(id) || r.identifiers.aliases.includes(id));
    const alias = s.aliases.find((a) => a.alias.toLowerCase() === id.toLowerCase());
    if (alias && alias.status === "unresolved") return { matches: [], research: { alias: alias.alias, candidates: alias.candidates, reason: "unresolved alias: verify against primary advisories before mapping" } };
    const viaAlias = alias ? live.filter((r) => alias.candidates.includes(r.id)) : [];
    const recs = [...new Set([...direct, ...viaAlias])].slice(0, MAX_RESULTS);
    if (!recs.length && !/^CVE-\d{4}-\d{4,}$/i.test(id) && !/^GHSA-/i.test(id)) return { matches: [], research: { alias: id, candidates: [], reason: "unknown identifier: research needed; no guessed mapping" } };
    return { matches: recs.map((r) => (q.version && r.product ? applicability(r, { ecosystem: r.product.ecosystem, name: r.product.name, version: q.version, provenance: "installed" }) : { record: r, applicability: "unknown", caveats: ["no version given"] })) };
  }
  const recs = live.filter((r) => (!q.product || r.product.name === q.product) && (!q.ecosystem || r.product.ecosystem === q.ecosystem)).slice(0, MAX_RESULTS);
  return {
    matches: recs.map((r) => applicability(r, { ecosystem: r.product.ecosystem, name: r.product.name, ...(q.version ? { version: q.version } : {}), provenance: "installed" })),
  };
}
