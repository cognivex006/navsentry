/**
 * Product evidence and applicability during a run (SPEC-0.1.3 §6.6-C). Production evidence is passive:
 * the Server / X-Powered-By headers NSC-INFO-001 already observes. A server's runtime version is never
 * inferred from the agent's runtime, browser behaviour or a client banner. Unrecognised tokens are
 * gaps whose names are withheld, so a custom (possibly identifying) string never reaches a proposal.
 */
import type { Exchange } from "../transports/types.js";
import type { CheckResult, KnowledgeResult } from "../types.js";
import { applicability, snapshotStatus, type ProductEvidence, type Snapshot } from "./model.js";
import type { Proposal } from "./propose.js";

/** Banner token → product identity. Only these well-known public product names are recognised. */
const TOKENS: Record<string, Pick<ProductEvidence, "ecosystem" | "name">> = {
  "apache": { ecosystem: "server", name: "apache-httpd" },
  "nginx": { ecosystem: "server", name: "nginx" },
  "microsoft-iis": { ecosystem: "server", name: "iis" },
  "openresty": { ecosystem: "server", name: "openresty" },
  "lighttpd": { ecosystem: "server", name: "lighttpd" },
  "caddy": { ecosystem: "server", name: "caddy" },
  "jetty": { ecosystem: "server", name: "jetty" },
  "apache-coyote": { ecosystem: "server", name: "tomcat" },
  "tomcat": { ecosystem: "server", name: "tomcat" },
  "php": { ecosystem: "runtime", name: "php" },
  "openssl": { ecosystem: "os-package", name: "openssl" },
  "express": { ecosystem: "npm", name: "express" },
  "asp.net": { ecosystem: "runtime", name: "aspnet" },
};
const DISTRO = /\b(Ubuntu|Debian|CentOS|Red ?Hat|RHEL|Fedora|Amazon Linux|SUSE|Alpine|Raspbian)\b/i;

export function bannerEvidence(exchanges: Exchange[]): { evidence: ProductEvidence[]; unrecognised: number } {
  const out = new Map<string, ProductEvidence>();
  let unrecognised = 0;
  for (const ex of exchanges) {
    for (const h of ["server", "x-powered-by"]) {
      for (const v of ex.raw?.headers[h] ?? []) {
        const distro = DISTRO.exec(v)?.[1];
        for (const m of v.matchAll(/([A-Za-z][A-Za-z0-9.-]{1,40})(?:\/(v?\d+(?:\.\d+){0,3}[0-9A-Za-z.-]*))?/g)) {
          const token = m[1]!.toLowerCase();
          if (DISTRO.test(m[1]!) || ["win64", "win32", "unix", "mod_ssl"].includes(token)) continue;
          const id = TOKENS[token];
          if (!id) { if (m[2]) unrecognised++; continue; }
          const e: ProductEvidence = { ...id, provenance: "http-banner", ...(m[2] ? { version: m[2].replace(/^v/, "") } : {}), ...(distro ? { distribution: distro } : {}) };
          out.set(`${e.ecosystem}/${e.name}/${e.version ?? ""}`, e);
        }
      }
    }
  }
  return { evidence: [...out.values()], unrecognised };
}

export function evaluateKnowledge(s: Snapshot, exchanges: Exchange[], now = new Date()): { knowledge: KnowledgeResult; checks: CheckResult[]; proposals: Proposal[] } {
  const status = snapshotStatus(s, now);
  const { evidence, unrecognised } = bannerEvidence(exchanges);
  const rows: KnowledgeResult["applicability"] = [];
  const gaps: KnowledgeResult["gaps"] = [];
  const proposals: Proposal[] = [];
  const checks: CheckResult[] = [];
  for (const e of evidence) {
    const recs = s.records.filter((r) => r.product.ecosystem === e.ecosystem && r.product.name === e.name);
    const label = `${e.ecosystem}/${e.name}${e.version ? ` ${e.version}` : ""}`;
    if (!recs.length) {
      gaps.push({ kind: "unknown-product", product: label, detail: "no records for this product in the snapshot (not proof of absence)" });
      proposals.push({ kind: "research-needed", product: { ecosystem: e.ecosystem, name: e.name }, summary: `No advisory records for ${e.ecosystem}/${e.name} in the packaged snapshot; observed through passive version evidence during an authorized run.`, sources: [], confidence: "low", missing: ["primary advisories with affected and fixed versions", "an approved advisory source (governance)"] });
      rows.push({ product: label, provenance: e.provenance, applicability: "unknown", caveats: ["no records in the snapshot"], case: e.ecosystem === "npm" ? "NSC-SUPPLY-002" : "NSC-SUPPLY-001" });
      continue;
    }
    for (const r of recs) {
      const m = applicability(r, e);
      if (m.applicability === "not-applicable") continue;
      rows.push({ product: label, provenance: e.provenance, recordId: r.id, identifiers: [...r.identifiers.cve, ...r.identifiers.advisory], applicability: m.applicability, caveats: m.caveats, case: r.nsc, fix: r.fix });
      if (Date.parse(r.nextReviewAt) < now.getTime()) {
        gaps.push({ kind: "stale-record", product: label, detail: `record ${r.id} is past its review date` });
        proposals.push({ kind: "stale", product: { ecosystem: r.product.ecosystem, name: r.product.name }, recordId: r.id, summary: `Record ${r.id} is past its next-review date and needs re-verification against primary sources.`, sources: [], confidence: "low", missing: ["re-verification of affected and fixed versions"] });
      }
    }
  }
  if (unrecognised) gaps.push({ kind: "unmapped-evidence", detail: `${unrecognised} version banner token(s) not recognised as a known product (names withheld)` });
  // NSC-SUPPLY-001: a reliable affected-version match supports SUSPECTED, never validated exploitability.
  for (const row of rows.filter((x) => x.case === "NSC-SUPPLY-001")) {
    const ex = exchanges.find((x) => (x.raw?.headers["server"] ?? []).concat(x.raw?.headers["x-powered-by"] ?? []).length);
    const base = { ruleId: "NSC-SUPPLY-001", target: ex ? `${ex.record.method} ${ex.record.url}` : row.product, transport: "direct-http", requestIds: ex ? [ex.record.id] : [] };
    if (row.applicability === "affected") checks.push({ ...base, status: "FAIL", summary: `${row.product} matches the affected range of ${row.recordId}`, observations: [`record ${row.recordId}${row.identifiers?.length ? ` (${row.identifiers.join(", ")})` : ""}`, ...row.caveats], lifecycle: "SUSPECTED" });
    else checks.push({ ...base, status: "NOT_TESTED", summary: `${row.product}: applicability ${row.applicability}`, observations: row.caveats, reason: row.applicability === "not-affected" ? "outside the affected ranges of the known records; an offline snapshot cannot prove no other advisory exists" : `applicability unknown: ${row.caveats.join("; ") || "insufficient evidence"}` });
  }
  return {
    knowledge: { snapshot: status, applicability: rows, gaps, proposals: [] },
    checks,
    proposals,
  };
}

/** Applicability rows for evidence that has records (lockfile packages); no per-package proposals. */
export function evaluateEvidence(s: Snapshot, evidence: ProductEvidence[]): KnowledgeResult["applicability"] {
  const rows: KnowledgeResult["applicability"] = [];
  for (const e of evidence) {
    for (const r of s.records.filter((x) => x.product.ecosystem === e.ecosystem && x.product.name === e.name)) {
      const m = applicability(r, e);
      if (m.applicability === "not-applicable") continue;
      rows.push({ product: `${e.ecosystem}/${e.name}${e.version ? ` ${e.version}` : ""}`, provenance: e.provenance, recordId: r.id, identifiers: [...r.identifiers.cve, ...r.identifiers.advisory], applicability: m.applicability, caveats: m.caveats, case: r.nsc, fix: r.fix });
    }
  }
  return rows;
}
