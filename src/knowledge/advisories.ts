/**
 * Packaged advisory snapshot (SPEC-0.1.3 §6.6-A). Authoritative source of the generated
 * `docs/knowledge/VULNERABILITY-KB.md` (never hand-edited; `npm run docs:catalog`).
 *
 * It holds no real CVE records yet: importing them needs an APPROVED advisory-source entry in
 * governance/third-party.json (license, terms, provenance). Promotion of a reviewed proposal into
 * this file is a maintainer change with source verification, fixture tests and independent review.
 */
import type { Snapshot } from "./model.js";

export const SNAPSHOT: Snapshot = {
  version: "0.1.3-empty",
  generatedAt: "2026-11-03",
  records: [],
  aliases: [],
};
