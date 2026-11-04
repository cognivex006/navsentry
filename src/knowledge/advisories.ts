/**
 * Packaged advisory snapshot (SPEC-0.1.3 §6.6-A). Authoritative source of the generated
 * `docs/knowledge/VULNERABILITY-KB.md` (never hand-edited; `npm run docs:catalog`).
 *
 * Source: GitHub Advisory Database (CC-BY 4.0, approved in governance/third-party.json 2026-11-03).
 * Each record carries its advisory URL as attribution. Facts were copied by hand from the
 * GitHub-reviewed advisory pages; no API or bulk download was used.
 *
 * Review 2026-11-04: an independent, fresh-context agent review (owner-requested) re-checked every
 * field against the GHSA pages, the NVD API and the jQuery 3.4.0 / 3.5.0 release notes and accepted all
 * three; the records were then promoted from `candidate` to `reviewed`. Where NVD differs (its own
 * CVSS scores, a 1.2 lower bound for CVE-2020-11022 that contradicts its own description), GHSA is kept.
 */
import type { Snapshot } from "./model.js";

const JQUERY = { ecosystem: "npm", name: "jquery", packaging: "upstream" } as const;
const CLIENT = ["client-side JavaScript library loaded by the page"];
const LIBVULN = "STA-LIBVULN matches the jQuery licence banner in served bundles (SUSPECTED); a patched or re-bundled copy can keep an old banner";
const UPGRADE_GUARD = "jQuery 3.5 changed htmlPrefilter: re-run every story flow that renders HTML (dialogs, templates, plugins) after the upgrade and compare with `navsentry compare`.";

export const SNAPSHOT: Snapshot = {
  version: "2026-11-04.1",
  generatedAt: "2026-11-04",
  records: [
    {
      id: "GHSA-gxr4-xjj5-5px2", revision: 2, state: "reviewed",
      product: JQUERY,
      identifiers: { cve: ["CVE-2020-11022"], advisory: ["GHSA-gxr4-xjj5-5px2"], aliases: [] },
      versionScheme: "semver", affected: [{ introduced: "1.12.0", fixed: "3.5.0" }],
      preconditions: ["the page passes HTML from an untrusted source to a jQuery DOM manipulation method such as .html() or .append(), even after sanitizing"],
      surface: CLIENT,
      severity: { source: "GitHub Advisory Database", score: 6.9, vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N", scoringVersion: "3.1" },
      safeEvidence: "jQuery version from an owner-provided inventory or a served version banner; never a payload",
      nsc: "NSC-SUPPLY-002", detector: "STA-LIBVULN", capability: LIBVULN,
      fix: "Upgrade jQuery to 3.5.0 or later (CWE-79).",
      regressionGuard: UPGRADE_GUARD,
      sources: [{ url: "https://github.com/advisories/GHSA-gxr4-xjj5-5px2", published: "2020-04-29", updated: "2026-07-09" }],
      verifiedAt: "2026-11-03", nextReviewAt: "2027-05-03",
    },
    {
      id: "GHSA-jpcq-cgw6-v4j6", revision: 2, state: "reviewed",
      product: JQUERY,
      identifiers: { cve: ["CVE-2020-11023"], advisory: ["GHSA-jpcq-cgw6-v4j6"], aliases: [] },
      versionScheme: "semver", affected: [{ introduced: "1.0.3", fixed: "3.5.0" }],
      preconditions: ["the page passes HTML containing <option> elements from an untrusted source to a jQuery DOM manipulation method, even after sanitizing"],
      surface: CLIENT,
      severity: { source: "GitHub Advisory Database", score: 6.9, vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N/E:H", scoringVersion: "3.1" },
      safeEvidence: "jQuery version from an owner-provided inventory or a served version banner; never a payload",
      nsc: "NSC-SUPPLY-002", detector: "STA-LIBVULN", capability: LIBVULN,
      fix: "Upgrade jQuery to 3.5.0 or later (CWE-79).",
      regressionGuard: UPGRADE_GUARD,
      sources: [{ url: "https://github.com/advisories/GHSA-jpcq-cgw6-v4j6", published: "2020-04-29", updated: "2025-10-22" }],
      verifiedAt: "2026-11-03", nextReviewAt: "2027-05-03",
    },
    {
      id: "GHSA-6c3j-c64m-qhgq", revision: 2, state: "reviewed",
      product: JQUERY,
      identifiers: { cve: ["CVE-2019-11358"], advisory: ["GHSA-6c3j-c64m-qhgq"], aliases: [] },
      versionScheme: "semver", affected: [{ introduced: "1.1.4", fixed: "3.4.0" }],
      preconditions: ["the page calls jQuery.extend(true, {}, ...) on an unsanitized object that can carry an enumerable __proto__ property"],
      surface: CLIENT,
      severity: { source: "GitHub Advisory Database", score: 6.1, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", scoringVersion: "3.1" },
      safeEvidence: "jQuery version from an owner-provided inventory or a served version banner; never a payload",
      nsc: "NSC-SUPPLY-002", detector: "STA-LIBVULN", capability: LIBVULN,
      fix: "Upgrade jQuery to 3.4.0 or later (CWE-79, CWE-1321); 3.5.0 or later also fixes CVE-2020-11022 and CVE-2020-11023.",
      regressionGuard: "Deep-merge behaviour of jQuery.extend changes for __proto__ keys only; re-run story flows that merge configuration objects.",
      sources: [{ url: "https://github.com/advisories/GHSA-6c3j-c64m-qhgq", published: "2019-04-26", updated: "2024-11-05" }],
      verifiedAt: "2026-11-03", nextReviewAt: "2027-05-03",
    },
  ],
  aliases: [],
};
