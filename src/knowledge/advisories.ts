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
 *
 * Bootstrap 2026-11-24: six npm `bootstrap` records copied by hand from their GHSA pages (npm ranges only;
 * other ecosystems on the same page are not used). GHSA-9mvj-f7w8-pvh2 (CVE-2024-6484) is not included:
 * GitHub withdrew it on 2025-09-11 and the CVE was rescinded. CVE-2024-6485 has no fixed release.
 * Review 2026-11-24: an independent, fresh-context agent re-checked every field against the GHSA pages
 * and accepted all six; they were promoted from `candidate` to `reviewed`. GHSA-4p24-vmcr-4gqj / CVE-2016-10735
 * and GHSA-3wqf-4x89-9g79 / CVE-2018-14040 were added and independently reviewed the same way later on
 * 2026-11-24.
 *
 * AngularJS 2026-11-24: fifteen npm `angular` records copied by hand from their GHSA pages (npm ranges only).
 * The listing for `ecosystem:npm angular` (4 pages) was read in full, plus three advisories it does not
 * surface. An independent, fresh-context agent re-checked every field against the GHSA pages and accepted
 * all fifteen; they were promoted from `candidate` to `reviewed`. Ten have no fixed release (AngularJS is
 * end of life). GHSA-28hp-fgcr-2r4h shows no CVSS on its page, so its severity carries no score.
 */
import type { Snapshot } from "./model.js";

const JQUERY = { ecosystem: "npm", name: "jquery", packaging: "upstream" } as const;
const CLIENT = ["client-side JavaScript library loaded by the page"];
const LIBVULN = "STA-LIBVULN matches the jQuery licence banner in served bundles (SUSPECTED); a patched or re-bundled copy can keep an old banner";
const UPGRADE_GUARD = "jQuery 3.5 changed htmlPrefilter: re-run every story flow that renders HTML (dialogs, templates, plugins) after the upgrade and compare with `navsentry compare`.";

const BOOTSTRAP = { ecosystem: "npm", name: "bootstrap", packaging: "upstream" } as const;
const BS_LIBVULN = "STA-LIBVULN matches the Bootstrap licence banner in served JavaScript bundles (SUSPECTED); a stylesheet banner alone is not used, and a patched or re-bundled copy can keep an old banner";
const BS_EVIDENCE = "Bootstrap version from an owner-provided inventory or a served JavaScript banner; never a payload";
const BS_GUARD = "Re-run every story flow that opens tooltips, popovers, collapses, scrollspy or affix after the upgrade and compare with `navsentry compare`; Bootstrap 3 → 4/5 is a breaking migration.";
const bs = (id: string, cve: string, affected: { introduced?: string; fixed?: string; lastAffected?: string }[], pre: string, vector: string, score: number, fix: string, published: string, updated: string) => ({
  id, revision: 2, state: "reviewed" as const, product: BOOTSTRAP,
  identifiers: { cve: [cve], advisory: [id], aliases: [] },
  versionScheme: "semver" as const, affected, preconditions: [pre], surface: CLIENT,
  severity: { source: "GitHub Advisory Database", score, vector, scoringVersion: vector.slice(5, 8) },
  safeEvidence: BS_EVIDENCE, nsc: "NSC-SUPPLY-002" as const, detector: "STA-LIBVULN", capability: BS_LIBVULN,
  fix, regressionGuard: BS_GUARD,
  sources: [{ url: `https://github.com/advisories/${id}`, published, updated }],
  verifiedAt: "2026-11-24", nextReviewAt: "2027-05-24",
});
const V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N";

const ANGULAR = { ecosystem: "npm", name: "angular", packaging: "upstream" } as const;
const NG_LIBVULN = "STA-LIBVULN matches the AngularJS licence banner line in served bundles (SUSPECTED); AngularJS module files (angular-route, angular-sanitize, ...) carry the same banner, and a patched or re-bundled copy can keep an old one";
const NG_EVIDENCE = "AngularJS version from an owner-provided inventory or a served version banner; never a payload";
const NG_GUARD = "AngularJS 1.x reached end of life in January 2022 and most of these issues have no fixed release: plan a migration off AngularJS, and re-run every story flow after any upgrade or mitigation and compare with `navsentry compare`.";
const ng = (id: string, cve: string[], affected: { introduced?: string; fixed?: string; lastAffected?: string }[], pre: string, sev: { score: number; vector: string } | undefined, fix: string, published: string, updated: string) => ({
  id, revision: 2, state: "reviewed" as const, product: ANGULAR,
  identifiers: { cve, advisory: [id], aliases: [] },
  versionScheme: "semver" as const, affected, preconditions: [pre], surface: CLIENT,
  severity: sev ? { source: "GitHub Advisory Database", score: sev.score, vector: sev.vector, scoringVersion: sev.vector.slice(5, 8) } : { source: "GitHub Advisory Database (Moderate; no CVSS shown)" },
  safeEvidence: NG_EVIDENCE, nsc: "NSC-SUPPLY-002" as const, detector: "STA-LIBVULN", capability: NG_LIBVULN,
  fix, regressionGuard: NG_GUARD,
  sources: [{ url: `https://github.com/advisories/${id}`, published, updated }],
  verifiedAt: "2026-11-24", nextReviewAt: "2027-05-24",
});
const NG_LAST = [{ lastAffected: "1.8.3" }];
const NG_NOFIX = "No fixed AngularJS release exists (end of life): migrate off AngularJS, or avoid the affected API with untrusted input";
const REDOS = { score: 5.3, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" };
const NG_V4_LOW = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:P";

export const SNAPSHOT: Snapshot = {
  version: "2026-11-24.4",
  generatedAt: "2026-11-24",
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
    bs("GHSA-9v3m-8fp8-mj99", "CVE-2019-8331", [{ introduced: "3.0.0", fixed: "3.4.1" }, { introduced: "4.0.0", fixed: "4.3.1" }],
      "the page passes an untrusted value to the data-template (or template) option of a tooltip or popover",
      "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "Upgrade Bootstrap to 3.4.1, or 4.3.1 or later (CWE-79).", "2019-02-22", "2026-06-02"),
    bs("GHSA-3mgp-fx93-9xv5", "CVE-2018-20676", [{ fixed: "3.4.0" }],
      "the page passes an untrusted value to the data-viewport (or viewport) option of a tooltip",
      V30, 6.1, "Upgrade Bootstrap to 3.4.0 or later (CWE-79).", "2019-01-17", "2024-08-05"),
    bs("GHSA-ph58-4vrj-w6hr", "CVE-2018-20677", [{ fixed: "3.4.0" }],
      "the page passes an untrusted value to the target option of the affix plugin",
      V30, 6.1, "Upgrade Bootstrap to 3.4.0 or later (CWE-79).", "2019-01-17", "2024-08-05"),
    bs("GHSA-pj7m-g53m-7638", "CVE-2018-14041", [{ introduced: "4.0.0", fixed: "4.1.2" }],
      "the page passes an untrusted value to the data-target (or target) option of scrollspy",
      V30, 6.1, "Upgrade Bootstrap to 4.1.2 or later (CWE-79).", "2018-09-13", "2025-11-19"),
    bs("GHSA-7mvr-5x2g-wfc8", "CVE-2018-14042", [{ introduced: "2.3.0", fixed: "3.4.0" }, { introduced: "4.0.0", fixed: "4.1.2" }],
      "the page passes an untrusted value to the data-container (or container) option of a tooltip",
      V30, 6.1, "Upgrade Bootstrap to 3.4.0, or 4.1.2 or later (CWE-79).", "2018-09-13", "2026-06-08"),
    bs("GHSA-vxmc-5x29-h64v", "CVE-2024-6485", [{ introduced: "1.4.0", lastAffected: "3.4.1" }],
      "the page puts an untrusted value in the data-loading-text attribute of a button handled by the button plugin",
      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:L", 6.4, "No fixed Bootstrap 3 release exists: migrate to Bootstrap 4 or later, or stop using the button plugin's loading state with untrusted text (CWE-79).", "2024-07-11", "2025-11-03"),
    bs("GHSA-4p24-vmcr-4gqj", "CVE-2016-10735", [{ introduced: "2.0.4", fixed: "3.4.0" }, { introduced: "4.0.0-beta", fixed: "4.0.0-beta.2" }],
      "the page passes an untrusted value to a data-target attribute handled by a Bootstrap plugin (a different issue from CVE-2018-14041)",
      V30, 6.1, "Upgrade Bootstrap 3 to 3.4.0 or later, or Bootstrap 4 to 4.0.0-beta.2 or later (CWE-79).", "2019-01-17", "2024-08-05"),
    bs("GHSA-3wqf-4x89-9g79", "CVE-2018-14040", [{ introduced: "2.3.0", fixed: "3.4.0" }, { introduced: "4.0.0", fixed: "4.1.2" }],
      "the page passes an untrusted value to the collapse plugin's data-parent attribute",
      V30, 6.1, "Upgrade Bootstrap 3 to 3.4.0 or later, or Bootstrap 4 to 4.1.2 or later (CWE-79).", "2022-05-13", "2024-08-05"),
    ng("GHSA-89mq-4x47-5v83", ["CVE-2019-10768"], [{ fixed: "1.7.9" }], "the page passes an untrusted object to the deprecated angular.merge()", { score: 7.5, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" }, "Upgrade AngularJS to 1.7.9 or later (CWE-20, CWE-915, CWE-1321).", "2019-11-20", "2025-11-20"),
    ng("GHSA-5cp4-xmrw-59wf", [], [{ fixed: "1.8.0" }], "the page passes untrusted HTML to a JQLite insertion method (append, after, prepend, replaceWith, angular.element)", { score: 5.0, vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L" }, "Upgrade AngularJS to 1.8.0 or later (CWE-79).", "2020-08-05", "2023-01-09"),
    ng("GHSA-mhp6-pxh8-r675", ["CVE-2020-7676"], [{ fixed: "1.8.0" }], "the page inserts sanitized HTML containing <option> elements through JQLite, which wraps them in <select> and changes parsing", { score: 5.4, vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" }, "Upgrade AngularJS to 1.8.0 or later (CWE-79).", "2020-06-18", "2025-11-20"),
    ng("GHSA-r5fx-8r73-v86c", ["CVE-2019-14863"], [{ fixed: "1.5.0-beta.1" }], "the page binds untrusted values to xlink:href attributes", { score: 6.1, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" }, "Upgrade AngularJS to 1.5.0-beta.1 or later (CWE-79).", "2020-02-14", "2023-01-27"),
    ng("GHSA-28hp-fgcr-2r4h", [], [{ fixed: "1.6.0" }], "the page makes JSONP requests to URLs that are not trusted resource URLs", undefined, "Upgrade AngularJS to 1.6.0 or later (CWE-79).", "2019-06-27", "2023-01-09"),
    ng("GHSA-m2h2-264f-f486", ["CVE-2022-25844"], [{ introduced: "1.7.0" }], "the page sets a custom locale rule with an untrusted NUMBER_FORMATS.PATTERNS[1].posPre value (ReDoS)", REDOS, `${NG_NOFIX} (CWE-770, CWE-1333).`, "2022-05-03", "2025-11-03"),
    ng("GHSA-prc3-vjfx-vhm9", ["CVE-2022-25869"], NG_LAST, "users run Internet Explorer with insecure page caching and the page interpolates untrusted values inside <textarea> elements", { score: 6.1, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" }, `${NG_NOFIX} (CWE-79).`, "2022-07-16", "2025-07-28"),
    ng("GHSA-2vrf-hf26-jrp5", ["CVE-2023-26116"], NG_LAST, "the page calls angular.copy() on untrusted input (ReDoS)", REDOS, `${NG_NOFIX} (CWE-1333).`, "2023-03-30", "2025-11-03"),
    ng("GHSA-2qqx-w9hr-q5gx", ["CVE-2023-26117"], NG_LAST, "the page passes untrusted input to the $resource service (ReDoS)", REDOS, `${NG_NOFIX} (CWE-1333).`, "2023-03-30", "2025-11-03"),
    ng("GHSA-qwqh-hm9m-p5hr", ["CVE-2023-26118"], NG_LAST, "the page validates untrusted input with an <input type=\"url\"> element (ReDoS)", REDOS, `${NG_NOFIX} (CWE-1333).`, "2023-03-30", "2025-11-03"),
    ng("GHSA-4w4v-5hc9-xrr2", ["CVE-2024-21490"], [{ introduced: "1.3.0", lastAffected: "1.8.3" }], "the page binds untrusted values with the ng-srcset directive (super-linear backtracking)", { score: 7.5, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }, `${NG_NOFIX} (CWE-1333).`, "2024-02-10", "2025-11-03"),
    ng("GHSA-m9gf-397r-hwpg", ["CVE-2024-8372"], [{ introduced: "1.3.0-rc.4", lastAffected: "1.8.3" }], "the page relies on image source restrictions for untrusted values bound to [srcset]", { score: 2.9, vector: NG_V4_LOW }, `${NG_NOFIX} (CWE-1289).`, "2024-09-09", "2025-11-03"),
    ng("GHSA-mqm9-c95h-x2p6", ["CVE-2024-8373"], NG_LAST, "the page relies on image source restrictions for untrusted values bound to [srcset] on <source> elements", { score: 2.9, vector: NG_V4_LOW }, `${NG_NOFIX} (CWE-791).`, "2024-09-09", "2025-11-03"),
    ng("GHSA-j58c-ww9w-pwp5", ["CVE-2025-0716"], NG_LAST, "the page relies on sanitization of untrusted href or xlink:href values on SVG elements", { score: 2.9, vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N/E:P" }, `${NG_NOFIX} (CWE-791).`, "2025-04-29", "2025-11-03"),
    ng("GHSA-7x27-g8rg-x87w", ["CVE-2026-11998"], [{ introduced: "1.2.0-rc.3", lastAffected: "1.8.3" }], "the page trusts resource URLs through SCE allow-list patterns, which can match only part of a URL", { score: 7.6, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:L" }, `${NG_NOFIX} (CWE-79, CWE-791).`, "2026-06-24", "2026-07-17"),
  ],
  aliases: [],
};
