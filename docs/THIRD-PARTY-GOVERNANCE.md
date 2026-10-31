# Third-party governance (dependencies, tools, SaaS)

Release-blocking policy. Machine-readable decisions: [governance/third-party.json](../governance/third-party.json) (checked by GATE-06).

## Owner decisions (2026-10-31)
- **GitHub Actions, Dependabot, GitHub Apps and scheduled hosted workflows are prohibited.** All automation runs locally.
- **Every SaaS must have its service terms studied before use**, including acceptable-use, rate limits, data-sharing and account rules. Default is not to adopt.

## Before adding anything
1. **Necessity** — can Node built-ins or existing code do it? Zero runtime dependencies is the default.
2. **Identity & provenance** — official registry/vendor, publisher, repository, maintenance activity, exact version ≥ 14 days old.
3. **License & terms** — license text; for services: ToS, AUP, API terms, privacy/DPA, automated-use rules. Record URLs and the review date.
4. **Advisories** — exact version and tree (`npm audit`; for important components also OSV/GitHub Advisory **web pages read manually** — their APIs are not adopted). One empty database is not proof of absence.
5. **Pin & record** — `--save-exact --ignore-scripts`; add the entry (`reviewed`, `review_due`, `decision`); `npm run gate`.
6. **Block** on critical/high exploitable advisories, malicious/unsafe provenance, licensing/ToS conflicts or missing evidence (INCOMPLETE).

## Terms findings that shape the design
| Provider | Key points (read 2026-10-31) | Consequence |
|---|---|---|
| GitHub ToS / AUP / malware policy | Dual-use security research allowed; prohibited: using GitHub to deliver attacks or gain unauthorized access, automated excessive bulk activity, inauthentic automated accounts, posting others' personal information; suspension at GitHub's discretion | Repo hosts code/docs only; no automation; no customer data; SECURITY.md + disclaimer present |
| npm Terms / Open-Source Terms (2022-03-10) | Install without account; no unreasonable request volume; no website crawling | Normal installs/audit only |
| Playwright (Apache-2.0) | Default browsers are open-source builds; branded Chrome/Edge under vendor terms | Optional, not installed; browser licenses to be reviewed before M1b |
| OWASP Top 10 / ASVS / WSTG | CC BY-SA content | IDs/names + links only |

## Boundary
NavSentry's own dependency governance (this document) is different from assessing a **target's** components (NSC-SUPPLY-001), which may only be claimed with owner-provided inventory/SBOM, never from HTTP fingerprints alone.
