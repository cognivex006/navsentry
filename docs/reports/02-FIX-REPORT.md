# 02 — Fix Report (รายงานการปรับแก้ไขพร้อมหลักฐาน) — สำหรับ AI/Agent

- Report ID: `RPT-02` · Date: 2026-10-31 · Environment: Windows 11 Pro, Node 26.13.0, npm 11.20.0
- Input: [01-ISSUE-REGISTER](01-ISSUE-REGISTER.md) · Next: [03-QA-REPORT](03-QA-REPORT.md)
- Rule: each `FIX-*` names the issue it closes, the files changed, the **evidence actually observed**, and a checklist an agent can re-run. Nothing here is a claim without a command and its observed output.

## Evidence commands (re-runnable)

```bash
npm ci --ignore-scripts
```

```bash
npm test
```

```bash
npm run gate
```

```bash
node dist/scripts/demo.js run
```

Observed on 2026-10-31: `npm test` → **30 pass, 0 fail**; `npm run gate` → **PASS (8/8)**; demo → before 34 findings / after 5 findings (all NSC-CRYPT-006, expected: the local fixture is plain HTTP) / compare `IMPROVED_NO_DRIFT`, 14 fixed, 0 drift.

---

### FIX-PRM-GOV-001 — Local gates instead of hosted CI
- **Closes:** PRM-GOV-001 · **Files:** `scripts/local-gate.ts`, `package.json` (`gate` script), `docs/adr/0002-local-gates-no-hosted-ci.md`, `DEVELOPMENT.md`
- **Evidence:** `npm run gate` output row `GATE-01 | No GitHub Actions workflows (owner policy) | PASS | .github/workflows absent`.
- **Checklist:**
  - [x] No `.github/` directory in the repository
  - [x] Gate fails if a workflow file is added (GATE-01 logic)
  - [x] Gate reports PASS / FAIL / INCOMPLETE, never PASS on missing evidence (npm audit offline → INCOMPLETE)

### FIX-PRM-GOV-002 — Manual, reviewed dependency updates
- **Closes:** PRM-GOV-002 · **Files:** `DEVELOPMENT.md#dependency-updates`, `.npmrc` (`ignore-scripts=true`, `save-exact=true`)
- **Evidence:** `npm ls --all` → typescript@6.0.3, @types/node@22.20.5, undici-types@6.21.0 (3 packages, all dev-only). TypeScript 6.0.3 (2026-04-16) chosen over 7.0.2 to keep a pure-JS toolchain.
- **Checklist:** [x] exact pins · [x] install scripts disabled · [x] zero runtime dependencies (`dependencies` absent)

### FIX-PRM-GOV-003 — Third-party / SaaS terms register
- **Closes:** PRM-GOV-003 · **Files:** `governance/third-party.json`, `docs/THIRD-PARTY-GOVERNANCE.md`
- **Evidence:** official pages read on 2026-10-31 — GitHub ToS, Acceptable Use Policies, Active Malware or Exploits policy; npm Terms of Use and Open-Source Terms (updated 2022-03-10); Playwright LICENSE (Apache-2.0) and browsers page; OWASP Top 10:2025 and ASVS 5.0.0 pages. GATE-06 PASS: "all locked packages approved and in review window".
- **Checklist:** [x] each npm package has license, source, why, review date, review due · [x] each service has a decision (APPROVED / APPROVED_WITH_CONDITIONS / PENDING_REVIEW / NOT_ADOPTED / PROHIBITED) · [ ] Playwright browser-binary licenses reviewed (open, before M1b)

### FIX-PRM-DATA-001 — Anonymization and publication gate
- **Closes:** PRM-DATA-001 · **Files:** `src/catalog.ts` (SRC-A…F labels only), `scripts/local-gate.ts` (GATE-08), `test/transports.test.ts` (`catalog stays anonymized`), `.gitignore` (`.navsentry/`)
- **Evidence:** GATE-08 `PASS | 36 files scanned with 4 generic + 14 owner terms` (before docs were added; re-run in QA). Test `catalog stays anonymized (public repository)` ✔.
- **Checklist:** [x] no customer names, hosts, IPs or source paths in tracked files · [x] owner terms kept untracked · [x] sample reports contain no synthetic secrets (`grep` for the national ID, session value, email and private IP returned nothing)

### FIX-PRM-SAFE-001 — Safe CLI argv builders
- **Closes:** PRM-SAFE-001 (design) · **Files:** `src/transports/optional.ts`
- **Evidence:** tests ✔ `curl argv: -q first, no redirects, no shell metacharacter interpretation`, ✔ `PowerShell argv passes values as parameters, never as script text`, ✔ `child environment is scrubbed`. `navsentry doctor` → `DETECTED curl-cli curl 8.21.0 (Windows)…` and `DETECTED powershell-http 7.6.9`, both "not usable until M3" (honest).
- **Checklist:** [x] fixed executable locations · [x] `shell:false` · [x] CR/LF header rejection · [ ] Windows PowerShell 5.1 error handling (open, M3)

### FIX-PRM-SAFE-002 — Connect-time scope enforcement
- **Closes:** PRM-SAFE-002 · **Files:** `src/scope.ts`, `src/transports/direct-http.ts`, `src/checks/tls.ts`
- **Evidence:** tests ✔ `hostname resolving to loopback without approval is refused at connect time` (demo server hit count **0**), ✔ `private addresses need explicit approval; metadata is blocked even with approval`, ✔ `address classification covers private, metadata, mapped and NAT64 forms`, ✔ `redirect escapes are not followed and are recorded as denials`.
- **Checklist:** [x] every resolved address checked · [x] metadata always blocked · [x] redirects re-checked per hop · [x] encoded `..`/`/` refused

### FIX-PRM-SAFE-003 / SAFE-004 — Honest handling of active classes and TLS limits
- **Files:** `src/catalog.ts` (`manual-active`), `src/runner.ts` (`skipReason`), `src/checks/tls.ts`
- **Evidence:** test ✔ `vulnerable fixture…` asserts `NSC-INJ-001` = `NOT_TESTED`; plan output lists skipped cases with reasons.
- **Checklist:** [x] no injection/DoS/smuggling payload exists in the code base · [x] TLS client limitation → INCONCLUSIVE

### FIX-PRM-ARCH-001 — Working vertical slice
- **Files (new):** `src/{types,config,scope,budget,redact,contract,catalog,runner,compare,cli}.ts`, `src/checks/{passive,tls}.ts`, `src/transports/{types,direct-http,optional,registry}.ts`, `src/report/render.ts`, `scripts/{gen-catalog-docs,local-gate,demo}.ts`, `test/*.ts`, `test/fixtures/demo-server.ts` (≈3,700 lines TypeScript)
- **Evidence:** CLI run — `doctor` exit 0; `validate` exit 0; `plan` prints `"networkEffects": "none"`; `discover` without `--dry-run` exits 3 with "scheduled for milestone M1b" (no fake capability); invalid manifest exits 3 listing both problems and **without echoing the secret**.
- **Checklist:** [x] 20 automated case checks · [x] JSON/Markdown(en/th)/SARIF 2.1.0 · [x] exit codes separate CLI status from security result

### FIX-PRM-MAP-001 — Dual OWASP mapping
- **Files:** `src/catalog.ts`, generated `docs/ISSUE-CVE-MATRIX.md` §7
- **Evidence:** every case carries `owasp2021` and `owasp2025`; ASVS mapped to 5.0 chapter names only.
- **Checklist:** [x] Top 10:2025 IDs match top10.owasp.org/2025 (A01…A10 verified 2026-10-31) · [ ] ASVS 5.0 requirement IDs (open — needs line-by-line verification)

### FIX-PRM-RPT-001 — Legitimate-response protection (`compare`)
- **Files:** `src/contract.ts`, `src/compare.ts`, `docs/samples/compare.md`
- **Evidence:** ✔ `secure fixture passes and compare proves no legitimate-response drift` (verdict `IMPROVED_NO_DRIFT`); ✔ `compare detects a fix that changes the legitimate response contract` (status and JSON-shape drift reported). The secure fixture changes `/api/error` from a stack trace to a generic message **with the same status 500 and the same JSON keys** — the pattern every ERR fix should follow.
- **Checklist:** [x] security headers excluded from contract (expected to change) · [x] probe requests excluded · [x] CLI `compare` exits 1 on drift or regression

### FIX-PRM-RPT-002 / RPT-003 — IDs, matrix, prompts, templates
- **Files:** `src/catalog.ts` (50 cases), generated `docs/cases/CASE-CATALOG.md` (VERIFY/FIX/RECHECK prompt per case) and `docs/ISSUE-CVE-MATRIX.md`, `docs/reports/templates/{ISSUE,FIX,QA}.md`
- **Evidence:** GATE-03 `Generated case catalog / matrix up to date | PASS`; ✔ `catalog integrity: unique IDs, valid categories, mappings present`.

### FIX-PRM-SRC-001/002/003 — Source interpretation
- **Files:** `src/catalog.ts` caveats; `src/runner.ts` (`SUSPECT_ONLY`); `src/redact.ts` (mod-11 national-ID checksum, Luhn)
- **Evidence:** ✔ `national ID checksum and Luhn` (invalid checksum rejected); vulnerable demo finding NSC-PRIV-001 has lifecycle `SUSPECTED`, confidence `medium`.

### Browser re-verification (real page)
- **What:** Demo apps served on `127.0.0.1:4173` (vulnerable) and `127.0.0.1:4174` (secure), inspected in a real Chromium-based browser pane.
- **Observed:**
  - Secure page headers: `content-security-policy: default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'`, `x-content-type-options: nosniff`, `cache-control: no-store`, no `server`/`x-powered-by`; `document.cookie` empty (session cookie HttpOnly).
  - Vulnerable page: session cookie readable by JS, no CSP/XFO, `server: Apache/2.4.29 (Ubuntu)`, `x-powered-by: PHP/7.2.1`, unmasked 13-digit ID and email in `/api/profile`.
  - Framing the secure app from the vulnerable origin: browser console `Framing 'http://127.0.0.1:4174/' violates the following Content Security Policy directive: "frame-ancestors 'self'". The request has been blocked.` Screenshot: [evidence/browser-recheck-frame-ancestors.jpg](evidence/browser-recheck-frame-ancestors.jpg).
- **Matches NavSentry results:** NSC-CONF-003, NSC-SESS-002, NSC-INFO-001, NSC-PRIV-001, NSC-INFO-004 FAIL on vulnerable; PASS on secure.
