# 01 — Issue Register (รายการแจ้งจุดปัญหา) — สำหรับ AI/Agent

- Report ID: `RPT-01` · Date: 2026-10-31 · Scope: NavSentry Master Prompt v1.0 + source assessment documents (SRC-A…SRC-F)
- Companion reports: [02-FIX-REPORT](02-FIX-REPORT.md) · [03-QA-REPORT](03-QA-REPORT.md) · Human summary: [HUMAN-SUMMARY](HUMAN-SUMMARY.md)
- Vulnerability cases (application-level) live in [CASE-CATALOG](../cases/CASE-CATALOG.md) and [ISSUE-CVE-MATRIX](../ISSUE-CVE-MATRIX.md). This register covers **problems in the prompt, plan and process** (`PRM-*`).

## How to use (Agent)

1. Pick an issue by ID. Run its **VERIFY** checklist against the repository at the stated paths.
2. If it is still open, apply the decision in [02-FIX-REPORT](02-FIX-REPORT.md) or the linked plan item.
3. Record the result in [03-QA-REPORT](03-QA-REPORT.md) using the `QA-<ID>` entry; a FAIL needs improvement criteria.

Priority legend: 🔴 **IMMEDIATE** ต้องแก้ทันที · 🟠 **CAUTION** แก้ได้แต่กระทบ ต้องระวัง · 🟡 **PLANNED** รอได้/วางแผน

ID categories: `GOV` governance/third-party · `DATA` data exposure · `SAFE` operational safety · `ARCH` architecture · `MAP` standards mapping · `RPT` reporting · `SRC` source-document interpretation · `PROC` process

## Summary table

| ID | Title | Priority | OWASP / reference | Status after this delivery |
|---|---|---|---|---|
| PRM-GOV-001 | Prompt requires hosted CI / workflow actions; owner forbids GitHub Actions | 🔴 IMMEDIATE | A03:2025 Supply Chain, A08:2025 | FIXED (ADR-0002, GATE-01) |
| PRM-GOV-002 | "Dependency update PRs" implies Dependabot/GitHub automation | 🔴 IMMEDIATE | A03:2025 | FIXED (manual update procedure) |
| PRM-GOV-003 | SaaS / third-party terms not studied for OSV, NVD, Postman, visual providers, ZAP, browser binaries | 🔴 IMMEDIATE | A03:2025 | FIXED for v0.1 scope (register); Playwright PENDING_REVIEW |
| PRM-DATA-001 | Public repo + customer assessment reports → data leak risk | 🔴 IMMEDIATE | A01:2025, A04:2025, CWE-359 | FIXED (anonymization + GATE-08 + test) |
| PRM-DATA-002 | GitHub CLI token carries unneeded `workflow` scope | 🟡 PLANNED (owner action) | A07:2025, least privilege | OPEN — owner action |
| PRM-SAFE-001 | curl/PowerShell pitfalls not specified (.curlrc, proxies, auto-redirects, PS 5.1 parsing) | 🔴 IMMEDIATE (before M3) | A05:2025 Injection, CWE-88 | FIXED in design + argv builders; PS 5.1 path OPEN |
| PRM-SAFE-002 | DNS-rebinding/metadata protection not achievable with plain `fetch` | 🔴 IMMEDIATE | A01:2025 (SSRF), CWE-918 | FIXED (connect-time lookup guard) |
| PRM-SAFE-003 | Source findings include active classes (SQLi, SSTI, LDAPi, LFI, smuggling, DoS) | 🟠 CAUTION | A05:2025, A02:2025 | FIXED (manual-active, never automated) |
| PRM-SAFE-004 | Legacy TLS probing limited by local OpenSSL | 🟡 PLANNED | A04:2025 | FIXED (INCONCLUSIVE, never PASS) |
| PRM-ARCH-001 | Scope too large for one pass; risk of "empty adapter interfaces" | 🟠 CAUTION | A06:2025 Insecure Design | FIXED (milestone plan, honest adapters) |
| PRM-ARCH-002 | Browser scope enforcement limits undeclared (service workers, WebSocket, internal traffic) | 🟡 PLANNED (M1b) | A01:2025 | OPEN — M1b requirement |
| PRM-ARCH-003 | YAML manifest vs zero-dependency core | 🟡 PLANNED | A03:2025 | DECIDED (JSON in v0.1, ADR-0003) |
| PRM-ARCH-004 | "Current Node LTS" unspecified; platform matrix unexecuted | 🟡 PLANNED | — | PARTIAL (engines ≥22.12; Windows only executed) |
| PRM-MAP-001 | OWASP version drift (2021 note vs Top 10:2025; ASVS 5.0 renumbered) | 🟠 CAUTION | OWASP Top 10:2025, ASVS 5.0.0 | FIXED (dual mapping; ASVS chapter-level) |
| PRM-RPT-001 | No guarantee that fixes keep legitimate responses unchanged | 🔴 IMMEDIATE | A06:2025, A10:2025 | FIXED (response contract + `compare`) |
| PRM-RPT-002 | No stable case IDs, categories or occurrence matrix | 🟠 CAUTION | — | FIXED (NSC IDs + matrix) |
| PRM-RPT-003 | Reports lack agent prompts, FACT/EVIDENCE/ACCEPTANCE, QA improvement criteria, human summary | 🟠 CAUTION | — | FIXED |
| PRM-SRC-001 | Source findings mix DAST, SAST and infra; counts inflate one root cause | 🟠 CAUTION | A03/A05:2025 | FIXED (automation classes, root-cause note) |
| PRM-SRC-002 | Scanner false positives/exceptions not modelled | 🟠 CAUTION | A10:2025 | FIXED (SUSPECTED lifecycle, checksum, caveats) |
| PRM-SRC-003 | Scanner recommends a deprecated, harmful control (HPKP) | 🟠 CAUTION | A04:2025 | FIXED (dismiss guidance in NSC-CRYPT-004) |
| PRM-PROC-001 | Prompt forbids direct main writes; owner asked to push | 🟡 PLANNED | — | DONE on branch `feat/navsentry-v0.1.0`; creating `main` is an owner decision |
| PRM-PROC-002 | DevSift reference docs only partially reviewed | 🟡 PLANNED | — | PARTIAL (see list) |

---

## Details

### PRM-GOV-001 — Hosted CI / workflow actions required by the prompt
- **FACT:** The master prompt requires "SCA in CI", "lockfile checks on PR, scheduled vulnerability scans, dependency update PRs", "pinned workflow actions by immutable SHA" and "Windows/Linux CI tests". The owner forbids GitHub Workflow Actions (previous account suspended).
- **EVIDENCE:** Master prompt v1.0, sections *Third-party dependency governance* items 4 and 8, *Milestones* M3/M5, *Acceptance tests* ("CI and local tests run actual assertions").
- **IMPACT:** Following the prompt literally violates an explicit owner constraint and re-creates the account risk.
- **DECISION:** Replace every hosted-CI requirement with the local gate `npm run gate` (GATE-01…08) and an optional local git hook. See [ADR-0002](../adr/0002-local-gates-no-hosted-ci.md).
- **VERIFY checklist:**
  - [ ] `.github/workflows/` does not exist in the repository
  - [ ] `npm run gate` exists and GATE-01 checks for workflows
  - [ ] No doc instructs users to enable GitHub Actions/Dependabot
- **Agent prompt:** `Verify PRM-GOV-001 in the navsentry repo: confirm no .github/workflows, run "npm run gate", quote GATE-01 row, grep docs for "GitHub Actions" and confirm every mention is a prohibition. Report PASS/FAIL with evidence.`

### PRM-GOV-002 — Automated dependency-update PRs
- **FACT:** "dependency update PRs with tests" implies Dependabot/Renovate (GitHub App/SaaS automation).
- **DECISION:** Updates are manual: `npm outdated` → choose versions ≥14 days old → review license/terms/advisories → update `governance/third-party.json` → `npm run gate`. Documented in [DEVELOPMENT.md](../DEVELOPMENT.md#dependency-updates).
- **VERIFY:** [ ] no `.github/dependabot.yml` · [ ] DEVELOPMENT.md has the manual procedure.

### PRM-GOV-003 — SaaS / third-party terms not studied
- **FACT:** Prompt mentions OSV, NVD, GitHub Advisory Database, Postman/Newman, visual computer-use providers, OWASP ZAP and Playwright browsers without terms review. Owner requires every SaaS's service terms to be studied.
- **EVIDENCE:** Terms reviewed on 2026-10-31 and recorded in [governance/third-party.json](../../governance/third-party.json): GitHub ToS/AUP/malware policy (dual-use research allowed; no attack delivery, no automated bulk/inauthentic activity, no third-party personal data), npm terms (install volume fine; no website crawling), Playwright Apache-2.0 (branded Chrome/Edge under vendor terms).
- **DECISION:** v0.1 adopts **no SaaS**. OSV/NVD/GitHub Advisory API/Postman cloud/visual providers/ZAP are `NOT_ADOPTED` until reviewed; Playwright `PENDING_REVIEW` before M1b. Target data must never go to a SaaS without the target owner's approval.
- **VERIFY:** [ ] every lockfile package has an APPROVED entry (GATE-06) · [ ] every service named in docs appears in `services_and_tools` with a decision and date.

### PRM-DATA-001 — Public repository and customer assessment data
- **FACT:** `cognivex006/navsentry` is **public**. The source PDFs contain customer names, hostnames, internal IPs and source file paths.
- **DECISION:** Sources are referenced only as SRC-A…SRC-F with generic descriptions. Customer terms live in the untracked `.navsentry/forbidden-terms.txt`; GATE-08 scans every tracked file; `test/transports.test.ts` blocks IPs, source paths and organization domains in the catalog.
- **VERIFY:** [ ] GATE-08 PASS with owner terms present · [ ] `git log -p | grep` for customer terms returns nothing (run locally with the private list).
- **Caution:** if anything ever leaks, rewriting history is not enough once pushed — rotate/notify per SECURITY.md.

### PRM-DATA-002 — `workflow` OAuth scope on the GitHub CLI token
- **FACT:** `gh auth status` shows scopes `gist, read:org, repo, workflow`. NavSentry never needs `workflow`.
- **DECISION:** Owner action (not performed by the agent): `gh auth refresh -h github.com --remove-scopes workflow`.
- **VERIFY:** [ ] `gh auth status` no longer lists `workflow`.

### PRM-SAFE-001 — CLI transport pitfalls
- **FACT:** curl reads `~/.curlrc` unless `-q` is the **first** argument, honours `*_PROXY` env vars, and may follow redirects; Windows PowerShell 5.1 `Invoke-WebRequest` follows up to 5 redirects by default and uses legacy HTML parsing without `-UseBasicParsing`; `-SkipHttpErrorCheck` exists only in PowerShell 7+.
- **DECISION:** `buildCurlArgv` (`-q` first, `--max-redirs 0`, `--proto =http,https`, `--noproxy *`, CR/LF rejection) and `buildPwshArgv` (fixed script, values as parameters, `-MaximumRedirection 0`, `-UseBasicParsing`, `-NoProfile`) plus `scrubbedEnv()`; executables only from fixed system paths. Tested in `test/transports.test.ts`.
- **OPEN:** Windows PowerShell 5.1 has no `-SkipHttpErrorCheck`; M3 must handle 4xx/5xx via try/catch on `WebException` or restrict the adapter to PowerShell 7.

### PRM-SAFE-002 — DNS rebinding and metadata protection
- **FACT:** Node's global `fetch` cannot validate the address actually connected to without adding the `undici` dependency.
- **DECISION:** `direct-http` uses `node:http/https` with a custom `lookup` that checks **every** resolved address at connect time; metadata addresses are always blocked; private networks need `network.allow_private` with approver and reason. Test: a hostname resolving to loopback without approval sends zero bytes.

### PRM-SAFE-003 — Active vulnerability classes in the sources
- **FACT:** SRC-E includes SQL injection, server-side script injection, LDAP injection, local file inclusion, HTTP request smuggling and parse-double DoS. Confirming them needs payloads that can alter data or affect other users.
- **DECISION:** Catalogued as `manual-active` (NSC-INJ-001/002/003/006, NSC-CONF-008, NSC-ERR-002). NavSentry reports them `NOT_TESTED` with the reason; their VERIFY prompts require separate written authorization and a staging target.

### PRM-SAFE-004 — Legacy TLS probing limits
- **FACT:** OpenSSL 3 in Node cannot offer SSLv3 and may refuse TLS 1.0/1.1 locally.
- **DECISION:** `client-unsupported` outcomes make NSC-CRYPT-001 `INCONCLUSIVE` with advice to use a dedicated TLS scanner; SSLv3 is never claimed tested.

### PRM-ARCH-001 — Scope vs. "no empty adapter interfaces"
- **FACT:** Six transports, nine test families, import, ZAP and a DevSift bridge cannot all be built and verified in one pass; the prompt itself forbids empty interfaces.
- **DECISION:** Deliver a working vertical slice (M0 + M1-core): scope gate, budget, redaction, direct-http, 20 deterministic case checks, TLS probe, JSON/Markdown/SARIF, compare, local gate, 30 tests. Optional adapters report honest `UNAVAILABLE`/`DETECTED, not usable` and their safety-critical argv builders are tested. Remaining work is in [DEV-PLAN](../DEV-PLAN.md).

### PRM-ARCH-002 — Browser channels that cannot be fully constrained
- **FACT:** Page-level route interception does not cover WebSocket frames after upgrade, service-worker fetches unless blocked, or browser-internal traffic.
- **DECISION (M1b acceptance):** `serviceWorkers: 'block'`, route-level allowlist with deny default, WebSocket URL checks at creation, popups/new pages checked, and the limitation declared in `unenforceableChannels`.

### PRM-ARCH-003 — YAML manifest
- **DECISION:** JSON manifests in v0.1 (zero runtime dependencies). YAML requires a governed dependency (candidate `yaml`, ISC) and a safe-load review; tracked in DEV-PLAN M1b.

### PRM-ARCH-004 — Runtime/platform matrix
- **FACT:** Only Windows 11 + Node 26.13.0 was executed. `engines: >=22.12`.
- **DECISION:** Declared in [TESTING.md](../TESTING.md#platform-matrix) as unexecuted for Linux/macOS and Node 22/24; run locally (WSL/containers) before claiming support.

### PRM-MAP-001 — OWASP version drift
- **FACT:** The Thai OWASP note (SRC-F) is Top 10:2021. Top 10:2025 is current (SSRF folded into A01; new A03 Supply Chain and A10 Exceptional Conditions). ASVS 5.0.0 (published 30 May 2025) renumbered chapters, so ASVS 4.0.3 requirement IDs are invalid.
- **DECISION:** Every case maps to **both** 2021 and 2025, plus CWE and WSTG. ASVS is mapped at **chapter level** only; requirement-level IDs stay unmapped until verified against the ASVS 5.0.0 text (no invented IDs).

### PRM-RPT-001 — Fixes must not change what legitimate callers receive
- **FACT:** The owner requires remediations that do not alter responses for genuine requesters. The prompt has no such mechanism.
- **DECISION:** Each observed request stores a **response contract** (status, content type, non-security header names, JSON key/type shape hash, size bucket). `navsentry compare` reports per-case transitions plus contract drift; every case has a `regressionGuard`. Demo evidence: verdict `IMPROVED_NO_DRIFT`, 14 cases fixed, 0 drift ([compare.md](../samples/compare.md)).

### PRM-RPT-002 / PRM-RPT-003 — IDs, matrix and agent-ready reports
- **DECISION:** Permanent IDs `NSC-<CAT>-<NNN>` (50 cases, 13 categories), occurrence log, CVE/CWE/OWASP indexes, per-case VERIFY/FIX/RECHECK prompts, and report templates in [templates/](templates/).

### PRM-SRC-001 — Mixed source types and inflated counts
- **FACT:** SRC-B/C/D report 1,077 "Header Manipulation" instances, all from shared header-forwarding helpers — one root cause. SRC-E mixes host/network VA items with web findings.
- **DECISION:** Automation classes (`auto`, `assisted`, `manual-active`, `sast-only`, `infra`) separate what runtime testing can prove; NSC-INJ-005 states "fix once in the shared helper".

### PRM-SRC-002 — Scanner false positives and exceptions
- **FACT:** SRC-E accepted three Exceptions: a 13-digit internal function ID flagged as a national ID, a web-server product absent from the container deployment, and OPTIONS enabled for CORS.
- **DECISION:** Pattern-based rules produce `SUSPECTED` findings; national IDs need a valid mod-11 checksum; OPTIONS only fails when dangerous methods are advertised; version fingerprints never prove a component is present.

### PRM-SRC-003 — Harmful "fix" recommended by a scanner
- **FACT:** SRC-E lists "Missing Public Key Pinning". HPKP was removed from browsers and can lock users out.
- **DECISION:** NSC-CRYPT-004 instructs to **not** deploy HPKP and to record a DISMISSED decision.

### PRM-PROC-001 — Pushing to `main`
- **FACT:** The prompt says not to merge to main without explicit authorization; the owner explicitly asked to push to the empty repository.
- **OUTCOME:** A local guard hook blocked pushing to `main`, so the work was pushed to `feat/navsentry-v0.1.0` (consistent with the prompt). Because the repository was empty, GitHub made that branch the default. Owner action: review, then create/rename `main` from it (GitHub → Settings → Branches → rename default branch) and protect `main`. The bootstrap commit message mentions `main`; that wording is superseded by this entry.

### PRM-PROC-002 — DevSift reference coverage
- **Read (read-only, via `gh api`):** `AGENTS.md`, `SECURITY.md`, `docs/THIRD-PARTY-TERMS.md`, `docs/development/EVIDENCE.md` (partial), `REPORT-MODEL.md` (partial), `SECURITY-GATE.md` (partial), `REPORT-TEMPLATE.md` (partial), repository listings of `devsift` and `devsift-specs`.
- **Not read:** `DEVELOPMENT.md`, `CHANGELOG.md`, `README.md`, `docs/AGENT-INTEGRATIONS.md`, `docs/development/README.md`, `THREAT-MODEL.md` (downloaded, not reviewed), and all of `devsift-specs` content.
- **Adopted principles:** incomplete ≠ clean; proposals are not fixes; unknown impact is disclosed rather than invented; consumer vs maintainer separation; terms evidence with dates; direct REPORT.md link.
