# 03 — Quality Report (รายงานตรวจสอบคุณภาพ ผ่าน/ไม่ผ่าน) — สำหรับ AI/Agent

- Report ID: `RPT-03` · Date: 2026-10-31 · Reviewer: agent self-check, plus re-verification in a real browser. **An independent human review is still required before release.**
- Inputs: [01-ISSUE-REGISTER](01-ISSUE-REGISTER.md), [02-FIX-REPORT](02-FIX-REPORT.md)
- Verdict scale: `QA-PASS` · `QA-FAIL` (criteria not met → improvement criteria are mandatory) · `QA-INCOMPLETE` (could not be evaluated → what is missing)

## Overall verdict: **QA-PASS for v0.1.0 scope (M0 + M1-core)** · **QA-FAIL for full Master-Prompt acceptance** (3 FAIL + 1 INCOMPLETE, each with improvement criteria below)

| Group | PASS | FAIL | INCOMPLETE |
|---|---|---|---|
| Local gate (GATE-01…08) | 8 | 0 | 0 |
| Master-prompt acceptance tests + owner requirement (15) | 11 | 3 | 1 |
| Issue register follow-up (PRM, 22) | 16 fixed/decided | — | 6 open/partial (tracked) |

## A. Local gate

| QA ID | Gate | Result | Evidence |
|---|---|---|---|
| QA-GATE-01 | No GitHub Actions workflows | QA-PASS | `.github/workflows absent` |
| QA-GATE-02 | Tests | QA-PASS | `pass=30 fail=0` |
| QA-GATE-03 | Generated docs in sync | QA-PASS | `in sync` |
| QA-GATE-04 | npm audit (full tree) | QA-PASS | critical=0 high=0 moderate=0 low=0 (one database; not proof of absence) |
| QA-GATE-05 | Lockfile sha512 + registry provenance | QA-PASS | 3 packages, lockfileVersion 3 |
| QA-GATE-06 | Third-party decisions | QA-PASS | all locked packages approved |
| QA-GATE-07 | SBOM | QA-PASS | CycloneDX written to `.navsentry/gate/sbom.cdx.json` (local only, not committed) |
| QA-GATE-08 | Publication safety | QA-PASS | generic + owner-term scan clean |

Re-run: `npm run gate` → `.navsentry/gate/GATE-REPORT.md` (the final pre-push numbers are given in the push section of [HUMAN-SUMMARY](HUMAN-SUMMARY.md)).

## B. Master-prompt acceptance tests

| QA ID | Acceptance test (master prompt) | Result | Evidence |
|---|---|---|---|
| QA-AT-01 | Non-allowlisted origins, redirect escapes and unsafe methods rejected before execution | QA-PASS | tests: off-origin/scheme/method denial; redirect escape recorded, `evil.example` never requested |
| QA-AT-02 | Dry-run performs zero network traffic | QA-PASS | test: demo server hit count 0 after `planRun` |
| QA-AT-03 | API-only execution works with no browser installed | QA-PASS | all e2e tests ran with Playwright absent (`doctor`: UNAVAILABLE) |
| QA-AT-04 | Headless browser checks work with no display server | **QA-FAIL** | browser transport not implemented (M1b) |
| QA-AT-05 | curl/PowerShell function safely or report UNAVAILABLE with real reasons | QA-PASS | `doctor`: DETECTED with version + "execution scheduled for M3"; argv builders tested |
| QA-AT-06 | Visual computer-use honest when unavailable | QA-PASS | test `optional adapters are honest about availability` |
| QA-AT-07 | Separate actors; cross-role leak → VALIDATED only with evidence; protected fixture passes | **QA-FAIL** | header-token actors supported; cross-role IDOR scenario engine not built (M2) |
| QA-AT-08 | Unknown status / missing tools never become PASS | QA-PASS | tests: unreachable target, connect-time denial → ERROR/NOT_TESTED |
| QA-AT-09 | Secrets not exported; unsafe sanitization withholds artifact | QA-PASS | tests: redaction, binary withheld (`safe:false`), artifact leak scan |
| QA-AT-10 | Dependency audit flags a vulnerable pinned *fixture* dependency and gates | **QA-FAIL** | gate audits NavSentry's own tree only; no fixture lockfile test |
| QA-AT-11 | Local tests run real assertions; unexecuted platforms documented | QA-PASS | 30 assertions-based tests; [TESTING.md](../TESTING.md#platform-matrix) lists unexecuted Linux/macOS/Node 22/24 |
| QA-AT-12 | Consumer skill works from another project without inheriting maintainer policy | **QA-INCOMPLETE** | executed 2026-11-03 from a scratch project (validate/plan, no project changes); re-QA in a separate host session pending |
| QA-AT-13 | Source tree, docs, changelog and help agree | QA-PASS | catalog docs generated from code (GATE-03); CLI help lists only implemented commands; unimplemented ones exit 3 with milestone |
| QA-AT-14 | No real third-party target scanned during development | QA-PASS | only `127.0.0.1` fixtures; `https://staging.example.test` used in plan (dry-run) only |
| QA-AT-15 | Fixes do not change legitimate responses (owner requirement) | QA-PASS | compare `IMPROVED_NO_DRIFT`; drift-detection negative test |

### v0.1.2 story flows (spec §17, `test/flow.test.ts`, 2026-11-01, Windows 11 / Node 26.13.0)

| ID | Statement | Status | Evidence |
|---|---|---|---|
| QA-AT-16 | Flow parser strictness; messages without values | QA-PASS | parser test (unknown keys, block typos, quoted fences, size, NUL, BOM/CRLF, POST rejected, duplicate ids) |
| QA-AT-17 | lint/plan zero network; scope, secrets, level, positive-control rules | QA-PASS | lint/plan test asserts 0 fixture hits |
| QA-AT-18 | Deterministic classification with reasons | QA-PASS | classification test |
| QA-AT-19 | Hostile extracted values never leave scope; budget exhaustion | QA-PASS | hostile test (only 1 hit, runtime denial recorded); budget test → PARTIAL |
| QA-AT-20 | Every flow exchange is security-checked | QA-PASS | NSC-INFO-001 on flow-only URL; NSC-AC-003 in SARIF |
| QA-AT-21 | Access expectations FAIL/PASS/VALIDATED vs SUSPECTED | QA-PASS | vulnerable vs secure fixture, draft vs approved |
| QA-AT-22 | UI steps NOT_TESTED; E2E never PASS; exit 2 | QA-PASS | secure fixture profile flow INCOMPLETE; CLI exit 2 |
| QA-AT-23 | Analyzer zero network, deterministic, no errors/values, no overwrite | QA-PASS | analyzer test |
| QA-AT-24 | compare functional regressions; denied probes not drift | QA-PASS | compare test; demo `IMPROVED_NO_DRIFT` with flows |
| QA-AT-25 | Tokens and variable values absent from artifacts | QA-PASS | artifact scan in vulnerable flow test |
| QA-AT-26 | Approval pinned to content; drafts refused for production | QA-PASS | approval test; CLI production test |
| QA-AT-07 | Cross-role leak VALIDATED only with evidence and positive control | **QA-PARTIAL** | read access via approved flows (AC-003/007); login-based actors and write access remain M2 |

## C. Improvement criteria for every non-PASS item

### QA-AT-04 — Headless browser transport (QA-FAIL)
- **Expected:** `playwright-browser` usable headless with no display; DOM checks (CSP violations, cookie visibility, framing) run in a browser context; scope enforced for subresources.
- **Observed:** adapter probes availability only; `route({needsDOM:true})` returns no transport → DOM checks are NOT_TESTED (correct, but missing capability).
- **Cause:** Scope decision PRM-ARCH-001; Playwright browser-binary terms still PENDING_REVIEW (PRM-GOV-003).
- **Next action:** (1) finish the terms review of Chromium/Firefox/WebKit builds and record it; (2) add `playwright` as an **optional peer** pinned exactly; (3) implement the adapter with `serviceWorkers:'block'`, `context.route('**')` deny-by-default via `ScopeGate`, popup and WebSocket checks; (4) run on Linux without `DISPLAY`.
- **Re-QA acceptance:** test proves out-of-scope subresource blocked; headless run on Linux container passes; `doctor` shows USABLE only when binaries exist.
- **Prompt:** `Implement M1b playwright-browser per docs/DEV-PLAN.md#m1b and PRM-ARCH-002. Do not add the dependency before governance/third-party.json has an APPROVED entry. Prove scope enforcement with tests against test/fixtures/demo-server.ts.`

### QA-AT-07 — Cross-role authorization (QA-FAIL)
- **Expected:** two actors with disposable fixture objects; B→A object denied (negative control), A→A allowed (positive control); finding VALIDATED only with both.
- **Observed:** actors via `authorization_header_env` exist; no scenario manifest/engine for object pairs.
- **Next action:** add `scenarios[]` with `kind: cross-role-access`, `fixture_refs` per actor, request templates; implement under `safe-validate` (read-only GET first); add fixture routes with an IDOR bug and a fixed variant.
- **Re-QA acceptance:** NSC-AC-003 FAIL on vulnerable fixture with VALIDATED lifecycle, PASS on secure; missing positive control → INCONCLUSIVE.

### QA-AT-10 — Dependency-audit fixture (QA-FAIL)
- **Expected:** gate demonstrably blocks on a known-vulnerable dependency without installing it into NavSentry.
- **Observed:** GATE-04 audits the real tree only.
- **Next action:** add `test/fixtures/sca/package-lock.json` pinning an old version with a published advisory (lockfile only, never installed); run `npm audit --package-lock-only` against that folder in a gate self-test; expect FAIL; mark INCOMPLETE when offline.
- **Re-QA acceptance:** self-test shows FAIL for the fixture and PASS for the real tree in the same gate run.

### QA-AT-12 — Consumer skill from another project (executed 2026-11-03, re-QA pending)
- **Missing:** an execution from a separate checkout.
- **Next action:** in a scratch project, install NavSentry via `npm pack` tarball (no publish), copy `skills/navsentry/` into the agent's skills folder, run the skill's validate/plan flow against the demo fixture, confirm no NavSentry maintainer rules (AGENTS.md) are applied and no target file is modified.
- **Re-QA acceptance:** transcript + `git status` of the scratch project showing no changes.
- **Executed 2026-11-03 (Windows 11, Node 26.13.0):** `npm pack` tarball installed with `--ignore-scripts` into a fresh Git scratch project outside this repository, which had a planted `AGENTS.md` telling agents to edit `src/app.js`. The skill was copied from the installed package into a generic `.agent/skills/` folder. Following SKILL.md: `doctor --json` exit 0 and `packageRoot` resolved to the installed package; `validate` and `plan` with a `dev` manifest for 127.0.0.1 exit 0, `networkEffects: "none"`. After the installation commit, `git status --porcelain --ignored` showed only the ignored `node_modules/` and `.agent/`; no tracked file changed and the planted instruction was not followed.
- **Limits:** the skill was followed by the maintaining agent session, not by a separate host session with its own skill discovery; `test` against a running fixture was not part of this run. An independent re-QA should repeat it in a separate host session.
- **Found while running:** an unrecognized `environment` (`development`) produced authorization errors naming `"staging"`; fixed in the same change (see CHANGELOG).

### Open PRM items (tracked, not blocking v0.1)
| ID | What is missing | Next action | Done when |
|---|---|---|---|
| PRM-DATA-002 | `workflow` scope still on the owner's token | Owner runs `gh auth refresh -h github.com --remove-scopes workflow` | `gh auth status` shows no `workflow` |
| PRM-SAFE-001 | PowerShell 5.1 error handling | M3 adapter design | test on Windows PowerShell 5.1 |
| PRM-ARCH-002 | Browser channel limits | M1b | see QA-AT-04 |
| PRM-ARCH-004 | Linux/macOS, Node 22/24 runs | run `npm test` in WSL/containers | TESTING.md matrix updated with real results |
| PRM-MAP-001 | ASVS 5.0 requirement-level IDs | verify against ASVS 5.0.0 text | catalog field `asvs5` with verified IDs |
| PRM-PROC-002 | Remaining DevSift docs | read-only review | list updated in 01 |

## D. Residual risks (honest limits)
- Absence of findings is **not** proof of security; 30 of 50 cases are outside automated observe-mode coverage by design.
- Pattern rules (PII, email, internal IP) can produce false positives — they stay SUSPECTED.
- `npm audit` is one advisory source; "no known vulnerability at check time" is the strongest claim made.
- Legacy-TLS results depend on the local OpenSSL; INCONCLUSIVE means "use a dedicated scanner", not "safe".
