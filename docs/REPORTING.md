# Reporting

## Artifacts per run (`navsentry test` or `navsentry scan`, `--out <dir>`)
| File | Content |
|---|---|
| `run.json` | Full `RunResult` (schema v1): scope, transports, redacted requests with response contracts, checks, findings, coverage, budget, denials, incomplete reasons |
| `REPORT.md` | Human report (language from manifest `report.language`, en/th) — always give users this direct link |
| `report.sarif` | SARIF 2.1.0 for code-scanning viewers (findings only) |
| `flows.json` | With `--flows`: `FlowRunResult` (schema 1) — per flow: level and reasons, executability, review state, status, value-free step assertions, linked finding fingerprints, manual replay checklist |
| `TEST-REPORT.md` | With `--flows`: functional report (en/th). Security result first, then functional results by level. See [FLOWS.md](FLOWS.md). |
| `client-findings.json` | `scan --mode page\|spider`: client-asset findings with masked previews only |
| `page-models/` | With `--analyze`: one redacted page model per HTML page |
| `VISUAL-SESSION.md`, `session.json` | `navsentry browse`: action log and findings of a visual-driver session |
| `junit.xml` | With `--flows --junit`: one testsuite per flow, one testcase per step (NOT_TESTED/INCONCLUSIVE → skipped) |

`navsentry report --input run.json --format markdown|json|sarif [--lang th]` re-renders from a validated run file. `--input flows.json --format markdown|json|junit` re-renders a flow result.

## Reading a report
- **Execution status** (COMPLETE/PARTIAL/FAILED) is about the tool; **security result** (FINDINGS / NO_FINDINGS_IN_TESTED_SCOPE / INCOMPLETE) is about the target.
- Coverage lists every catalog case; NOT_TESTED rows carry a reason (manual-active, sast-only, planned, disabled…).
- Each finding gives severity, confidence, lifecycle, **priority** (IMMEDIATE / CAUTION / PLANNED), OWASP 2025+2021, CWE, WSTG, ASVS chapter, expected vs observed, reproduction, recommendation, **regression guard** and a link to the agent prompts.

## Before/after workflow
1. `navsentry test … --out runs/before`
2. Fix (see the case's FIX prompt) and deploy to the same environment.
3. `navsentry test … --out runs/after`
4. `navsentry compare --before runs/before/run.json --after runs/after/run.json`
   - `IMPROVED_NO_DRIFT` → done; `IMPROVED_WITH_DRIFT` → each drift row needs owner approval; `REGRESSED` → stop; `FUNCTIONAL_REGRESSION` (a flow step went PASS → FAIL/ERROR) → stop and get the owner's decision.
   - Pass the run directories to compare flows too: `navsentry compare --before runs/before --after runs/after`.

## Delivery reports for agents and humans
Templates: [reports/templates](reports/templates/) (ISSUE, FIX, QA). This delivery's reports: [01](reports/01-ISSUE-REGISTER.md), [02](reports/02-FIX-REPORT.md), [03](reports/03-QA-REPORT.md), [Human summary](reports/HUMAN-SUMMARY.md).

## What a report never contains
Live tokens, cookie values, passwords, PII values, unredacted bodies, invented payloads/traces, "fixed" claims without an after-run, flow variable values, flow narrative text, manual replay results presented as PASS.
