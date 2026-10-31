# Reporting

## Artifacts per run (`navsentry test --out <dir>`)
| File | Content |
|---|---|
| `run.json` | Full `RunResult` (schema v1): scope, transports, redacted requests with response contracts, checks, findings, coverage, budget, denials, incomplete reasons |
| `REPORT.md` | Human report (language from manifest `report.language`, en/th) — always give users this direct link |
| `report.sarif` | SARIF 2.1.0 for code-scanning viewers (findings only) |

`navsentry report --input run.json --format markdown|json|sarif [--lang th]` re-renders from a validated run file.

## Reading a report
- **Execution status** (COMPLETE/PARTIAL/FAILED) is about the tool; **security result** (FINDINGS / NO_FINDINGS_IN_TESTED_SCOPE / INCOMPLETE) is about the target.
- Coverage lists every catalog case; NOT_TESTED rows carry a reason (manual-active, sast-only, planned, disabled…).
- Each finding gives severity, confidence, lifecycle, **priority** (IMMEDIATE / PLANNED / CAUTION), OWASP 2025+2021, CWE, WSTG, ASVS chapter, expected vs observed, reproduction, recommendation, **regression guard** and a link to the agent prompts.

## Before/after workflow
1. `navsentry test … --out runs/before`
2. Fix (see the case's FIX prompt) and deploy to staging.
3. `navsentry test … --out runs/after`
4. `navsentry compare --before runs/before/run.json --after runs/after/run.json`
   - `IMPROVED_NO_DRIFT` → done; `IMPROVED_WITH_DRIFT` → each drift row needs owner approval; `REGRESSED` → stop.

## Delivery reports for agents and humans
Templates: [reports/templates](reports/templates/) (ISSUE, FIX, QA). This delivery's reports: [01](reports/01-ISSUE-REGISTER.md), [02](reports/02-FIX-REPORT.md), [03](reports/03-QA-REPORT.md), [Human summary](reports/HUMAN-SUMMARY.md).

## What a report never contains
Live tokens, cookie values, passwords, PII values, unredacted bodies, invented payloads/traces, "fixed" claims without an after-run.
