# Reporting

## Artifacts per run (`navsentry test --out <dir>`)
| File | Content |
|---|---|
| `run.json` | Full `RunResult` (schema v1): scope, transports, redacted requests with response contracts, checks, findings, coverage, budget, denials, incomplete reasons |
| `REPORT.md` | Human report (language from manifest `report.language`, en/th) — always give users this direct link |
| `REPORT.html` | The same report as one offline HTML file: colours by status and action level, a level filter, Export Markdown and Print / PDF. No external resources; a CSP allows only the file's own hashed style and script |
| `report.sarif` | SARIF 2.1.0 for code-scanning viewers (findings only) |
| `flows.json` | With `--flows`: `FlowRunResult` (schema 1) — per flow: level and reasons, executability, review state, status, value-free step assertions, linked finding fingerprints, manual replay checklist |
| `TEST-REPORT.md` | With `--flows`: functional report (en/th). Security result first, then functional results by level. See [FLOWS.md](FLOWS.md). |
| `junit.xml` | With `--flows --junit`: one testsuite per flow, one testcase per step (NOT_TESTED/INCONCLUSIVE → skipped) |

`navsentry report --input run.json --format markdown|html|json|sarif [--lang th] [--out <file>]` re-renders from a validated run file. `--out` writes the file and never overwrites one; without it, HTML is refused on a terminal (scan already wrote `REPORT.html`) and every format still goes to stdout when piped. `--input flows.json --format markdown|json|junit` re-renders a flow result.

## Reading a report
- **Replay timeline** (browser flows): TEST-REPORT.md shows a screenshot of the headless browser after each browser step, from `<run>/shots/` (git-ignored, at most 60 per run). It is evidence of what NavSentry clicked and what the page showed, including the page at a failed step. To drive a page step by step yourself, use `navsentry browse start`.
- **Verdict:** the first line of the Summary answers "Do I need to fix something now?": 🔴 yes (an IMMEDIATE or CAUTION finding, or test objects left behind), 🟡 schedule it (PLANNED findings only), 🟢 no fix needed in the tested scope (not proof of security), ⚪ can't tell (an incomplete run, or flows that failed or did not run, when nothing needs a fix now). `scan` prints the same line, and `scan --json` has it as `verdict`.
- **Execution status** (COMPLETE/PARTIAL/FAILED) is about the tool; **security result** (FINDINGS / NO_FINDINGS_IN_TESTED_SCOPE / INCOMPLETE) is about the target.
- Coverage lists every catalog case; NOT_TESTED rows carry a reason (manual-active, sast-only, planned, disabled…).
- Every report has the same twelve sections, in this order. A section without data says so.
  1. Summary
  2. Findings
  3. Fix verification
  4. Known vulnerabilities
  5. Coverage
  6. Not tested and limitations
  7. Transports and engine
  8. Requests refused before sending
  9. Redirect chains
  10. Client assets and browser
  11. Knowledge gaps
  12. Run details
- Each case gets one finding card, which lists every affected target. The card gives:
  - action level, severity, and why it matters;
  - expected vs observed, and how to reproduce;
  - how to fix, with **before/after examples** for common stacks (nginx, Express, ASP.NET Core, Spring, front-end builds). The examples are reviewed, but NavSentry does not execute them;
  - how to recheck, when it counts as fixed, and what must not break;
  - OWASP 2025/2021, CWE, WSTG and ASVS references.
- Action levels come from the case's severity and priority:
  - 🔴 IMMEDIATE and 🟠 CAUTION keep the case's priority;
  - 🟡 PLANNED is scheduled work;
  - 🔵 OPTIONAL is low-severity planned hardening; it may be skipped with a recorded reason;
  - ⚪ INFO is an observation with info severity.
- Known vulnerabilities show the advisory's CVSS score and vector, with the source of the score.

## Before/after workflow
1. `navsentry test … --out runs/before`
2. Fix (see the finding card's fix and before/after examples) and deploy to the same environment.
3. `navsentry test … --out runs/after`
4. `navsentry compare --before runs/before/run.json --after runs/after/run.json`
   - `IMPROVED_NO_DRIFT` → done; `IMPROVED_WITH_DRIFT` → each drift row needs owner approval; `REGRESSED` → stop; `FUNCTIONAL_REGRESSION` (a flow step went PASS → FAIL/ERROR) → stop and get the owner's decision.
   - Pass the run directories to compare flows too: `navsentry compare --before runs/before --after runs/after`.

## Delivery reports for agents and humans
Templates: [reports/templates](reports/templates/) (ISSUE, FIX, QA). This delivery's reports: [01](reports/01-ISSUE-REGISTER.md), [02](reports/02-FIX-REPORT.md), [03](reports/03-QA-REPORT.md), [Human summary](reports/HUMAN-SUMMARY.md).

## What a report never contains
Live tokens, cookie values, passwords, PII values, unredacted bodies, invented payloads/traces, "fixed" claims without an after-run, flow variable values, flow narrative text, manual replay results presented as PASS.
