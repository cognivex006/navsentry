# ADR-0002: Local quality gates, no hosted CI

- Status: Accepted (owner decision) · Date: 2026-10-31

## Context
The master prompt asks for CI SCA, scheduled scans, dependency-update PRs and SHA-pinned workflow actions. The owner prohibits GitHub Workflow Actions after a previous GitHub account was suspended, and requires a terms study for any SaaS.

## Decision
No `.github/workflows`, Dependabot, GitHub Apps or other hosted automation. `npm run gate` runs eight gates locally (workflows absent, tests, generated docs, npm audit, lockfile provenance, terms decisions, SBOM, publication safety) and writes `.navsentry/gate/GATE-REPORT.md`. Results are PASS / FAIL / INCOMPLETE; offline evidence is INCOMPLETE. Contributors run it before every push; the PR description carries the summary.

## Consequences
+ No platform-automation risk; reproducible on any machine. − Relies on discipline: an unrun gate gives no protection; scheduled re-audits must be done manually (review_due dates in the register).
