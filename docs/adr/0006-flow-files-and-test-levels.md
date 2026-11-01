# ADR-0006: Story flows as Markdown files with JSON blocks; deterministic test levels

- Status: Accepted (owner instruction to implement the 0.1.2 spec) · Date: 2026-11-01

## Context
The owner wants replayable test cases per user story, classified as E2E or Integration, with a report on both functionality and vulnerabilities, while vulnerability finding stays the primary purpose. Constraints: zero runtime dependencies and no YAML (ADR-0003), every request through `ScopeGate` and `Budget` (ADR-0004), no browser transport yet (M1b), no mutations (M2). Full design: [SPEC-0.1.2-FLOW-TEST-CASES](../specs/SPEC-0.1.2-FLOW-TEST-CASES.md).

## Decision
1. A flow is one `*.flow.md` file per story. Machine content lives only in top-level fenced blocks tagged `navsentry-flow` (one) and `navsentry-step` (one per step), parsed with `JSON.parse` and validated strictly (unknown keys rejected). Everything else is narrative that is never parsed, executed or reported.
2. The test level is derived, never guessed: any UI action or `navigate` step → `e2e`, otherwise `integration`. A declared level that disagrees is a lint error.
3. Flows run inside `executeTest` with the run's single `DirectHttpAdapter`, `ScopeGate`, `Budget` and `Redactor`. `src/flow/` has no network imports (tested). Every flow exchange also runs the per-exchange security checks, so flows are the safe alternative to crawling.
4. UI steps are parsed and classified but reported `NOT_TESTED` until a governed browser transport exists. A flow with any unexecuted step is never `PASS`.
5. Owner-declared `access: denied` expectations, paired with a positive control, drive the new `flow` automation class (NSC-AC-002, NSC-AC-003 read access, NSC-AC-007). Drafts yield at most `SUSPECTED`; approval is pinned to a content hash (`flow approve`).

## Consequences
+ Story-level replay and functional regression detection in `compare` without new dependencies. + Security coverage grows with owner-curated paths. − JSON inside Markdown is more verbose than a custom grammar. − E2E flows with UI steps stay `INCOMPLETE` (exit 2) until M1b. − Approval is a process control, not cryptographic identity.
