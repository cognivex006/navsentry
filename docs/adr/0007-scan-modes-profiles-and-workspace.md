# ADR-0007: Scan modes, environment profiles and workspace hygiene

- Status: Accepted (owner decisions D1–D10 on 2026-11-02, recommended options) · Date: 2026-11-02

## Context
The 0.1.3 owner request adds scan modes (`page`, `spider`, `flow`), two environments with different safety needs, local page analysis, larger response bodies and a code-enforced rule that no run leaves temporary files in the project. Constraints: zero runtime dependencies (ADR-0003), every request through `ScopeGate` and `Budget` (ADR-0004), no hosted automation (ADR-0002). Full design: [SPEC-0.1.3](../specs/SPEC-0.1.3-SCAN-MODES-AND-WORKSPACE.md).

## Decision
1. **Profiles are derived, not declared.** `environment` keeps its enum. `local` and `dev` map to the `development` profile; `staging` and `production` map to `production` (D4). The profile supplies defaults before parsing (D6) and adds guards: required `authorization.reference` and `expires_at`, an authorization window checked before any network activity, deadline cancellation of in-flight work, approved flows only, and refusal of live-key credentials. A profile never adds origins.
2. **`scanMode` is separate from `mode`.** `run.json.mode` stays the safety mode. `scanMode`, `profile`, `engine`, `capture` and `workspace` are additive optional fields; schema version 1 is unchanged.
3. **Engines map to existing transports.** Analysis is a local stage (`--analyze`), not an engine. An engine that is not USABLE runs nothing and its checks are `NOT_TESTED`; NavSentry never falls back to another engine. Computer Use is deferred beyond 0.1.3 because S1 cannot be enforced in a host-owned browser.
4. **Page-model runtime is pure Node (D3).** No CPython, no governance entry. Extractors are declarative JSON only; NavSentry never executes model-generated code (D5).
5. **Streamed capture.** The fixed 1 MiB body cap is replaced by configurable budgets (D9): bytes are counted and hashed as they arrive, a bounded prefix is retained, and every capture records `complete | truncated | aborted`. Anything not captured completely is incomplete, never PASS.
6. **Workspace hygiene is a check.** NavSentry writes only `<project>/.navsentry/` (self-ignoring) and explicit `--out` files. Ephemeral work lives in a locked `.navsentry/work/<run-id>/`, deleted at exit and on SIGINT/SIGTERM. Before/after snapshots turn any leftover or unexpected change into `WORKSPACE_DIRTY`, a new exit code 4 (D8) with precedence 3 > 4 > 1 > 2 > 0. Deletion never follows links and never trusts inventory metadata. The maintainer gate adds GATE-09.

## Consequences
+ Production runs carry an auditable authorization window. + Large bodies no longer come back silently truncated. + Leftovers fail loudly in consumer projects and in this repository. − Staging and production manifests need `reference` and `expires_at` (migration in CHANGELOG). − Snapshots compare metadata, so they detect common changes but do not prove byte identity, and they see changes made by any process during the run. − Spider, page analysis, static asset scanning and the knowledge base land in later 0.1.3 milestones.
