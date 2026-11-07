# Architecture

## Pipeline

1. **Manifest** (`config.ts`) — strict parse; unknown keys and plaintext secrets rejected; production limited to `observe`.
2. **Planner** (`runner.ts#planRun`) — builds steps (TLS probe per HTTPS origin; GET per seed × actor; CORS probe; OPTIONS probe) and the list of skipped cases with reasons. Performs **no network or DNS activity**.
3. **Authorization & Scope Gate** (`scope.ts`) — `checkRequest` (scheme, credentials, origin, method, encoded traversal, deny/allow globs, literal IP class) before any I/O; `checkResolvedAddress` inside the socket `lookup` for every resolved address (DNS rebinding, metadata, private networks need named approval).
   In safe-validate, `checkMutation(url, method, entry)` allows a non-observe request only when it exactly matches a declared fixture entry; `checkRequest` keeps refusing those methods ([ADR-0010](adr/0010-safe-validate-fixtures.md)).
4. **Budget** (`budget.ts`) — max requests, requests/second, duration; exhaustion makes the run `PARTIAL`. A safe-validate create reserves its cleanup slots (`reserve`/`release`), which ordinary requests cannot use.
4a. **Fixture lifecycle** (`fixtures/`) — config parsing, pending intents (`fixtures.pending.json`), create → id check → `exists`, reverse-order cleanup with `verify_gone`, leftovers (run FAILED), and the `SignalCoordinator` for SIGINT/SIGTERM. Every request goes through the runner's send (ScopeGate → Budget → connect-time check).
5. **Transport router** (`transports/registry.ts`) — chooses the lowest-cost *usable* adapter whose declared capabilities satisfy the check; if none, the check is `NOT_TESTED` (never silently downgraded, e.g. a DOM check is never "proven" by HTTP).
6. **Transports** — `direct-http` (usable), `tls-probe` (usable), `playwright-browser` (usable for development flows when the Chromium headless shell is installed, [ADR-0008](adr/0008-playwright-engine-s1.md)), `visual-computer-use` (the `navsentry browse` visual driver on that engine, [ADR-0009](adr/0009-visual-driver-on-owned-browser.md)), `curl-cli` / `powershell-http` (probe only), `zap-passive` (unavailable).
7. **Checks** (`checks/`) — deterministic functions over in-memory raw responses that emit redacted, value-free observations.
8. **Redaction** (`redact.ts`) — applied to URLs, headers and body excerpts before anything is stored; binary/undecodable bodies are withheld (`safe:false` → run lists the gap).
9. **Model & reports** — `RunResult` (schema v1) → JSON, Markdown (en/th), SARIF 2.1.0; `compare` for before/after.
10. **Flows** (`src/flow/`, ADR-0006) — `parse` (top-level `navsentry-*` JSON blocks in `*.flow.md`), `lint` (static ScopeGate check, redaction scan, positive controls, approval hash), `classify` (E2E/Integration), `execute` (steps through the runner's `send`; every exchange also runs the security checks; access post-pass emits NSC-AC-002/003/007 results), `analyze` (offline drafts from `run.json`). Output: `flows.json` (`FlowRunResult` schema 1), `TEST-REPORT.md`, optional JUnit. `src/flow/` has no network imports.

## Transport capability model

| Adapter | Mode | DOM | JS | Cookies | Trust | State | Unenforceable channels |
|---|---|---|---|---|---|---|---|
| direct-http | http | – | – | ✓ | in-process | usable | none |
| tls-probe | tls | – | – | – | in-process | usable | none |
| playwright-browser | browser | ✓ | ✓ | ✓ | in-process | usable (M1b; every request fulfilled through direct-http) | WebSocket (disabled), service workers (disabled), browser-internal traffic (disabled by launch flags, not by ScopeGate) |
| curl-cli | cli-http | – | – | ✓ | vetted executable | probe (M3) | — |
| powershell-http | cli-http | – | – | ✓ | vetted executable | probe (M3) | — |
| visual-computer-use | visual | ✓ | ✓ | ✓ | in-process (NavSentry-owned browser) | usable in development (`navsentry browse`, observe-only) | same as playwright-browser; screenshots reach the agent's model provider (owner consent) |
| zap-passive | proxy | – | – | – | vetted executable | unavailable | — |

Selection principle: lowest risk that can verify the claim. A CLI or browserless check never proves a browser-only property.

## Data model highlights
- `CheckStatus` PASS/FAIL/INCONCLUSIVE/NOT_TESTED/ERROR; coverage per case = worst observed status; no rows → NOT_TESTED with a reason.
- `Finding` fingerprint = `sha256(caseId + method + URL without query)`; lifecycle VALIDATED for direct deterministic evidence, SUSPECTED for pattern evidence.
- `ResponseContract` = status, media type, non-volatile non-security header names, JSON key/type skeleton hash, body-size bucket.
- `executionStatus` (CLI) is separate from `securityResult` (FINDINGS / NO_FINDINGS_IN_TESTED_SCOPE / INCOMPLETE). Flows add a third, separate `functionalResult` (PASS / FAIL / INCOMPLETE).
- Flow requests carry `ObservedRequest.flow` and record template URLs (`/api/orders/{{orderA}}`), so fingerprints and `compare` keys are stable across runs. Findings that rest on draft flows carry `CheckResult.basis = "draft-flow"` and stay SUSPECTED.

## DevSift interoperability (planned M4)
Separate product. A versioned adapter will read NavSentry `run.json` + SARIF and DevSift reports and correlate by CWE/case ID and route, keeping runtime evidence and source evidence provenance separate. No DevSift internals are imported.
