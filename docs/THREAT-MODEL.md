# Threat Model

Assets: target availability and data; credentials for test actors; evidence/report contents; the operator's machine; the NavSentry supply chain; the owner's GitHub account.

| ID | Threat | Control (implemented) | Residual / planned |
|---|---|---|---|
| TM-01 | Scanning an unauthorized host (typo, redirect, link) | Origin allowlist, authorization acknowledgement, redirect re-check per hop, no crawling | Live discovery (M1b) must reuse the gate |
| TM-02 | DNS rebinding / SSRF into internal or cloud metadata | Connect-time `lookup` validation of every address; metadata always blocked; named private approvals | Browser transport must enforce the same (M1b) |
| TM-03 | Causing damage (state change, DoS) | Safe methods only; `allow_mutations` refused; budgets; production observe-only; no payload code | `safe-validate` fixtures (M2) need cleanup/rollback |
| TM-04 | Leaking secrets/PII into reports | Redaction before persistence; set-cookie values dropped; binary withheld; tests scan artifacts | Redaction is defensive, not proof; unknown formats may pass |
| TM-05 | Prompt injection from target content | Target data never interpreted as instructions; agent skill states it; checks are deterministic code | LLM planner (future) must keep this boundary |
| TM-06 | Command injection via CLI transports | argv arrays, `shell:false`, fixed executable paths, scrubbed env, `-q` for curl, fixed PowerShell script | Execution not enabled until M3 tests on each OS |
| TM-07 | Malicious/compromised dependency | Zero runtime deps; exact pins; ignore-scripts; lockfile sha512 + registry check; audit; SBOM; terms register | Single advisory source; no signature verification of npm tarballs beyond integrity |
| TM-08 | Owner account suspension (platform policy) | No GitHub Actions/Apps/bulk API automation; public repo content reviewed against GitHub AUP | Owner should remove `workflow` token scope |
| TM-09 | Publishing customer data from source reports | SRC labels; GATE-08 with untracked owner terms; catalog anonymization test | Depends on the owner keeping the terms file current |
| TM-10 | False assurance ("zero findings = safe") | Coverage matrix with NOT_TESTED reasons; INCOMPLETE security result; wording in every report | Human review still required |
| TM-12 | A flow file widens scope (origin, path, method, headers) | No host keys; static ScopeGate lint; runtime ScopeGate per request and redirect hop; unknown keys rejected; no custom headers | — |
| TM-13 | Target-controlled values steer requests (extracted IDs) | Strict value charset, `.`/`..` rejected, whole-segment substitution with encoding, ScopeGate after substitution, no header templating, no cross-flow state | — |
| TM-14 | Prompt injection through analyzer inputs (run.json, story text, target repos) | Deterministic analyzer; narrative never executed or reported; generated flows are drafts; skill: data, not instructions | Host agent discipline |
| TM-15 | Secrets or PII committed in consumer flow files | Env references only; `fill` values only via vars; every literal scanned with the Redactor detectors; secret-like keys rejected | Unknown formats may pass the detectors |
| TM-16 | False assurance: "E2E passed" while UI steps did not run | Router-based executability; INCOMPLETE, never PASS; "HTTP-level only" label; manual replay kept separate | — |
| TM-17 | Load caused by many flows | Shared budget and rate limit; no loops or retries; step/flow limits; estimate in `plan` | — |
| TM-18 | Baking vulnerable or erroneous behaviour into expectations | Analyzer skips ≥500, security headers, cookies and values; "public?" decisions left to the owner; security checks independent of expectations | Owner may approve a wrong expectation |
| TM-19 | GET with side effects (logout, delete links) | Lint warning; analyzer skips such paths; skill requires owner confirmation | GET side effects are invisible to NavSentry |
| TM-20 | Self-approval by an agent | Hash-pinned approval; skill rule; drafts capped at SUSPECTED; drafts refused for production | Approval is a process control, not identity |
| TM-11 | Over-trusting scanner output in sources | SUSPECTED lifecycle, checksum validation, caveats, HPKP dismissal | Owner-specific exceptions must be recorded per project |
