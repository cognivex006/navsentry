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
| TM-11 | Over-trusting scanner output in sources | SUSPECTED lifecycle, checksum validation, caveats, HPKP dismissal | Owner-specific exceptions must be recorded per project |
