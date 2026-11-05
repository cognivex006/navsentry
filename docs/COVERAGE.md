# Coverage (v0.2.0)

| Automation class | Cases | Meaning in a run |
|---|---|---|
| auto | 26 | Deterministic check executes in `observe` mode |
| flow | 6 | Deterministic check that runs only where a flow declares it: access expectations with a positive control (NSC-AC-002, NSC-AC-003, NSC-AC-007) and, in safe-validate, CSRF (NSC-AC-006), session after logout (NSC-AUTH-002) and fixture invariants (NSC-BIZ-001); otherwise NOT_TESTED |
| planned-auto | 1 | NOT_TESTED — needs a future `active-approved` mode (NSC-INJ-004; marker reflections are recorded as observations) |
| assisted | 7 | NOT_TESTED — evidence needs an operator/agent (see prompts) |
| manual-active | 7 | NOT_TESTED — needs active payloads and separate authorization |
| sast-only | 3 | NOT_TESTED — source-code finding (SAST/DevSift) |
| infra | 7 | NOT_TESTED — host/network VA, outside web scope |
| **Total** | **57** | |

Automated (`auto`): NSC-CONF-001/002/003/004/006/007/009, NSC-INFO-001/003/004/006/007/008, NSC-ERR-001, NSC-PRIV-001/002, NSC-SESS-001/002/003/004, NSC-CRYPT-001/003/006, NSC-AC-004/008, NSC-SUPPLY-002. NSC-INFO-006 (console output) needs `--engine playwright`; with the http engine it is NOT_TESTED.

Per-OWASP-2025 coverage is generated in [ISSUE-CVE-MATRIX.md §7](ISSUE-CVE-MATRIX.md#7-owasp-top-102025-coverage).

Not covered yet (honest gaps): DOM-based XSS, injection of any kind, SSRF, file handling, rate-limiting behavior, and in-browser DOM checks (CSP violations, cookie visibility, framing). CSRF, session after logout, write access in IDOR and business invariants are covered only in safe-validate, where the owner declares fixtures (development profile). UI steps need `--engine playwright` (development); `fill`, `select` and `submit` run only in safe-validate. Cross-role access is covered only where flows declare it.
