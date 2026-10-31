# Coverage (v0.1.0)

| Automation class | Cases | Meaning in a run |
|---|---|---|
| auto | 20 | Deterministic check executes in `observe` mode |
| planned-auto | 6 | NOT_TESTED — scheduled (M2) |
| assisted | 7 | NOT_TESTED — evidence needs an operator/agent (see prompts) |
| manual-active | 7 | NOT_TESTED — needs active payloads and separate authorization |
| sast-only | 3 | NOT_TESTED — source-code finding (SAST/DevSift) |
| infra | 7 | NOT_TESTED — host/network VA, outside web scope |
| **Total** | **50** | |

Automated in v0.1: NSC-CONF-001/002/003/004/006/007, NSC-INFO-001/003/004, NSC-ERR-001, NSC-PRIV-001/002, NSC-SESS-001/002/003/004, NSC-CRYPT-001/003/006, NSC-AC-004.

Per-OWASP-2025 coverage is generated in [ISSUE-CVE-MATRIX.md §7](ISSUE-CVE-MATRIX.md#7-owasp-top-102025-coverage).

Not covered at all yet (honest gaps): DOM-based XSS, cross-role authorization, CSRF, session lifecycle, business logic, SSRF, file handling, rate-limiting behavior.
