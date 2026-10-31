# NavSentry Report — demo-after (local)

- Run ID: `18c3ac9b-f65d-454a-9457-82b4f6cb42a8`
- Started: 2026-10-31T06:06:20.338Z · Finished: 2026-10-31T06:06:21.459Z
- Tool: navsentry 0.1.0 · Node 26.13.0 · win32-x64
- Mode: `observe` · Origins: `http://127.0.0.1:4174`
- Execution status: **COMPLETE** · Security result: **FINDINGS**
- Requests: 15/100 · Denied before execution: 1

## Summary

| PASS | FAIL | INCONCLUSIVE | ERROR | NOT_TESTED | Findings |
|---|---|---|---|---|---|
| 15 | 1 | 0 | 0 | 34 | 5 |

> Zero findings does not mean the application is secure. NOT_TESTED, INCONCLUSIVE and ERROR rows are gaps, not passes.

## Findings

### NSC-CRYPT-006 — Cleartext HTTP served without redirect to HTTPS

- Fingerprint: `692d436b6be4d23f9a12f0bd` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4174/`
- OWASP: A04:2025 Cryptographic Failures; A02:2021 Cryptographic Failures
- CWE: CWE-319 · WSTG: WSTG-CRYP-03 · ASVS 5.0: V12 Secure Communication

**Expected:** http:// requests receive 301/308 to the https:// equivalent | No application content or Set-Cookie on http://

**Observed (redacted):**
- Plain HTTP serves content (HTTP 200) without HTTPS redirect
- no redirect

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CRYPT-006, transport direct-http)
- Type http://<host>/ in the browser: it switches to https://

**Recommendation:** Redirect all HTTP to HTTPS at the edge; for internal service ports, enable TLS or restrict them to the internal network.

**Regression guard:** Machine clients that POST to http:// may not follow redirects with a body (use 308 to preserve method) — inventory them first.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-crypt-006`

### NSC-CRYPT-006 — Cleartext HTTP served without redirect to HTTPS

- Fingerprint: `de541519ea628034bf10b279` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4174/api/profile`
- OWASP: A04:2025 Cryptographic Failures; A02:2021 Cryptographic Failures
- CWE: CWE-319 · WSTG: WSTG-CRYP-03 · ASVS 5.0: V12 Secure Communication

**Expected:** http:// requests receive 301/308 to the https:// equivalent | No application content or Set-Cookie on http://

**Observed (redacted):**
- Plain HTTP serves content (HTTP 200) without HTTPS redirect
- no redirect

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CRYPT-006, transport direct-http)
- Type http://<host>/ in the browser: it switches to https://

**Recommendation:** Redirect all HTTP to HTTPS at the edge; for internal service ports, enable TLS or restrict them to the internal network.

**Regression guard:** Machine clients that POST to http:// may not follow redirects with a body (use 308 to preserve method) — inventory them first.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-crypt-006`

### NSC-CRYPT-006 — Cleartext HTTP served without redirect to HTTPS

- Fingerprint: `fc727d7983201f01a45728e6` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4174/api/error`
- OWASP: A04:2025 Cryptographic Failures; A02:2021 Cryptographic Failures
- CWE: CWE-319 · WSTG: WSTG-CRYP-03 · ASVS 5.0: V12 Secure Communication

**Expected:** http:// requests receive 301/308 to the https:// equivalent | No application content or Set-Cookie on http://

**Observed (redacted):**
- Plain HTTP serves content (HTTP 500) without HTTPS redirect
- no redirect

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CRYPT-006, transport direct-http)
- Type http://<host>/ in the browser: it switches to https://

**Recommendation:** Redirect all HTTP to HTTPS at the edge; for internal service ports, enable TLS or restrict them to the internal network.

**Regression guard:** Machine clients that POST to http:// may not follow redirects with a body (use 308 to preserve method) — inventory them first.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-crypt-006`

### NSC-CRYPT-006 — Cleartext HTTP served without redirect to HTTPS

- Fingerprint: `218a567e36a7e353d513883d` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4174/api/token`
- OWASP: A04:2025 Cryptographic Failures; A02:2021 Cryptographic Failures
- CWE: CWE-319 · WSTG: WSTG-CRYP-03 · ASVS 5.0: V12 Secure Communication

**Expected:** http:// requests receive 301/308 to the https:// equivalent | No application content or Set-Cookie on http://

**Observed (redacted):**
- Plain HTTP serves content (HTTP 200) without HTTPS redirect
- no redirect

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CRYPT-006, transport direct-http)
- Type http://<host>/ in the browser: it switches to https://

**Recommendation:** Redirect all HTTP to HTTPS at the edge; for internal service ports, enable TLS or restrict them to the internal network.

**Regression guard:** Machine clients that POST to http:// may not follow redirects with a body (use 308 to preserve method) — inventory them first.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-crypt-006`

### NSC-CRYPT-006 — Cleartext HTTP served without redirect to HTTPS

- Fingerprint: `1ba566e5dfe0fcb2056cd0b3` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4174/go-out`
- OWASP: A04:2025 Cryptographic Failures; A02:2021 Cryptographic Failures
- CWE: CWE-319 · WSTG: WSTG-CRYP-03 · ASVS 5.0: V12 Secure Communication

**Expected:** http:// requests receive 301/308 to the https:// equivalent | No application content or Set-Cookie on http://

**Observed (redacted):**
- Plain HTTP serves content (HTTP 302) without HTTPS redirect
- Location scheme: http:

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CRYPT-006, transport direct-http)
- Type http://<host>/ in the browser: it switches to https://

**Recommendation:** Redirect all HTTP to HTTPS at the edge; for internal service ports, enable TLS or restrict them to the internal network.

**Regression guard:** Machine clients that POST to http:// may not follow redirects with a body (use 308 to preserve method) — inventory them first.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-crypt-006`

## Coverage matrix

| Case | Title | Status | Targets | Reason |
|---|---|---|---|---|
| NSC-CONF-001 | HSTS missing or weak | NOT_TESTED | 0 | plain HTTP target |
| NSC-CONF-002 | Content Security Policy missing or unsafe | PASS | 1 |  |
| NSC-CONF-003 | Clickjacking protection missing | PASS | 1 |  |
| NSC-CONF-004 | MIME sniffing not disabled / insecure Content-Type | PASS | 4 |  |
| NSC-CONF-005 | Debug mode / development features enabled | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-CONF-006 | Unnecessary HTTP methods or method override enabled | PASS | 5 |  |
| NSC-CONF-007 | Insecure cache policy for sensitive responses | PASS | 1 |  |
| NSC-CONF-008 | HTTP request smuggling / desync | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-INFO-001 | Server / framework version disclosure | PASS | 5 |  |
| NSC-INFO-003 | Internal IP address disclosure | PASS | 5 |  |
| NSC-INFO-004 | Email address disclosure | PASS | 5 |  |
| NSC-ERR-001 | Verbose error, stack trace or unhandled exception exposed | PASS | 5 |  |
| NSC-ERR-002 | Denial of service via expensive input parsing | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-PRIV-001 | National ID / personal identifier disclosure | PASS | 5 |  |
| NSC-PRIV-002 | Sensitive data in URL / GET query | PASS | 5 |  |
| NSC-SESS-001 | Cookie without Secure flag | NOT_TESTED | 0 | plain HTTP target |
| NSC-SESS-002 | Cookie without HttpOnly flag | PASS | 1 |  |
| NSC-SESS-003 | Cookie SameSite missing or contradictory | PASS | 1 |  |
| NSC-SESS-004 | JWT missing protection claims or weak algorithm | PASS | 1 |  |
| NSC-CRYPT-001 | Legacy TLS/SSL protocol versions enabled | NOT_TESTED | 0 | not exercised by this run's targets |
| NSC-CRYPT-002 | Weak TLS cipher suites or key exchange | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-CRYPT-003 | Insufficient certificate key size or weak signature | NOT_TESTED | 0 | not exercised by this run's targets |
| NSC-CRYPT-004 | Missing public key pinning (deprecated control) | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-CRYPT-005 | Hardcoded encryption key | NOT_TESTED | 0 | source-code finding; use a SAST tool / DevSift |
| NSC-CRYPT-006 | Cleartext HTTP served without redirect to HTTPS | FAIL | 5 |  |
| NSC-AC-001 | Authorization bypass through test/debug endpoint | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-AC-002 | Missing authentication on API endpoint | NOT_TESTED | 0 | deterministic check planned for M2 |
| NSC-AC-003 | IDOR / BOLA (cross-user object access) | NOT_TESTED | 0 | deterministic check planned for M2 |
| NSC-AC-004 | Permissive CORS policy | PASS | 5 |  |
| NSC-AC-005 | Server-side request forgery (SSRF) | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-AC-006 | Missing CSRF protection on state-changing requests | NOT_TESTED | 0 | deterministic check planned for M2 |
| NSC-AUTH-001 | Hardcoded API credentials | NOT_TESTED | 0 | source-code finding; use a SAST tool / DevSift |
| NSC-AUTH-002 | Session not invalidated after logout / stale session | NOT_TESTED | 0 | deterministic check planned for M2 |
| NSC-INJ-001 | SQL injection | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-INJ-002 | Server-side script / template / code injection | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-INJ-003 | LDAP injection | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-INJ-004 | Reflected / DOM cross-site scripting | NOT_TESTED | 0 | deterministic check planned for M2 |
| NSC-INJ-005 | HTTP header manipulation / CRLF injection / unvalidated header forwarding | NOT_TESTED | 0 | source-code finding; use a SAST tool / DevSift |
| NSC-INJ-006 | Local file inclusion / path traversal | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-SUPPLY-001 | Unpatched server component with known vulnerabilities | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-LOG-001 | Security logging and alerting gaps | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-BIZ-001 | Business logic flaw | NOT_TESTED | 0 | deterministic check planned for M2 |
| NSC-INFRA-001 | ICMP timestamp response enabled | NOT_TESTED | 0 | network/host VA item outside web scope |
| NSC-INFRA-002 | ICMP redirects accepted | NOT_TESTED | 0 | network/host VA item outside web scope |
| NSC-INFRA-003 | Unsafe default umask / home directory permissions | NOT_TESTED | 0 | network/host VA item outside web scope |
| NSC-INFRA-004 | Weak SSH MAC algorithms | NOT_TESTED | 0 | network/host VA item outside web scope |
| NSC-INFRA-005 | FTP credentials transmitted in cleartext | NOT_TESTED | 0 | network/host VA item outside web scope |
| NSC-INFRA-006 | Database ports reachable from untrusted networks | NOT_TESTED | 0 | network/host VA item outside web scope |
| NSC-INFRA-007 | OS package vulnerabilities / untrusted package repository | NOT_TESTED | 0 | network/host VA item outside web scope |
| NSC-INFO-005 | WAF / reverse proxy detected (informational) | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |

## Transports

| Transport | Available | Usable | Version | Reason |
|---|---|---|---|---|
| direct-http | true | true | 26.13.0 | built-in node:http/https |
| playwright-browser | false | false | — | optional package 'playwright' is not installed (NavSentry never installs it automatically) |
| curl-cli | true | false | curl 8.21.0 (Windows) libcurl/8.21.0 Schannel zlib/1.3.2 WinIDN WinLDAP | detected; request execution is scheduled for milestone M3 (argv builder implemented and tested) |
| powershell-http | true | false | 7.6.9 | detected; request execution is scheduled for milestone M3 (argv builder implemented and tested) |
| visual-computer-use | false | false | — | no visual provider configured; interface only (provider terms must be reviewed before integration) |
| zap-passive | false | false | — | phase-2 integration; not implemented |

## Incomplete / limitations

None

## Requests denied before execution

- GET `http://evil.example/steal` — redirect not followed: origin http://evil.example is not in targets.origins
