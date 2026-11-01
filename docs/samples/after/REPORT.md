# NavSentry Report — demo-after (local)

- Run ID: `841daba1-525d-487c-9413-a747e421e45b`
- Started: 2026-11-01T15:00:02.728Z · Finished: 2026-11-01T15:00:05.158Z
- Tool: navsentry 0.1.2 · Node 26.13.0 · win32-x64
- Mode: `observe` · Origins: `http://127.0.0.1:4174`
- Execution status: **COMPLETE** · Security result: **FINDINGS**
- Requests: 39/100 · Denied before execution: 4

## Summary

| PASS | FAIL | INCONCLUSIVE | ERROR | NOT_TESTED | Findings |
|---|---|---|---|---|---|
| 17 | 2 | 0 | 0 | 32 | 11 |

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

### NSC-CRYPT-006 — Cleartext HTTP served without redirect to HTTPS

- Fingerprint: `3585c95db6c6d12721e0affe` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4174/api/orders`
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

- Fingerprint: `74c1939329689193ff67afab` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4174/api/orders/{{orderA}}`
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

- Fingerprint: `fc8f24db6bc1fbad7593d749` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4174/api/me`
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

- Fingerprint: `91750bce609f47a4105f2edb` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4174/api/admin/stats`
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

- Fingerprint: `ef51e0debbf6974b84b21ba4` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4174/app/profile`
- OWASP: A04:2025 Cryptographic Failures; A02:2021 Cryptographic Failures
- CWE: CWE-319 · WSTG: WSTG-CRYP-03 · ASVS 5.0: V12 Secure Communication

**Expected:** http:// requests receive 301/308 to the https:// equivalent | No application content or Set-Cookie on http://

**Observed (redacted):**
- Plain HTTP serves content (HTTP 200) without HTTPS redirect
- no redirect
- Location scheme: http:

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CRYPT-006, transport direct-http)
- Type http://<host>/ in the browser: it switches to https://

**Recommendation:** Redirect all HTTP to HTTPS at the edge; for internal service ports, enable TLS or restrict them to the internal network.

**Regression guard:** Machine clients that POST to http:// may not follow redirects with a body (use 308 to preserve method) — inventory them first.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-crypt-006`

### NSC-CONF-007 — Insecure cache policy for sensitive responses

- Fingerprint: `c7f7bfc1c9a7ba376305d571` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4174/api/error`
- OWASP: A06:2025 Insecure Design; A02:2025 Security Misconfiguration; A04:2021 Insecure Design; A05:2021 Security Misconfiguration
- CWE: CWE-524, CWE-525 · WSTG: WSTG-ATHN-06 · ASVS 5.0: V14 Data Protection

**Expected:** Responses served to authenticated actors or setting session cookies send `Cache-Control: no-store` (or `private, no-cache` where justified) | Static public assets may stay cacheable

**Observed (redacted):**
- Sensitive response is cacheable
- Cache-Control absent

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-007, transport direct-http)
- DevTools > Network: authenticated API responses show no-store

**Recommendation:** Add no-store on authenticated/sensitive routes (middleware by route group); keep long caching only for fingerprinted static assets.

**Regression guard:** Do not apply no-store to static assets (performance regression). Scope the header by route. Verify with `navsentry compare` and page-load timing.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-007`

## Coverage matrix

| Case | Title | Status | Targets | Reason |
|---|---|---|---|---|
| NSC-CONF-001 | HSTS missing or weak | NOT_TESTED | 0 | plain HTTP target |
| NSC-CONF-002 | Content Security Policy missing or unsafe | PASS | 5 |  |
| NSC-CONF-003 | Clickjacking protection missing | PASS | 5 |  |
| NSC-CONF-004 | MIME sniffing not disabled / insecure Content-Type | PASS | 24 |  |
| NSC-CONF-005 | Debug mode / development features enabled | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-CONF-006 | Unnecessary HTTP methods or method override enabled | PASS | 5 |  |
| NSC-CONF-007 | Insecure cache policy for sensitive responses | FAIL | 20 |  |
| NSC-CONF-008 | HTTP request smuggling / desync | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-INFO-001 | Server / framework version disclosure | PASS | 29 |  |
| NSC-INFO-003 | Internal IP address disclosure | PASS | 29 |  |
| NSC-INFO-004 | Email address disclosure | PASS | 29 |  |
| NSC-ERR-001 | Verbose error, stack trace or unhandled exception exposed | PASS | 29 |  |
| NSC-ERR-002 | Denial of service via expensive input parsing | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-PRIV-001 | National ID / personal identifier disclosure | PASS | 29 |  |
| NSC-PRIV-002 | Sensitive data in URL / GET query | PASS | 29 |  |
| NSC-SESS-001 | Cookie without Secure flag | NOT_TESTED | 0 | plain HTTP target |
| NSC-SESS-002 | Cookie without HttpOnly flag | PASS | 4 |  |
| NSC-SESS-003 | Cookie SameSite missing or contradictory | PASS | 4 |  |
| NSC-SESS-004 | JWT missing protection claims or weak algorithm | PASS | 4 |  |
| NSC-CRYPT-001 | Legacy TLS/SSL protocol versions enabled | NOT_TESTED | 0 | not exercised by this run's targets |
| NSC-CRYPT-002 | Weak TLS cipher suites or key exchange | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-CRYPT-003 | Insufficient certificate key size or weak signature | NOT_TESTED | 0 | not exercised by this run's targets |
| NSC-CRYPT-004 | Missing public key pinning (deprecated control) | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-CRYPT-005 | Hardcoded encryption key | NOT_TESTED | 0 | source-code finding; use a SAST tool / DevSift |
| NSC-CRYPT-006 | Cleartext HTTP served without redirect to HTTPS | FAIL | 29 |  |
| NSC-AC-001 | Authorization bypass through test/debug endpoint | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-AC-002 | Missing authentication on API endpoint | PASS | 2 |  |
| NSC-AC-003 | IDOR / BOLA (cross-user object access) | PASS | 1 |  |
| NSC-AC-007 | Missing function-level authorization (vertical privilege escalation) | PASS | 1 |  |
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
| curl-cli | true | false | curl 8.22.0 (Windows) libcurl/8.22.0 Schannel zlib/1.3.2 WinIDN WinLDAP | detected; request execution is scheduled for milestone M3 (argv builder implemented and tested) |
| powershell-http | true | false | 7.6.9 | detected; request execution is scheduled for milestone M3 (argv builder implemented and tested) |
| visual-computer-use | false | false | — | no visual provider configured; interface only (provider terms must be reviewed before integration) |
| zap-passive | false | false | — | phase-2 integration; not implemented |

## Incomplete / limitations

None

## Requests denied before execution

- GET `http://evil.example/steal` — redirect not followed: origin http://evil.example is not in targets.origins
- GET `http://evil.example/steal` — redirect not followed: origin http://evil.example is not in targets.origins
- GET `http://evil.example/steal` — redirect not followed: origin http://evil.example is not in targets.origins
- GET `http://evil.example/steal` — redirect not followed: origin http://evil.example is not in targets.origins

## Flows

- 2 flows / 11 steps · Functional result: **INCOMPLETE**
- URLs covered beyond seed paths: 5
- Findings raised by flow requests: 5
- Details: [TEST-REPORT.md](TEST-REPORT.md)
