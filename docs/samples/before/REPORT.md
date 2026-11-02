# NavSentry Report — demo-before (local)

- Run ID: `07cab76a-5f94-418d-b373-720b3ca0c67f`
- Started: 2026-11-01T15:00:00.125Z · Finished: 2026-11-01T15:00:02.727Z
- Tool: navsentry 0.1.2 · Node 26.13.0 · win32-x64
- Mode: `observe` · Origins: `http://127.0.0.1:4173`
- Execution status: **COMPLETE** · Security result: **FINDINGS**
- Requests: 39/100 · Denied before execution: 4

## Summary

| PASS | FAIL | INCONCLUSIVE | ERROR | NOT_TESTED | Findings |
|---|---|---|---|---|---|
| 1 | 18 | 0 | 0 | 32 | 58 |

> Zero findings does not mean the application is secure. NOT_TESTED, INCONCLUSIVE and ERROR rows are gaps, not passes.

## Findings

### NSC-AC-002 — Missing authentication on API endpoint

- Fingerprint: `2ed31545305ed6fa20e0a163` · Severity: **high** · Confidence: medium · Lifecycle: **SUSPECTED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/api/me`
- OWASP: A01:2025 Broken Access Control; A07:2025 Authentication Failures; A01:2021 Broken Access Control; A07:2021 Identification and Authentication Failures
- CWE: CWE-306 · WSTG: WSTG-ATHZ-02 · ASVS 5.0: V8 Authorization, V4 API and Web Service

**Expected:** Anonymous requests to protected endpoints return 401 | Authenticated legitimate actor still gets the same 2xx contract

**Observed (redacted):**
- Missing authentication on API endpoint: access was granted
- actor anonymous received 200 application/json with the same response contract as positive control S4 (reader_a)
- flow orders-access step S5

**Reproduce:**
- navsentry test --config <manifest> --flows <flows-dir>  (rule NSC-AC-002, flow orders-access step S5)
- Open the endpoint in a private browser window: 401/redirect to login

**Recommendation:** Apply authentication middleware with deny-by-default to the whole API group; whitelist truly public routes explicitly.

**Regression guard:** Public endpoints used before login (health, login config, static config) must be explicitly allow-listed; compare anonymous and authenticated runs before/after.

**Limitations:**
- Evaluated only where a flow declares anonymous `access: denied` with an authenticated positive control; a 2xx with a different contract (login page) is INCONCLUSIVE, not FAIL.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-ac-002`

### NSC-AC-002 — Missing authentication on API endpoint

- Fingerprint: `fee0a4fff083aa2abb24c113` · Severity: **high** · Confidence: medium · Lifecycle: **SUSPECTED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/app/profile`
- OWASP: A01:2025 Broken Access Control; A07:2025 Authentication Failures; A01:2021 Broken Access Control; A07:2021 Identification and Authentication Failures
- CWE: CWE-306 · WSTG: WSTG-ATHZ-02 · ASVS 5.0: V8 Authorization, V4 API and Web Service

**Expected:** Anonymous requests to protected endpoints return 401 | Authenticated legitimate actor still gets the same 2xx contract

**Observed (redacted):**
- Missing authentication on API endpoint: access was granted
- actor anonymous received 200 text/html with the same response contract as positive control S1 (reader_a)
- flow profile-journey step S4

**Reproduce:**
- navsentry test --config <manifest> --flows <flows-dir>  (rule NSC-AC-002, flow profile-journey step S4)
- Open the endpoint in a private browser window: 401/redirect to login

**Recommendation:** Apply authentication middleware with deny-by-default to the whole API group; whitelist truly public routes explicitly.

**Regression guard:** Public endpoints used before login (health, login config, static config) must be explicitly allow-listed; compare anonymous and authenticated runs before/after.

**Limitations:**
- Evaluated only where a flow declares anonymous `access: denied` with an authenticated positive control; a 2xx with a different contract (login page) is INCONCLUSIVE, not FAIL.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-ac-002`

### NSC-AC-003 — IDOR / BOLA (cross-user object access)

- Fingerprint: `3eef519c1454dd179dcdf801` · Severity: **high** · Confidence: medium · Lifecycle: **SUSPECTED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/api/orders/{{orderA}}`
- OWASP: A01:2025 Broken Access Control; A01:2021 Broken Access Control
- CWE: CWE-639, CWE-284 · WSTG: WSTG-ATHZ-04 · ASVS 5.0: V8 Authorization

**Expected:** Actor B receives 403/404 for actor A's fixture object | Actor A still receives 200 for its own object (positive control)

**Observed (redacted):**
- IDOR / BOLA (cross-user object access): access was granted
- actor reader_b received 200 application/json with the same response contract as positive control S2 (reader_a)
- flow orders-access step S3

**Reproduce:**
- navsentry test --config <manifest> --flows <flows-dir>  (rule NSC-AC-003, flow orders-access step S3)
- As actor B in a separate browser profile, paste actor A's object URL: access denied

**Recommendation:** Enforce ownership/tenant checks in the service layer for every object lookup; prefer scoped queries (WHERE owner_id = current_user).

**Regression guard:** Shared/delegated objects (team, admin, delegated approver) must keep access — encode those rules explicitly and test them as positive controls.

**Limitations:**
- UI hiding alone NEVER proves authorization.
- 0.1.2 verifies read access only (flow step with object_owner and access: denied); modification needs safe-validate (M2).

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-ac-003`

### NSC-AC-007 — Missing function-level authorization (vertical privilege escalation)

- Fingerprint: `4394e9188345a42229ec9d40` · Severity: **high** · Confidence: medium · Lifecycle: **SUSPECTED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/api/admin/stats`
- OWASP: A01:2025 Broken Access Control; A01:2021 Broken Access Control
- CWE: CWE-285, CWE-862 · WSTG: WSTG-ATHZ-03 · ASVS 5.0: V8 Authorization

**Expected:** Lower role receives 401/403 | Privileged role keeps its 2xx contract (positive control)

**Observed (redacted):**
- Missing function-level authorization (vertical privilege escalation): access was granted
- actor reader_a received 200 application/json with the same response contract as positive control S6 (admin)
- flow orders-access step S7

**Reproduce:**
- navsentry test --config <manifest> --flows <flows-dir>  (rule NSC-AC-007, flow orders-access step S7)
- As the lower-role user in a separate browser profile, open the privileged URL: access denied

**Recommendation:** Enforce deny-by-default role/permission checks on the server for every privileged route or handler; do not rely on hidden menus.

**Regression guard:** Delegated or support roles that legitimately use the function must be encoded as positive controls before tightening.

**Limitations:**
- Hidden menus or disabled buttons never prove authorization.
- Evaluated only where a flow declares access: denied for the lower role with a privileged positive control.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-ac-007`

### NSC-PRIV-001 — National ID / personal identifier disclosure

- Fingerprint: `f41e08127666743eabc5170c` · Severity: **high** · Confidence: medium · Lifecycle: **SUSPECTED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/api/profile`
- OWASP: A01:2025 Broken Access Control; A04:2025 Cryptographic Failures; A01:2021 Broken Access Control; A02:2021 Cryptographic Failures
- CWE: CWE-359, CWE-200 · WSTG: WSTG-INFO-05 · ASVS 5.0: V14 Data Protection, V8 Authorization

**Expected:** No checksum-valid national ID / card number appears in responses to actors not entitled to it | Where required for the owner, values are masked (e.g. x-xxxx-xxxxx-12-3)

**Observed (redacted):**
- Checksum-valid personal identifiers in response
- thai-national-id (mod-11 valid): 1
- card-number (Luhn valid): 0
- values never stored

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-PRIV-001, transport direct-http)
- Open the endpoint as an unentitled actor and confirm the field is absent or masked

**Recommendation:** Remove or mask the field in the response DTO for unentitled callers; enforce field-level authorization server-side.

**Regression guard:** Masking changes values, not keys: keep the field name and type so clients do not break, unless the owner approves removal. Verify JSON shape with `navsentry compare`.

**Limitations:**
- SRC-E accepted this as an Exception because the 13-digit value was an internal function identifier, not a citizen ID. NavSentry applies the mod-11 checksum to cut such false positives, but a checksum-valid match is still SUSPECTED until a human confirms the field semantics.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-priv-001`

### NSC-AC-004 — Permissive CORS policy

- Fingerprint: `1165ff5cd1b67e24ef43e674` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **CAUTION** — Fix with caution (may affect legitimate users)
- Target: `GET http://127.0.0.1:4173/`
- OWASP: A01:2025 Broken Access Control; A02:2025 Security Misconfiguration; A01:2021 Broken Access Control; A05:2021 Security Misconfiguration
- CWE: CWE-942, CWE-346 · WSTG: WSTG-CLNT-07 · ASVS 5.0: V3 Web Frontend Security, V4 API and Web Service

**Expected:** Untrusted test origins are not reflected | Credentials are never allowed with wildcard or reflected origins | Allowed origins are an explicit allowlist

**Observed (redacted):**
- Untrusted Origin reflected WITH credentials
- ACAO reflects probe origin
- credentials=true

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-AC-004, transport direct-http)
- From the legitimate front-end origin the app still works (no CORS errors in Console)

**Recommendation:** Replace origin reflection with an exact-match allowlist; never combine credentials with '*' or 'null'.

**Regression guard:** List every legitimate front-end origin (prod, staging, mobile webviews) before tightening; missing one causes CORS errors only in browsers.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-ac-004`

### NSC-AC-004 — Permissive CORS policy

- Fingerprint: `a85dcc5898250cee68ce9f5c` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **CAUTION** — Fix with caution (may affect legitimate users)
- Target: `GET http://127.0.0.1:4173/api/profile`
- OWASP: A01:2025 Broken Access Control; A02:2025 Security Misconfiguration; A01:2021 Broken Access Control; A05:2021 Security Misconfiguration
- CWE: CWE-942, CWE-346 · WSTG: WSTG-CLNT-07 · ASVS 5.0: V3 Web Frontend Security, V4 API and Web Service

**Expected:** Untrusted test origins are not reflected | Credentials are never allowed with wildcard or reflected origins | Allowed origins are an explicit allowlist

**Observed (redacted):**
- Untrusted Origin reflected WITH credentials
- ACAO reflects probe origin
- credentials=true

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-AC-004, transport direct-http)
- From the legitimate front-end origin the app still works (no CORS errors in Console)

**Recommendation:** Replace origin reflection with an exact-match allowlist; never combine credentials with '*' or 'null'.

**Regression guard:** List every legitimate front-end origin (prod, staging, mobile webviews) before tightening; missing one causes CORS errors only in browsers.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-ac-004`

### NSC-AC-004 — Permissive CORS policy

- Fingerprint: `3c425a79d30a4412cf0aef98` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **CAUTION** — Fix with caution (may affect legitimate users)
- Target: `GET http://127.0.0.1:4173/api/error`
- OWASP: A01:2025 Broken Access Control; A02:2025 Security Misconfiguration; A01:2021 Broken Access Control; A05:2021 Security Misconfiguration
- CWE: CWE-942, CWE-346 · WSTG: WSTG-CLNT-07 · ASVS 5.0: V3 Web Frontend Security, V4 API and Web Service

**Expected:** Untrusted test origins are not reflected | Credentials are never allowed with wildcard or reflected origins | Allowed origins are an explicit allowlist

**Observed (redacted):**
- Untrusted Origin reflected WITH credentials
- ACAO reflects probe origin
- credentials=true

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-AC-004, transport direct-http)
- From the legitimate front-end origin the app still works (no CORS errors in Console)

**Recommendation:** Replace origin reflection with an exact-match allowlist; never combine credentials with '*' or 'null'.

**Regression guard:** List every legitimate front-end origin (prod, staging, mobile webviews) before tightening; missing one causes CORS errors only in browsers.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-ac-004`

### NSC-AC-004 — Permissive CORS policy

- Fingerprint: `bdbf0331bd0333d584e46a9f` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **CAUTION** — Fix with caution (may affect legitimate users)
- Target: `GET http://127.0.0.1:4173/api/token`
- OWASP: A01:2025 Broken Access Control; A02:2025 Security Misconfiguration; A01:2021 Broken Access Control; A05:2021 Security Misconfiguration
- CWE: CWE-942, CWE-346 · WSTG: WSTG-CLNT-07 · ASVS 5.0: V3 Web Frontend Security, V4 API and Web Service

**Expected:** Untrusted test origins are not reflected | Credentials are never allowed with wildcard or reflected origins | Allowed origins are an explicit allowlist

**Observed (redacted):**
- Untrusted Origin reflected WITH credentials
- ACAO reflects probe origin
- credentials=true

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-AC-004, transport direct-http)
- From the legitimate front-end origin the app still works (no CORS errors in Console)

**Recommendation:** Replace origin reflection with an exact-match allowlist; never combine credentials with '*' or 'null'.

**Regression guard:** List every legitimate front-end origin (prod, staging, mobile webviews) before tightening; missing one causes CORS errors only in browsers.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-ac-004`

### NSC-AC-004 — Permissive CORS policy

- Fingerprint: `8cc7d85071e0e64554baa4e1` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **CAUTION** — Fix with caution (may affect legitimate users)
- Target: `GET http://127.0.0.1:4173/go-out`
- OWASP: A01:2025 Broken Access Control; A02:2025 Security Misconfiguration; A01:2021 Broken Access Control; A05:2021 Security Misconfiguration
- CWE: CWE-942, CWE-346 · WSTG: WSTG-CLNT-07 · ASVS 5.0: V3 Web Frontend Security, V4 API and Web Service

**Expected:** Untrusted test origins are not reflected | Credentials are never allowed with wildcard or reflected origins | Allowed origins are an explicit allowlist

**Observed (redacted):**
- Untrusted Origin reflected WITH credentials
- ACAO reflects probe origin
- credentials=true

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-AC-004, transport direct-http)
- From the legitimate front-end origin the app still works (no CORS errors in Console)

**Recommendation:** Replace origin reflection with an exact-match allowlist; never combine credentials with '*' or 'null'.

**Regression guard:** List every legitimate front-end origin (prod, staging, mobile webviews) before tightening; missing one causes CORS errors only in browsers.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-ac-004`

### NSC-CONF-002 — Content Security Policy missing or unsafe

- Fingerprint: `22fb68e2405cb97eec3d9987` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **CAUTION** — Fix with caution (may affect legitimate users)
- Target: `GET http://127.0.0.1:4173/`
- OWASP: A02:2025 Security Misconfiguration; A05:2025 Injection; A05:2021 Security Misconfiguration; A03:2021 Injection
- CWE: CWE-693, CWE-1021 · WSTG: WSTG-CONF-12 · ASVS 5.0: V3 Web Frontend Security

**Expected:** Every HTML response has an enforcing Content-Security-Policy | script-src (or default-src) contains no 'unsafe-inline' without nonce/hash, no 'unsafe-eval', no '*' | object-src 'none' and base-uri restricted

**Observed (redacted):**
- Content-Security-Policy header missing
- header absent

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-002, transport direct-http)
- Load each main page with DevTools Console open: no CSP violation errors for legitimate functionality

**Recommendation:** Deploy Content-Security-Policy-Report-Only first, collect violations from real traffic, refactor inline scripts to nonces/hashes, then switch to the enforcing header.

**Regression guard:** An enforcing CSP that is too strict silently breaks scripts, maps, analytics and third-party widgets. Always ship Report-Only first and test every critical page in a real browser. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-002`

### NSC-CONF-002 — Content Security Policy missing or unsafe

- Fingerprint: `86733b9437764e1560fc2e38` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **CAUTION** — Fix with caution (may affect legitimate users)
- Target: `GET http://127.0.0.1:4173/app/profile`
- OWASP: A02:2025 Security Misconfiguration; A05:2025 Injection; A05:2021 Security Misconfiguration; A03:2021 Injection
- CWE: CWE-693, CWE-1021 · WSTG: WSTG-CONF-12 · ASVS 5.0: V3 Web Frontend Security

**Expected:** Every HTML response has an enforcing Content-Security-Policy | script-src (or default-src) contains no 'unsafe-inline' without nonce/hash, no 'unsafe-eval', no '*' | object-src 'none' and base-uri restricted

**Observed (redacted):**
- Content-Security-Policy header missing
- header absent

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-002, transport direct-http)
- Load each main page with DevTools Console open: no CSP violation errors for legitimate functionality

**Recommendation:** Deploy Content-Security-Policy-Report-Only first, collect violations from real traffic, refactor inline scripts to nonces/hashes, then switch to the enforcing header.

**Regression guard:** An enforcing CSP that is too strict silently breaks scripts, maps, analytics and third-party widgets. Always ship Report-Only first and test every critical page in a real browser. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-002`

### NSC-CRYPT-006 — Cleartext HTTP served without redirect to HTTPS

- Fingerprint: `32ef940ba82b43d1703edd81` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/`
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

- Fingerprint: `60cd89eec0834c6173a1ca52` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/api/profile`
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

- Fingerprint: `ffd914e5cdf3c67a36d0007d` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/api/error`
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

- Fingerprint: `54c1aea904006f550b35a853` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/api/token`
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

- Fingerprint: `05f978ecba4b2322dfa90ab1` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/go-out`
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

- Fingerprint: `fee4e2b13b1a34242abf2210` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/api/orders`
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

- Fingerprint: `2f0c13798b3f6290b328e559` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/api/orders/{{orderA}}`
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

- Fingerprint: `7c6bc49d2e83bb56b8b62a1f` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/api/me`
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

- Fingerprint: `410d1fcc3d4bf29a8b41f77d` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/api/admin/stats`
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

- Fingerprint: `0e1ff75fa30e8a236884445c` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/app/profile`
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

### NSC-ERR-001 — Verbose error, stack trace or unhandled exception exposed

- Fingerprint: `678b4c40706a4b10d28bed40` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **IMMEDIATE** — Fix immediately
- Target: `GET http://127.0.0.1:4173/api/error`
- OWASP: A10:2025 Mishandling of Exceptional Conditions; A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration; A04:2021 Insecure Design
- CWE: CWE-209, CWE-248, CWE-550 · WSTG: WSTG-ERRH-01, WSTG-ERRH-02 · ASVS 5.0: V16 Security Logging and Error Handling

**Expected:** No in-scope response contains stack-trace/exception signatures | Errors return a generic message plus a correlation ID; details go to server logs only | HTTP status codes stay meaningful (4xx for client errors, 5xx for server faults)

**Observed (redacted):**
- Internal error details exposed (HTTP 500)
- Exception class name

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-ERR-001, transport direct-http)
- Reproduce the original error condition with a benign request (e.g. missing parameter) and confirm a generic error body

**Recommendation:** Add a global exception handler that logs details server-side and returns a standard error envelope (e.g. RFC 9457 problem+json) without internals; disable framework detailed errors in non-dev environments.

**Regression guard:** Keep the SAME status code and the SAME error envelope fields that clients parse (e.g. `success`, `code`, `message`); only remove internal details. Prove it with `navsentry compare` (status + JSON shape must match).

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-err-001`

### NSC-SESS-004 — JWT missing protection claims or weak algorithm

- Fingerprint: `f5515664499e6e3369c2e269` · Severity: **medium** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/token`
- OWASP: A07:2025 Authentication Failures; A04:2025 Cryptographic Failures; A07:2021 Identification and Authentication Failures; A02:2021 Cryptographic Failures
- CWE: CWE-347, CWE-613 · WSTG: WSTG-SESS-10 · ASVS 5.0: V9 Self-contained Tokens

**Expected:** alg is not 'none' | exp present and lifetime appropriate (e.g. <= 1h for access tokens) | aud and iss present and validated server-side

**Observed (redacted):**
- JWT missing protection claims or weak alg
- token#1: alg=none
- token#1: exp claim missing
- token#1: iss claim missing
- token#1: aud claim missing

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-SESS-004, transport direct-http)
- Log in, copy the token from DevTools > Network/Storage into a local decoder (offline), check claims

**Recommendation:** Issue tokens with exp/iat/aud/iss; validate them on every API; reject alg none and unexpected algorithms.

**Regression guard:** Adding aud/exp validation rejects old long-lived tokens: plan a token refresh window and communicate client changes.

**Limitations:**
- NavSentry decodes but never verifies or forges tokens.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-sess-004`

### NSC-CONF-003 — Clickjacking protection missing

- Fingerprint: `e8e83ba35b2ee4153cc31db5` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **CAUTION** — Fix with caution (may affect legitimate users)
- Target: `GET http://127.0.0.1:4173/`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-1021 · WSTG: WSTG-CLNT-09 · ASVS 5.0: V3 Web Frontend Security

**Expected:** HTML responses send CSP frame-ancestors 'self' (or an explicit allowlist) and/or X-Frame-Options DENY|SAMEORIGIN

**Observed (redacted):**
- No frame-ancestors or valid X-Frame-Options
- frame-ancestors absent
- X-Frame-Options absent

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-003, transport direct-http)
- From a different local origin, embed the page in an <iframe>: the browser refuses to render it

**Recommendation:** Send `Content-Security-Policy: frame-ancestors 'self' <approved-parents>` plus `X-Frame-Options: SAMEORIGIN` for legacy browsers.

**Regression guard:** Inventory legitimate embedding (portals, SSO, map widgets) before choosing DENY. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-003`

### NSC-CONF-003 — Clickjacking protection missing

- Fingerprint: `537cf1850c28c8f706b2ddec` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **CAUTION** — Fix with caution (may affect legitimate users)
- Target: `GET http://127.0.0.1:4173/app/profile`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-1021 · WSTG: WSTG-CLNT-09 · ASVS 5.0: V3 Web Frontend Security

**Expected:** HTML responses send CSP frame-ancestors 'self' (or an explicit allowlist) and/or X-Frame-Options DENY|SAMEORIGIN

**Observed (redacted):**
- No frame-ancestors or valid X-Frame-Options
- frame-ancestors absent
- X-Frame-Options absent

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-003, transport direct-http)
- From a different local origin, embed the page in an <iframe>: the browser refuses to render it

**Recommendation:** Send `Content-Security-Policy: frame-ancestors 'self' <approved-parents>` plus `X-Frame-Options: SAMEORIGIN` for legacy browsers.

**Regression guard:** Inventory legitimate embedding (portals, SSO, map widgets) before choosing DENY. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-003`

### NSC-CONF-004 — MIME sniffing not disabled / insecure Content-Type

- Fingerprint: `524856164cab65da7f0ca455` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-16, CWE-430 · WSTG: WSTG-CONF-12 · ASVS 5.0: V3 Web Frontend Security, V4 API and Web Service

**Expected:** Every response with a body has an explicit Content-Type | X-Content-Type-Options: nosniff on every response | text/html responses declare a charset

**Observed (redacted):**
- text response without charset; X-Content-Type-Options: nosniff missing
- text response without charset
- X-Content-Type-Options: nosniff missing

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-004, transport direct-http)
- DevTools > Network: each document, script and JSON response shows Content-Type and nosniff

**Recommendation:** Add `X-Content-Type-Options: nosniff` globally and make every handler set an accurate Content-Type (with charset for text).

**Regression guard:** nosniff blocks scripts/styles served with a wrong type: fix wrong Content-Type on static files first. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-004`

### NSC-CONF-004 — MIME sniffing not disabled / insecure Content-Type

- Fingerprint: `aef9e8a5b6b1e659dadc2fa1` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/profile`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-16, CWE-430 · WSTG: WSTG-CONF-12 · ASVS 5.0: V3 Web Frontend Security, V4 API and Web Service

**Expected:** Every response with a body has an explicit Content-Type | X-Content-Type-Options: nosniff on every response | text/html responses declare a charset

**Observed (redacted):**
- X-Content-Type-Options: nosniff missing

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-004, transport direct-http)
- DevTools > Network: each document, script and JSON response shows Content-Type and nosniff

**Recommendation:** Add `X-Content-Type-Options: nosniff` globally and make every handler set an accurate Content-Type (with charset for text).

**Regression guard:** nosniff blocks scripts/styles served with a wrong type: fix wrong Content-Type on static files first. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-004`

### NSC-CONF-004 — MIME sniffing not disabled / insecure Content-Type

- Fingerprint: `a2f6a8f688dc2ea498a0a7a9` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/error`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-16, CWE-430 · WSTG: WSTG-CONF-12 · ASVS 5.0: V3 Web Frontend Security, V4 API and Web Service

**Expected:** Every response with a body has an explicit Content-Type | X-Content-Type-Options: nosniff on every response | text/html responses declare a charset

**Observed (redacted):**
- X-Content-Type-Options: nosniff missing

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-004, transport direct-http)
- DevTools > Network: each document, script and JSON response shows Content-Type and nosniff

**Recommendation:** Add `X-Content-Type-Options: nosniff` globally and make every handler set an accurate Content-Type (with charset for text).

**Regression guard:** nosniff blocks scripts/styles served with a wrong type: fix wrong Content-Type on static files first. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-004`

### NSC-CONF-004 — MIME sniffing not disabled / insecure Content-Type

- Fingerprint: `81e4f06fbc3ebd6e19ad70a2` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/token`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-16, CWE-430 · WSTG: WSTG-CONF-12 · ASVS 5.0: V3 Web Frontend Security, V4 API and Web Service

**Expected:** Every response with a body has an explicit Content-Type | X-Content-Type-Options: nosniff on every response | text/html responses declare a charset

**Observed (redacted):**
- X-Content-Type-Options: nosniff missing

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-004, transport direct-http)
- DevTools > Network: each document, script and JSON response shows Content-Type and nosniff

**Recommendation:** Add `X-Content-Type-Options: nosniff` globally and make every handler set an accurate Content-Type (with charset for text).

**Regression guard:** nosniff blocks scripts/styles served with a wrong type: fix wrong Content-Type on static files first. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-004`

### NSC-CONF-004 — MIME sniffing not disabled / insecure Content-Type

- Fingerprint: `8abac78f653ee5b014e2f490` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/orders`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-16, CWE-430 · WSTG: WSTG-CONF-12 · ASVS 5.0: V3 Web Frontend Security, V4 API and Web Service

**Expected:** Every response with a body has an explicit Content-Type | X-Content-Type-Options: nosniff on every response | text/html responses declare a charset

**Observed (redacted):**
- X-Content-Type-Options: nosniff missing
- X-Content-Type-Options: nosniff missing

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-004, transport direct-http)
- DevTools > Network: each document, script and JSON response shows Content-Type and nosniff

**Recommendation:** Add `X-Content-Type-Options: nosniff` globally and make every handler set an accurate Content-Type (with charset for text).

**Regression guard:** nosniff blocks scripts/styles served with a wrong type: fix wrong Content-Type on static files first. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-004`

### NSC-CONF-004 — MIME sniffing not disabled / insecure Content-Type

- Fingerprint: `887c9e474229a3f22403e9f7` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/orders/{{orderA}}`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-16, CWE-430 · WSTG: WSTG-CONF-12 · ASVS 5.0: V3 Web Frontend Security, V4 API and Web Service

**Expected:** Every response with a body has an explicit Content-Type | X-Content-Type-Options: nosniff on every response | text/html responses declare a charset

**Observed (redacted):**
- X-Content-Type-Options: nosniff missing

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-004, transport direct-http)
- DevTools > Network: each document, script and JSON response shows Content-Type and nosniff

**Recommendation:** Add `X-Content-Type-Options: nosniff` globally and make every handler set an accurate Content-Type (with charset for text).

**Regression guard:** nosniff blocks scripts/styles served with a wrong type: fix wrong Content-Type on static files first. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-004`

### NSC-CONF-004 — MIME sniffing not disabled / insecure Content-Type

- Fingerprint: `6b1e8104436e4050b9e69aea` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/me`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-16, CWE-430 · WSTG: WSTG-CONF-12 · ASVS 5.0: V3 Web Frontend Security, V4 API and Web Service

**Expected:** Every response with a body has an explicit Content-Type | X-Content-Type-Options: nosniff on every response | text/html responses declare a charset

**Observed (redacted):**
- X-Content-Type-Options: nosniff missing

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-004, transport direct-http)
- DevTools > Network: each document, script and JSON response shows Content-Type and nosniff

**Recommendation:** Add `X-Content-Type-Options: nosniff` globally and make every handler set an accurate Content-Type (with charset for text).

**Regression guard:** nosniff blocks scripts/styles served with a wrong type: fix wrong Content-Type on static files first. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-004`

### NSC-CONF-004 — MIME sniffing not disabled / insecure Content-Type

- Fingerprint: `b8fb462c3914484b16461887` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/admin/stats`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-16, CWE-430 · WSTG: WSTG-CONF-12 · ASVS 5.0: V3 Web Frontend Security, V4 API and Web Service

**Expected:** Every response with a body has an explicit Content-Type | X-Content-Type-Options: nosniff on every response | text/html responses declare a charset

**Observed (redacted):**
- X-Content-Type-Options: nosniff missing

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-004, transport direct-http)
- DevTools > Network: each document, script and JSON response shows Content-Type and nosniff

**Recommendation:** Add `X-Content-Type-Options: nosniff` globally and make every handler set an accurate Content-Type (with charset for text).

**Regression guard:** nosniff blocks scripts/styles served with a wrong type: fix wrong Content-Type on static files first. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-004`

### NSC-CONF-004 — MIME sniffing not disabled / insecure Content-Type

- Fingerprint: `61ef9ac144885a9aee7c1d64` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/app/profile`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-16, CWE-430 · WSTG: WSTG-CONF-12 · ASVS 5.0: V3 Web Frontend Security, V4 API and Web Service

**Expected:** Every response with a body has an explicit Content-Type | X-Content-Type-Options: nosniff on every response | text/html responses declare a charset

**Observed (redacted):**
- X-Content-Type-Options: nosniff missing

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-004, transport direct-http)
- DevTools > Network: each document, script and JSON response shows Content-Type and nosniff

**Recommendation:** Add `X-Content-Type-Options: nosniff` globally and make every handler set an accurate Content-Type (with charset for text).

**Regression guard:** nosniff blocks scripts/styles served with a wrong type: fix wrong Content-Type on static files first. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-004`

### NSC-CONF-006 — Unnecessary HTTP methods or method override enabled

- Fingerprint: `2c67c0722e7817b6d2c8bf9d` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `OPTIONS http://127.0.0.1:4173/`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-650, CWE-16 · WSTG: WSTG-CONF-06 · ASVS 5.0: V13 Configuration, V4 API and Web Service

**Expected:** OPTIONS on in-scope resources does not advertise TRACE/TRACK/CONNECT | Only methods actually used by the resource are advertised | Method-override headers are ignored (verified manually under safe-validate)

**Observed (redacted):**
- Dangerous methods advertised: TRACE
- advertised: GET, POST, OPTIONS, TRACE

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-006, transport direct-http)
- Send OPTIONS to the resource (NavSentry or curl -X OPTIONS -i) and inspect Allow

**Recommendation:** Restrict methods per route at the web server/framework; disable TRACE; remove method-override middleware unless strictly required.

**Regression guard:** CORS preflight legitimately needs OPTIONS: do not block OPTIONS globally, only restrict what it advertises. Keep the methods real clients use.

**Limitations:**
- OPTIONS itself being enabled is normal for CORS; SRC-E recorded it as an accepted Exception. NavSentry fails only on dangerous advertised methods.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-006`

### NSC-CONF-006 — Unnecessary HTTP methods or method override enabled

- Fingerprint: `2c2f89f8d79380769fbb925a` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `OPTIONS http://127.0.0.1:4173/api/profile`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-650, CWE-16 · WSTG: WSTG-CONF-06 · ASVS 5.0: V13 Configuration, V4 API and Web Service

**Expected:** OPTIONS on in-scope resources does not advertise TRACE/TRACK/CONNECT | Only methods actually used by the resource are advertised | Method-override headers are ignored (verified manually under safe-validate)

**Observed (redacted):**
- Dangerous methods advertised: TRACE
- advertised: GET, POST, OPTIONS, TRACE

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-006, transport direct-http)
- Send OPTIONS to the resource (NavSentry or curl -X OPTIONS -i) and inspect Allow

**Recommendation:** Restrict methods per route at the web server/framework; disable TRACE; remove method-override middleware unless strictly required.

**Regression guard:** CORS preflight legitimately needs OPTIONS: do not block OPTIONS globally, only restrict what it advertises. Keep the methods real clients use.

**Limitations:**
- OPTIONS itself being enabled is normal for CORS; SRC-E recorded it as an accepted Exception. NavSentry fails only on dangerous advertised methods.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-006`

### NSC-CONF-006 — Unnecessary HTTP methods or method override enabled

- Fingerprint: `c7c1849474ca4043dcd3c780` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `OPTIONS http://127.0.0.1:4173/api/error`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-650, CWE-16 · WSTG: WSTG-CONF-06 · ASVS 5.0: V13 Configuration, V4 API and Web Service

**Expected:** OPTIONS on in-scope resources does not advertise TRACE/TRACK/CONNECT | Only methods actually used by the resource are advertised | Method-override headers are ignored (verified manually under safe-validate)

**Observed (redacted):**
- Dangerous methods advertised: TRACE
- advertised: GET, POST, OPTIONS, TRACE

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-006, transport direct-http)
- Send OPTIONS to the resource (NavSentry or curl -X OPTIONS -i) and inspect Allow

**Recommendation:** Restrict methods per route at the web server/framework; disable TRACE; remove method-override middleware unless strictly required.

**Regression guard:** CORS preflight legitimately needs OPTIONS: do not block OPTIONS globally, only restrict what it advertises. Keep the methods real clients use.

**Limitations:**
- OPTIONS itself being enabled is normal for CORS; SRC-E recorded it as an accepted Exception. NavSentry fails only on dangerous advertised methods.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-006`

### NSC-CONF-006 — Unnecessary HTTP methods or method override enabled

- Fingerprint: `82249f07a283138dc5d24c22` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `OPTIONS http://127.0.0.1:4173/api/token`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-650, CWE-16 · WSTG: WSTG-CONF-06 · ASVS 5.0: V13 Configuration, V4 API and Web Service

**Expected:** OPTIONS on in-scope resources does not advertise TRACE/TRACK/CONNECT | Only methods actually used by the resource are advertised | Method-override headers are ignored (verified manually under safe-validate)

**Observed (redacted):**
- Dangerous methods advertised: TRACE
- advertised: GET, POST, OPTIONS, TRACE

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-006, transport direct-http)
- Send OPTIONS to the resource (NavSentry or curl -X OPTIONS -i) and inspect Allow

**Recommendation:** Restrict methods per route at the web server/framework; disable TRACE; remove method-override middleware unless strictly required.

**Regression guard:** CORS preflight legitimately needs OPTIONS: do not block OPTIONS globally, only restrict what it advertises. Keep the methods real clients use.

**Limitations:**
- OPTIONS itself being enabled is normal for CORS; SRC-E recorded it as an accepted Exception. NavSentry fails only on dangerous advertised methods.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-006`

### NSC-CONF-006 — Unnecessary HTTP methods or method override enabled

- Fingerprint: `5937abdc7d03f39d27e36260` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `OPTIONS http://127.0.0.1:4173/go-out`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-650, CWE-16 · WSTG: WSTG-CONF-06 · ASVS 5.0: V13 Configuration, V4 API and Web Service

**Expected:** OPTIONS on in-scope resources does not advertise TRACE/TRACK/CONNECT | Only methods actually used by the resource are advertised | Method-override headers are ignored (verified manually under safe-validate)

**Observed (redacted):**
- Dangerous methods advertised: TRACE
- advertised: GET, POST, OPTIONS, TRACE

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-006, transport direct-http)
- Send OPTIONS to the resource (NavSentry or curl -X OPTIONS -i) and inspect Allow

**Recommendation:** Restrict methods per route at the web server/framework; disable TRACE; remove method-override middleware unless strictly required.

**Regression guard:** CORS preflight legitimately needs OPTIONS: do not block OPTIONS globally, only restrict what it advertises. Keep the methods real clients use.

**Limitations:**
- OPTIONS itself being enabled is normal for CORS; SRC-E recorded it as an accepted Exception. NavSentry fails only on dangerous advertised methods.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-006`

### NSC-CONF-007 — Insecure cache policy for sensitive responses

- Fingerprint: `78cfb26ba86a9c964485e562` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/`
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

### NSC-CONF-007 — Insecure cache policy for sensitive responses

- Fingerprint: `973b78c7baf56069037bc3e8` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/profile`
- OWASP: A06:2025 Insecure Design; A02:2025 Security Misconfiguration; A04:2021 Insecure Design; A05:2021 Security Misconfiguration
- CWE: CWE-524, CWE-525 · WSTG: WSTG-ATHN-06 · ASVS 5.0: V14 Data Protection

**Expected:** Responses served to authenticated actors or setting session cookies send `Cache-Control: no-store` (or `private, no-cache` where justified) | Static public assets may stay cacheable

**Observed (redacted):**
- Sensitive response is cacheable
- Cache-Control: public, max-age=600

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-CONF-007, transport direct-http)
- DevTools > Network: authenticated API responses show no-store

**Recommendation:** Add no-store on authenticated/sensitive routes (middleware by route group); keep long caching only for fingerprinted static assets.

**Regression guard:** Do not apply no-store to static assets (performance regression). Scope the header by route. Verify with `navsentry compare` and page-load timing.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-conf-007`

### NSC-CONF-007 — Insecure cache policy for sensitive responses

- Fingerprint: `b2ae6e48d832d0fbdb60a801` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/error`
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

### NSC-CONF-007 — Insecure cache policy for sensitive responses

- Fingerprint: `82c6f694fc9f9f46f387b272` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/app/profile`
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

### NSC-INFO-001 — Server / framework version disclosure

- Fingerprint: `65014b06eef67557fa1224fa` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-200, CWE-497 · WSTG: WSTG-INFO-02 · ASVS 5.0: V13 Configuration

**Expected:** No response header or default error page exposes a product version number | X-Powered-By / X-AspNet-Version headers removed

**Observed (redacted):**
- Product version disclosed
- server: Apache/2.4.29 (Ubuntu)
- x-powered-by: PHP/7.2.1

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-INFO-001, transport direct-http)
- DevTools > Network > Response Headers: no version numbers

**Recommendation:** Remove/blank version headers at the server/proxy (e.g. server_tokens off, removeServerHeader, enableVersionHeader=false) and use custom error pages.

**Regression guard:** Header removal does not change bodies; confirm with `navsentry compare` (Server/X-Powered-By are excluded from the contract).

**Limitations:**
- Version hiding is defence in depth, not a fix for an unpatched component (see NSC-SUPPLY-001).

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-info-001`

### NSC-INFO-001 — Server / framework version disclosure

- Fingerprint: `96c85dadbfe772b1946bb878` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/profile`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-200, CWE-497 · WSTG: WSTG-INFO-02 · ASVS 5.0: V13 Configuration

**Expected:** No response header or default error page exposes a product version number | X-Powered-By / X-AspNet-Version headers removed

**Observed (redacted):**
- Product version disclosed
- server: Apache/2.4.29 (Ubuntu)
- x-powered-by: PHP/7.2.1

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-INFO-001, transport direct-http)
- DevTools > Network > Response Headers: no version numbers

**Recommendation:** Remove/blank version headers at the server/proxy (e.g. server_tokens off, removeServerHeader, enableVersionHeader=false) and use custom error pages.

**Regression guard:** Header removal does not change bodies; confirm with `navsentry compare` (Server/X-Powered-By are excluded from the contract).

**Limitations:**
- Version hiding is defence in depth, not a fix for an unpatched component (see NSC-SUPPLY-001).

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-info-001`

### NSC-INFO-001 — Server / framework version disclosure

- Fingerprint: `81615fe0efd01296eabb4b0e` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/error`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-200, CWE-497 · WSTG: WSTG-INFO-02 · ASVS 5.0: V13 Configuration

**Expected:** No response header or default error page exposes a product version number | X-Powered-By / X-AspNet-Version headers removed

**Observed (redacted):**
- Product version disclosed
- server: Apache/2.4.29 (Ubuntu)
- x-powered-by: PHP/7.2.1

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-INFO-001, transport direct-http)
- DevTools > Network > Response Headers: no version numbers

**Recommendation:** Remove/blank version headers at the server/proxy (e.g. server_tokens off, removeServerHeader, enableVersionHeader=false) and use custom error pages.

**Regression guard:** Header removal does not change bodies; confirm with `navsentry compare` (Server/X-Powered-By are excluded from the contract).

**Limitations:**
- Version hiding is defence in depth, not a fix for an unpatched component (see NSC-SUPPLY-001).

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-info-001`

### NSC-INFO-001 — Server / framework version disclosure

- Fingerprint: `567f8480c5da9b5ed13762ea` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/token`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-200, CWE-497 · WSTG: WSTG-INFO-02 · ASVS 5.0: V13 Configuration

**Expected:** No response header or default error page exposes a product version number | X-Powered-By / X-AspNet-Version headers removed

**Observed (redacted):**
- Product version disclosed
- server: Apache/2.4.29 (Ubuntu)
- x-powered-by: PHP/7.2.1

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-INFO-001, transport direct-http)
- DevTools > Network > Response Headers: no version numbers

**Recommendation:** Remove/blank version headers at the server/proxy (e.g. server_tokens off, removeServerHeader, enableVersionHeader=false) and use custom error pages.

**Regression guard:** Header removal does not change bodies; confirm with `navsentry compare` (Server/X-Powered-By are excluded from the contract).

**Limitations:**
- Version hiding is defence in depth, not a fix for an unpatched component (see NSC-SUPPLY-001).

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-info-001`

### NSC-INFO-001 — Server / framework version disclosure

- Fingerprint: `40d2944d5782beb316fdf3df` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/go-out`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-200, CWE-497 · WSTG: WSTG-INFO-02 · ASVS 5.0: V13 Configuration

**Expected:** No response header or default error page exposes a product version number | X-Powered-By / X-AspNet-Version headers removed

**Observed (redacted):**
- Product version disclosed
- server: Apache/2.4.29 (Ubuntu)
- x-powered-by: PHP/7.2.1

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-INFO-001, transport direct-http)
- DevTools > Network > Response Headers: no version numbers

**Recommendation:** Remove/blank version headers at the server/proxy (e.g. server_tokens off, removeServerHeader, enableVersionHeader=false) and use custom error pages.

**Regression guard:** Header removal does not change bodies; confirm with `navsentry compare` (Server/X-Powered-By are excluded from the contract).

**Limitations:**
- Version hiding is defence in depth, not a fix for an unpatched component (see NSC-SUPPLY-001).

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-info-001`

### NSC-INFO-001 — Server / framework version disclosure

- Fingerprint: `b6438cdb4cfb8485c2c39cb4` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/orders`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-200, CWE-497 · WSTG: WSTG-INFO-02 · ASVS 5.0: V13 Configuration

**Expected:** No response header or default error page exposes a product version number | X-Powered-By / X-AspNet-Version headers removed

**Observed (redacted):**
- Product version disclosed
- server: Apache/2.4.29 (Ubuntu)
- x-powered-by: PHP/7.2.1

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-INFO-001, transport direct-http)
- DevTools > Network > Response Headers: no version numbers

**Recommendation:** Remove/blank version headers at the server/proxy (e.g. server_tokens off, removeServerHeader, enableVersionHeader=false) and use custom error pages.

**Regression guard:** Header removal does not change bodies; confirm with `navsentry compare` (Server/X-Powered-By are excluded from the contract).

**Limitations:**
- Version hiding is defence in depth, not a fix for an unpatched component (see NSC-SUPPLY-001).

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-info-001`

### NSC-INFO-001 — Server / framework version disclosure

- Fingerprint: `10818924dc8a1a6ca8a01ce1` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/orders/{{orderA}}`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-200, CWE-497 · WSTG: WSTG-INFO-02 · ASVS 5.0: V13 Configuration

**Expected:** No response header or default error page exposes a product version number | X-Powered-By / X-AspNet-Version headers removed

**Observed (redacted):**
- Product version disclosed
- server: Apache/2.4.29 (Ubuntu)
- x-powered-by: PHP/7.2.1

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-INFO-001, transport direct-http)
- DevTools > Network > Response Headers: no version numbers

**Recommendation:** Remove/blank version headers at the server/proxy (e.g. server_tokens off, removeServerHeader, enableVersionHeader=false) and use custom error pages.

**Regression guard:** Header removal does not change bodies; confirm with `navsentry compare` (Server/X-Powered-By are excluded from the contract).

**Limitations:**
- Version hiding is defence in depth, not a fix for an unpatched component (see NSC-SUPPLY-001).

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-info-001`

### NSC-INFO-001 — Server / framework version disclosure

- Fingerprint: `557b65c1e49e747d5e8b1ff7` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/me`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-200, CWE-497 · WSTG: WSTG-INFO-02 · ASVS 5.0: V13 Configuration

**Expected:** No response header or default error page exposes a product version number | X-Powered-By / X-AspNet-Version headers removed

**Observed (redacted):**
- Product version disclosed
- server: Apache/2.4.29 (Ubuntu)
- x-powered-by: PHP/7.2.1

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-INFO-001, transport direct-http)
- DevTools > Network > Response Headers: no version numbers

**Recommendation:** Remove/blank version headers at the server/proxy (e.g. server_tokens off, removeServerHeader, enableVersionHeader=false) and use custom error pages.

**Regression guard:** Header removal does not change bodies; confirm with `navsentry compare` (Server/X-Powered-By are excluded from the contract).

**Limitations:**
- Version hiding is defence in depth, not a fix for an unpatched component (see NSC-SUPPLY-001).

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-info-001`

### NSC-INFO-001 — Server / framework version disclosure

- Fingerprint: `f3e727a639f1686ee83fcfde` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/admin/stats`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-200, CWE-497 · WSTG: WSTG-INFO-02 · ASVS 5.0: V13 Configuration

**Expected:** No response header or default error page exposes a product version number | X-Powered-By / X-AspNet-Version headers removed

**Observed (redacted):**
- Product version disclosed
- server: Apache/2.4.29 (Ubuntu)
- x-powered-by: PHP/7.2.1

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-INFO-001, transport direct-http)
- DevTools > Network > Response Headers: no version numbers

**Recommendation:** Remove/blank version headers at the server/proxy (e.g. server_tokens off, removeServerHeader, enableVersionHeader=false) and use custom error pages.

**Regression guard:** Header removal does not change bodies; confirm with `navsentry compare` (Server/X-Powered-By are excluded from the contract).

**Limitations:**
- Version hiding is defence in depth, not a fix for an unpatched component (see NSC-SUPPLY-001).

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-info-001`

### NSC-INFO-001 — Server / framework version disclosure

- Fingerprint: `4bab2545a1262edeea8cda03` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/app/profile`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-200, CWE-497 · WSTG: WSTG-INFO-02 · ASVS 5.0: V13 Configuration

**Expected:** No response header or default error page exposes a product version number | X-Powered-By / X-AspNet-Version headers removed

**Observed (redacted):**
- Product version disclosed
- server: Apache/2.4.29 (Ubuntu)
- x-powered-by: PHP/7.2.1

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-INFO-001, transport direct-http)
- DevTools > Network > Response Headers: no version numbers

**Recommendation:** Remove/blank version headers at the server/proxy (e.g. server_tokens off, removeServerHeader, enableVersionHeader=false) and use custom error pages.

**Regression guard:** Header removal does not change bodies; confirm with `navsentry compare` (Server/X-Powered-By are excluded from the contract).

**Limitations:**
- Version hiding is defence in depth, not a fix for an unpatched component (see NSC-SUPPLY-001).

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-info-001`

### NSC-INFO-003 — Internal IP address disclosure

- Fingerprint: `3cb08c2e2fd70219f7d3f68a` · Severity: **low** · Confidence: medium · Lifecycle: **SUSPECTED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/profile`
- OWASP: A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration
- CWE: CWE-200 · WSTG: WSTG-INFO-05 · ASVS 5.0: V13 Configuration

**Expected:** No in-scope response contains private IPv4/IPv6 literals in headers or bodies

**Observed (redacted):**
- Private IP address literals disclosed
- headers: 0 match(es)
- body: 1 match(es)
- values masked

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-INFO-003, transport direct-http)
- Search the raw response (DevTools > Network > Response) for 10./172.16-31./192.168. patterns

**Recommendation:** Stop echoing upstream addresses (Via, X-Backend-Server, error messages, config endpoints); configure the proxy to strip them.

**Regression guard:** If a client legitimately consumes an address field (e.g. a config endpoint), replace it with a public hostname rather than removing the field; verify JSON shape with `navsentry compare`.

**Limitations:**
- Dotted version/build strings that start with 10. or 192.168. can match; review context before VALIDATED.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-info-003`

### NSC-SESS-002 — Cookie without HttpOnly flag

- Fingerprint: `61ec1e54ebcfb120565cf348` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **CAUTION** — Fix with caution (may affect legitimate users)
- Target: `GET http://127.0.0.1:4173/`
- OWASP: A02:2025 Security Misconfiguration; A07:2025 Authentication Failures; A05:2021 Security Misconfiguration; A07:2021 Identification and Authentication Failures
- CWE: CWE-1004 · WSTG: WSTG-SESS-02 · ASVS 5.0: V3 Web Frontend Security, V7 Session Management

**Expected:** Session/auth cookies have HttpOnly | Cookies intentionally read by JS (e.g. double-submit CSRF token) are documented exceptions

**Observed (redacted):**
- Session-like cookie(s) readable by JavaScript
- SESSIONID: HttpOnly missing on session-like cookie

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-SESS-002, transport direct-http)
- DevTools > Application > Cookies: HttpOnly ticked for session cookies

**Recommendation:** Enable HttpOnly for session/auth cookies in the framework configuration.

**Regression guard:** Front-end code that reads the cookie will break — search the client code for document.cookie usage first and move it to a header/endpoint.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-sess-002`

### NSC-SESS-003 — Cookie SameSite missing or contradictory

- Fingerprint: `3ef098d4f9d97c697a600f59` · Severity: **low** · Confidence: high · Lifecycle: **VALIDATED**
- Priority: **CAUTION** — Fix with caution (may affect legitimate users)
- Target: `GET http://127.0.0.1:4173/`
- OWASP: A01:2025 Broken Access Control; A02:2025 Security Misconfiguration; A01:2021 Broken Access Control; A05:2021 Security Misconfiguration
- CWE: CWE-1275, CWE-352 · WSTG: WSTG-SESS-02, WSTG-SESS-05 · ASVS 5.0: V3 Web Frontend Security, V7 Session Management

**Expected:** Session cookies set SameSite=Lax or Strict | Any SameSite=None cookie also has Secure and a documented cross-site need

**Observed (redacted):**
- SameSite missing or contradictory
- SESSIONID: SameSite missing

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-SESS-003, transport direct-http)
- DevTools > Application > Cookies: SameSite column

**Recommendation:** Set SameSite=Lax by default; use None; Secure only for cookies that must travel cross-site (SSO, embedded apps).

**Regression guard:** SameSite=Strict/Lax can break SAML/OIDC form_post callbacks and payment redirects; test every external login/redirect flow.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-sess-003`

### NSC-INFO-004 — Email address disclosure

- Fingerprint: `8d3f0ad3b969625397e56ce9` · Severity: **info** · Confidence: medium · Lifecycle: **SUSPECTED**
- Priority: **PLANNED** — Planned fix
- Target: `GET http://127.0.0.1:4173/api/profile`
- OWASP: A01:2025 Broken Access Control; A01:2021 Broken Access Control
- CWE: CWE-200, CWE-359 · WSTG: WSTG-INFO-05 · ASVS 5.0: V14 Data Protection

**Expected:** Anonymous responses expose no personal/staff email except intentional public contact addresses listed by the owner

**Observed (redacted):**
- 1 email address(es) in response
- count: 1
- domain shapes: *.example
- addresses masked

**Reproduce:**
- navsentry test --config <manifest>  (rule NSC-INFO-004, transport direct-http)
- Open the endpoint anonymously and search the response for '@'

**Recommendation:** Remove addresses from config/diagnostic endpoints; return them only to authorized users who need them.

**Regression guard:** If a UI shows an email field to its owner, keep it for the authenticated owner; remove it only from anonymous/other-user responses.

**Limitations:**
- Public contact addresses are expected; record them as reviewed exceptions instead of failing forever.

Agent prompt: see `docs/cases/CASE-CATALOG.md#nsc-info-004`

## Coverage matrix

| Case | Title | Status | Targets | Reason |
|---|---|---|---|---|
| NSC-CONF-001 | HSTS missing or weak | NOT_TESTED | 0 | plain HTTP target |
| NSC-CONF-002 | Content Security Policy missing or unsafe | FAIL | 6 |  |
| NSC-CONF-003 | Clickjacking protection missing | FAIL | 6 |  |
| NSC-CONF-004 | MIME sniffing not disabled / insecure Content-Type | FAIL | 25 |  |
| NSC-CONF-005 | Debug mode / development features enabled | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-CONF-006 | Unnecessary HTTP methods or method override enabled | FAIL | 5 |  |
| NSC-CONF-007 | Insecure cache policy for sensitive responses | FAIL | 20 |  |
| NSC-CONF-008 | HTTP request smuggling / desync | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-INFO-001 | Server / framework version disclosure | FAIL | 29 |  |
| NSC-INFO-003 | Internal IP address disclosure | FAIL | 29 |  |
| NSC-INFO-004 | Email address disclosure | FAIL | 29 |  |
| NSC-ERR-001 | Verbose error, stack trace or unhandled exception exposed | FAIL | 29 |  |
| NSC-ERR-002 | Denial of service via expensive input parsing | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-PRIV-001 | National ID / personal identifier disclosure | FAIL | 29 |  |
| NSC-PRIV-002 | Sensitive data in URL / GET query | PASS | 29 |  |
| NSC-SESS-001 | Cookie without Secure flag | NOT_TESTED | 0 | plain HTTP target |
| NSC-SESS-002 | Cookie without HttpOnly flag | FAIL | 4 |  |
| NSC-SESS-003 | Cookie SameSite missing or contradictory | FAIL | 4 |  |
| NSC-SESS-004 | JWT missing protection claims or weak algorithm | FAIL | 4 |  |
| NSC-CRYPT-001 | Legacy TLS/SSL protocol versions enabled | NOT_TESTED | 0 | not exercised by this run's targets |
| NSC-CRYPT-002 | Weak TLS cipher suites or key exchange | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-CRYPT-003 | Insufficient certificate key size or weak signature | NOT_TESTED | 0 | not exercised by this run's targets |
| NSC-CRYPT-004 | Missing public key pinning (deprecated control) | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-CRYPT-005 | Hardcoded encryption key | NOT_TESTED | 0 | source-code finding; use a SAST tool / DevSift |
| NSC-CRYPT-006 | Cleartext HTTP served without redirect to HTTPS | FAIL | 29 |  |
| NSC-AC-001 | Authorization bypass through test/debug endpoint | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-AC-002 | Missing authentication on API endpoint | FAIL | 2 |  |
| NSC-AC-003 | IDOR / BOLA (cross-user object access) | FAIL | 1 |  |
| NSC-AC-007 | Missing function-level authorization (vertical privilege escalation) | FAIL | 1 |  |
| NSC-AC-004 | Permissive CORS policy | FAIL | 5 |  |
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

- 2 flows / 11 steps · Functional result: **FAIL**
- URLs covered beyond seed paths: 5
- Findings raised by flow requests: 22
- Details: [TEST-REPORT.md](TEST-REPORT.md)
