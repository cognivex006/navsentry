# NavSentry Report — demo-after (local)

- Run ID: `39a332c1-39f9-418b-9528-cd6ed6a05543`
- Started: 2026-11-06T07:07:04.466Z · Finished: 2026-11-06T07:07:07.262Z
- Tool: navsentry 0.2.0 · Node 26.13.0 · win32-x64
- Mode: `observe` · Profile: `development` · Origins: `http://127.0.0.1:4174`
- Execution status: **COMPLETE** · Security result: **FINDINGS**
- Requests: 39/100 · Denied before execution: 4

## Summary

| 🔴 IMMEDIATE | 🟠 CAUTION | 🟡 PLANNED | 🔵 OPTIONAL | ⚪ INFO |
|---|---|---|---|---|
| 1 | 0 | 0 | 1 | 0 |

| PASS | FAIL | INCONCLUSIVE | ERROR | NOT_TESTED | Findings |
|---|---|---|---|---|---|
| 17 | 2 | 0 | 0 | 38 | 11 |

**What to do first:**

- 🔴 IMMEDIATE · NSC-CRYPT-006 — Cleartext HTTP served without redirect to HTTPS (10)

> Zero findings does not mean the application is secure. NOT_TESTED, INCONCLUSIVE and ERROR rows are gaps, not passes.

## Findings

### 🔴 IMMEDIATE — Fix now

#### 🔴 NSC-CRYPT-006 — Cleartext HTTP served without redirect to HTTPS

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **IMMEDIATE** | **medium** | CRYPT | 10 |

**Why it matters:** An in-scope http:// origin serves application content instead of redirecting to HTTPS.

**Expected:** http:// requests receive 301/308 to the https:// equivalent | No application content or Set-Cookie on http://

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4174/` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4174/api/profile` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4174/api/error` | high | VALIDATED | Plain HTTP serves content (HTTP 500) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4174/api/token` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4174/go-out` | high | VALIDATED | Plain HTTP serves content (HTTP 302) without HTTPS redirect; Location scheme: http: |
| `GET http://127.0.0.1:4174/api/orders` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4174/api/orders/{{orderA}}` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4174/api/me` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4174/api/admin/stats` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4174/app/profile` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect; Location scheme: http: |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-CRYPT-006, transport direct-http)
- Type http://<host>/ in the browser: it switches to https://

**How to fix:** Redirect all HTTP to HTTPS at the edge; for internal service ports, enable TLS or restrict them to the internal network.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **nginx**

  Before:

  ```nginx
  server {
      listen 80;
      server_name shop.example.test;
      location / { proxy_pass http://app; }
  }
  ```

  After:

  ```nginx
  server {
      listen 80;
      server_name shop.example.test;
      return 301 https://shop.example.test$request_uri;
  }
  ```

- **Node.js / Express**

  Before:

  ```js
  app.listen(80);
  ```

  After:

  ```js
  app.set("trust proxy", 1);
  app.use((req, res, next) =>
    req.secure ? next() : res.redirect(301, "https://shop.example.test" + req.originalUrl));
  ```

  Redirect to a fixed host, never to the request's Host header.

- **ASP.NET Core**

  Before:

  ```csharp
  app.MapControllers();
  ```

  After:

  ```csharp
  app.UseHttpsRedirection();
  app.MapControllers();
  ```

- **Spring Boot / Spring Security**

  Before:

  ```java
  http.authorizeHttpRequests(a -> a.anyRequest().authenticated());
  ```

  After:

  ```java
  http.requiresChannel(c -> c.anyRequest().requiresSecure())
      .authorizeHttpRequests(a -> a.anyRequest().authenticated());
  ```

  Spring Security 6.x; newer versions also offer `redirectToHttps`.

**How to recheck:**

- Type http://<host>/ in the browser: it switches to https://
- Re-run → NSC-CRYPT-006 PASS
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- http:// requests receive 301/308 to the https:// equivalent
- No application content or Set-Cookie on http://

**Must not break:** Machine clients that POST to http:// may not follow redirects with a body (use 308 to preserve method) — inventory them first.

References: OWASP A04:2025 Cryptographic Failures; A02:2021 Cryptographic Failures · CWE CWE-319 · WSTG WSTG-CRYP-03 · ASVS 5.0 V12 Secure Communication

Fingerprints: `692d436b6be4d23f9a12f0bd` `de541519ea628034bf10b279` `fc727d7983201f01a45728e6` `218a567e36a7e353d513883d` `1ba566e5dfe0fcb2056cd0b3` `3585c95db6c6d12721e0affe` `74c1939329689193ff67afab` `fc8f24db6bc1fbad7593d749` `91750bce609f47a4105f2edb` `ef51e0debbf6974b84b21ba4`

### 🔵 OPTIONAL — Hardening: may be skipped with a recorded reason

#### 🔵 NSC-CONF-007 — Insecure cache policy for sensitive responses

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **OPTIONAL** | **low** | CONF | 1 |

**Why it matters:** Authenticated or personal API/document responses are cacheable (no `Cache-Control: no-store`/`private`), so shared caches or the browser can retain them.

**Expected:** Responses served to authenticated actors or setting session cookies send `Cache-Control: no-store` (or `private, no-cache` where justified) | Static public assets may stay cacheable

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4174/api/error` | high | VALIDATED | Sensitive response is cacheable; Cache-Control absent |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-CONF-007, transport direct-http)
- DevTools > Network: authenticated API responses show no-store

**How to fix:** Add no-store on authenticated/sensitive routes (middleware by route group); keep long caching only for fingerprinted static assets.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **nginx**

  Before:

  ```nginx
  location /api/ {
      proxy_pass http://app;
  }
  ```

  After:

  ```nginx
  location /api/ {
      proxy_pass http://app;
      add_header Cache-Control "no-store" always;
  }
  ```

- **Node.js / Express**

  Before:

  ```js
  app.use("/api", apiRouter);
  ```

  After:

  ```js
  app.use("/api", (req, res, next) => { res.set("Cache-Control", "no-store"); next(); }, apiRouter);
  ```

- **ASP.NET Core**

  Before:

  ```csharp
  [HttpGet("profile")]
  public IActionResult Profile() => Ok(_svc.Profile());
  ```

  After:

  ```csharp
  [HttpGet("profile")]
  [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
  public IActionResult Profile() => Ok(_svc.Profile());
  ```

- **Spring Boot / Spring Security**

  Before:

  ```java
  http.headers(h -> h.cacheControl(c -> c.disable()));
  ```

  After:

  ```java
  http.headers(h -> h.cacheControl(Customizer.withDefaults())); // no-cache, no-store
  ```

**How to recheck:**

- DevTools > Network: authenticated API responses show no-store
- Log out, press Back: sensitive pages are not shown from cache
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- Responses served to authenticated actors or setting session cookies send `Cache-Control: no-store` (or `private, no-cache` where justified)
- Static public assets may stay cacheable

**Must not break:** Do not apply no-store to static assets (performance regression). Scope the header by route. Verify with `navsentry compare` and page-load timing.

References: OWASP A06:2025 Insecure Design; A02:2025 Security Misconfiguration; A04:2021 Insecure Design; A05:2021 Security Misconfiguration · CWE CWE-524, CWE-525 · WSTG WSTG-ATHN-06 · ASVS 5.0 V14 Data Protection

Fingerprints: `c7f7bfc1c9a7ba376305d571`

## Fix verification

No previous run compared. After a fix, run the same scan again and use `navsentry compare --before <dir> --after <dir>`.

## Known vulnerabilities

- Snapshot `2026-11-04.1` · sha256 `42e5d2a7d39cf6e2` · 3 record(s), 3 reviewed, 0 stale · oldest verification 2026-11-03
- Offline snapshot: it cannot prove that no newer advisory exists. Zero matches never means no vulnerabilities.

### Known vulnerability applicability

| Product (evidence) | Record | Identifiers | Severity (source) | Applicability | Case | Caveats |
|---|---|---|---|---|---|---|
| — No product versions observed. | | | | | | |

## Coverage

| Case | Title | Status | Targets | Reason |
|---|---|---|---|---|
| NSC-CONF-001 | HSTS missing or weak | NOT_TESTED | 0 | plain HTTP target |
| NSC-CONF-002 | Content Security Policy missing or unsafe | PASS | 5 |  |
| NSC-CONF-003 | Clickjacking protection missing | PASS | 5 |  |
| NSC-CONF-004 | MIME sniffing not disabled / insecure Content-Type | PASS | 24 |  |
| NSC-CONF-009 | Configuration or VCS files publicly reachable | NOT_TESTED | 0 | not exercised by this run's targets |
| NSC-CONF-005 | Debug mode / development features enabled | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-CONF-006 | Unnecessary HTTP methods or method override enabled | PASS | 5 |  |
| NSC-CONF-007 | Insecure cache policy for sensitive responses | FAIL | 20 |  |
| NSC-CONF-008 | HTTP request smuggling / desync | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-INFO-001 | Server / framework version disclosure | PASS | 29 |  |
| NSC-INFO-007 | Secrets embedded in client-side assets | NOT_TESTED | 0 | not exercised by this run's targets |
| NSC-INFO-006 | Sensitive data written to the browser console | NOT_TESTED | 0 | no JS runtime (http engine) |
| NSC-INFO-008 | Source maps with source content served publicly | NOT_TESTED | 0 | not exercised by this run's targets |
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
| NSC-AC-008 | Open redirect | NOT_TESTED | 0 | not exercised by this run's targets |
| NSC-AC-004 | Permissive CORS policy | PASS | 5 |  |
| NSC-AC-005 | Server-side request forgery (SSRF) | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-AC-006 | Missing CSRF protection on state-changing requests | NOT_TESTED | 0 | needs a flow with an access expectation (docs/FLOWS.md) |
| NSC-AUTH-001 | Hardcoded API credentials | NOT_TESTED | 0 | source-code finding; use a SAST tool / DevSift |
| NSC-AUTH-002 | Session not invalidated after logout / stale session | NOT_TESTED | 0 | needs a flow with an access expectation (docs/FLOWS.md) |
| NSC-INJ-001 | SQL injection | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-INJ-002 | Server-side script / template / code injection | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-INJ-003 | LDAP injection | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-INJ-004 | Reflected / DOM cross-site scripting | NOT_TESTED | 0 | deterministic check planned for active-approved (design) |
| NSC-INJ-005 | HTTP header manipulation / CRLF injection / unvalidated header forwarding | NOT_TESTED | 0 | source-code finding; use a SAST tool / DevSift |
| NSC-INJ-006 | Local file inclusion / path traversal | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-SUPPLY-001 | Unpatched server component with known vulnerabilities | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-SUPPLY-002 | Client-side library with known vulnerabilities | NOT_TESTED | 0 | not exercised by this run's targets |
| NSC-LOG-001 | Security logging and alerting gaps | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-BIZ-001 | Business logic flaw | NOT_TESTED | 0 | needs a flow with an access expectation (docs/FLOWS.md) |
| NSC-INFRA-001 | ICMP timestamp response enabled | NOT_TESTED | 0 | network/host VA item outside web scope |
| NSC-INFRA-002 | ICMP redirects accepted | NOT_TESTED | 0 | network/host VA item outside web scope |
| NSC-INFRA-003 | Unsafe default umask / home directory permissions | NOT_TESTED | 0 | network/host VA item outside web scope |
| NSC-INFRA-004 | Weak SSH MAC algorithms | NOT_TESTED | 0 | network/host VA item outside web scope |
| NSC-INFRA-005 | FTP credentials transmitted in cleartext | NOT_TESTED | 0 | network/host VA item outside web scope |
| NSC-INFRA-006 | Database ports reachable from untrusted networks | NOT_TESTED | 0 | network/host VA item outside web scope |
| NSC-INFRA-007 | OS package vulnerabilities / untrusted package repository | NOT_TESTED | 0 | network/host VA item outside web scope |
| NSC-INFO-005 | WAF / reverse proxy detected (informational) | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |

### Coverage by template

Not a spider run: only the requested pages were scanned.

## Not tested and limitations

None.

- NOT_TESTED cases: 38 (Coverage)

## Transports and engine

| Transport | Available | Usable | Version | Reason |
|---|---|---|---|---|
| direct-http | true | true | 26.13.0 | built-in node:http/https |
| playwright-browser | true | true | 1.64.1 | playwright-core with Chromium headless shell; every request is fulfilled through ScopeGate and Budget (S1) |
| curl-cli | true | false | curl 8.22.0 (Windows) libcurl/8.22.0 Schannel zlib/1.3.2 WinIDN WinLDAP | detected; request execution is scheduled for milestone M3 (argv builder implemented and tested) |
| powershell-http | true | false | 7.6.9 | detected; request execution is scheduled for milestone M3 (argv builder implemented and tested) |
| visual-computer-use | true | true | 1.64.1 | visual driver over playwright-browser: `navsentry browse` (development; needs transports.visual_computer_use: true) |
| zap-passive | false | false | — | phase-2 integration; not implemented |

## Requests refused before sending

- GET `http://evil.example/steal` — redirect not followed: origin http://evil.example is not in targets.origins
- GET `http://evil.example/steal` — redirect not followed: origin http://evil.example is not in targets.origins
- GET `http://evil.example/steal` — redirect not followed: origin http://evil.example is not in targets.origins
- GET `http://evil.example/steal` — redirect not followed: origin http://evil.example is not in targets.origins

## Redirect chains

Every hop was checked by ScopeGate before it was requested.

- `http://127.0.0.1:4174/go-out` as anonymous
  - 302 `http://127.0.0.1:4174/go-out` → `http://evil.example/steal` · not followed: origin http://evil.example is not in targets.origins
- `http://127.0.0.1:4174/go-out` as reader_a
  - 302 `http://127.0.0.1:4174/go-out` → `http://evil.example/steal` · not followed: origin http://evil.example is not in targets.origins
- `http://127.0.0.1:4174/go-out` as reader_b
  - 302 `http://127.0.0.1:4174/go-out` → `http://evil.example/steal` · not followed: origin http://evil.example is not in targets.origins
- `http://127.0.0.1:4174/go-out` as admin
  - 302 `http://127.0.0.1:4174/go-out` → `http://evil.example/steal` · not followed: origin http://evil.example is not in targets.origins

## Client assets and browser

### Client assets

Not scanned in this mode.

### Browser console

Not captured (no browser engine in this run).

### Analyzer

Not run (add `--analyze`).

## Knowledge gaps

### Knowledge gaps / proposed updates

| Gap | Product | Detail |
|---|---|---|
| — None. | | |

## Run details

- Budget: 39/100 requests · denied before execution 4

### Fixtures and cleanup

Not used (observe mode).

### Capture

| Wire bytes | Decoded bytes | Truncated | Aborted | Partially inspected bodies |
|---|---|---|---|---|
| 2116 | 2116 | 0 | 0 | 0 |

### Workspace

None.

## Flows

- 2 flows / 11 steps · Functional result: **INCOMPLETE**
- URLs covered beyond seed paths: 5
- Findings raised by flow requests: 5
- Details: [TEST-REPORT.md](TEST-REPORT.md)
