# NavSentry Report — demo-before (local)

- Run ID: `4dec9615-c686-4ef0-9fbf-b6e49d63ed74`
- Started: 2026-11-07T02:56:33.974Z · Finished: 2026-11-07T02:56:36.546Z
- Tool: navsentry 0.2.0 · Node 26.13.0 · win32-x64
- Mode: `observe` · Profile: `development` · Origins: `http://127.0.0.1:4173`
- Execution status: **COMPLETE** · Security result: **FINDINGS**
- Requests: 39/100 · Denied before execution: 4

## Summary

> 🔴 **Do I need to fix something now?** Yes. Fix 11 issue(s) now, before the next release. They are listed under "What to do first".

| 🔴 IMMEDIATE | 🟠 CAUTION | 🟡 PLANNED | 🔵 OPTIONAL | ⚪ INFO |
|---|---|---|---|---|
| 6 | 5 | 1 | 5 | 1 |

| PASS | FAIL | INCONCLUSIVE | ERROR | NOT_TESTED | Findings |
|---|---|---|---|---|---|
| 1 | 18 | 0 | 0 | 38 | 58 |

**What to do first:**

- 🔴 IMMEDIATE · NSC-AC-002 — Missing authentication on API endpoint (2)
- 🔴 IMMEDIATE · NSC-AC-003 — IDOR / BOLA (cross-user object access) (1)
- 🔴 IMMEDIATE · NSC-AC-007 — Missing function-level authorization (vertical privilege escalation) (1)
- 🔴 IMMEDIATE · NSC-PRIV-001 — National ID / personal identifier disclosure (1)
- 🔴 IMMEDIATE · NSC-CRYPT-006 — Cleartext HTTP served without redirect to HTTPS (10)
- 🔴 IMMEDIATE · NSC-ERR-001 — Verbose error, stack trace or unhandled exception exposed (1)
- 🟠 CAUTION · NSC-AC-004 — Permissive CORS policy (5)
- 🟠 CAUTION · NSC-CONF-002 — Content Security Policy missing or unsafe (2)
- 🟠 CAUTION · NSC-CONF-003 — Clickjacking protection missing (2)
- 🟠 CAUTION · NSC-SESS-002 — Cookie without HttpOnly flag (1)
- 🟠 CAUTION · NSC-SESS-003 — Cookie SameSite missing or contradictory (1)

> Zero findings does not mean the application is secure. NOT_TESTED, INCONCLUSIVE and ERROR rows are gaps, not passes.

## Findings

### 🔴 IMMEDIATE — Fix now

#### 🔴 NSC-AC-002 — Missing authentication on API endpoint

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **IMMEDIATE** | **high** | AC | 2 |

**Why it matters:** An endpoint that returns non-public data responds 2xx to an anonymous actor.

**Expected:** Anonymous requests to protected endpoints return 401 | Authenticated legitimate actor still gets the same 2xx contract

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/api/me` | medium | SUSPECTED | Missing authentication on API endpoint: access was granted; actor anonymous received 200 application/json with the same response contract as positive control S4 (reader_a); flow orders-access step S5 |
| `GET http://127.0.0.1:4173/app/profile` | medium | SUSPECTED | Missing authentication on API endpoint: access was granted; actor anonymous received 200 text/html with the same response contract as positive control S1 (reader_a); flow profile-journey step S4 |

**How to reproduce:**

- navsentry test --config <manifest> --flows <flows-dir>  (rule NSC-AC-002, flow orders-access step S5)
- Open the endpoint in a private browser window: 401/redirect to login

**How to fix:** Apply authentication middleware with deny-by-default to the whole API group; whitelist truly public routes explicitly.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **Node.js / Express**

  Before:

  ```js
  app.get("/api/me", meHandler);
  ```

  After:

  ```js
  app.use("/api", requireAuth); // deny by default
  app.get("/api/me", meHandler);
  // public routes are registered before requireAuth, explicitly
  ```

- **ASP.NET Core**

  Before:

  ```csharp
  builder.Services.AddAuthorization();
  ```

  After:

  ```csharp
  builder.Services.AddAuthorization(o => o.FallbackPolicy =
      new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
  // mark public endpoints with [AllowAnonymous]
  ```

- **Spring Boot / Spring Security**

  Before:

  ```java
  http.authorizeHttpRequests(a -> a.anyRequest().permitAll());
  ```

  After:

  ```java
  http.authorizeHttpRequests(a -> a
      .requestMatchers("/api/public/**").permitAll()
      .anyRequest().authenticated());
  ```

**How to recheck:**

- Open the endpoint in a private browser window: 401/redirect to login
- Logged-in user still sees data
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- Anonymous requests to protected endpoints return 401
- Authenticated legitimate actor still gets the same 2xx contract

**Must not break:** Public endpoints used before login (health, login config, static config) must be explicitly allow-listed; compare anonymous and authenticated runs before/after.

**Limitations:**

- Evaluated only where a flow declares anonymous `access: denied` with an authenticated positive control; a 2xx with a different contract (login page) is INCONCLUSIVE, not FAIL.

References: OWASP A01:2025 Broken Access Control; A07:2025 Authentication Failures; A01:2021 Broken Access Control; A07:2021 Identification and Authentication Failures · CWE CWE-306 · WSTG WSTG-ATHZ-02 · ASVS 5.0 V8 Authorization, V4 API and Web Service

Fingerprints: `2ed31545305ed6fa20e0a163` `fee0a4fff083aa2abb24c113`

#### 🔴 NSC-AC-003 — IDOR / BOLA (cross-user object access)

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **IMMEDIATE** | **high** | AC | 1 |

**Why it matters:** An actor can read or modify an object owned by another actor by changing an identifier, because ownership is not checked server-side.

**Expected:** Actor B receives 403/404 for actor A's fixture object | Actor A still receives 200 for its own object (positive control)

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/api/orders/{{orderA}}` | medium | SUSPECTED | IDOR / BOLA (cross-user object access): access was granted; actor reader_b received 200 application/json with the same response contract as positive control S2 (reader_a); flow orders-access step S3 |

**How to reproduce:**

- navsentry test --config <manifest> --flows <flows-dir>  (rule NSC-AC-003, flow orders-access step S3)
- As actor B in a separate browser profile, paste actor A's object URL: access denied

**How to fix:** Enforce ownership/tenant checks in the service layer for every object lookup; prefer scoped queries (WHERE owner_id = current_user).

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **Node.js / Express**

  Before:

  ```js
  const order = await db.orders.findById(req.params.id);
  res.json(order);
  ```

  After:

  ```js
  const order = await db.orders.findOne({ id: req.params.id, ownerId: req.user.id });
  if (!order) return res.status(404).json({ error: "not found" });
  res.json(order);
  ```

- **ASP.NET Core**

  Before:

  ```csharp
  var order = await db.Orders.FindAsync(id);
  ```

  After:

  ```csharp
  var order = await db.Orders.SingleOrDefaultAsync(o => o.Id == id && o.OwnerId == userId);
  if (order is null) return NotFound();
  ```

- **Spring Boot / Spring Security**

  Before:

  ```java
  Order order = repo.findById(id).orElseThrow();
  ```

  After:

  ```java
  Order order = repo.findByIdAndOwnerId(id, currentUser.getId())
      .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
  ```

**How to recheck:**

- As actor B in a separate browser profile, paste actor A's object URL: access denied
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- Actor B receives 403/404 for actor A's fixture object
- Actor A still receives 200 for its own object (positive control)

**Must not break:** Shared/delegated objects (team, admin, delegated approver) must keep access — encode those rules explicitly and test them as positive controls.

**Limitations:**

- UI hiding alone NEVER proves authorization.
- Read access: a flow step with object_owner and access: denied. Modification (safe-validate, 0.2.0-c): the same step as a declared fixture mutation, with the owner's own mutation as the positive control.
- Whether actor B's change took effect is not compared: NavSentry does not record response body values.

References: OWASP A01:2025 Broken Access Control; A01:2021 Broken Access Control · CWE CWE-639, CWE-284 · WSTG WSTG-ATHZ-04 · ASVS 5.0 V8 Authorization

Fingerprints: `3eef519c1454dd179dcdf801`

#### 🔴 NSC-AC-007 — Missing function-level authorization (vertical privilege escalation)

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **IMMEDIATE** | **high** | AC | 1 |

**Why it matters:** A lower-privileged authenticated actor receives the same 2xx contract as a privileged actor on a privileged function, because the server does not check the role or permission.

**Expected:** Lower role receives 401/403 | Privileged role keeps its 2xx contract (positive control)

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/api/admin/stats` | medium | SUSPECTED | Missing function-level authorization (vertical privilege escalation): access was granted; actor reader_a received 200 application/json with the same response contract as positive control S6 (admin); flow orders-access step S7 |

**How to reproduce:**

- navsentry test --config <manifest> --flows <flows-dir>  (rule NSC-AC-007, flow orders-access step S7)
- As the lower-role user in a separate browser profile, open the privileged URL: access denied

**How to fix:** Enforce deny-by-default role/permission checks on the server for every privileged route or handler; do not rely on hidden menus.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **Node.js / Express**

  Before:

  ```js
  app.get("/api/admin/stats", requireAuth, stats);
  ```

  After:

  ```js
  const requireRole = (role) => (req, res, next) =>
    req.user?.roles.includes(role) ? next() : res.sendStatus(403);
  app.get("/api/admin/stats", requireAuth, requireRole("admin"), stats);
  ```

- **ASP.NET Core**

  Before:

  ```csharp
  [Authorize]
  [HttpGet("admin/stats")]
  ```

  After:

  ```csharp
  [Authorize(Roles = "Admin")]
  [HttpGet("admin/stats")]
  ```

- **Spring Boot / Spring Security**

  Before:

  ```java
  .requestMatchers("/api/admin/**").authenticated()
  ```

  After:

  ```java
  .requestMatchers("/api/admin/**").hasRole("ADMIN")
  ```

**How to recheck:**

- As the lower-role user in a separate browser profile, open the privileged URL: access denied
- The privileged user still sees the function
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- Lower role receives 401/403
- Privileged role keeps its 2xx contract (positive control)

**Must not break:** Delegated or support roles that legitimately use the function must be encoded as positive controls before tightening.

**Limitations:**

- Hidden menus or disabled buttons never prove authorization.
- Evaluated only where a flow declares access: denied for the lower role with a privileged positive control.

References: OWASP A01:2025 Broken Access Control; A01:2021 Broken Access Control · CWE CWE-285, CWE-862 · WSTG WSTG-ATHZ-03 · ASVS 5.0 V8 Authorization

Fingerprints: `4394e9188345a42229ec9d40`

#### 🔴 NSC-PRIV-001 — National ID / personal identifier disclosure

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **IMMEDIATE** | **high** | PRIV | 1 |

**Why it matters:** API or page responses contain 13-digit values that pass the Thai national ID checksum (or card numbers passing Luhn), exposing PII regulated by PDPA.

**Expected:** No checksum-valid national ID / card number appears in responses to actors not entitled to it | Where required for the owner, values are masked (e.g. x-xxxx-xxxxx-12-3)

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/api/profile` | medium | SUSPECTED | Checksum-valid personal identifiers in response; thai-national-id (mod-11 valid): 1; card-number (Luhn valid): 0; values never stored |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-PRIV-001, transport direct-http)
- Open the endpoint as an unentitled actor and confirm the field is absent or masked

**How to fix:** Remove or mask the field in the response DTO for unentitled callers; enforce field-level authorization server-side.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **Node.js / Express**

  Before:

  ```js
  res.json({ name: u.name, nationalId: u.nationalId });
  ```

  After:

  ```js
  const mask = (v) => "x".repeat(v.length - 4) + v.slice(-4);
  res.json({ name: u.name, nationalId: canSeeId(req.user, u) ? u.nationalId : mask(u.nationalId) });
  ```

- **ASP.NET Core**

  Before:

  ```csharp
  return Ok(new { u.Name, u.NationalId });
  ```

  After:

  ```csharp
  return Ok(new { u.Name, NationalId = CanSeeId(User, u) ? u.NationalId : Mask(u.NationalId) });
  ```

- **Spring Boot / Spring Security**

  Before:

  ```java
  record ProfileDto(String name, String nationalId) {}
  ```

  After:

  ```java
  record ProfileDto(String name, String nationalIdMasked) {}
  // map with mask(u.getNationalId()) unless the caller is entitled
  ```

**How to recheck:**

- Open the endpoint as an unentitled actor and confirm the field is absent or masked
- Re-run → NSC-PRIV-001 PASS
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- No checksum-valid national ID / card number appears in responses to actors not entitled to it
- Where required for the owner, values are masked (e.g. x-xxxx-xxxxx-12-3)

**Must not break:** Masking changes values, not keys: keep the field name and type so clients do not break, unless the owner approves removal. Verify JSON shape with `navsentry compare`.

**Limitations:**

- SRC-E accepted this as an Exception because the 13-digit value was an internal function identifier, not a citizen ID. NavSentry applies the mod-11 checksum to cut such false positives, but a checksum-valid match is still SUSPECTED until a human confirms the field semantics.

References: OWASP A01:2025 Broken Access Control; A04:2025 Cryptographic Failures; A01:2021 Broken Access Control; A02:2021 Cryptographic Failures · CWE CWE-359, CWE-200 · WSTG WSTG-INFO-05 · ASVS 5.0 V14 Data Protection, V8 Authorization

Fingerprints: `f41e08127666743eabc5170c`

#### 🔴 NSC-CRYPT-006 — Cleartext HTTP served without redirect to HTTPS

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **IMMEDIATE** | **medium** | CRYPT | 10 |

**Why it matters:** An in-scope http:// origin serves application content instead of redirecting to HTTPS.

**Expected:** http:// requests receive 301/308 to the https:// equivalent | No application content or Set-Cookie on http://

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4173/api/profile` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4173/api/error` | high | VALIDATED | Plain HTTP serves content (HTTP 500) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4173/api/token` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4173/go-out` | high | VALIDATED | Plain HTTP serves content (HTTP 302) without HTTPS redirect; Location scheme: http: |
| `GET http://127.0.0.1:4173/api/orders` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4173/api/orders/{{orderA}}` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4173/api/me` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4173/api/admin/stats` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |
| `GET http://127.0.0.1:4173/app/profile` | high | VALIDATED | Plain HTTP serves content (HTTP 200) without HTTPS redirect; no redirect |

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

Fingerprints: `32ef940ba82b43d1703edd81` `60cd89eec0834c6173a1ca52` `ffd914e5cdf3c67a36d0007d` `54c1aea904006f550b35a853` `05f978ecba4b2322dfa90ab1` `fee4e2b13b1a34242abf2210` `2f0c13798b3f6290b328e559` `7c6bc49d2e83bb56b8b62a1f` `410d1fcc3d4bf29a8b41f77d` `0e1ff75fa30e8a236884445c`

#### 🔴 NSC-ERR-001 — Verbose error, stack trace or unhandled exception exposed

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **IMMEDIATE** | **medium** | ERR | 1 |

**Why it matters:** Error responses include stack traces, exception class names, SQL/ORM messages or framework error pages, leaking internals and indicating failing-open error handling.

**Expected:** No in-scope response contains stack-trace/exception signatures | Errors return a generic message plus a correlation ID; details go to server logs only | HTTP status codes stay meaningful (4xx for client errors, 5xx for server faults)

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/api/error` | high | VALIDATED | Internal error details exposed (HTTP 500); Exception class name |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-ERR-001, transport direct-http)
- Reproduce the original error condition with a benign request (e.g. missing parameter) and confirm a generic error body

**How to fix:** Add a global exception handler that logs details server-side and returns a standard error envelope (e.g. RFC 9457 problem+json) without internals; disable framework detailed errors in non-dev environments.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **Node.js / Express**

  Before:

  ```js
  app.use((err, req, res, next) => {
    res.status(500).send(err.stack);
  });
  ```

  After:

  ```js
  app.use((err, req, res, next) => {
    logger.error(err); // details stay in server logs
    res.status(500).type("application/problem+json")
      .json({ title: "Internal error", status: 500 });
  });
  ```

- **ASP.NET Core**

  Before:

  ```csharp
  app.UseDeveloperExceptionPage();
  ```

  After:

  ```csharp
  builder.Services.AddProblemDetails();
  // ...
  if (app.Environment.IsDevelopment()) app.UseDeveloperExceptionPage();
  else app.UseExceptionHandler();
  ```

- **Spring Boot / Spring Security**

  Before:

  ```properties
  server.error.include-stacktrace=always
  server.error.include-message=always
  ```

  After:

  ```properties
  server.error.include-stacktrace=never
  server.error.include-message=never
  server.error.include-exception=false
  ```

**How to recheck:**

- Reproduce the original error condition with a benign request (e.g. missing parameter) and confirm a generic error body
- Confirm the detailed exception is present in server logs with the same correlation ID
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- No in-scope response contains stack-trace/exception signatures
- Errors return a generic message plus a correlation ID; details go to server logs only
- HTTP status codes stay meaningful (4xx for client errors, 5xx for server faults)

**Must not break:** Keep the SAME status code and the SAME error envelope fields that clients parse (e.g. `success`, `code`, `message`); only remove internal details. Prove it with `navsentry compare` (status + JSON shape must match).

References: OWASP A10:2025 Mishandling of Exceptional Conditions; A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration; A04:2021 Insecure Design · CWE CWE-209, CWE-248, CWE-550 · WSTG WSTG-ERRH-01, WSTG-ERRH-02 · ASVS 5.0 V16 Security Logging and Error Handling

Fingerprints: `678b4c40706a4b10d28bed40`

### 🟠 CAUTION — Fix carefully: may affect legitimate users

#### 🟠 NSC-AC-004 — Permissive CORS policy

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **CAUTION** | **medium** | AC | 5 |

**Why it matters:** The server reflects an arbitrary Origin (or 'null') in Access-Control-Allow-Origin, especially together with Access-Control-Allow-Credentials: true.

**Expected:** Untrusted test origins are not reflected | Credentials are never allowed with wildcard or reflected origins | Allowed origins are an explicit allowlist

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/` | high | VALIDATED | Untrusted Origin reflected WITH credentials; ACAO reflects probe origin; credentials=true |
| `GET http://127.0.0.1:4173/api/profile` | high | VALIDATED | Untrusted Origin reflected WITH credentials; ACAO reflects probe origin; credentials=true |
| `GET http://127.0.0.1:4173/api/error` | high | VALIDATED | Untrusted Origin reflected WITH credentials; ACAO reflects probe origin; credentials=true |
| `GET http://127.0.0.1:4173/api/token` | high | VALIDATED | Untrusted Origin reflected WITH credentials; ACAO reflects probe origin; credentials=true |
| `GET http://127.0.0.1:4173/go-out` | high | VALIDATED | Untrusted Origin reflected WITH credentials; ACAO reflects probe origin; credentials=true |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-AC-004, transport direct-http)
- From the legitimate front-end origin the app still works (no CORS errors in Console)

**How to fix:** Replace origin reflection with an exact-match allowlist; never combine credentials with '*' or 'null'.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **Node.js / Express**

  Before:

  ```js
  res.set("Access-Control-Allow-Origin", req.headers.origin);
  res.set("Access-Control-Allow-Credentials", "true");
  ```

  After:

  ```js
  const ALLOWED = new Set(["https://app.example.test"]);
  if (ALLOWED.has(req.headers.origin)) {
    res.set("Access-Control-Allow-Origin", req.headers.origin);
    res.set("Access-Control-Allow-Credentials", "true");
    res.vary("Origin");
  }
  ```

- **ASP.NET Core**

  Before:

  ```csharp
  p.SetIsOriginAllowed(_ => true).AllowCredentials();
  ```

  After:

  ```csharp
  p.WithOrigins("https://app.example.test").AllowCredentials();
  ```

- **Spring Boot / Spring Security**

  Before:

  ```java
  config.addAllowedOriginPattern("*");
  config.setAllowCredentials(true);
  ```

  After:

  ```java
  config.setAllowedOrigins(List.of("https://app.example.test"));
  config.setAllowCredentials(true);
  ```

- **nginx**

  Before:

  ```nginx
  add_header Access-Control-Allow-Origin $http_origin always;
  ```

  After:

  ```nginx
  map $http_origin $cors_origin {
      default "";
      "https://app.example.test" $http_origin;
  }
  # in the server block:
  add_header Access-Control-Allow-Origin $cors_origin always;
  add_header Vary Origin always;
  ```

**How to recheck:**

- From the legitimate front-end origin the app still works (no CORS errors in Console)
- Re-run → NSC-AC-004 PASS
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- Untrusted test origins are not reflected
- Credentials are never allowed with wildcard or reflected origins
- Allowed origins are an explicit allowlist

**Must not break:** List every legitimate front-end origin (prod, staging, mobile webviews) before tightening; missing one causes CORS errors only in browsers.

References: OWASP A01:2025 Broken Access Control; A02:2025 Security Misconfiguration; A01:2021 Broken Access Control; A05:2021 Security Misconfiguration · CWE CWE-942, CWE-346 · WSTG WSTG-CLNT-07 · ASVS 5.0 V3 Web Frontend Security, V4 API and Web Service

Fingerprints: `1165ff5cd1b67e24ef43e674` `a85dcc5898250cee68ce9f5c` `3c425a79d30a4412cf0aef98` `bdbf0331bd0333d584e46a9f` `8cc7d85071e0e64554baa4e1`

#### 🟠 NSC-CONF-002 — Content Security Policy missing or unsafe

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **CAUTION** | **medium** | CONF | 2 |

**Why it matters:** HTML responses have no enforcing Content-Security-Policy, or the policy allows 'unsafe-inline'/'unsafe-eval' scripts or wildcard script sources, so injected script is not contained.

**Expected:** Every HTML response has an enforcing Content-Security-Policy | script-src (or default-src) contains no 'unsafe-inline' without nonce/hash, no 'unsafe-eval', no '*' | object-src 'none' and base-uri restricted

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/` | high | VALIDATED | Content-Security-Policy header missing; header absent |
| `GET http://127.0.0.1:4173/app/profile` | high | VALIDATED | Content-Security-Policy header missing; header absent |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-CONF-002, transport direct-http)
- Load each main page with DevTools Console open: no CSP violation errors for legitimate functionality

**How to fix:** Deploy Content-Security-Policy-Report-Only first, collect violations from real traffic, refactor inline scripts to nonces/hashes, then switch to the enforcing header.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **nginx**

  Before:

  ```nginx
  server {
      listen 443 ssl;
      # no Content-Security-Policy header
  }
  ```

  After:

  ```nginx
  server {
      listen 443 ssl;
      add_header Content-Security-Policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'" always;
  }
  ```

  Deploy as Content-Security-Policy-Report-Only first and move inline scripts to nonces or hashes before enforcing.

- **Node.js / Express**

  Before:

  ```js
  app.use(express.static("public"));
  ```

  After:

  ```js
  app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'");
    next();
  });
  app.use(express.static("public"));
  ```

  Deploy as Content-Security-Policy-Report-Only first and move inline scripts to nonces or hashes before enforcing.

- **ASP.NET Core**

  Before:

  ```csharp
  app.UseStaticFiles();
  ```

  After:

  ```csharp
  app.Use(async (context, next) =>
  {
      context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'";
      await next();
  });
  app.UseStaticFiles();
  ```

  Deploy as Content-Security-Policy-Report-Only first and move inline scripts to nonces or hashes before enforcing.

- **Spring Boot / Spring Security**

  Before:

  ```java
  http.headers(Customizer.withDefaults());
  ```

  After:

  ```java
  http.headers(h -> h
      .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'")));
  ```

  Deploy as Content-Security-Policy-Report-Only first and move inline scripts to nonces or hashes before enforcing.

**How to recheck:**

- Load each main page with DevTools Console open: no CSP violation errors for legitimate functionality
- Exercise main user flows (login, search, forms, maps) and confirm they still work
- Re-run `navsentry test` → NSC-CONF-002 PASS
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- Every HTML response has an enforcing Content-Security-Policy
- script-src (or default-src) contains no 'unsafe-inline' without nonce/hash, no 'unsafe-eval', no '*'
- object-src 'none' and base-uri restricted

**Must not break:** An enforcing CSP that is too strict silently breaks scripts, maps, analytics and third-party widgets. Always ship Report-Only first and test every critical page in a real browser. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

References: OWASP A02:2025 Security Misconfiguration; A05:2025 Injection; A05:2021 Security Misconfiguration; A03:2021 Injection · CWE CWE-693, CWE-1021 · WSTG WSTG-CONF-12 · ASVS 5.0 V3 Web Frontend Security

Fingerprints: `22fb68e2405cb97eec3d9987` `86733b9437764e1560fc2e38`

#### 🟠 NSC-CONF-003 — Clickjacking protection missing

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **CAUTION** | **low** | CONF | 2 |

**Why it matters:** HTML responses can be framed by any origin: neither CSP frame-ancestors nor X-Frame-Options is set.

**Expected:** HTML responses send CSP frame-ancestors 'self' (or an explicit allowlist) and/or X-Frame-Options DENY|SAMEORIGIN

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/` | high | VALIDATED | No frame-ancestors or valid X-Frame-Options; frame-ancestors absent; X-Frame-Options absent |
| `GET http://127.0.0.1:4173/app/profile` | high | VALIDATED | No frame-ancestors or valid X-Frame-Options; frame-ancestors absent; X-Frame-Options absent |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-CONF-003, transport direct-http)
- From a different local origin, embed the page in an <iframe>: the browser refuses to render it

**How to fix:** Send `Content-Security-Policy: frame-ancestors 'self' <approved-parents>` plus `X-Frame-Options: SAMEORIGIN` for legacy browsers.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **nginx**

  Before:

  ```nginx
  server {
      listen 443 ssl;
      # no X-Frame-Options header
  }
  ```

  After:

  ```nginx
  server {
      listen 443 ssl;
      add_header X-Frame-Options "SAMEORIGIN" always;
  }
  ```

  Also send `Content-Security-Policy: frame-ancestors 'self'` for current browsers.

- **Node.js / Express**

  Before:

  ```js
  app.use(express.static("public"));
  ```

  After:

  ```js
  app.use((req, res, next) => {
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
    next();
  });
  app.use(express.static("public"));
  ```

  Also send `Content-Security-Policy: frame-ancestors 'self'` for current browsers.

- **ASP.NET Core**

  Before:

  ```csharp
  app.UseStaticFiles();
  ```

  After:

  ```csharp
  app.Use(async (context, next) =>
  {
      context.Response.Headers["X-Frame-Options"] = "SAMEORIGIN";
      await next();
  });
  app.UseStaticFiles();
  ```

  Also send `Content-Security-Policy: frame-ancestors 'self'` for current browsers.

- **Spring Boot / Spring Security**

  Before:

  ```java
  http.headers(Customizer.withDefaults());
  ```

  After:

  ```java
  http.headers(h -> h
      .frameOptions(f -> f.sameOrigin()));
  ```

  Also send `Content-Security-Policy: frame-ancestors 'self'` for current browsers.

**How to recheck:**

- From a different local origin, embed the page in an <iframe>: the browser refuses to render it
- Pages that are legitimately embedded (e.g. portal widgets) still render inside their approved parent
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- HTML responses send CSP frame-ancestors 'self' (or an explicit allowlist) and/or X-Frame-Options DENY|SAMEORIGIN

**Must not break:** Inventory legitimate embedding (portals, SSO, map widgets) before choosing DENY. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

References: OWASP A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration · CWE CWE-1021 · WSTG WSTG-CLNT-09 · ASVS 5.0 V3 Web Frontend Security

Fingerprints: `e8e83ba35b2ee4153cc31db5` `537cf1850c28c8f706b2ddec`

#### 🟠 NSC-SESS-002 — Cookie without HttpOnly flag

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **CAUTION** | **low** | SESS | 1 |

**Why it matters:** Session-like cookies are readable by JavaScript (no HttpOnly), so any XSS can steal them.

**Expected:** Session/auth cookies have HttpOnly | Cookies intentionally read by JS (e.g. double-submit CSRF token) are documented exceptions

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/` | high | VALIDATED | Session-like cookie(s) readable by JavaScript; SESSIONID: HttpOnly missing on session-like cookie |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-SESS-002, transport direct-http)
- DevTools > Application > Cookies: HttpOnly ticked for session cookies

**How to fix:** Enable HttpOnly for session/auth cookies in the framework configuration.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **Node.js / Express**

  Before:

  ```js
  res.cookie("sid", sessionId);
  ```

  After:

  ```js
  res.cookie("sid", sessionId, { secure: true, httpOnly: true, sameSite: "lax", path: "/" });
  ```

- **ASP.NET Core**

  Before:

  ```csharp
  builder.Services.AddAuthentication().AddCookie();
  ```

  After:

  ```csharp
  builder.Services.AddAuthentication().AddCookie(o =>
  {
      o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
      o.Cookie.HttpOnly = true;
      o.Cookie.SameSite = SameSiteMode.Lax;
  });
  ```

- **Spring Boot / Spring Security**

  Before:

  ```properties
  # application.properties: session cookie defaults
  ```

  After:

  ```properties
  server.servlet.session.cookie.secure=true
  server.servlet.session.cookie.http-only=true
  server.servlet.session.cookie.same-site=lax
  ```

- **nginx**

  Before:

  ```nginx
  location / {
      proxy_pass http://app;
  }
  ```

  After:

  ```nginx
  location / {
      proxy_pass http://app;
      proxy_cookie_flags ~ secure httponly samesite=lax;
  }
  ```

  For cookies the application cannot change. Needs nginx 1.19.3 or newer.

**How to recheck:**

- DevTools > Application > Cookies: HttpOnly ticked for session cookies
- In Console, document.cookie does not show the session cookie
- Login/logout still work
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- Session/auth cookies have HttpOnly
- Cookies intentionally read by JS (e.g. double-submit CSRF token) are documented exceptions

**Must not break:** Front-end code that reads the cookie will break — search the client code for document.cookie usage first and move it to a header/endpoint.

References: OWASP A02:2025 Security Misconfiguration; A07:2025 Authentication Failures; A05:2021 Security Misconfiguration; A07:2021 Identification and Authentication Failures · CWE CWE-1004 · WSTG WSTG-SESS-02 · ASVS 5.0 V3 Web Frontend Security, V7 Session Management

Fingerprints: `61ec1e54ebcfb120565cf348`

#### 🟠 NSC-SESS-003 — Cookie SameSite missing or contradictory

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **CAUTION** | **low** | SESS | 1 |

**Why it matters:** Cookies omit SameSite, or set SameSite=None without Secure (rejected by modern browsers), weakening CSRF defences.

**Expected:** Session cookies set SameSite=Lax or Strict | Any SameSite=None cookie also has Secure and a documented cross-site need

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/` | high | VALIDATED | SameSite missing or contradictory; SESSIONID: SameSite missing |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-SESS-003, transport direct-http)
- DevTools > Application > Cookies: SameSite column

**How to fix:** Set SameSite=Lax by default; use None; Secure only for cookies that must travel cross-site (SSO, embedded apps).

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **Node.js / Express**

  Before:

  ```js
  res.cookie("sid", sessionId);
  ```

  After:

  ```js
  res.cookie("sid", sessionId, { secure: true, httpOnly: true, sameSite: "lax", path: "/" });
  ```

- **ASP.NET Core**

  Before:

  ```csharp
  builder.Services.AddAuthentication().AddCookie();
  ```

  After:

  ```csharp
  builder.Services.AddAuthentication().AddCookie(o =>
  {
      o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
      o.Cookie.HttpOnly = true;
      o.Cookie.SameSite = SameSiteMode.Lax;
  });
  ```

- **Spring Boot / Spring Security**

  Before:

  ```properties
  # application.properties: session cookie defaults
  ```

  After:

  ```properties
  server.servlet.session.cookie.secure=true
  server.servlet.session.cookie.http-only=true
  server.servlet.session.cookie.same-site=lax
  ```

- **nginx**

  Before:

  ```nginx
  location / {
      proxy_pass http://app;
  }
  ```

  After:

  ```nginx
  location / {
      proxy_pass http://app;
      proxy_cookie_flags ~ secure httponly samesite=lax;
  }
  ```

  For cookies the application cannot change. Needs nginx 1.19.3 or newer.

**How to recheck:**

- DevTools > Application > Cookies: SameSite column
- Test SSO/IdP callbacks and cross-site POST flows still keep the session
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- Session cookies set SameSite=Lax or Strict
- Any SameSite=None cookie also has Secure and a documented cross-site need

**Must not break:** SameSite=Strict/Lax can break SAML/OIDC form_post callbacks and payment redirects; test every external login/redirect flow.

References: OWASP A01:2025 Broken Access Control; A02:2025 Security Misconfiguration; A01:2021 Broken Access Control; A05:2021 Security Misconfiguration · CWE CWE-1275, CWE-352 · WSTG WSTG-SESS-02, WSTG-SESS-05 · ASVS 5.0 V3 Web Frontend Security, V7 Session Management

Fingerprints: `3ef098d4f9d97c697a600f59`

### 🟡 PLANNED — Schedule the fix

#### 🟡 NSC-SESS-004 — JWT missing protection claims or weak algorithm

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **PLANNED** | **medium** | SESS | 1 |

**Why it matters:** Observed JWTs use alg 'none', omit exp, or lack audience/issuer binding, so tokens live forever or can be replayed to other services.

**Expected:** alg is not 'none' | exp present and lifetime appropriate (e.g. <= 1h for access tokens) | aud and iss present and validated server-side

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/api/token` | high | VALIDATED | JWT missing protection claims or weak alg; token#1: alg=none; token#1: exp claim missing; token#1: iss claim missing; token#1: aud claim missing |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-SESS-004, transport direct-http)
- Log in, copy the token from DevTools > Network/Storage into a local decoder (offline), check claims

**How to fix:** Issue tokens with exp/iat/aud/iss; validate them on every API; reject alg none and unexpected algorithms.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **Node.js / Express**

  Before:

  ```js
  const claims = jwt.decode(token); // not verified
  ```

  After:

  ```js
  const claims = jwt.verify(token, key, {
    algorithms: ["HS256"],
    audience: "shop-api",
    issuer: "shop-auth",
  });
  // issue with: jwt.sign({ sub }, key, { algorithm: "HS256", expiresIn: "15m", audience: "shop-api", issuer: "shop-auth" })
  ```

  Uses the jsonwebtoken package. Never accept `alg: none`.

- **ASP.NET Core**

  Before:

  ```csharp
  o.TokenValidationParameters = new() { ValidateIssuer = false, ValidateAudience = false, ValidateLifetime = false };
  ```

  After:

  ```csharp
  o.TokenValidationParameters = new()
  {
      ValidateIssuer = true, ValidIssuer = "shop-auth",
      ValidateAudience = true, ValidAudience = "shop-api",
      ValidateLifetime = true, RequireExpirationTime = true,
      ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
  };
  ```

- **Spring Boot / Spring Security**

  Before:

  ```properties
  # resource server without issuer validation
  ```

  After:

  ```properties
  spring.security.oauth2.resourceserver.jwt.issuer-uri=https://auth.example.test/
  spring.security.oauth2.resourceserver.jwt.audiences=shop-api
  ```

**How to recheck:**

- Log in, copy the token from DevTools > Network/Storage into a local decoder (offline), check claims
- Use an expired test token: API returns 401
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- alg is not 'none'
- exp present and lifetime appropriate (e.g. <= 1h for access tokens)
- aud and iss present and validated server-side

**Must not break:** Adding aud/exp validation rejects old long-lived tokens: plan a token refresh window and communicate client changes.

**Limitations:**

- NavSentry decodes but never verifies or forges tokens.

References: OWASP A07:2025 Authentication Failures; A04:2025 Cryptographic Failures; A07:2021 Identification and Authentication Failures; A02:2021 Cryptographic Failures · CWE CWE-347, CWE-613 · WSTG WSTG-SESS-10 · ASVS 5.0 V9 Self-contained Tokens

Fingerprints: `f5515664499e6e3369c2e269`

### 🔵 OPTIONAL — Hardening: may be skipped with a recorded reason

#### 🔵 NSC-CONF-004 — MIME sniffing not disabled / insecure Content-Type

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **OPTIONAL** | **low** | CONF | 9 |

**Why it matters:** Responses with a body lack `X-Content-Type-Options: nosniff`, or omit Content-Type / charset, letting browsers guess the type.

**Expected:** Every response with a body has an explicit Content-Type | X-Content-Type-Options: nosniff on every response | text/html responses declare a charset

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/` | high | VALIDATED | text response without charset; X-Content-Type-Options: nosniff missing; text response without charset; X-Content-Type-Options: nosniff missing |
| `GET http://127.0.0.1:4173/api/profile` | high | VALIDATED | X-Content-Type-Options: nosniff missing |
| `GET http://127.0.0.1:4173/api/error` | high | VALIDATED | X-Content-Type-Options: nosniff missing |
| `GET http://127.0.0.1:4173/api/token` | high | VALIDATED | X-Content-Type-Options: nosniff missing |
| `GET http://127.0.0.1:4173/api/orders` | high | VALIDATED | X-Content-Type-Options: nosniff missing; X-Content-Type-Options: nosniff missing |
| `GET http://127.0.0.1:4173/api/orders/{{orderA}}` | high | VALIDATED | X-Content-Type-Options: nosniff missing |
| `GET http://127.0.0.1:4173/api/me` | high | VALIDATED | X-Content-Type-Options: nosniff missing |
| `GET http://127.0.0.1:4173/api/admin/stats` | high | VALIDATED | X-Content-Type-Options: nosniff missing |
| `GET http://127.0.0.1:4173/app/profile` | high | VALIDATED | X-Content-Type-Options: nosniff missing |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-CONF-004, transport direct-http)
- DevTools > Network: each document, script and JSON response shows Content-Type and nosniff

**How to fix:** Add `X-Content-Type-Options: nosniff` globally and make every handler set an accurate Content-Type (with charset for text).

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **nginx**

  Before:

  ```nginx
  server {
      listen 443 ssl;
      # no X-Content-Type-Options header
  }
  ```

  After:

  ```nginx
  server {
      listen 443 ssl;
      add_header X-Content-Type-Options "nosniff" always;
  }
  ```

  Every handler must also send an accurate Content-Type, with charset for text.

- **Node.js / Express**

  Before:

  ```js
  app.use(express.static("public"));
  ```

  After:

  ```js
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    next();
  });
  app.use(express.static("public"));
  ```

  Every handler must also send an accurate Content-Type, with charset for text.

- **ASP.NET Core**

  Before:

  ```csharp
  app.UseStaticFiles();
  ```

  After:

  ```csharp
  app.Use(async (context, next) =>
  {
      context.Response.Headers["X-Content-Type-Options"] = "nosniff";
      await next();
  });
  app.UseStaticFiles();
  ```

  Every handler must also send an accurate Content-Type, with charset for text.

- **Spring Boot / Spring Security**

  Before:

  ```java
  http.headers(Customizer.withDefaults());
  ```

  After:

  ```java
  http.headers(h -> h
      .contentTypeOptions(Customizer.withDefaults()));
  ```

  Every handler must also send an accurate Content-Type, with charset for text.

**How to recheck:**

- DevTools > Network: each document, script and JSON response shows Content-Type and nosniff
- Re-run → NSC-CONF-004 PASS
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- Every response with a body has an explicit Content-Type
- X-Content-Type-Options: nosniff on every response
- text/html responses declare a charset

**Must not break:** nosniff blocks scripts/styles served with a wrong type: fix wrong Content-Type on static files first. Run `navsentry compare` between the pre-fix and post-fix runs: every legitimate request must keep the same status, content type, non-security header set and JSON shape; only security headers may differ.

References: OWASP A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration · CWE CWE-16, CWE-430 · WSTG WSTG-CONF-12 · ASVS 5.0 V3 Web Frontend Security, V4 API and Web Service

Fingerprints: `524856164cab65da7f0ca455` `aef9e8a5b6b1e659dadc2fa1` `a2f6a8f688dc2ea498a0a7a9` `81e4f06fbc3ebd6e19ad70a2` `8abac78f653ee5b014e2f490` `887c9e474229a3f22403e9f7` `6b1e8104436e4050b9e69aea` `b8fb462c3914484b16461887` `61ef9ac144885a9aee7c1d64`

#### 🔵 NSC-CONF-006 — Unnecessary HTTP methods or method override enabled

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **OPTIONAL** | **low** | CONF | 5 |

**Why it matters:** The server advertises (Allow / Access-Control-Allow-Methods) methods such as TRACE, TRACK, PUT or DELETE on resources that do not need them, or honours X-HTTP-Method-Override.

**Expected:** OPTIONS on in-scope resources does not advertise TRACE/TRACK/CONNECT | Only methods actually used by the resource are advertised | Method-override headers are ignored (verified manually under safe-validate)

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `OPTIONS http://127.0.0.1:4173/` | high | VALIDATED | Dangerous methods advertised: TRACE; advertised: GET, POST, OPTIONS, TRACE |
| `OPTIONS http://127.0.0.1:4173/api/profile` | high | VALIDATED | Dangerous methods advertised: TRACE; advertised: GET, POST, OPTIONS, TRACE |
| `OPTIONS http://127.0.0.1:4173/api/error` | high | VALIDATED | Dangerous methods advertised: TRACE; advertised: GET, POST, OPTIONS, TRACE |
| `OPTIONS http://127.0.0.1:4173/api/token` | high | VALIDATED | Dangerous methods advertised: TRACE; advertised: GET, POST, OPTIONS, TRACE |
| `OPTIONS http://127.0.0.1:4173/go-out` | high | VALIDATED | Dangerous methods advertised: TRACE; advertised: GET, POST, OPTIONS, TRACE |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-CONF-006, transport direct-http)
- Send OPTIONS to the resource (NavSentry or curl -X OPTIONS -i) and inspect Allow

**How to fix:** Restrict methods per route at the web server/framework; disable TRACE; remove method-override middleware unless strictly required.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **nginx**

  Before:

  ```nginx
  location / {
      proxy_pass http://app;
  }
  ```

  After:

  ```nginx
  location / {
      limit_except GET HEAD POST { deny all; }
      proxy_pass http://app;
  }
  ```

- **Node.js / Express**

  Before:

  ```js
  app.use(methodOverride("_method"));
  ```

  After:

  ```js
  // method-override removed
  app.use((req, res, next) =>
    ["TRACE", "TRACK"].includes(req.method) ? res.sendStatus(405) : next());
  ```

**How to recheck:**

- Send OPTIONS to the resource (NavSentry or curl -X OPTIONS -i) and inspect Allow
- Re-run → NSC-CONF-006 PASS
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- OPTIONS on in-scope resources does not advertise TRACE/TRACK/CONNECT
- Only methods actually used by the resource are advertised
- Method-override headers are ignored (verified manually under safe-validate)

**Must not break:** CORS preflight legitimately needs OPTIONS: do not block OPTIONS globally, only restrict what it advertises. Keep the methods real clients use.

**Limitations:**

- OPTIONS itself being enabled is normal for CORS; SRC-E recorded it as an accepted Exception. NavSentry fails only on dangerous advertised methods.

References: OWASP A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration · CWE CWE-650, CWE-16 · WSTG WSTG-CONF-06 · ASVS 5.0 V13 Configuration, V4 API and Web Service

Fingerprints: `2c67c0722e7817b6d2c8bf9d` `2c2f89f8d79380769fbb925a` `c7c1849474ca4043dcd3c780` `82249f07a283138dc5d24c22` `5937abdc7d03f39d27e36260`

#### 🔵 NSC-CONF-007 — Insecure cache policy for sensitive responses

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **OPTIONAL** | **low** | CONF | 4 |

**Why it matters:** Authenticated or personal API/document responses are cacheable (no `Cache-Control: no-store`/`private`), so shared caches or the browser can retain them.

**Expected:** Responses served to authenticated actors or setting session cookies send `Cache-Control: no-store` (or `private, no-cache` where justified) | Static public assets may stay cacheable

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/` | high | VALIDATED | Sensitive response is cacheable; Cache-Control absent |
| `GET http://127.0.0.1:4173/api/profile` | high | VALIDATED | Sensitive response is cacheable; Cache-Control: public, max-age=600 |
| `GET http://127.0.0.1:4173/api/error` | high | VALIDATED | Sensitive response is cacheable; Cache-Control absent |
| `GET http://127.0.0.1:4173/app/profile` | high | VALIDATED | Sensitive response is cacheable; Cache-Control absent |

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

Fingerprints: `78cfb26ba86a9c964485e562` `973b78c7baf56069037bc3e8` `b2ae6e48d832d0fbdb60a801` `82c6f694fc9f9f46f387b272`

#### 🔵 NSC-INFO-001 — Server / framework version disclosure

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **OPTIONAL** | **low** | INFO | 10 |

**Why it matters:** Headers (Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version) or error pages reveal product versions, helping attackers pick exploits.

**Expected:** No response header or default error page exposes a product version number | X-Powered-By / X-AspNet-Version headers removed

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/` | high | VALIDATED | Product version disclosed; server: Apache/2.4.29 (Ubuntu); x-powered-by: PHP/7.2.1 |
| `GET http://127.0.0.1:4173/api/profile` | high | VALIDATED | Product version disclosed; server: Apache/2.4.29 (Ubuntu); x-powered-by: PHP/7.2.1 |
| `GET http://127.0.0.1:4173/api/error` | high | VALIDATED | Product version disclosed; server: Apache/2.4.29 (Ubuntu); x-powered-by: PHP/7.2.1 |
| `GET http://127.0.0.1:4173/api/token` | high | VALIDATED | Product version disclosed; server: Apache/2.4.29 (Ubuntu); x-powered-by: PHP/7.2.1 |
| `GET http://127.0.0.1:4173/go-out` | high | VALIDATED | Product version disclosed; server: Apache/2.4.29 (Ubuntu); x-powered-by: PHP/7.2.1 |
| `GET http://127.0.0.1:4173/api/orders` | high | VALIDATED | Product version disclosed; server: Apache/2.4.29 (Ubuntu); x-powered-by: PHP/7.2.1 |
| `GET http://127.0.0.1:4173/api/orders/{{orderA}}` | high | VALIDATED | Product version disclosed; server: Apache/2.4.29 (Ubuntu); x-powered-by: PHP/7.2.1 |
| `GET http://127.0.0.1:4173/api/me` | high | VALIDATED | Product version disclosed; server: Apache/2.4.29 (Ubuntu); x-powered-by: PHP/7.2.1 |
| `GET http://127.0.0.1:4173/api/admin/stats` | high | VALIDATED | Product version disclosed; server: Apache/2.4.29 (Ubuntu); x-powered-by: PHP/7.2.1 |
| `GET http://127.0.0.1:4173/app/profile` | high | VALIDATED | Product version disclosed; server: Apache/2.4.29 (Ubuntu); x-powered-by: PHP/7.2.1 |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-INFO-001, transport direct-http)
- DevTools > Network > Response Headers: no version numbers

**How to fix:** Remove/blank version headers at the server/proxy (e.g. server_tokens off, removeServerHeader, enableVersionHeader=false) and use custom error pages.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **nginx**

  Before:

  ```nginx
  http {
  }
  ```

  After:

  ```nginx
  http {
      server_tokens off;
      proxy_hide_header X-Powered-By;
  }
  ```

- **Node.js / Express**

  Before:

  ```js
  const app = express();
  ```

  After:

  ```js
  const app = express();
  app.disable("x-powered-by");
  ```

- **ASP.NET Core**

  Before:

  ```csharp
  var builder = WebApplication.CreateBuilder(args);
  ```

  After:

  ```csharp
  var builder = WebApplication.CreateBuilder(args);
  builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false);
  ```

**How to recheck:**

- DevTools > Network > Response Headers: no version numbers
- Request a non-existent path: error page shows no version
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- No response header or default error page exposes a product version number
- X-Powered-By / X-AspNet-Version headers removed

**Must not break:** Header removal does not change bodies; confirm with `navsentry compare` (Server/X-Powered-By are excluded from the contract).

**Limitations:**

- Version hiding is defence in depth, not a fix for an unpatched component (see NSC-SUPPLY-001).

References: OWASP A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration · CWE CWE-200, CWE-497 · WSTG WSTG-INFO-02 · ASVS 5.0 V13 Configuration

Fingerprints: `65014b06eef67557fa1224fa` `96c85dadbfe772b1946bb878` `81615fe0efd01296eabb4b0e` `567f8480c5da9b5ed13762ea` `40d2944d5782beb316fdf3df` `b6438cdb4cfb8485c2c39cb4` `10818924dc8a1a6ca8a01ce1` `557b65c1e49e747d5e8b1ff7` `f3e727a639f1686ee83fcfde` `4bab2545a1262edeea8cda03`

#### 🔵 NSC-INFO-003 — Internal IP address disclosure

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **OPTIONAL** | **low** | INFO | 1 |

**Why it matters:** Response headers or bodies contain RFC 1918 / loopback / link-local addresses, revealing internal topology.

**Expected:** No in-scope response contains private IPv4/IPv6 literals in headers or bodies

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/api/profile` | medium | SUSPECTED | Private IP address literals disclosed; headers: 0 match(es); body: 1 match(es); values masked |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-INFO-003, transport direct-http)
- Search the raw response (DevTools > Network > Response) for 10./172.16-31./192.168. patterns

**How to fix:** Stop echoing upstream addresses (Via, X-Backend-Server, error messages, config endpoints); configure the proxy to strip them.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **nginx**

  Before:

  ```nginx
  location / {
      proxy_pass http://10.0.0.12:8080;
  }
  ```

  After:

  ```nginx
  location / {
      proxy_pass http://10.0.0.12:8080;
      proxy_hide_header X-Backend-Server;
      proxy_hide_header Via;
  }
  ```

- **Node.js / Express**

  Before:

  ```js
  res.json({ ok: true, node: os.hostname(), ip: req.socket.localAddress });
  ```

  After:

  ```js
  res.json({ ok: true });
  ```

**How to recheck:**

- Search the raw response (DevTools > Network > Response) for 10./172.16-31./192.168. patterns
- Re-run → NSC-INFO-003 PASS
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- No in-scope response contains private IPv4/IPv6 literals in headers or bodies

**Must not break:** If a client legitimately consumes an address field (e.g. a config endpoint), replace it with a public hostname rather than removing the field; verify JSON shape with `navsentry compare`.

**Limitations:**

- Dotted version/build strings that start with 10. or 192.168. can match; review context before VALIDATED.

References: OWASP A02:2025 Security Misconfiguration; A05:2021 Security Misconfiguration · CWE CWE-200 · WSTG WSTG-INFO-05 · ASVS 5.0 V13 Configuration

Fingerprints: `3cb08c2e2fd70219f7d3f68a`

### ⚪ INFO — Observation only: no action needed

#### ⚪ NSC-INFO-004 — Email address disclosure

| Action | Severity | Category | Affected targets |
|---|---|---|---|
| **INFO** | **info** | INFO | 1 |

**Why it matters:** Responses expose email addresses (often staff/developer addresses in config or API payloads) that enable phishing and enumeration.

**Expected:** Anonymous responses expose no personal/staff email except intentional public contact addresses listed by the owner

**Observed (redacted):**

| Target | Confidence | Lifecycle | Observed |
|---|---|---|---|
| `GET http://127.0.0.1:4173/api/profile` | medium | SUSPECTED | 1 email address(es) in response; count: 1; domain shapes: *.example; addresses masked |

**How to reproduce:**

- navsentry test --config <manifest>  (rule NSC-INFO-004, transport direct-http)
- Open the endpoint anonymously and search the response for '@'

**How to fix:** Remove addresses from config/diagnostic endpoints; return them only to authorized users who need them.

**Fix examples (reviewed examples; NavSentry does not execute them):**

- **Any stack**

  Before:

  ```js
  res.json({ app: "shop", support: "<staff-email>" });
  ```

  After:

  ```js
  res.json({ app: "shop" }); // contact details only for authorized users
  ```

**How to recheck:**

- Open the endpoint anonymously and search the response for '@'
- Re-run → NSC-INFO-004 PASS or reviewed DISMISSED for intentional contacts
- Run the same NavSentry scan again and compare it with this run.

**Fixed when:**

- Anonymous responses expose no personal/staff email except intentional public contact addresses listed by the owner

**Must not break:** If a UI shows an email field to its owner, keep it for the authenticated owner; remove it only from anonymous/other-user responses.

**Limitations:**

- Public contact addresses are expected; record them as reviewed exceptions instead of failing forever.

References: OWASP A01:2025 Broken Access Control; A01:2021 Broken Access Control · CWE CWE-200, CWE-359 · WSTG WSTG-INFO-05 · ASVS 5.0 V14 Data Protection

Fingerprints: `8d3f0ad3b969625397e56ce9`

## Fix verification

No previous run compared. After a fix, run the same scan again and use `navsentry compare --before <dir> --after <dir>`.

## Known vulnerabilities

- Snapshot `2026-11-04.1` · sha256 `42e5d2a7d39cf6e2` · 3 record(s), 3 reviewed, 0 stale · oldest verification 2026-11-03
- Offline snapshot: it cannot prove that no newer advisory exists. Zero matches never means no vulnerabilities.

### Known vulnerability applicability

| Product (evidence) | Record | Identifiers | Severity (source) | Applicability | Case | Caveats |
|---|---|---|---|---|---|---|
| server/apache-httpd 2.4.29 (http-banner) | — | — | — | **unknown** | NSC-SUPPLY-001 | no records in the snapshot |
| runtime/php 7.2.1 (http-banner) | — | — | — | **unknown** | NSC-SUPPLY-001 | no records in the snapshot |

## Coverage

| Case | Title | Status | Targets | Reason |
|---|---|---|---|---|
| NSC-CONF-001 | HSTS missing or weak | NOT_TESTED | 0 | plain HTTP target |
| NSC-CONF-002 | Content Security Policy missing or unsafe | FAIL | 6 |  |
| NSC-CONF-003 | Clickjacking protection missing | FAIL | 6 |  |
| NSC-CONF-004 | MIME sniffing not disabled / insecure Content-Type | FAIL | 25 |  |
| NSC-CONF-009 | Configuration or VCS files publicly reachable | NOT_TESTED | 0 | not exercised by this run's targets |
| NSC-CONF-005 | Debug mode / development features enabled | NOT_TESTED | 0 | evidence collection needs an operator/agent; see the case's agent prompt |
| NSC-CONF-006 | Unnecessary HTTP methods or method override enabled | FAIL | 5 |  |
| NSC-CONF-007 | Insecure cache policy for sensitive responses | FAIL | 20 |  |
| NSC-CONF-008 | HTTP request smuggling / desync | NOT_TESTED | 0 | requires active payloads; never automated without active-approved authorization |
| NSC-INFO-001 | Server / framework version disclosure | FAIL | 29 |  |
| NSC-INFO-007 | Secrets embedded in client-side assets | NOT_TESTED | 0 | not exercised by this run's targets |
| NSC-INFO-006 | Sensitive data written to the browser console | NOT_TESTED | 0 | no JS runtime (http engine) |
| NSC-INFO-008 | Source maps with source content served publicly | NOT_TESTED | 0 | not exercised by this run's targets |
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
| NSC-AC-008 | Open redirect | NOT_TESTED | 0 | not exercised by this run's targets |
| NSC-AC-004 | Permissive CORS policy | FAIL | 5 |  |
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
| NSC-SUPPLY-001 | Unpatched server component with known vulnerabilities | NOT_TESTED | 0 | applicability unknown: no records in the snapshot |
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

- `http://127.0.0.1:4173/go-out` as anonymous
  - 302 `http://127.0.0.1:4173/go-out` → `http://evil.example/steal` · not followed: origin http://evil.example is not in targets.origins
- `http://127.0.0.1:4173/go-out` as reader_a
  - 302 `http://127.0.0.1:4173/go-out` → `http://evil.example/steal` · not followed: origin http://evil.example is not in targets.origins
- `http://127.0.0.1:4173/go-out` as reader_b
  - 302 `http://127.0.0.1:4173/go-out` → `http://evil.example/steal` · not followed: origin http://evil.example is not in targets.origins
- `http://127.0.0.1:4173/go-out` as admin
  - 302 `http://127.0.0.1:4173/go-out` → `http://evil.example/steal` · not followed: origin http://evil.example is not in targets.origins

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
| unknown-product | server/apache-httpd 2.4.29 | no records for this product in the snapshot (not proof of absence) |
| unknown-product | runtime/php 7.2.1 | no records for this product in the snapshot (not proof of absence) |

## Run details

- Budget: 39/100 requests · denied before execution 4

### Fixtures and cleanup

Not used (observe mode).

### Capture

| Wire bytes | Decoded bytes | Truncated | Aborted | Partially inspected bodies |
|---|---|---|---|---|
| 2067 | 2067 | 0 | 0 | 0 |

### Workspace

None.

## Flows

- 2 flows / 11 steps · Functional result: **FAIL**
- URLs covered beyond seed paths: 5
- Findings raised by flow requests: 22
- Details: [TEST-REPORT.md](TEST-REPORT.md)
