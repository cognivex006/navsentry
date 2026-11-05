# SPEC 0.2.0 — M2 safe-validate: login actors, fixture mutations and cleanup

- Status: **ACCEPTED** · Drafted: 2026-11-04 · Review: round 1 done 2026-11-04, 22 findings resolved ([§13](#13-review-log)) · Owner decisions D1–D9: decided 2026-11-04 with the recommended options ([§12](#12-owner-decisions)) · Implementation: 0.2.0-a in progress on `feat/0.2.0-a` (tests 1–7)
- Related: [DEV-PLAN](../DEV-PLAN.md) M2 · [SPEC-0.1.2](SPEC-0.1.2-FLOW-TEST-CASES.md) §16 · [SPEC-0.1.3](SPEC-0.1.3-SCAN-MODES-AND-WORKSPACE.md) · ADR-0004, ADR-0008, ADR-0009 · TM-03
- Cases: NSC-AC-002, NSC-AC-003 (modification), NSC-AC-006, NSC-AUTH-002, NSC-BIZ-001, NSC-INJ-004 (reflection only)
- No code may be written for a milestone below until this spec is ACCEPTED and its owner decisions are recorded.

## 0. สรุปสำหรับเจ้าของงาน
- M2 เพิ่มโหมด `safe-validate`: ทดสอบที่ **เปลี่ยนข้อมูลได้** แต่เฉพาะกับ **ข้อมูลทดสอบที่เจ้าของประกาศไว้** (fixture) และต้อง **ลบคืนทุกครั้ง** (cleanup)
- ใช้ได้เฉพาะ development profile (`local` / `dev`) staging และ production ยังเป็น observe อย่างเดียว (แก้ bug ที่ staging ผ่านการตรวจไปแล้วใน PR นี้)
- เพิ่ม login ด้วย username/password จาก env, actor แบบ cookie session, CSRF, session หลัง logout และกฎธุรกิจที่เจ้าของประกาศ
- **ยังไม่มี payload โจมตี** (injection, brute force, DoS) ตามกฎข้อ 6 XSS ทำได้แค่ดูว่าข้อความ marker ธรรมดาสะท้อนกลับมาไหม
- ถ้าลบข้อมูลทดสอบคืนไม่สำเร็จ หรือไม่แน่ใจว่าสร้างไปแล้วหรือยัง run เป็น FAILED พร้อมรายการที่ต้องลบเอง
- visual driver ยังเป็น observe อย่างเดียวใน 0.2.0 (ยังไม่พิมพ์)
- เจ้าของตัดสินใจครบ 9 ข้อแล้ว (2026-11-04) ใช้ตัวเลือกที่แนะนำทั้งหมด

## 1. Goals
| ID | Goal |
|---|---|
| M2-G1 | Login actors: username/password from `*_env` through a declared login, and cookie-session actors, each in its own isolated context. |
| M2-G2 | Mutation steps in `safe-validate`, restricted to owner-declared fixture and auth endpoints, with tracked, verified cleanup. |
| M2-G3 | NSC-AC-003 modification with an executed positive control. |
| M2-G4 | NSC-AC-006 CSRF for cookie-session actors. |
| M2-G5 | NSC-AUTH-002 session reuse after logout. |
| M2-G6 | NSC-BIZ-001 owner-declared invariants on fixture objects. |
| M2-G7 | `fill`, `select` and `submit` flow steps on the playwright engine under the same rules. |
| M2-G8 | NSC-INJ-004 limited to a plain marker reflection observation. |

## 2. Non-goals
- Any injection, smuggling, brute-force, fuzzing or DoS payload (hard rule 6); these need a future `active-approved` design.
- Mutations in the production profile (`staging`, `production` or an unrecognized environment).
- Mutations outside declared fixture and auth endpoints, or endpoints NavSentry discovers or guesses.
- Typing or mutations in the visual driver (`navsentry browse`): it stays observe-only in 0.2.0 (review #16). A later spec may add a fixture lifecycle there.
- Credential stuffing, password policy, MFA bypass and lockout tests.

## 3. Safety model

### 3.1 Modes and profiles
| Profile | `observe` | `safe-validate` |
|---|---|---|
| development (`local`, `dev`) | allowed | allowed, with §3.2 |
| production (`staging`, `production`, unrecognized) | allowed | refused at config time |

The config check uses the profile, not the environment name (fixed with this spec: `src/config.ts` previously compared `environment === "production"`, so `staging` passed; review #6). `safety.allow_mutations` stays rejected, and `safety.allowed_methods` stays observe-only: mutation permission exists only as declared entries (§3.2), never as one boolean or method list.

### 3.2 Manifest additions (development profile, `safe-validate` only)
```json
{
  "safety": { "mode": "safe-validate", "max_mutations": 20, "cleanup_window_seconds": 30 },
  "auth_endpoints": {
    "login":  { "method": "POST", "path": "/api/session" },
    "logout": { "method": "POST", "path": "/api/session/logout" }
  },
  "fixtures": {
    "orders": {
      "owner_actor": "reader_a",
      "cleanup_actor": "fixture_admin",
      "create":   { "method": "POST",   "path": "/api/test-fixtures/orders", "body": { "json": { "note": "{{marker}}" } }, "extract": { "id": "/id" } },
      "exists":   { "method": "GET",    "path": "/api/orders/{{id}}", "expect_status": [200] },
      "cleanup":  { "method": "DELETE", "path": "/api/test-fixtures/orders/{{id}}", "expect_status": [200, 204, 404] },
      "verify_gone": { "method": "GET", "path": "/api/orders/{{id}}", "expect_status": [404, 410] },
      "allowed_mutations": [
        { "method": "PATCH", "path": "/api/orders/{{id}}", "content_type": "application/json", "max_body_bytes": 4096 },
        { "method": "POST",  "path": "/api/orders/{{id}}/cancel", "content_type": "application/x-www-form-urlencoded", "max_body_bytes": 1024, "csrf": { "token_from": { "cookie": "csrf_token" }, "send_as": { "header": "x-csrf-token" } } }
      ]
    }
  }
}
```
- Every declared path must be in `allowed_paths` and outside `denied_paths`, checked at config time. A violation is a config error (exit 3).
- `{{id}}` is the only placeholder in fixture paths. `exists`, `cleanup` and `verify_gone` run as `cleanup_actor` (default: `owner_actor`; review #13, #14).
- `max_mutations` (default 20, max 200) counts every non-observe request, including login and logout.
- `cleanup_window_seconds` (default 30, 10–300): creates stop when less than this remains before the run deadline or `authorization.expires_at` (§6.1).

### 3.3 Request matching (S13) and identifiers
- **ScopeGate gains `checkMutation(url, method, entry)`** (review #10). `checkRequest` is unchanged and keeps refusing every non-observe method for all observe paths. `checkMutation` runs the same origin, scheme, port, credential, path-glob and address checks, then requires the method to equal the entry's method and the **final normalised** `URL.pathname` to match the entry's template with exactly one path segment per placeholder (review #1). It runs before the request and again at connect time (the DNS check), like `checkRequest`.
- **Identifiers** (`{{id}}`, imported or extracted variables used in mutation paths) must be a JSON string or integer matching `^[A-Za-z0-9_-]{1,128}$`; `.`, `..`, empty and anything with `%`, `/`, `?`, `#` or `~` are refused before the URL is built. After building, the template match is checked on the parsed URL, so normalisation cannot change which entry matched.
- **Redirects** (review #9): direct-http never follows a redirect from a mutation, login, logout, cleanup or `verify_gone` request; a 3xx is a result. In the browser, every hop is a new routed request and is matched again; a 307/308 to an undeclared path is refused.
- **Browser requests** (review #8): the route handler forwards `postData` to direct-http (which gains a bounded request body). A browser non-observe request is fulfilled only if `checkMutation` matches an `allowed_mutations`, `create`, `login` or `logout` entry, its `content-type` equals the entry's, and its body is within `max_body_bytes`. Its sha256 is recorded, never its content. NavSentry cannot vet what a page puts in a form body beyond type and size; that residual is stated in TM-32.

### 3.4 Invariants (new, testable)
| ID | Invariant |
|---|---|
| S13 | A non-observe request is sent only if `checkMutation` matches a declared `create`, `allowed_mutations`, `cleanup`, `login` or `logout` entry, in the development profile, in `safe-validate`, inside the authorization window, within `max_mutations`, and (for creates) with the cleanup reserve held. Otherwise it is refused before any byte is sent. This holds for http steps, browser requests (including page JavaScript `fetch`/XHR, not only form submits), redirects and retries. |
| S14 | Before a create is sent, its intent is appended to `fixtures.pending.json` in the work directory (fsync). Every create whose id was extracted is registered for cleanup before the next request. Cleanup runs for every registered object at normal end, after failures, after budget or mutation-limit exhaustion and on the first SIGINT/SIGTERM, within the reserve and the window of §6.1. |
| S15 | A run is `executionStatus: FAILED` (exit 2) and lists leftovers if any registered object was not cleaned and verified gone, or if any create's outcome is unknown (timeout, reset, truncated or unparseable response; review #5). It is never COMPLETE. |
| S16 | For http steps, mutation bodies are built only from the declared JSON body template, run variables and the run marker; no string is interpreted as code, markup or a query. For browser requests, the body is built by the page and is bounded by the entry's content type and size (§3.3). |
| S17 | Credentials (`password_env`, `cookie_env`, session cookies, tokens) never appear in artifacts, logs, page models or console facts; they are known secrets of the Redactor. `cookie_env` is refused in the production profile, as live tokens are. |

### 3.5 Run marker
- A random marker `nsv-<16 hex>` per run, independent of the run ID, recorded in run.json (review #19). It is available as `{{marker}}`.
- `x-navsentry-run` is added to every request NavSentry sends, including browser-originated mutations fulfilled through direct-http.
- Cleanup acts only on ids this run extracted. It never deletes by search, by marker or by type.

## 4. Flow format and config changes (additive)

### 4.1 Mutation steps
```json
{ "id": "S3", "action": "http", "actor": "reader_b",
  "request": { "method": "PATCH", "path": "/api/orders/{{orderA}}", "body": { "json": { "note": "{{marker}}" } } },
  "fixture": "orders", "expect": { "access": "denied", "deny_status": [403, 404] }, "object_owner": "reader_a" }
```

### 4.2 Fixture steps
- `{ "action": "fixture_create", "fixture": "orders", "actor": "reader_a", "as": "orderA" }`: holds the cleanup reserve, writes the pending intent, creates, extracts and validates the id, registers cleanup, then runs `exists` as the positive control. A failed `exists` makes the step ERROR, and the object stays registered for cleanup.
- `{ "action": "fixture_verify_gone", "var": "orderA" }`: optional mid-flow check.
- Cleanup has no step: it is automatic (S14).

### 4.3 Actors
```json
"actors": {
  "reader_a": { "login": { "flow": "login-reader-a" }, "username_env": "NS_A_USER", "password_env": "NS_A_PASS" },
  "reader_b": { "login": { "http": "login", "body": { "json": { "user": "{{username}}", "password": "{{password}}" } } }, "username_env": "NS_B_USER", "password_env": "NS_B_PASS" },
  "reader_c": { "cookie_env": "NS_C_COOKIE" },
  "fixture_admin": { "authorization_header_env": "NS_FIXTURE_ADMIN" }
}
```
- A browser login is a referenced flow: `navigate` → `fill` (values only `{{username}}`/`{{password}}`) → `submit` → `see`. Its submit must match `auth_endpoints.login` (S13).
- An http login sends the declared body to `auth_endpoints.login`; the response's `set-cookie` becomes the actor's session.
- A failed login makes that actor's steps NOT_TESTED "login failed", never a FAIL of the target, and that actor may not create fixtures.
- A fixture's `cleanup_actor` may not be logged out during the run (lint error), so cleanup keeps a session (review #13).

### 4.4 Exact parser and config changes (review #12)
| Where | Change |
|---|---|
| `src/flow/parse.ts` step keys | add `fixture`, `as`, `var`; `request.body` as `{json: object}` (string leaves, 4 KiB after filling) |
| `ACTIONS` / `UI_ACTIONS` | add `fixture_create`, `fixture_verify_gone`; `fill`/`select`/`submit` become executable in `safe-validate` on the playwright engine |
| `request.method` | `POST`/`PUT`/`PATCH`/`DELETE` only with `fixture` set and a matching entry (lint) |
| `src/config.ts` actor keys | add `login`, `cookie_env`; `cookie_env` refused in production |
| `src/config.ts` top level | add `fixtures`, `auth_endpoints`; both only with `safe-validate` + development |
| `safety` keys | add `max_mutations`, `cleanup_window_seconds` |
| lint | every placeholder in a mutation path is an id variable; no logout of a `cleanup_actor`; `csrf` only on cookie-session actors' entries |

### 4.5 Approval and hashing (review #11)
`content_sha256` of a flow that uses `fixture`, `fixture_create` or a login gains the canonical JSON of the referenced fixture entries, `auth_endpoints` entries and referenced login flows. Editing any of them invalidates approval. `flow approve` prints the fixture and auth paths being approved.

## 5. Security checks
### 5.1 NSC-AC-003 modification
Positive control: owner A modifies A's fixture object (allowed). Then actor B tries the same mutation (must be denied). A same-contract 2xx for B is FAIL; A then reads the object, and whether B's change took effect is reported. VALIDATED needs an approved flow.

### 5.2 NSC-AC-006 CSRF (review #15)
Only for cookie-session actors (login or `cookie_env`) and entries with `csrf`; header-token actors are NOT_TESTED "CSRF needs a cookie session".
1. Control: cookie + token sent as declared + `Origin` and `Referer` equal to the target origin → must succeed.
2. Cookie, no token, same origin → must be rejected.
3. Cookie + token + `Origin: https://navsentry-csrf-probe.invalid` and no `Referer` → must be rejected.
Rejected means 401, 403, 419, 422 or a redirect to `login_path`. 2xx with the control's contract is FAIL. Every probe is a fixture mutation under S13 and counts against `max_mutations`.

### 5.3 NSC-AUTH-002 session after logout
Positive control: an authenticated read; then `auth_endpoints.logout`; then the same read with the pre-logout session. 2xx with the same contract → FAIL; 401/403/redirect to `login_path` → PASS. The logged-out actor is never a `cleanup_actor`.

### 5.4 NSC-BIZ-001 invariants
Owner-declared only, on fixture objects: JSON-pointer comparisons (`>=`, `<=`, `==`, `!=`, `in`) and forbidden transitions. NavSentry never invents an invariant.

### 5.5 NSC-INJ-004 (review #22)
The marker (letters and digits only) is placed by a create or `fill`. If a later page shows it inside an attribute or script context, that is recorded as a fact in `run.json → observations`, never a case result. NSC-INJ-004 stays NOT_TESTED: "testing output encoding needs an injection payload (active-approved)". The catalog entry's evidence and webRecheck are updated to say so.

## 6. Cleanup and failure semantics
### 6.1 Budget and time (review #2, #3)
- `Budget` gains `reserve(n)`, `release(n)` and `takeReserved()`. A create first reserves its worst-case cleanup cost `2 × (1 + (verify_gone ? 1 : 0))` (one retry each). It is refused if the reserve cannot be held within `max_requests`. Cleanup requests draw from the reserve and are still rate-limited.
- Creates stop when the time left before the earlier of the run deadline and `authorization.expires_at` is less than `cleanup_window_seconds`. Cleanup must finish inside that window. Nothing is sent after the authorization window, not even cleanup; anything not cleaned by then is a leftover.

### 6.2 Order, retries, signals
- Reverse creation order, as `cleanup_actor`.
- Retries only for `cleanup` and `verify_gone`: one retry after 1 s on a network error or 5xx (review #17). A 404 on cleanup counts as done. Creates, mutations, login and logout are never retried.
- **Signal coordinator** (review #4): it replaces the immediate exit in `beginRun` for safe-validate runs. The first SIGINT/SIGTERM stops new requests, runs cleanup within the window (at most 30 s), writes reports, then releases the work directory and exits. A second signal skips cleanup, writes the leftover list and `fixtures.pending.json`, then exits.
- SIGKILL: `fixtures.pending.json` (written before each create) survives. The next run's sweep reports those entries as possible leftovers, with fixture names and display ids, and never deletes them.

### 6.3 Leftovers (review #20)
`run.json → fixtures.leftovers[]` records the fixture, display id (or "unknown — create outcome lost", with the marker), last status and reason. REPORT.md lists them with the exact manual action. The consumer skill tells the user which objects to remove and never improvises a delete. Agent-facing summaries mask ids the same way as other identifier-like path segments. Test fixtures use synthetic ids only.

## 7. Reports and wire model (review #18)
- REPORT.md: *Fixtures and cleanup* (created, cleaned, verified gone, leftovers) and *Mutations* (method, display path, fixture or auth entry, actor, status, body hash).
- run.json: `fixtures`, `mutations`, `observations` and `marker` blocks, documented in `src/types.ts`. Schema version stays 1, because these are additive and `executionStatus: FAILED` and exit 2 already exist in v1. CHANGELOG states the new FAILED cause.

## 8. Threat model additions
| ID | Threat | Control | Residual |
|---|---|---|---|
| TM-32 | A mutation hits real data | Development only; declared entries only; `checkMutation` on the normalised path; strict ids; no redirects followed; cleanup by id only | A mis-declared fixture endpoint can touch real data; a browser form body is checked only for type and size |
| TM-33 | Test data is left behind | Pending intent before create; reserve; cleanup window; retries; verify_gone; FAILED with leftovers; sweep reports pending entries | Side effects (emails, webhooks, audit rows) are not cleaned |
| TM-34 | Credentials leak through login | Env-only values; known Redactor secrets; never in page models or console facts | — |
| TM-35 | CSRF probe treated as an attack | Reserved `.invalid` origin; only owner-marked entries; counts against `max_mutations` | — |

## 9. Acceptance tests (fixture only, 127.0.0.1)
1. Config: `fixtures` with observe; `safe-validate` with `staging`, `production` or an unrecognized environment; an out-of-scope fixture path; `allow_mutations: true`; `cookie_env` in production → exit 3 with zero requests.
2. S13 refusals before sending, with the fixture server seeing no non-observe request: an undeclared POST from an http step, a form submit, a page JavaScript `fetch` POST and a 307 to an undeclared path.
3. Ids: `..`, `%2e%2e`, `a/b`, `?x`, `#`, `~`, empty and 200-character ids are refused before a URL is built; a DELETE never reaches the collection path.
4. Cleanup: runs after a failing step, after `max_requests` or `max_mutations` is exhausted (the reserve still covers cleanup), and on a first SIGINT. This uses a deterministic harness in which the fixture server holds a request until the signal is sent. A second SIGINT writes the leftovers and pending file and exits.
5. Reserve and window: a create is refused when the reserve does not fit, and when less than `cleanup_window_seconds` remains; no request is sent after `expires_at`.
6. Lost create: a server that times out or truncates the create response gives FAILED, exit 2 and an "unknown outcome" leftover with the marker; the create is not retried.
7. Leftovers: a server refusing DELETE, or `verify_gone` still seeing the object, gives FAILED with a leftover; after a simulated kill, the next sweep reports `fixtures.pending.json` entries and deletes nothing.
8. AC-003 modification: vulnerable → FAIL VALIDATED (approved); secure → PASS; no positive control → INCONCLUSIVE.
9. AC-006: vulnerable → FAIL; secure → PASS; header-token actor → NOT_TESTED; only the `.invalid` origin is used.
10. AUTH-002: vulnerable → FAIL; secure → PASS; logging out a `cleanup_actor` is a lint error.
11. BIZ-001: violated invariant → FAIL; secure → PASS; none declared → NOT_TESTED.
12. Login: browser and http login; wrong password → NOT_TESTED "login failed" and no creates; no password, cookie or token in any artifact.
13. Approval: editing a referenced fixture entry, auth entry or login flow invalidates the flow's approval.
14. INJ-004: a reflected marker is a fact in `observations`, and the case stays NOT_TESTED with the reason.
15. Visual driver in `safe-validate`: still observe-only; a non-observe request from the page is refused.

## 10. Milestones
| Milestone | Scope | Depends on |
|---|---|---|
| 0.2.0-a | Config keys and refusals; `checkMutation`; id rules; Budget reserve; cleanup window; pending intents; fixture registry, cleanup and leftovers; signal coordinator; http mutation steps without redirects; reports; tests 1–7 | spec ACCEPTED, D1–D4, D9 |
| 0.2.0-b | Request bodies in direct-http; browser `postData` matching; login and cookie-session actors; `fill`/`select`/`submit`; approval hashing; tests 2 (browser), 12, 13, 15 | a, D5, D6 |
| 0.2.0-c | AC-003 modification, AC-006, AUTH-002 flows and catalog updates; tests 8–10 | a, b, D7 |
| 0.2.0-d | BIZ-001 invariants, INJ-004 observation; tests 11, 14 | a, D8 |

## 11. Docs to update with the implementation
FLOWS.md, flow examples, README and CLI help, ARCHITECTURE, THREAT-MODEL (TM-32 to TM-35), SKILL.md (declaring fixtures, never improvising a delete, reporting leftovers), the catalog entries and milestones for the cases in §5, CHANGELOG and DEV-PLAN.

## 12. Owner decisions
Decided 2026-11-04: the owner accepted every recommended option below.

| ID | Question | Decision (recommended) |
|---|---|---|
| D1 | Should `safe-validate` stay development-only? | Yes. Staging is the production profile and stays observe-only. |
| D2 | What is the default and maximum for `max_mutations`? | 20 and 200. |
| D3 | What happens when cleanup fails or a create's outcome is unknown? | FAILED, exit 2, a leftover list; the agent never retries with its own delete. |
| D4 | Should `exists` after create and `verify_gone` after cleanup be required? | `exists` required; `verify_gone` required when the API can show deletion, and recommended in the docs. |
| D5 | Should login go through the browser, over http, or both? | Both. Browser for login pages; http for APIs. |
| D6 | May the visual driver type in 0.2.0? | No. It stays observe-only; a later spec adds its own fixture lifecycle. |
| D7 | Should the CSRF probe use a fixed reserved origin? | Yes: `https://navsentry-csrf-probe.invalid`. |
| D8 | INJ-004 in M2? | A marker reflection fact only; encoding tests wait for `active-approved`. |
| D9 | Is cleanup allowed after `authorization.expires_at`? | No. Creates stop `cleanup_window_seconds` before the earlier deadline; nothing is sent after the window. |

## 13. Review log
### Round 1 — 2026-11-04 (independent fresh-context agent review against the code and specs)
22 findings (8 High, 9 Medium, 5 Low); all resolved in this revision.

| # | Severity | Finding | Resolution |
|---|---|---|---|
| 1 | High | An extracted id such as `..` could widen a DELETE after URL normalisation; the matching point was unclear. | §3.3: strict id pattern; match on the normalised pathname, one segment per placeholder; test 3. |
| 2 | High | The Budget deadline would block cleanup, contradicting "always clean up". | §6.1, D9: creates stop at the cleanup window; nothing is sent after the authorization window; test 5. |
| 3 | High | No reserve API existed in `Budget`, and the reserve was not sized. | §6.1: `reserve`/`release`/`takeReserved`, with the worst-case cost reserved per create. |
| 4 | High | `beginRun`'s SIGINT handler exits immediately, so signal cleanup was impossible. | §6.2: signal coordinator; second-signal behaviour; pending intent written before each create. |
| 5 | High | A create with a lost response leaves an untracked object. | S14, S15: pending intent; unknown outcome means FAILED; never retried; test 6. |
| 6 | High | `staging` + `safe-validate` passed the config check (`environment === "production"`). | Fixed in code with this spec (profile-based check and a test); §3.1; test 1. |
| 7 | High | HTTP login and logout were mutations without a declaration. | `auth_endpoints` added and matched by S13. |
| 8 | High | S16 cannot hold for browser-built bodies; the route handler did not forward bodies. | §3.3: `postData` forwarded; content type and size checked; body hash recorded; S16 narrowed; TM-32 residual. |
| 9 | Medium | Redirects from mutations were unspecified and could repeat a method to a new path. | §3.3: no redirects followed for mutation-class requests; the browser re-matches each hop; test 2. |
| 10 | Medium | ScopeGate refuses every non-observe method, with no design for an exception. | §3.3: new `checkMutation`; `checkRequest` and `allowed_methods` unchanged. |
| 11 | Medium | Approval did not cover manifest fixtures or login flows. | §4.5: they are included in the hash; test 13. |
| 12 | Medium | The parser and config would reject the new keys; the changes were not listed. | §4.4: an exact change table. |
| 13 | Medium | Cleanup could lose its session through logout or a failed login. | `cleanup_actor`; logout of it is a lint error; a failed login blocks creates. |
| 14 | Medium | `verify_gone`'s actor and positive control were loose. | `exists` control after create; both run as `cleanup_actor`. |
| 15 | Medium | The CSRF probe was not tied to cookie sessions, and its headers were undefined. | §5.2: cookie-session actors only, with exact headers and rejection statuses. |
| 16 | Medium | The visual driver had no fixture lifecycle. | Kept observe-only in 0.2.0 (non-goal, D6); test 15. |
| 17 | Medium | Retries could repeat non-idempotent requests. | §6.2: retries only for cleanup and `verify_gone`. |
| 18 | Low | The schema version and the new FAILED cause were unclear. | §7: additive blocks; FAILED and exit 2 already in v1; CHANGELOG note. |
| 19 | Low | The marker was derived from the run ID; the header scope was unclear. | §3.5: random marker recorded; header on every request. |
| 20 | Low | Leftover ids are target data. | §6.3: masked in agent summaries; synthetic ids in fixtures. |
| 21 | Low | Acceptance tests had gaps. | §9 expanded to 15 tests, covering every finding above. |
| 22 | Low | The INJ-004 status was ambiguous. | §5.5: a fact in `observations`, never a case result; catalog update. |

## 14. Implementation readiness checklist
- [x] Owner answers D1–D9 (2026-11-04, recommended options).
- [x] Review round 1 recorded in §13 with every finding resolved.
- [ ] Vulnerable and secure fixture apps designed for §9, with the same response contract for legitimate callers.
- [ ] ADR for safe-validate, fixtures and `checkMutation`.
- [ ] Threat model TM-32 to TM-35 merged.
