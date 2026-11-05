# Story flows (test cases)

A **flow** is one Markdown file per user story that NavSentry can replay. Each flow is classified automatically as **Integration** (API level) or **E2E** (user journey). Running flows produces a functional report (`TEST-REPORT.md`, `flows.json`) next to the security report (`REPORT.md`).

Security stays the primary purpose:
- every flow request goes through the same scope gate, request budget and redaction as the seed requests;
- every flow response runs the same security checks as the seed responses.

Flows also add access-control checks for the paths and actors you declare.

Design and rationale: [ADR-0006](adr/0006-flow-files-and-test-levels.md) and the [0.1.2 spec](specs/SPEC-0.1.2-FLOW-TEST-CASES.md).

## What 0.1.2 and 0.1.3 can and cannot replay
| Step action | Replayed? |
|---|---|
| `http`: API request (`GET`, `HEAD` or `OPTIONS`) | Yes |
| `navigate`: page load (`GET`) | Yes, at HTTP level only: status, headers, redirects and text in the HTML the server returns. No rendering or JavaScript. |
| `click`, `see`, `wait_for` | With `scan --mode flow --engine playwright` (development profile, Chromium headless shell installed): yes, in the browser, after a `navigate` step for the same actor. Otherwise `NOT_TESTED` with the reason. |
| `fill`, `select`, `submit` | With `--engine playwright` in `safe-validate` (development profile, 0.2.0-b): yes. Every non-observe request they cause must match a declared entry (see [Browser requests](#browser-requests-in-safe-validate-020-b)). Otherwise `NOT_TESTED`, because they may change state. |
| `fixture_create`, and `http` with `POST`/`PUT`/`PATCH`/`DELETE` | Only with `safety.mode: safe-validate` in the development profile and a fixture declared in the manifest (0.2.0-a). See [Fixtures and mutations](#fixtures-and-mutations-safe-validate-020-a). |

If any step of a flow did not run, the flow is `INCOMPLETE`, never `PASS`. `TEST-REPORT.md` lists those steps as a manual replay checklist. Record a manual replay in a separate file based on [templates/MANUAL-REPLAY.md](reports/templates/MANUAL-REPLAY.md).

## File format
- Name flow files `*.flow.md`. Keep them in your application repository, for example `navsentry/flows/`.
- NavSentry reads only top-level fenced blocks tagged `navsentry-flow` (exactly one, first) and `navsentry-step` (one per step, run in document order).
- Everything else in the file is narrative for people. NavSentry never interprets it and never copies it into reports. The heading just above a step becomes that step's default title.
- Block contents must be valid JSON. Unknown keys are errors. A block tag that starts with `navsentry` but is not one of the two tags is an error. So is a `navsentry` block that is indented, quoted or inside a list.

Examples: [examples/flows/](../examples/flows/) (Integration with access control, and E2E). They lint against [examples/manifest.flows.example.json](../examples/manifest.flows.example.json).

### Flow header (`navsentry-flow`)
| Key | Required | Rules |
|---|---|---|
| `flow` | ✓ | `"1"` |
| `id` | ✓ | `^[a-z0-9][a-z0-9-]{1,62}$`. Permanent: `compare` matches on it, so renaming a flow breaks the comparison. |
| `title`, `story` | ✓ | ≤ 120 / ≤ 1000 characters. No secrets or personal data (checked with the redaction detectors). |
| `level` | – | `auto` (default), `integration` or `e2e`. A declared level that differs from the derived level is an error. |
| `origin` | cond. | Must be one of the manifest origins. Required when the manifest lists more than one origin. |
| `actors` | ✓ | Manifest actor names. `anonymous` is always available. Every step actor must be listed here. |
| `tags` | – | ≤ 10 items, `[a-z0-9-]` |
| `login_path` | – | A redirect to this path counts as "access denied". |
| `console` | – | `"silent"`: any console output during a step fails the functional assertion `console_silent` with the count (needs `--engine playwright`; NOT_TESTED otherwise). A security finding needs sensitive content (NSC-INFO-006). |
| `vars` | – | `name → {"value": "<safe literal>"}` or `{"env": "UPPER_SNAKE"}`. Environment values are treated as secrets. |
| `review` | – | `{"status": "draft"}` (default). Approval is written by `flow approve`. |
| `provenance` | – | `{kind: analyzer\|agent\|human, from_run?, sources?, created_at?}` (information only) |

### Step (`navsentry-step`)
| Key | Rules |
|---|---|
| `id` | `S1`, `S2`, … unique within the flow |
| `action` | `http`, `navigate`, `click`, `fill`, `select`, `submit`, `see`, `wait_for`, `fixture_create`, `fixture_verify_gone` and `logout` (safe-validate) |
| `actor` | Must be listed in the header's `actors` |
| `request` | `http`/`navigate` only: `{method, path, query?, accept?}`. `path` starts with `/` and contains no query string, `..`, backslash or encoded separators. A `{{var}}` placeholder must be a whole path segment or a whole query value. `accept` is `json`, `text` or `any`; `navigate` always sends an HTML `Accept`. Custom headers are not supported: credentials come only from manifest actors. |
| `target` | UI actions only: exactly one of `{role, name}`, `{label}`, `{text}`, `{test_id}` |
| `value` | `fill`/`select` only: `{"var": "<name>"}`. Literal values are not allowed, which keeps personal data out of the file. |
| `expect` | Required for `http`/`navigate`; not allowed on UI steps |
| `extract` | `name → {"from": "json", "pointer": "/items/0/id"}` or `{"from": "header", "name": "<header>"}`. Credential headers cannot be extracted. |
| `follow_redirects` | Default `false`. When `true`, follows at most 5 hops and re-checks scope at every hop. |
| `object_owner` | The actor that owns the object this step reads. With `access: denied` it marks an IDOR check (NSC-AC-003). |
| `depends_on` | Earlier step IDs that must pass before this step runs |
| `fixture` | safe-validate only: the declared fixture that a `fixture_create` or mutation step uses |
| `as` | `fixture_create` only: the variable that receives the created id |
| `check` | Mutation steps only: `"csrf"` runs the NSC-AC-006 probes instead of one request (see [Security checks](#security-checks-in-safe-validate-020-c)). The step takes no `expect`. |
| `request.body` | Mutation steps only: `{"json": {...}}`, at most 4096 bytes. A string value that is exactly `{{name}}` takes a run variable or `{{marker}}`. Any other `{{` is an error. |

### Expectations (`expect`)
| Key | Meaning |
|---|---|
| `status` | `[200, 204]`, or a class: `"2xx"`, `"3xx"`, `"4xx"` |
| `content_type` | Exact `type/subtype` (parameters ignored) |
| `headers_present`, `headers_absent` | Header names. Security, cookie and auth headers are rejected here because the security checks cover them. |
| `json` | Up to 20 items `{pointer, type?, equals?, exists?, min_items?}` (RFC 6901 pointers) |
| `shape` | The 16-hex JSON shape hash from the response contract |
| `text_present`, `text_absent` | Up to 10 markers, 1–100 characters each, case-sensitive |
| `redirect_to` | Expects a 3xx to this path on the flow origin |
| `access` | `allowed` (expects 2xx) or `denied`; see below |
| `deny_status` | Status codes that count as denied. Default `[401, 403]`; you can add `404`. |

`HEAD` and `OPTIONS` steps support only `status`, header expectations and `access` (`access` on `HEAD` only). Reports never show response values. They show only status codes, media types, JSON types, and whether something was present, absent, matched or different.

### Access expectations (security)
A `denied` step needs a **positive control**: an `allowed` step on the same method, path template and query, by another actor in the same flow. Lint enforces this. The `denied` step is evaluated after all steps have run:

| Response | Result |
|---|---|
| Status in `deny_status`, or a redirect to `login_path` | PASS |
| 2xx with the same media type and JSON shape as the positive control | **FAIL** (security finding) |
| 2xx with a different response contract (for example a login page) | INCONCLUSIVE |
| No passing positive control | INCONCLUSIVE |

| Step | Case |
|---|---|
| Actor `anonymous` | NSC-AC-002 Missing authentication |
| `object_owner` set | NSC-AC-003 IDOR/BOLA (read access) |
| Any other authenticated actor | NSC-AC-007 Missing function-level authorization |

A finding from an **approved** flow is `VALIDATED`. A finding from a draft flow is `SUSPECTED`.

### Variables
At run time a value is used only if it matches `^[A-Za-z0-9._~-]{1,128}$` and is not `.` or `..`. A value that fails this rule makes the step `ERROR` without echoing the value, and steps that need it become `NOT_TESTED`. The URL built from the value is checked by the scope gate before it is sent, so a value taken from a target response can never steer a request out of scope.

Reports and `run.json` record flow URLs in template form (`/api/orders/{{orderA}}`). Variable values are therefore not written into URLs, `flows.json` or `TEST-REPORT.md`. Body excerpts in `run.json` are redacted like any other response.

### Limits
| Item | Limit |
|---|---|
| File / one block | 256 KiB / 64 KiB |
| Flows per set / steps per flow | 200 / 50 |
| Variables per flow / `json` items per step / text markers per step | 20 / 20 / 10 |

There are no loops and no retries. The manifest request budget is shared with the seed requests.

## Fixtures and mutations (safe-validate, 0.2.0-a)
A flow may change state only through a fixture that the owner declared in the manifest ([ADR-0010](adr/0010-safe-validate-fixtures.md)). This needs `safety.mode: safe-validate` and `environment` `local` or `dev`; any other combination is a config error (exit 3).

```json
"safety": { "mode": "safe-validate", "max_mutations": 20, "cleanup_window_seconds": 30 },
"fixtures": {
  "orders": {
    "owner_actor": "reader_a", "cleanup_actor": "fixture_admin",
    "create":  { "method": "POST", "path": "/api/test-fixtures/orders", "body": { "json": { "note": "{{marker}}" } }, "extract": { "id": "/id" } },
    "exists":  { "method": "GET", "path": "/api/orders/{{id}}", "expect_status": [200] },
    "cleanup": { "method": "DELETE", "path": "/api/test-fixtures/orders/{{id}}", "expect_status": [200, 204, 404] },
    "verify_gone": { "method": "GET", "path": "/api/orders/{{id}}", "expect_status": [404, 410] },
    "allowed_mutations": [{ "method": "PATCH", "path": "/api/orders/{{id}}", "content_type": "application/json", "max_body_bytes": 4096 }]
  }
}
```

Steps:
```json
{ "id": "S1", "action": "fixture_create", "actor": "reader_a", "fixture": "orders", "as": "orderA" }
{ "id": "S2", "action": "http", "actor": "reader_a", "fixture": "orders",
  "request": { "method": "PATCH", "path": "/api/orders/{{orderA}}", "body": { "json": { "note": "{{marker}}" } } }, "expect": { "status": "2xx" } }
```

- `fixture_create` runs as the fixture's `owner_actor`. It holds the cleanup reserve, writes a pending intent, creates the object, validates the id and registers it for cleanup, then runs `exists` as the positive control. A failed `exists` makes the step ERROR, and the object is still cleaned.
- A mutation step must match one `allowed_mutations` entry exactly: the same method, and the same path once each variable segment becomes `{{id}}`. Every variable in its path must pass the id rule `^[A-Za-z0-9_-]{1,128}$`. It never follows redirects and takes no query.
- `{ "action": "fixture_verify_gone", "actor": "reader_a", "var": "orderA" }` checks mid-flow, through the fixture's `verify_gone` as `cleanup_actor`, that an object this run created is gone (for example after a declared DELETE). Gone is PASS, still present is FAIL. The object stays registered, so cleanup still runs; a 404 there counts as done. The variable must come from an earlier `fixture_create`, and the fixture must declare `verify_gone`.
- Cleanup has no step. It always runs at the end, in reverse order, as `cleanup_actor`, including after failures, after the limits are hit and on Ctrl+C. Do not write delete steps.
- A run that leaves anything behind, or loses a create's response, is `FAILED` (exit 2). REPORT.md lists each leftover with the exact manual action.

## Login and cookie-session actors (safe-validate, 0.2.0-b)
Credentials come only from environment variables. NavSentry treats them as secrets and never writes them, or the session cookies it receives, to any artifact.

```json
"auth_endpoints": { "login": { "method": "POST", "path": "/api/session", "content_type": "application/json", "max_body_bytes": 512 } },
"actors": {
  "reader_a": { "login": { "http": "login", "body": { "json": { "user": "{{username}}", "password": "{{password}}" } } }, "username_env": "NS_A_USER", "password_env": "NS_A_PASS" },
  "reader_b": { "login": { "flow": "login-reader-b" }, "username_env": "NS_B_USER", "password_env": "NS_B_PASS" },
  "reader_c": { "cookie_env": "NS_C_COOKIE" }
}
```

- **http login:** the declared body is sent once to `auth_endpoints.login`. The only placeholders allowed in the body are `{{username}}` and `{{password}}`. The response's `set-cookie` values become the actor's session. The login counts against `max_mutations` and is never retried.
- **Browser login:** the referenced flow runs first, in the actor's own browser context, with `--engine playwright`. It may use only `navigate`, `fill` (values `{{username}}` and `{{password}}` only), `submit`, `click`, `see` and `wait_for`, and every step runs as that actor. Its submit must match `auth_endpoints.login`. The cookies in the context afterwards become the session for the actor's http steps too. Select the login flow together with the flows that use it.
- **Cookie session:** `cookie_env` holds a full `Cookie` header value. It is refused in the production profile.
- A failed login (wrong password, non-2xx response, no session cookie, or a login flow that is not PASS) makes that actor's steps `NOT_TESTED` with "login failed", never a FAIL of the target. That actor cannot create fixtures.

## Browser requests in safe-validate (0.2.0-b)
In `safe-validate`, a browser request that is not GET, HEAD or OPTIONS is sent only when all of the following hold:
- `ScopeGate.checkMutation` matches one declared `allowed_mutations`, `login` or `logout` entry. Fixture `create` entries are never offered to the browser, because a create must register its cleanup.
- The request's `content-type` equals the entry's `content_type`.
- The body is within the entry's `max_body_bytes`.

Each redirect hop is a new request and is matched again, so a 307 to an undeclared path is refused. This holds for form submits and for page JavaScript (`fetch`, XHR). NavSentry records the body's sha256, never its content. It cannot check what a page puts in a form body beyond its type and size (TM-32). The visual driver (`navsentry browse`) stays observe-only in every mode.

### Approval covers the manifest entries
A flow that uses a fixture or a login actor is approved together with the entries it relies on: the referenced fixture entries, `auth_endpoints` and the referenced login flow. Editing any of them invalidates the approval. Run `navsentry flow approve --flows <file> --by <name> --config <manifest>`; without `--config`, approving a flow that uses fixtures exits 3.

## Security checks in safe-validate (0.2.0-c)

**NSC-AC-003, modification.** Use the access steps you already know on a declared fixture mutation. The owner's own mutation (`access: allowed`) is the positive control. The other actor's identical mutation is `object_owner` + `access: denied`. A 2xx with the control's contract is FAIL, and with an approved flow the finding is VALIDATED. If the positive control did not pass, the result is INCONCLUSIVE. NavSentry does not compare whether the other actor's change took effect, because it does not record response body values.

```json
{ "id": "S2", "action": "http", "actor": "reader_a", "fixture": "orders", "request": { "method": "PATCH", "path": "/api/orders/{{o}}", "body": { "json": { "note": "{{marker}}" } } }, "expect": { "access": "allowed" } }
{ "id": "S3", "action": "http", "actor": "reader_b", "fixture": "orders", "object_owner": "reader_a", "request": { "method": "PATCH", "path": "/api/orders/{{o}}", "body": { "json": { "note": "{{marker}}" } } }, "expect": { "access": "denied", "deny_status": [403, 404] } }
```

**NSC-AC-006, CSRF.** Mark an `allowed_mutations` entry with `csrf`, for example `{"token_from": {"cookie": "csrf_token"}, "send_as": {"header": "x-csrf-token"}}`. A step with `"check": "csrf"` then sends three requests with the actor's cookie session, all counted against `max_mutations`:
1. without the token, from the same origin;
2. with the token, `Origin: https://navsentry-csrf-probe.invalid` and no `Referer`;
3. with the token, from the same origin (the control; it runs last because it may change the object).

Rejected means 401, 403, 419, 422 or a redirect to `login_path`. A 2xx probe with the control's contract is FAIL. Header-token actors are NOT_TESTED ("CSRF needs a cookie session") and nothing is sent. Entries may declare `content_type: application/x-www-form-urlencoded`. The step's JSON body must then be flat, and it is sent form-encoded.

**NSC-AUTH-002, session after logout.** `auth_endpoints.logout` must be declared. The step's `request` is an authenticated GET or HEAD:

```json
{ "id": "S5", "action": "logout", "actor": "reader_c", "request": { "method": "GET", "path": "/api/me" } }
```

The step sends the read (it must return 2xx, the positive control), then the logout, then the same read with the pre-logout session. A 401, a 403 or a redirect to `login_path` is PASS. A 2xx with the same contract is FAIL. After this step the actor is logged out, so its later steps are NOT_TESTED. Logging out a fixture's `cleanup_actor` is a lint error.

## Business invariants and marker reflections (safe-validate, 0.2.0-d)

**NSC-BIZ-001.** The owner declares rules on a fixture. NavSentry never invents one:

```json
"invariants": [{ "name": "total-not-negative", "pointer": "/total", "op": ">=", "value": 0 },
               { "name": "known-status", "pointer": "/status", "op": "in", "value": ["open", "cancelled", "refunded"] }],
"forbidden_transitions": [{ "name": "no-refund-while-open", "pointer": "/status", "from": "open", "to": "refunded" }]
```

- Before cleanup, NavSentry reads each object through `exists`, as `cleanup_actor`, and evaluates the rules.
- A transition compares the value right after create with the value before cleanup.
- A violated rule is FAIL, and all rules holding is PASS. An absent pointer or a non-JSON response is INCONCLUSIVE.
- Without any declared rule, the case is NOT_TESTED.
- Only rule names and the declared values are reported. Observed values stay in memory.

**NSC-INJ-004.** The run marker `nsv-<16 hex>` may be put in a create body or filled into a form (`"value": {"var": "marker"}`). When a later HTML response shows it inside a tag (attribute) or a `<script>` element, `run.json → observations` records the context, the count and the URL, and REPORT.md lists them. This is a fact, not a result. The case stays NOT_TESTED, because testing output encoding needs an injection payload (active-approved).

## Drafts from an OpenAPI document (0.1.3)
`navsentry flow import --openapi openapi.json --config <manifest> --out navsentry/flows/drafts` turns documented GET operations into draft integration flows. A protected operation (`security` set) becomes a pair: an authenticated actor `access: allowed` and anonymous `access: denied`. Path and required query parameters become variables with `env` references such as `NAVSENTRY_VAR_ORDER_ID`: set them to test values before running. The document is a contract claim, not observed behaviour, so review every step. IMPORT.md lists every operation that was not encoded and why.

## Chained flows (0.1.3)
A flow can depend on other flows in the same flow root and reuse values they extracted. This replaces the 0.1.2 rule that variables never cross flows, under the rules below ([SPEC-0.1.3 §5.5](specs/SPEC-0.1.3-SCAN-MODES-AND-WORKSPACE.md)).

```json
{ "flow": "1", "id": "order-detail", "title": "Open my first order", "story": "…", "actors": ["reader_a"],
  "requires": ["list-orders"],
  "imports": { "orderId": "list-orders.orderId" } }
```

- `requires`: up to 10 flow IDs, resolved only within the `--flows` root. Missing flows, cycles and a flow that requires itself are lint errors.
- `imports`: local name → `"<flowId>.<variable>"`. The flow must be in `requires` and must extract that variable. A name may not collide with a local variable or extract.
- Only a value extracted in a step that ended `PASS` is imported. Values stay in memory and never appear in reports.
- A value may not cross an actor or origin boundary unless the reviewed flow says so: `{"from": "list-orders.orderId", "allow_cross_actor": true}` (or `allow_cross_origin`). Use this only for a deliberate case, such as an access-control test.
- Flows run in dependency order. A shared dependency runs once per run. If a required flow is not `PASS`, the dependent flow is `NOT_TESTED` with "dependency <id> is <status>", never `FAIL` or `PASS`.
- `--only` and `--level` pull in required flows that are eligible. A draft dependency is not selected without `--include-drafts`, so in production its dependents are `NOT_TESTED`.
- Approval covers the dependency closure: a dependent flow's hash includes the hashes of everything it requires, so editing a required flow invalidates every flow that depends on it. `flow approve` loads the whole flow root (`--root`, default: the file's directory). Flows without `requires` keep their 0.1.2 hash.

## Classification
1. Any UI action → **E2E**.
2. Otherwise, any `navigate` step → **E2E**.
3. Otherwise → **Integration**.

**Executability:**
- `full`: every step can run in this release.
- `partial`: some steps need the browser transport.
- `none`: no step can run.

An E2E flow that could run only at HTTP level is labelled "E2E (HTTP-level only)".

## Workflow
None of these commands sends network traffic, except `navsentry test`:

```bash
navsentry flow analyze --config manifest.json --from-run runs/before/run.json --out navsentry/flows
```

```bash
navsentry flow init --id orders-access --title "Orders access control" --story "..." --out navsentry/flows
```

```bash
navsentry flow lint --config manifest.json --flows navsentry/flows
```

```bash
navsentry plan --config manifest.json --flows navsentry/flows --include-drafts
```

```bash
navsentry flow approve --flows navsentry/flows/orders-access.flow.md --by "<owner name>"
```

```bash
navsentry test --config manifest.json --flows navsentry/flows --out runs/before
```

| Command | What it does |
|---|---|
| `flow analyze` | Drafts flows from observed, legitimate responses and writes `ANALYSIS.md`. `ANALYSIS.md` contains the endpoint inventory, questions for the owner such as "Is this endpoint public?", notes, and coverage gaps. It skips 5xx and 404 responses, side-effect paths, security headers, cookies and values. It never overwrites an existing flow file; `ANALYSIS.md` is regenerated on every run. |
| `flow approve` | An action for the owner only. It writes `review.status: approved` together with a content hash. Any later edit to the flow makes lint fail until the flow is approved again. |
| `test --flows` | Runs approved flows only. Add `--include-drafts` to include drafts; this is refused for production manifests. Other options: `--flows-only`, `--only <id,…>`, `--level integration\|e2e`, `--junit`. |
| `flow show` | Prints a flow as a human test script. |

**Outputs in `--out`:**
- `run.json` and `REPORT.md` (security first; `REPORT.md` gains a "Flows" section),
- `report.sarif`,
- `flows.json`,
- `TEST-REPORT.md`,
- `junit.xml` (with `--junit`).

**Exit codes for `test`:**

| Code | Meaning |
|---|---|
| 1 | Security findings, or a functional FAIL |
| 2 | The run is incomplete. This includes any E2E flow with UI steps in this release. |
| 0 | Otherwise |
| 3 | Invalid manifest or flows (detected before any request) |

## Fix verification
```bash
navsentry compare --before runs/before --after runs/after
```

When both run directories contain `flows.json`, `compare` also compares every unchanged step by `<flowId>/<stepId>`:
- a step that goes from PASS to FAIL or ERROR is a **functional regression**. The verdict is `FUNCTIONAL_REGRESSION`, exit 1, and the owner must decide what to do.
- steps whose content changed between the runs are listed as "not comparable".

The intended result after a fix is `IMPROVED_NO_DRIFT` with no functional regressions.
