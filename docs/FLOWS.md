# Story flows (test cases)

A **flow** is one Markdown file per user story that NavSentry can replay. Each flow is classified automatically as **Integration** (API level) or **E2E** (user journey). Running flows produces a functional report (`TEST-REPORT.md`, `flows.json`) next to the security report (`REPORT.md`).

Security stays the primary purpose:
- every flow request goes through the same scope gate, request budget and redaction as the seed requests;
- every flow response runs the same security checks as the seed responses.

Flows also add access-control checks for the paths and actors you declare.

Design and rationale: [ADR-0006](adr/0006-flow-files-and-test-levels.md) and the [0.1.2 spec](specs/SPEC-0.1.2-FLOW-TEST-CASES.md).

## What 0.1.2 can and cannot replay
| Step action | Replayed? |
|---|---|
| `http`: API request (`GET`, `HEAD` or `OPTIONS`) | Yes |
| `navigate`: page load (`GET`) | Yes, at HTTP level only: status, headers, redirects and text in the HTML the server returns. No rendering or JavaScript. |
| `click`, `select`, `see`, `wait_for` | No. The step is checked and classified, then reported `NOT_TESTED` because it needs the browser transport (M1b). |
| `fill`, `submit` | No. Same as above; these steps may also change data, which needs safe-validate mode (M2). |

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
| `vars` | – | `name → {"value": "<safe literal>"}` or `{"env": "UPPER_SNAKE"}`. Environment values are treated as secrets. |
| `review` | – | `{"status": "draft"}` (default). Approval is written by `flow approve`. |
| `provenance` | – | `{kind: analyzer\|agent\|human, from_run?, sources?, created_at?}` (information only) |

### Step (`navsentry-step`)
| Key | Rules |
|---|---|
| `id` | `S1`, `S2`, … unique within the flow |
| `action` | `http`, `navigate`, `click`, `fill`, `select`, `submit`, `see`, `wait_for` |
| `actor` | Must be listed in the header's `actors` |
| `request` | `http`/`navigate` only: `{method, path, query?, accept?}`. `path` starts with `/` and contains no query string, `..`, backslash or encoded separators. A `{{var}}` placeholder must be a whole path segment or a whole query value. `accept` is `json`, `text` or `any`; `navigate` always sends an HTML `Accept`. Custom headers are not supported: credentials come only from manifest actors. |
| `target` | UI actions only: exactly one of `{role, name}`, `{label}`, `{text}`, `{test_id}` |
| `value` | `fill`/`select` only: `{"var": "<name>"}`. Literal values are not allowed, which keeps personal data out of the file. |
| `expect` | Required for `http`/`navigate`; not allowed on UI steps |
| `extract` | `name → {"from": "json", "pointer": "/items/0/id"}` or `{"from": "header", "name": "<header>"}`. Credential headers cannot be extracted. |
| `follow_redirects` | Default `false`. When `true`, follows at most 5 hops and re-checks scope at every hop. |
| `object_owner` | The actor that owns the object this step reads. With `access: denied` it marks an IDOR check (NSC-AC-003). |
| `depends_on` | Earlier step IDs that must pass before this step runs |

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
