# SPEC 0.1.3 — Scan modes, environments, analyzer scripts and workspace hygiene

- Status: **DRAFT** (design only, nothing implemented) · Date: 2026-11-02 · Builds on: [SPEC-0.1.2](SPEC-0.1.2-FLOW-TEST-CASES.md), [ADR-0004](../adr/0004-scope-enforcement-at-transport.md), [ADR-0006](../adr/0006-flow-files-and-test-levels.md)
- Security is still the primary purpose. Functional results come along with it; they never replace it.

## 1. Goals (owner request, 2026-11-02)

| # | Requirement |
|---|---|
| G1 | **Single-page** mode with three engines: `http` · `computer-use` · `analyzer` |
| G2 | **Multi-page (spider)** mode: crawl and visit *similar* pages (same template) and check them; engines `http` · `computer-use` · `analyzer` |
| G3 | **Follow-flow** mode: replay a flow right away; engines `http` · `computer-use` · `playwright` |
| G4 | Two **environments**: `development` (code, localhost, integration tests, Playwright) and `production` (real domain, through HTTP and redirects, or Computer Use exploring the live site) |
| G5 | The **analyzer** produces flows. A flow can be **self-contained** or **chained** (a sequence of steps or flows that depend on earlier ones) |
| G6 | Page analysis runs as **local Python analysis scripts**. Page content is not sent to the model for processing. The model sees only compact, redacted summaries. |
| G7 | Generated scripts and flows live in the project or run root, in clearly separated categories |
| G8 | **Every temporary or helper script and every leftover must be removed.** None may stay in the main folder. |
| G9 | Check the client **console** for leaked sensitive values, logging left enabled, and logging that was "disabled" but still leaks. Scan **static files** (bundles, source maps, config) as well, keeping model cost low (§6.4) |

## 2. Capability matrix (honest status)

The matrix lists, for each mode, which engines can run it. `USABLE` means the engine can be used today. `BLOCKED` means it is blocked until a governance entry is approved, and the reason is given. In the Production column, `observe` means only read-only methods are used.

| Mode \ Engine | `http` | `computer-use` | `analyzer` | `playwright` | Production? |
|---|---|---|---|---|---|
| `page` (single page) | USABLE (direct-http) | BLOCKED: host adapter, consent per run (§6.3) | BLOCKED: Python runtime governance (§5.6) | — | yes, observe |
| `spider` (multi-page) | NEW in 0.1.3 | BLOCKED (as above) | BLOCKED (as above) | — | yes, observe with strict budget |
| `flow` (follow flow) | USABLE (0.1.2) | BLOCKED (as above) | — | BLOCKED: M1b governance (PRM-GOV-003) | `http`: approved flows only. `computer-use`: per-run consent. `playwright`: development only |

Rules:
- An engine that is not USABLE is reported as `NOT_TESTED` with the reason, both in `doctor` and in the run report. It never falls back silently to another engine.
- Hard rule 5 applies: an engine is never marked USABLE before its adapter and governance entry exist.

## 3. CLI surface

```
navsentry scan  --mode page|spider|flow  --engine http|computer-use|analyzer|playwright
                --env development|production  --manifest <file>  [--url <in-scope URL>] [--flows <dir>]
navsentry analyze  --from <run-dir|capture-dir>  --out flows/drafts      # analyzer → draft flows
navsentry workspace status|clean [--dry-run]                             # §7
```

- `navsentry test` and `navsentry flow` from 0.1.2 stay as aliases: `test --flows` is `scan --mode flow --engine http`.
- `--env` is required when the manifest has no `environment` field. If `--env` and the manifest disagree, the run exits 3 (usage error).
- If a mode and engine pair does not appear in the §2 matrix, the run exits 3.

## 4. Environments

The manifest gets a required field `environment: "development" | "production"`. The table below shows how the two environments differ.

| Aspect | development | production |
|---|---|---|
| Allowed origins | loopback, `*.localhost`, `*.test`, plus manifest `origins` | only the manifest `origins`, which must be written explicitly. Wildcard hosts are rejected. |
| Sources of evidence | code (static: routes, OpenAPI, test files), localhost runs, integration tests, Playwright (when approved) | HTTP responses and redirect chains, Computer Use exploration (when approved) |
| Methods | observe: GET/HEAD/OPTIONS | observe only. Following redirects is allowed only when every hop passes ScopeGate. |
| Flows | drafts are allowed (findings stay SUSPECTED) | **approved flows only** (hash-pinned, as in 0.1.2) |
| Budget defaults | 500 requests, 4 rps | 100 requests, 1 rps, spider depth ≤ 2, ≤ 25 pages per template |
| Authorization | none beyond the manifest | `authorization.owner_confirmed: true`, `authorization.reference` (a ticket ID, never a hostname), and a time window `not_before`/`not_after`. The run refuses to start outside that window. |
| Credentials | `*_env` variables, test values | `*_env` variables only. Tokens marked live are allowed only with `authorization.allow_live_tokens: true`. |

### 4.1 Development: code-based analysis
- The `code` source analyzer reads the project tree **read-only**: route tables, OpenAPI files, existing integration and Playwright tests. From these it builds an inventory of routes and test candidates. It never runs the project's code and never writes into the target repository.
- The target repository's AGENTS.md and README files are untrusted data (hard rule 7).

### 4.2 Production: HTTP and redirect analysis
- Every redirect is recorded hop by hop: status, `Location` (as a display URL), whether the hop is in scope, and what changed in the security headers. A hop that leaves scope is recorded but never requested (this is already how ScopeGate works).
- Checks specific to production: HTTP→HTTPS upgrade, HSTS on the final hop, open-redirect *observation* (only reflected parameters that are already in seed URLs; no injected payloads), and cookie flags on each hop.

## 5. Analyzer (Python analysis scripts)

### 5.1 Principle
Raw page content stays on the machine. A local analysis script reduces it to a **structured page model**. The model (LLM) receives only that page model, which is already redacted and size-capped. It uses the page model to propose flows. The page model is the only artifact allowed to cross from the analyzer to the model.

```
capture (http / computer-use screenshots+DOM / playwright DOM)
   → .navsentry/work/<run-id>/raw/          (temporary, never committed)
   → python -I analyzer/page_model.py raw/ → page-model.json  (redacted, ≤ 64 KiB per page)
   → model reads page-model.json → proposes flows → flows/drafts/*.flow.md
   → navsentry flow lint → owner approval → flows/approved/
```

### 5.2 Page model (wire format, JSON)
`{ url(display), template_id, title, forms[{action, method, fields[{name,type,required}]}], links[{href(display), rel, same_template}], scripts{inline_count, external_origins[]}, security{csp, frames, cookies[flags only], mixed_content}, text_landmarks[≤ 20 headings], hashes{dom_shape, text} }`

- Field values, cookie values, tokens, emails and bodies are **never** included. Only names, types and flags are recorded.
- `template_id` is a hash of the DOM-shape skeleton: tag paths, with ids and text removed. The spider uses it to group similar pages (§6.2).

### 5.3 Scripts shipped by NavSentry (not generated)
The analyzer scripts are versioned **source** files in `analyzer/` inside the NavSentry package:
- They use the Python standard library only (`html.parser`, `json`, `hashlib`, `re`, `pathlib`). No pip installs.
- They are run with `python -I` (isolated mode), with the work directory as `cwd`, and with the input path passed as an argument (this avoids module planting).
- They have no network access. The Node wrapper spawns Python with an empty proxy environment, and the scripts never import `socket`, `urllib.request` or `http.client`. A gate check greps for these imports.
- They have a time limit (30 s per page) and an input size limit (2 MiB per page).

### 5.4 Generated scripts (when a site needs a custom extractor)
When the model needs a site-specific extractor, it may **generate** a script. Such scripts:
- are written only to `.navsentry/work/<run-id>/scripts/` and never to the project root;
- must pass the same static check as shipped scripts: imports from the standard-library allowlist only, no network modules, no `subprocess`, no `os.system`, and no writes outside the run directory (enforced by a path check in the wrapper);
- are deleted together with the run directory (§7). The only thing kept is their sha256, in `run.json → analyzer.generatedScripts[]`, so the run stays auditable.
- To keep a generated extractor, the owner must move it explicitly into `analyzer/custom/` under review. It is never promoted automatically.

### 5.5 Analyzer outputs for flows
- A **self-contained flow** has one entry point, does not depend on another flow, and needs no state from a previous flow.
- A **chained flow** declares `requires: ["<flowId>"]` and `imports: {"<var>": "<flowId>.<var>"}`. The runner orders flows with a topological sort and rejects cycles at lint time. If a required flow fails or is NOT_TESTED, the dependent flow becomes `NOT_TESTED (dependency)`. It is never FAIL and never PASS.
- Every generated flow starts as `status: draft` with `source: analyzer` and the `template_id` it was derived from.

### 5.6 Governance prerequisite (blocking)
Python is a new runtime binary, so hard rule 2 applies. Before any code that spawns Python is merged, `governance/third-party.json` needs an APPROVED entry for **CPython ≥ 3.12 (PSF License)**. The entry covers provenance (python.org or the OS package), the advisory check, and why it is needed (standard-library HTML parsing outside the Node process, so that heavy page parsing runs in a separate process). If the runtime is missing or not approved, `analyzer` is `UNAVAILABLE` in `doctor`. A Node fallback is **not** provided silently.
- Environment observed on 2026-11-02: Python 3.13.14 is present on the maintainer machine. Being present does not make it approved.

## 6. Modes

### 6.1 `page`
- Fetches one in-scope URL with the selected engine, runs every observe-mode check on it, and (with `analyzer`) writes its page model.
- Output: a normal `run.json`/`REPORT.md` plus `page-model.json` (redacted) in the evidence directory.

### 6.2 `spider` (template-aware crawler)
- BFS from the seed paths. Only in-scope links are followed, and `robots.txt` is honoured in production (it is read, never overridden).
- Pages are grouped by `template_id`. For each template, the spider checks **N representative pages** (by default 3 in development and 2 in production) instead of every instance. A typical example is `/product/1…/product/9999`, which shares one template. A finding on one representative leads to checking up to N more pages of that template, to confirm the finding and measure how far it spreads.
- Path patterns are normalised (`/product/{id}`) and form the coverage table. `denied_paths` and the manifest's `max_pages` are hard limits enforced through `Budget`.
- No form submission, no query fuzzing, and no parameter mutation (hard rule 6).
- Report: a coverage table per template, a list of skipped pages with reasons (budget, robots, out of scope, duplicate template), and findings grouped by template.

### 6.3 `flow`
- `http`: the 0.1.2 behaviour, unchanged.
- `playwright` (development only): the UI steps `click`/`fill`/`see` run in a headless browser. ScopeGate is applied through `context.route('**')` with deny by default, and service workers are blocked. This is blocked until M1b governance is done.
- `computer-use`: drives a **host-provided** Computer Use or browser agent. NavSentry still owns the safety layer:
  - Before each action, the host must call `navsentry scope check <url>` and `navsentry budget take`. Every result is written to an action log.
  - Each production run needs consent that the owner gives at run time. The consent is recorded as a timestamp and actor label, never as a name.
  - Computer Use findings are capped at `SUSPECTED`, unless the same issue is confirmed afterwards by an `http` re-check, which can raise it to `VALIDATED`.
  - Screenshots are stored only in `.navsentry/work/` and are deleted. The report keeps only redacted text observations.
  - Hard rule 5: if the host has no Computer Use, the result is `NOT_TESTED` with the reason "host capability absent".

### 6.4 Client console and static asset checks (G9, owner request 2026-11-02)

The aim is to find sensitive values that leak to the client. There are two sources:

- **runtime console:** `console.*` output and uncaught errors;
- **static assets:** JS bundles, source maps and config files served to the browser.

Both are checked locally. The model never reads bundles or logs.

#### A. Runtime console (needs a browser engine)
- **Capture:**
  - With `playwright`, attach `page.on('console')`, `page.on('pageerror')` and `requestfailed` to every page and flow step.
  - With `computer-use`, the host forwards the console buffer through `navsentry console ingest`.
  - With `http` only, these checks are `NOT_TESTED` with the reason "no JS runtime".
- **Raw data stays ephemeral:** messages are written only to `.navsentry/work/<run-id>/console/`. A detector redacts each value before anything is promoted. A report keeps the message hash, the level, the source `file:line`, the rule ID and a masked preview such as `eyJ…[JWT,len=412]`.
- **Detectors:**

| Case | Detects | Status |
|---|---|---|
| NSC-CLI-001 | Secrets or tokens in console output: JWT, `Bearer`, API-key patterns, AWS/GCP/Azure key shapes, private-key headers, and values of in-scope cookies or `*_env` actor tokens (exact-match against known test tokens) | VALIDATED when it exactly matches a known test token, otherwise SUSPECTED |
| NSC-CLI-002 | PII in console output: email, phone or national-ID shapes | SUSPECTED |
| NSC-CLI-003 | Debug logging left on in a production build: `console.log`/`debug` present at all in production, verbose framework dev warnings, Redux/Vuex/state dumps, `[HMR]`/`webpack-dev-server` markers | FAIL in production, INFO in development |
| NSC-CLI-004 | Stack traces or internal paths in `pageerror`/console: absolute file paths, internal hostnames or IPs | SUSPECTED |
| NSC-CLI-005 | API response bodies echoed to the console, detected by the structural shape of JSON objects with fields such as `password\|token\|secret\|ssn` | SUSPECTED, with field names only |

- **"Disabled but still found" (residual check):** if the owner says logging is disabled (`expect.console: "silent"` in the manifest or flow), any console output at all is a FAIL with the count. NavSentry also checks the static side for evidence that logging was only *hidden*, which is NSC-CLI-006, SUSPECTED. The evidence it looks for:
  - `console.log = () => {}` overrides, where the original calls remain in the bundle and the arguments are still evaluated;
  - logger levels toggled at runtime through `localStorage`/query flags such as `?debug=1` or `localStorage.debug`. These are detected from the static bundle only. NavSentry never sets them on a production target;
  - `drop_console` absent from a minified bundle that still contains `console.` calls carrying sensitive-looking arguments.

#### B. Static asset scan (http engine, no browser needed)
- **Inventory:**
  - JS and CSS URLs come from the HTML that the page or spider already fetched, plus `*.map` files referenced by `//# sourceMappingURL`.
  - Well-known exposure paths are probed once per origin with HEAD and then GET: `/.env`, `/config.js`, `/env.js`, `/asset-manifest.json`, `/manifest.json`, `/.git/HEAD`, `/*.js.map`, `/__ENV.js`. These are GET-only observations from a fixed list (hard rule 6); they are not fuzzing.
- **Detectors:**

| Case | Detects | Status |
|---|---|---|
| NSC-STA-001 | Secrets in bundles: high-entropy strings near `key\|secret\|token\|password`, provider key shapes, private keys | VALIDATED when the provider format is exact or it matches a known test token, otherwise SUSPECTED |
| NSC-STA-002 | Source maps publicly reachable in production, with `sourcesContent` included | FAIL in production |
| NSC-STA-003 | Exposed config or env files (`/.env`, `env.js` with non-public keys, `.git/HEAD`) | FAIL |
| NSC-STA-004 | Internal endpoints or hosts embedded in bundles (RFC1918, `*.internal`, `localhost:*`, staging hostnames) | SUSPECTED |
| NSC-STA-005 | Debug or dev build shipped: unminified bundle, dev-mode framework flags, `sourceMappingURL` pointing to `file://` | FAIL in production |
| NSC-STA-006 | Vulnerable client libraries, identified from version banners such as `jQuery v1.x` against a locally pinned advisory snapshot (no SaaS lookup) | SUSPECTED, with version and advisory ID |

#### C. Cost optimisation (model budget)
Static scanning can be expensive if raw bundles reach the model, so the pipeline is **local-first, model-last**:

1. **Fetch once, dedupe by content hash.** Every asset is stored once by sha256. The same bundle on 200 pages is scanned once. A cache in `.navsentry/cache/assets/<sha256>.json` holds **findings only, not content** and is reused across runs until the hash changes. The cache is cleaned by `workspace clean`, and its age limit is configurable.
2. **Size and type gates.** Fonts, images and media are skipped by content type. Each asset is limited to 5 MiB, and anything larger is recorded as `skipped: size`. Known vendor chunks, identified by a stable hash across runs or a library banner, are scanned only for NSC-STA-006 and NSC-STA-001.
3. **Fast regex prefilter, then precise check.** A single pass over the file uses combined anchored patterns. Only candidate spans (±200 chars) go to the entropy and format validators. The whole bundle never goes anywhere.
4. **Source maps:** read `sources[]` names first; only scan `sourcesContent` when NSC-STA-002 already applies.
5. **Console streams:** messages are deduplicated by normalised template (numbers and ids stripped), so a log printed 10 000 times is checked once and counted.
6. **The model sees only a summary**, `client-findings.json`, which has a fixed schema: rule, asset display URL, `line:col`, masked preview, count and template hash. It is capped at 200 entries, and the rest are counted as `truncated`. The model's job is to triage and write the report wording, not to scan.
7. **Budget accounting.** `run.json → analyzer.cost` records the bytes scanned locally, the bytes sent to the model (target: < 1 % of scanned bytes) and the cache hit ratio, so the optimisation can be measured.

- **Engine:** detectors run in the same local analyzer as §5. They are Python standard library where approved; otherwise the core regex and entropy detectors have a **Node built-in fallback**, so 6.4-B (http) is not blocked by the Python governance step. This is a deliberate exception to §2's "no silent fallback": the fallback is declared and is reported as `engine: node-detector`.

## 7. Folder layout and workspace hygiene (G7, G8)

### 7.1 Persistent categories (in the project or run root)
```
<project>/navsentry/                 # only path NavSentry writes in a consumer project (configurable)
  manifest.json
  flows/
    approved/   <name>.flow.md       # hash-pinned, owner-approved; the only flows used in production
    drafts/     <name>.flow.md       # analyzer output or hand-written, awaiting review
    chains/     <chain>.chain.json   # ordered flow lists with requires/imports
  analyzer/custom/  *.py             # owner-promoted extractors (reviewed, versioned)
  reports/<run-id>/                  # run.json, REPORT*.md, TEST-REPORT*.md, junit.xml, report.sarif,
                                     # flows.json, page-models/ (redacted), compare.md
.navsentry/work/<run-id>/            # EPHEMERAL: raw captures, screenshots, generated scripts, tmp
```
- `.navsentry/` is added to the consumer's `.gitignore` the first time it is created, but only with consent. If the user declines, NavSentry prints the line for them to add.
- NavSentry keeps a tracked inventory, `navsentry/.navsentry-manifest.json`, which lists every file NavSentry created. `clean` deletes only files that appear in this inventory.

### 7.2 Lifecycle of ephemeral files
1. Each run creates `.navsentry/work/<run-id>/` and writes all intermediate files there.
2. When the run finishes (success, failure or SIGINT), a `finally` block deletes the work directory. A second safety net then sweeps any `work/*` directory older than 24 h at the start of the next run.
3. Only redacted artifacts are **promoted** into `navsentry/reports/<run-id>/`. Promotion runs the Redactor and the artifact leak scan from 0.1.2.
4. The run fails with `WORKSPACE_DIRTY` (exit 4) if, after cleanup, any file outside `navsentry/` and `.navsentry/` has been created or modified. The check compares a snapshot of the root listing taken before the run with one taken after. This makes G8 a check in code, not a promise.
5. `navsentry workspace status` lists the persistent categories, any leftover work directories, and files not in the inventory. `workspace clean [--dry-run]` deletes leftovers. Deleting is only possible inside `.navsentry/work/` and for files listed in the inventory. It never deletes outside these.

### 7.3 Inside the NavSentry repository (maintainers)
- The same rule applies to maintainers. Development scripts and edit helpers go to the OS temp directory or the agent scratchpad, never into the repository tree.
- New gate check **GATE-09 Workspace hygiene**: after `npm test`, `git status --porcelain --ignored` must show nothing new outside `dist/`, `node_modules/` and `.navsentry/`. Leftover `*.cjs`, `*.py` or `tmp*` files fail the gate.

## 8. Report additions
- Header: `environment`, `mode`, `engine`, and for production the authorization reference.
- A **Coverage by template** table (for spider).
- A **Redirect chains** table (production).
- **Analyzer**: the page models produced, the drafts proposed, and generated script hashes with the note "deleted".
- **Workspace**: files promoted, the result of the leftover check, and the cleanup status.

## 9. Safety invariants (testable)
| ID | Invariant |
|---|---|
| S1 | Every engine's network action passes through ScopeGate and Budget. Computer Use does this through the mandatory `scope check` and `budget take` calls, and an action-log entry with no matching check marks the run `INVALID`. |
| S2 | In production, only approved flows run, only observe methods are used, and the run stays inside the authorization window. Otherwise the run refuses to start (exit 3). |
| S3 | No raw page content reaches model-visible artifacts. Only `page-model.json` does, and it is redacted and size-capped. |
| S4 | Generated scripts have no network access, are allowlisted to the standard library, write only inside their run directory, and are deleted after the run. |
| S5 | After every run, nothing new exists outside `navsentry/` and `.navsentry/`; otherwise the run reports `WORKSPACE_DIRTY`. |
| S6 | An unavailable engine is reported `NOT_TESTED` with its reason, and NavSentry never falls back to another engine silently. |
| S7 | The spider never submits forms and never mutates parameters. |
| S8 | Raw console messages and asset content never appear in persisted artifacts or in model-visible input. Only masked previews and hashes do. |
| S9 | Debug toggles (`?debug=1`, `localStorage.debug`) are detected statically and are never activated on a target. |

## 10. Acceptance tests (fixture only, 127.0.0.1)
1. `page`+`http` on the vulnerable fixture: same findings as the seed scan.
2. `spider`: a fixture with 50 `/item/{id}` pages of one template and 3 other templates. The run visits 3 pages per template and records 47 pages as `skipped: duplicate template`, with ≤ 15 requests in total.
3. `spider` hostile fixture: an off-scope link, a `javascript:` link, and a redirect loop. None of them is followed, and each is recorded.
4. Production guard: a manifest with `environment: production` and a draft flow fails with exit 3. A run outside the authorization window also fails with exit 3. Production cannot be exercised for real in tests, so these tests use 127.0.0.1 with `environment: production`.
5. Analyzer (needs approved Python; otherwise the test is skipped and reported as INCOMPLETE): the page model contains no fixture token or field value; `template_id` is stable across 2 instances of a page; the drafts pass `flow lint`.
6. Generated-script sandbox: a script that imports `socket` is rejected, and so is one that writes `../x`.
7. Chains: chain A→B, where A fails, gives B `NOT_TESTED (dependency)`; a cycle is rejected by lint.
8. Hygiene: kill the run mid-way and the next run removes the stale work directory; planting a file at the root during a run gives `WORKSPACE_DIRTY`; GATE-09 fails when a `tmp.cjs` file is left in the repository.
9. Computer Use contract: when an action-log entry has no matching `scope check`, the run is `INVALID`; when the host capability is absent, the result is `NOT_TESTED`.
10. Static assets (vulnerable vs secure fixture):
    - The vulnerable fixture serves a bundle with a test token, a public `.map` with `sourcesContent`, `/env.js` with a non-public key, and an internal hostname. These produce STA-001, 002, 003 and 004.
    - The secure fixture keeps the same bundle contract without those values. It produces PASS and no contract drift.
    - No raw token appears in any artifact.
11. Cost: a bundle referenced by 50 pages is fetched and scanned once. A second run gets 100 % cache hits for unchanged assets. Model-visible bytes are below 1 % of the bytes scanned.
12. Console (needs `playwright`; otherwise INCOMPLETE):
    - A fixture page logs a test token. That gives CLI-001 VALIDATED with a masked preview only.
    - A page logs with `expect.console: "silent"`. That gives a FAIL.
    - A bundle with a `console.log = ()=>{}` override and `?debug` toggle code gives CLI-006 SUSPECTED, and the toggle is never set.
    - With the `http` engine, the console checks are reported `NOT_TESTED` with the reason "no JS runtime".

## 11. Milestones
| Step | Content | Blocked by |
|---|---|---|
| 0.1.3-a | `--env`, production guards, redirect chains, `spider` (http), workspace layout, cleanup, GATE-09 | — |
| 0.1.3-b | Python analyzer (shipped scripts, page model, drafts, generated-script sandbox, chains) | governance entry for CPython |
| 0.1.3-s | Static asset scan (§6.4-B) with the Node detector, hash cache and cost accounting | — |
| 0.1.3-k | Runtime console checks (§6.4-A) | M1b Playwright, or 0.1.3-c |
| 0.1.3-c | Computer Use host contract (`scope check`, `budget take`, action log) | owner decision on the host agent's terms |
| M1b | Playwright engine for `flow` (development) | PRM-GOV-003 |

## 12. Open questions for the owner
1. Should the default consumer folder be `navsentry/`, or something else such as `tests/security/`?
2. Spider representatives per template: is 3 in development and 2 in production acceptable?
3. Is CPython approved as a runtime? Alternatively, should the analyzer be pure Node, which would avoid the Python governance step but works against G6?
