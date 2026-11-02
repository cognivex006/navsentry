# SPEC 0.1.3 — Scan modes, environments, analyzer scripts and workspace hygiene

- Status: **DRAFT** (design only, nothing implemented) · Drafted: 2026-11-02 · Review: round 1 done 2026-11-02 (changes in [§13](#13-review-log)); round 2 pending
- Builds on: [SPEC-0.1.2](SPEC-0.1.2-FLOW-TEST-CASES.md), [ADR-0001](../adr/0001-typescript-node-stack.md), [ADR-0003](../adr/0003-zero-runtime-dependencies.md), [ADR-0004](../adr/0004-scope-enforcement-at-transport.md), [ADR-0006](../adr/0006-flow-files-and-test-levels.md) · Baseline: 0.1.2 (`feat/flows-0.1.2` @ `318825c`, not yet on `main`)
- Security is still the primary purpose. Functional results come along with it; they never replace it.
- Compatibility: 0.1.3 is additive. Existing manifests, flow files, the `test`/`flow`/`plan` commands, the `.navsentry/runs/` output and exit codes 0–3 keep working unchanged.

## 0. สรุปสำหรับเจ้าของงาน

**เป้าหมาย:** เพิ่มโหมดสแกน 3 แบบ ได้แก่ `page` (หน้าเดียว), `spider` (หลายหน้า โดยจัดกลุ่มหน้าที่ใช้ template เดียวกันแล้วตรวจแค่ตัวแทน) และ `flow` (เล่นตาม Flow) แยกโปรไฟล์ development กับ production ให้ชัด วิเคราะห์หน้าเว็บบนเครื่อง (โมเดลเห็นแค่สรุปที่ redact แล้ว) ตรวจ console และไฟล์ static ที่ส่งถึงเบราว์เซอร์ และบังคับด้วยโค้ดว่าไม่มีไฟล์ชั่วคราวค้างในโปรเจกต์

**ทำได้ทันทีโดยไม่ติด governance:** คำสั่ง `scan` กับโปรไฟล์ production, การบันทึก redirect ทีละ hop, `spider` ผ่าน HTTP, การสแกนไฟล์ static (ยกเว้นการเทียบเวอร์ชัน library กับ advisory), Flow แบบต่อกัน (chain), โครงสร้างโฟลเดอร์, การลบไฟล์ชั่วคราว และ GATE-09

**ยังติดอยู่ (รายงานเป็น `NOT_TESTED` พร้อมเหตุผล และไม่มีการสลับไปใช้ engine อื่นแบบเงียบ ๆ):**
- Python analyzer: ต้องมี governance entry ของ CPython และ ADR ใหม่ เพราะ ADR-0001 กำหนดให้ core ใช้เฉพาะ Node built-ins
- Playwright และการตรวจ console ขณะรัน: governance ของ Playwright ยังเป็น `PENDING_REVIEW`
- Computer Use: ผู้ให้บริการ visual ยังเป็น `NOT_ADOPTED` และ NavSentry บังคับ ScopeGate ตอน connect ในเบราว์เซอร์ของ host ไม่ได้
- การเทียบเวอร์ชัน library ฝั่ง client กับ advisory: แหล่งข้อมูล advisory ต้องผ่าน governance ก่อน

**ปรับจากร่างแรก (รายละเอียดใน §13):**
- ใช้ค่า `environment` เดิมของ manifest แทนการเปลี่ยน schema
- development ไม่ขยาย scope ให้ loopback อัตโนมัติ
- `analyzer` เป็นขั้นวิเคราะห์ ไม่ใช่ engine ที่ดึงข้อมูล
- ไม่รันสคริปต์ Python ที่โมเดลสร้างขึ้น แต่ใช้ extractor ที่เขียนเป็น JSON แทน
- รหัสเคสใช้ระบบ `NSC-<CATEGORY>-NNN` เดิม และผูกกับเคสที่มีอยู่แล้วเมื่อเป็นปัญหาเดียวกัน
- รายงานยังอยู่ใน `.navsentry/runs/` จึงไม่มีการ commit รายละเอียดช่องโหว่เข้า repository ของโปรเจกต์ที่ถูกทดสอบ

**ต้องการการตัดสินใจจากเจ้าของงาน:** [§12](#12-owner-decisions)

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

The goals are recorded as the owner stated them. Where the design maps a goal differently, the section says so: the `analyzer` engine in G1/G2 (§2), the limits of G6 (§5.1), and generated scripts in G7 (§5.4).

## 2. Capability matrix (honest status)

An **engine** fetches pages or drives a browser. Each engine maps to a transport that already exists in `transports.order`. **Analysis** is a separate local stage that runs on what an engine captured (`--analyze`). It never fetches anything, so it is not an engine. `--engine analyzer` is accepted as shorthand for `--engine http --analyze`, to match G1/G2.

| Engine | Transport (`transports.order`) | Status on 2026-11-02 |
|---|---|---|
| `http` | `direct-http` | USABLE |
| `playwright` | `playwright-browser` | BLOCKED: governance entry is `PENDING_REVIEW` (PRM-GOV-003); execution is scheduled for M1b |
| `computer-use` | `visual-computer-use`, and the manifest needs `transports.visual_computer_use: true` | BLOCKED: visual providers are `NOT_ADOPTED` in governance; the host contract (§6.3) is not built |

| Mode \ Engine | `http` | `playwright` | `computer-use` | `--analyze` (local) | Production profile |
|---|---|---|---|---|---|
| `page` (single page) | USABLE as `test` (seed scan); `scan` PLANNED for 0.1.3-a | — (not in G1; §12 D7) | BLOCKED | BLOCKED: page-model runtime (§5.6) | yes, observe |
| `spider` (multi-page) | PLANNED for 0.1.3-a | — (not in G2; §12 D7) | BLOCKED | BLOCKED (as above) | yes, observe with strict budget |
| `flow` (follow flow) | USABLE (0.1.2, `test --flows`) | BLOCKED; development only | BLOCKED | — | `http`: approved flows only. `computer-use`: per-run consent. `playwright`: refused |

Static asset checks (§6.4-B) run on whatever `http` fetched. They use the Node detector, so they do not wait for the Python decision.

Rules:
- An engine that is not USABLE is reported as `NOT_TESTED` with the reason, both in `doctor` and in the run report. It never falls back silently to another engine.
- Hard rule 5 applies: an engine is never marked USABLE before its adapter and governance entry exist.
- Status words come from the existing wire model; this spec adds none. Transport probes are `USABLE | DETECTED | UNAVAILABLE`. Checks are `PASS | FAIL | INCONCLUSIVE | NOT_TESTED | ERROR`. Findings are `SUSPECTED | VALIDATED | NEEDS_REVIEW | DISMISSED`. Runs are `executionStatus: COMPLETE | PARTIAL | FAILED`. `BLOCKED` and `PLANNED` appear only in the matrix above.

## 3. CLI surface

```
navsentry scan  --config <manifest.json>  --mode page|spider|flow  [--engine http|playwright|computer-use]
                [--analyze] [--env development|production] [--url <in-scope URL>] [--flows <path>] [--out <dir>]
navsentry flow analyze --config <manifest.json> --from-run <run.json> --out <dir>   # 0.1.2; also reads page-models/ beside run.json
navsentry workspace status|clean [--dry-run]                                       # §7
```

- `--config`, as in every existing command. `--engine` defaults to `http`.
- `test`, `flow`, `plan` and `discover --dry-run` keep their 0.1.2 behaviour. `test` is not deprecated in 0.1.3.
  - `scan --mode page --engine http` without `--url` is the same seed scan as `test`.
  - `scan --mode flow --flows <path>` is the same as `test --flows <path> --flows-only`.
  - Live `discover` is refused today ("scheduled for M1b"). It becomes `scan --mode spider`. `discover --dry-run` stays the zero-network plan.
- There is no separate `navsentry analyze`. Raw captures are deleted when the run ends (§7.2), so analysis has to happen inside the run (`--analyze`). The run persists only the redacted `page-models/`, and `flow analyze` turns the run and its page models into draft flows.
- `--env` is an optional safety assertion. If it is given and differs from the manifest's profile (§4), the run exits 3 before any network activity. It never overrides the manifest.
- A mode and engine pair marked `—` in §2 exits 3. A pair marked BLOCKED runs nothing on that engine and reports `NOT_TESTED` with the reason (exit 2, incomplete).
- Exit codes: 0–3 as today, plus **4 = `WORKSPACE_DIRTY`** (§7.2). When several apply, the precedence is 3 > 4 > 1 > 2 > 0. HELP, README and the header comment of `src/cli.ts` list the new code.

## 4. Environments (profiles)

The manifest already has a required `environment` field: `local | dev | staging | production` (`src/config.ts`). 0.1.3 does not change the field. It derives a **profile** from it:

| `environment` | Profile |
|---|---|
| `local`, `dev` | `development` |
| `staging`, `production` | `production` (recommended; §12 D4) |

The table below shows how the two profiles differ.

| Aspect | development | production |
|---|---|---|
| Allowed origins | Exactly the manifest `targets.origins`. Loopback and private addresses still need a `network.allow_private` approval per host. The profile never adds origins. | Same as development. In both profiles, an origin that contains `*` is rejected when the manifest loads. Today it would simply never match; with this rule it fails loudly. |
| Sources of evidence | code (static: routes, OpenAPI, test files; §4.1), localhost runs, integration tests, Playwright (when approved) | HTTP responses and redirect chains, Computer Use exploration (when approved) |
| Methods | observe: GET/HEAD/OPTIONS (already the only methods allowed in this release) | observe only; `safety.mode` is already forced to `observe` for production. Redirects are followed hop by hop, and every hop passes ScopeGate (already true for seeds, up to `MAX_REDIRECTS` = 5). |
| Flows | drafts with `--include-drafts`; their findings stay SUSPECTED (0.1.2) | **approved flows only** (hash-pinned). `--include-drafts` is refused, as in 0.1.2. |
| Budget defaults | the current defaults, unchanged: 200 requests, 2 rps, 30 pages; spider N = 3 per template | 100 requests, 1 rps, spider depth ≤ 2, N = 2 per template (≤ 2N pages per template including spread checks) |
| Authorization | `authorization.acknowledged: true` and `owner`, as today | as development, and `reference` (a ticket ID, never a hostname) and `expires_at` become required. New optional `not_before`. Outside `[not_before, expires_at]` the run refuses to start (exit 3). A run that passes `expires_at` stops, and the result is `PARTIAL`. |
| Credentials | `*_env` variables, test values | `*_env` variables only. A token with a recognised live-key prefix (for example `sk_live_`) is refused unless `authorization.allow_live_tokens: true`. |

- Explicit manifest budget values win over the profile defaults, within the existing validation ranges (§12 D6). `plan` prints the effective values.
- The new manifest keys (`authorization.not_before`, `authorization.allow_live_tokens`, and later `checks.console` and `workspace.ignore`) are additive. A 0.1.2 build rejects them as unknown keys, which is the safe failure.

### 4.1 Development: code-based analysis
- The `code` source analyzer reads the project tree **read-only**: route tables, OpenAPI files, existing integration and Playwright tests. From these it builds an inventory of routes and test candidates. It never runs the project's code, never writes into the target repository, and never follows a symlink or junction out of the tree.
- The target repository's AGENTS.md and README files are untrusted data (hard rule 7).
- Milestone 0.1.3-d (§11). The first slice is the 0.1.2 §19 candidate: import a local OpenAPI JSON file into draft integration flows.

### 4.2 Production: HTTP and redirect analysis
- Already implemented for seeds: redirects are followed hop by hop, and a hop that leaves scope is recorded in `denials` but never requested.
- New in 0.1.3: each hop is recorded with its status, `Location` (as a display URL), the scope decision, and what changed in the security headers.
- The checks on each hop reuse existing cases: HTTP→HTTPS upgrade (NSC-CRYPT-006), HSTS on the final hop (NSC-CONF-001), and cookie flags (NSC-SESS-001 to 003).
- Open-redirect *observation* has no case yet, so it needs a new catalog entry (proposed NSC-AC-008, CWE-601 as a candidate mapping). It looks only at reflected parameters that are already in seed URLs and injects no payloads.

## 5. Analyzer (local page analysis)

### 5.1 Principle
Raw page content stays on the machine. A local analysis script reduces it to a **structured page model**. The model (LLM) receives only that page model, which is already redacted and size-capped. It uses the page model to propose flows. The page model is the only artifact allowed to cross from the analyzer to the model.

```
engine capture (http body / playwright DOM / computer-use DOM text)
   → .navsentry/work/<run-id>/raw/                 (ephemeral, deleted when the run ends)
   → python -I -S -B <package>/analyzer/page_model.py <raw file>  → page model on stdout (redacted, ≤ 64 KiB per page)
   → promoted to <run dir>/page-models/            (Redactor + artifact leak scan, §7.2)
   → `flow analyze --from-run` and/or the agent read the page models → navsentry/flows/drafts/*.flow.md
   → navsentry flow lint → owner approval → navsentry/flows/approved/
```

**Limit of this guarantee.** NavSentry has no model API (no SaaS; see governance). "The model" is the host agent, and the agent can read any file it has access to. NavSentry guarantees only this: raw captures exist only in `.navsentry/work/` while the run is going, they are deleted at the end, and they never appear in reports or in the agent-facing artifacts. The consumer skill tells the agent not to open `.navsentry/work/`. NavSentry cannot stop an agent from opening a file during a run. G6 is therefore met by design and by skill instruction, not by isolation.

### 5.2 Page model (wire format, JSON)
`{ url(display), template{path_pattern, shape_hash}, title, forms[{action, method, fields[{name,type,required}]}], links[{href(display), rel, same_template}], scripts{inline_count, external_origins[]}, security{csp, frames, cookies[flags only], mixed_content}, text_landmarks[≤ 20 headings], hashes{dom_shape, text} }`

- Field values, cookie values, tokens, emails and bodies are **never** included. Only names, types and flags are recorded.
- `title` and `text_landmarks` are page text, so they pass through the Redactor and are cut to 120 characters each.
- `template` is computed in the Node core (§6.2), so the spider does not depend on the analyzer.
- Unknown fields are rejected when a page model is read back.

### 5.3 Scripts shipped by NavSentry (not generated)
The analyzer scripts are versioned **source** files in `analyzer/` inside the NavSentry package, and `package.json → files` gains `analyzer/`.
- They use the Python standard library only (`html.parser`, `json`, `hashlib`, `re`, `pathlib`). No pip installs. Each script is a single file, because `-I` removes the script's own directory from `sys.path` and sibling imports would fail.
- **Interpreter:** an absolute path from fixed trusted locations (the doctor probe), or an absolute path the owner sets. Never a bare `python` from `PATH`. This is the same rule as `TRUSTED_CURL`, and on Windows it also avoids the Microsoft Store alias stub. The version is checked (≥ 3.12).
- **Spawn:** `-I -S -B`: isolated mode; no `site`, so no `.pth` file can run code; and no `__pycache__` is written into the package, which would itself be a leftover (G8). Also `shell: false`, `scrubbedEnv()`, and the work directory as `cwd`. The input path is passed as an argument, and output goes to stdout as size-capped JSON, so the script writes no files.
- **Network:** there is no OS-level network sandbox. None is available without a new governed tool. Shipped scripts are kept network-free by review. A gate check helps that review: it allowlists the imports in `analyzer/*.py` and bans `__import__`, `importlib`, `exec`, `eval`, `compile`, `ctypes`, `socket`, `subprocess` and `os.system`. This is a review aid for reviewed code, not a sandbox.
- **Limits:** 30 s per page, 2 MiB input per page, 64 KiB output per page. An overrun makes that page's check `ERROR`; partial output is not used.

### 5.4 Site-specific extractors (declarative, never generated code)
When the model needs a site-specific extractor, it writes a **declarative extractor spec** in JSON, not a script. The shipped `page_model.py` interprets it.
- Schema: `{ "extractor": "1", "id", "match": {"path_pattern"}, "fields": [{"name", "select" (tag and attribute path), "attr"?, "regex"? (≤ 200 characters), "max_items" (≤ 50)}] }`. Unknown keys are rejected, and field names that look like secrets are rejected, as in manifests. Extracted values pass through the Redactor.
- Extractor specs are written only to `.navsentry/work/<run-id>/extractors/`, and they are deleted with the run directory (§7). The only thing kept is their sha256, in `run.json → analyzer.extractors[]`, so the run stays auditable.
- To keep an extractor, the owner must move it explicitly into `navsentry/analyzer/extractors/` under review. It is never promoted automatically.
- **NavSentry never executes model-generated code.** A generated script cannot be confined with what is approved today: a path check in the wrapper cannot see writes made inside the Python process, and an import check can be bypassed. Running generated code would need its own sandbox design and separate owner authorization, like `active-approved`. It is out of scope for 0.1.3 (§12 D5).

### 5.5 Analyzer outputs for flows
- A **self-contained flow** has one entry point, does not depend on another flow, and needs no state from a previous flow.
- A **chained flow** declares `requires: ["<flowId>"]` and `imports: {"<var>": "<flowId>.<var>"}` in its header. These are new additive keys, and a 0.1.2 parser rejects them. Chains **supersede** the 0.1.2 rule "variables never cross flows" (SPEC-0.1.2 §5.8), under these constraints:
  - Only a variable that the source flow extracted in a `PASS` step can be imported. The 0.1.2 runtime value rule, substitution rule and Redactor registration still apply.
  - The runner orders flows with a topological sort. Cycles and missing flows are lint errors.
  - If a required flow is not `PASS`, the dependent flow is `NOT_TESTED` with the reason "dependency <id> is <status>". It is never FAIL and never PASS.
  - The `content_sha256` of a dependent flow covers the hashes of the flows it requires. Editing a required flow therefore invalidates the approval of every flow that depends on it.
- Chains are declared only in flow headers. There is no separate chain file, because two sources of truth would drift.
- Every generated flow starts as `review.status: draft` with `provenance: {kind: "analyzer", from_run, template: "<path_pattern>"}`. The existing `provenance` object gains the `template` key.

### 5.6 Governance prerequisite (blocking)
- Python is a new runtime binary, so hard rule 2 applies. Before any code that spawns Python is merged, `governance/third-party.json` needs an APPROVED entry for **CPython ≥ 3.12 (PSF License)**. The entry covers provenance (python.org or the OS package), the advisory check, and why it is needed (standard-library HTML parsing outside the Node process).
- ADR-0001 says the core uses only Node built-ins. Spawning Python therefore also needs a new ADR (ADR-0007) that amends ADR-0001 for the optional analyzer.
- If the runtime is missing or not approved, `doctor` shows the analyzer as `UNAVAILABLE` with the reason, and `--analyze` gives `NOT_TESTED`. A Node fallback for the page model is **not** provided silently.
- Environment observed on 2026-11-02: Python 3.13.14 is present on the maintainer machine. Being present does not make it approved.

## 6. Modes

### 6.1 `page`
- Fetches one in-scope URL (`--url`) or, without `--url`, the manifest `seed_paths` (the same as today's `test`). It runs every observe-mode check on them and, with `--analyze`, writes their page models.
- Output: a normal `run.json`/`REPORT.md` plus `page-models/` (redacted) in the run directory.

### 6.2 `spider` (template-aware crawler)
- BFS from `seed_paths`. A link is queued only when the static `ScopeGate.checkRequest` allows it; the runtime check stays authoritative.
- `robots.txt` is fetched once per origin, through ScopeGate and Budget like any other request. Production honours it (it is read, never overridden). Development records it but does not enforce it.
- Pages are grouped in two stages. Both run in the Node core, so the spider is not blocked by §5.6.
  1. **Before fetching:** the path of each discovered URL is normalised into a `path_pattern`. Numeric, UUID, hash-like and long-slug segments become `{id}`, and query values are dropped. The spider picks **N representatives** per pattern (by default 3 in development and 2 in production) and records the rest as `skipped: duplicate template` without requesting them. A typical example is `/product/1…/product/9999`, which becomes `/product/{id}`.
  2. **After fetching:** a `shape_hash` confirms the group. It is the sha256 of the tag skeleton: tag names and nesting, with no text, ids, classes or attribute values, and with script and style bodies ignored. If representatives of one pattern have different shape hashes, the group splits, and each new group gets its own representatives within the budget. The shape hash is only a grouping heuristic, never evidence for a finding.
- A finding on one representative leads to checking up to N more pages of that pattern (so ≤ 2N per pattern), to confirm the finding and measure how far it spreads.
- `safety.max_pages`, `targets.denied_paths`, the depth limit and `Budget` are hard limits.
- No form submission, no query fuzzing, and no parameter mutation (hard rule 6). `javascript:`, `data:` and `mailto:` links are recorded and never followed.
- Report: a coverage table per pattern (pattern, representatives, shape hashes, skipped count), a list of skipped pages with reasons (budget, robots, out of scope, duplicate template, depth), and findings grouped by pattern.

### 6.3 `flow`
- `http`: the 0.1.2 behaviour, unchanged.
- `playwright` (development only; blocked until M1b governance is done): the UI steps `click`/`fill`/`see` run in a headless browser. ScopeGate is applied through `context.route('**')` with deny by default, and service workers are blocked (`serviceWorkers: 'block'`).
  - The adapter already declares the channels that `route()` cannot see: WebSocket frames after the upgrade, and browser-internal requests. `route()` also gives no connect-time check (ADR-0004).
  - The M1b design should evaluate a loopback forward proxy inside NavSentry, set as the browser's `--proxy-server`. It would apply `checkRequest`, `checkResolvedAddress` and `Budget` at CONNECT time, which covers those channels as well.
- `computer-use`: drives a **host-provided** Computer Use or browser agent. NavSentry still owns the safety layer, but the contract is **cooperative**:
  - The host's browser opens its own connections. NavSentry cannot enforce connect-time checks there, and it cannot block a request that the host never asked about. The adapter already lists this channel as unenforceable. This is why findings are capped and why production needs consent for each run.
  - The budget belongs to the run, so per-action calls need shared state:
    - `navsentry session start --config <m>` creates `.navsentry/work/<run-id>/session.json` (budget counters and lock) and prints the run ID.
    - `navsentry scope check --run <id> <url>` and `navsentry budget take --run <id>` update that state atomically.
    - `navsentry session end --run <id>` writes the run result.
    - Every call is written to the action log.
  - If an action-log entry has no matching `scope check`, the run gets `executionStatus: FAILED` with the reason "unchecked computer-use action", and none of its findings is reported as VALIDATED.
  - Each production run needs consent that the owner gives at run time. The consent is recorded as a timestamp and actor label, never as a name.
  - Computer Use findings are capped at `SUSPECTED`, unless the same issue is confirmed afterwards by an `http` re-check, which can raise it to `VALIDATED`.
  - Screenshots are stored only in `.navsentry/work/` and are deleted. The report keeps only redacted text observations.
  - Hard rule 5: if the host has no Computer Use, the result is `NOT_TESTED` with the reason "host capability absent".

### 6.4 Client console and static asset checks (G9, owner request 2026-11-02)

The aim is to find sensitive values that leak to the client. There are two sources:

- **runtime console:** `console.*` output and uncaught errors;
- **static assets:** JS bundles, source maps and config files served to the browser.

Both are checked locally. The model never reads bundles or logs.

**Catalog rule.** Case IDs follow `NSC-<CATEGORY>-NNN` (`src/catalog.ts`). A detector whose root cause matches an existing case adds a new *evidence source* to that case; it does not create a parallel case. New cases are proposed only for new root causes. The proposed numbers are the next free ones on 2026-11-02 (`NSC-INFO-002` is reserved and never reused). They become final only when they are added to the catalog with complete entries (FACT, EVIDENCE, ACCEPTANCE, webRecheck, fix, regressionGuard) and verified mappings; the CWE IDs below are candidates to verify then. Detector labels such as `CON-SECRET` are internal names. `CheckResult.ruleId` is always the case ID, so `checks.disabled` keeps working. Detectors reuse the Redactor's patterns (`src/redact.ts`), so there is one definition of each secret shape.

#### A. Runtime console (needs a browser engine)
- **Capture:**
  - With `playwright` (`flow`, development), attach `page.on('console')`, `page.on('pageerror')` and `requestfailed` to every page and flow step.
  - With `computer-use`, the host forwards the console buffer through `navsentry console ingest --run <id>`.
  - With `http` only, these checks are `NOT_TESTED` with the reason "no JS runtime". `page` and `spider` have no browser engine in G1/G2 (§12 D7).
- **Raw data stays ephemeral:** messages are written only to `.navsentry/work/<run-id>/console/`. A detector redacts each value before anything is promoted. A report keeps the message hash, the level, the source `file:line`, the case ID and a masked preview such as `eyJ…[JWT,len=412]`.
- **Detectors:**

| Detector | Detects | Case | Result |
|---|---|---|---|
| CON-SECRET | Secrets or tokens in console output: JWT, `Bearer`, API-key and provider key shapes, private-key headers, and exact matches of in-scope cookie values or `*_env` actor tokens | proposed **NSC-INFO-006** Sensitive data written to the browser console (candidate CWE-532) | VALIDATED only on an exact match with a known test token or in-scope cookie value (a deterministic assertion); otherwise SUSPECTED |
| CON-PII | Email, phone or national-ID shapes (the Thai ID with its checksum) | existing NSC-INFO-004 (email) and NSC-PRIV-001 (personal identifier) | SUSPECTED |
| CON-DEBUG | Debug output on a production build: state-store dumps (Redux/Vuex), framework dev-mode warnings, `[HMR]`/`webpack-dev-server` markers | existing NSC-CONF-005 Debug mode / development features enabled | production profile: check FAIL, finding SUSPECTED. Development: observation only. A plain count of `console.log` calls is recorded as an observation, never a FAIL: most production sites log something harmless, and a count alone proves nothing. |
| CON-TRACE | Stack traces, absolute file paths, internal hostnames or IPs in `pageerror` or console output | existing NSC-ERR-001 and NSC-INFO-003 | SUSPECTED |
| CON-ECHO | API response bodies echoed to the console, detected by the shape of JSON objects with keys such as `password\|token\|secret\|ssn` | proposed NSC-INFO-006 | SUSPECTED, with field names only |

- **"Disabled but still found" (residual check, NSC-INFO-006):** the owner can declare that logging is disabled, with `checks.console: "silent"` in the manifest or `console: "silent"` in a flow header (both new and additive). Then any console output at all makes the check FAIL, with the count. NavSentry also checks the static side for evidence that logging was only *hidden*, and reports that as SUSPECTED. The evidence it looks for:
  - `console.log = () => {}` overrides, where the original calls remain in the bundle and the arguments are still evaluated;
  - logger levels toggled at runtime through `localStorage`/query flags such as `?debug=1` or `localStorage.debug`. These are detected from the static bundle only. NavSentry never sets them on any target;
  - `drop_console` absent from a minified bundle that still contains `console.` calls carrying sensitive-looking arguments.

#### B. Static asset scan (http engine, no browser needed)
- **Inventory:**
  - JS and CSS URLs come from the HTML that the page or spider already fetched.
  - Source maps come from `//# sourceMappingURL` comments and the `SourceMap`/`X-SourceMap` response headers. For each discovered bundle, the `<bundle>.map` sibling is probed once.
  - A fixed list of well-known exposure paths is probed once per origin: `/.env`, `/.git/HEAD`, `/config.js`, `/env.js`, `/__ENV.js`, and `/asset-manifest.json` (used as an inventory source, not as a finding). `/manifest.json` is not probed, because a web app manifest is public by design. Each path gets a HEAD, and a GET follows only when the HEAD returns 2xx or 405.
  - These are GET-only observations from a fixed list (hard rule 6); they are not fuzzing. Every probe goes through ScopeGate and Budget. A path outside `allowed_paths` or inside `denied_paths` is `NOT_TESTED`, never forced.
- **Bodies of exposed files** are processed only in memory and in the work directory. Only key names and masked values are kept (S8).
- **Detectors:**

| Detector | Detects | Case | Result |
|---|---|---|---|
| STA-SECRET | Secrets in bundles: provider key shapes, private keys, high-entropy strings near `key\|secret\|token\|password` | proposed **NSC-INFO-007** Secrets embedded in client-side assets (candidates CWE-540, CWE-798); the runtime counterpart of NSC-AUTH-001, which is `sast-only` | VALIDATED only on an exact match with a known test token. An exact provider format gives SUSPECTED with high confidence: a format match does not prove that a key is live, and NavSentry never calls the provider to test it. |
| STA-SOURCEMAP | Source maps publicly reachable, with `sourcesContent` included | proposed **NSC-INFO-008** Source maps with source content served publicly (candidate CWE-540) | production profile: check FAIL, finding VALIDATED (the map was fetched and `sourcesContent` is not empty). Development: observation only. |
| STA-EXPOSED | Exposed config, env or VCS files (`/.env`, `env.js` with non-public keys, `/.git/HEAD`) | proposed **NSC-CONF-009** Configuration or VCS files publicly reachable (candidates CWE-538, CWE-527) | VALIDATED only when the body matches the file's format, for example `ref: refs/` for `.git/HEAD` or `KEY=` lines for `.env`. A 200 response with HTML (a single-page-app fallback) is not a finding. |
| STA-INTERNAL | Internal endpoints or hosts embedded in bundles (RFC1918, `*.internal`, `localhost:*`, staging-looking hostnames) | existing NSC-INFO-003 | SUSPECTED |
| STA-DEVBUILD | Debug or dev build shipped: unminified bundle, dev-mode framework flags, `sourceMappingURL` pointing to `file://` | existing NSC-CONF-005 | production profile: check FAIL, finding SUSPECTED |
| STA-LIBVULN | Vulnerable client libraries, identified from version banners such as `jQuery v1.x` against a locally pinned advisory snapshot (no SaaS lookup) | proposed **NSC-SUPPLY-002** Client-side library with known vulnerabilities (candidate CWE-1395) | SUSPECTED, with version and advisory ID. BLOCKED until the advisory data source has a governance entry: OSV, NVD and GitHub Advisory APIs are `NOT_ADOPTED`, and an offline snapshot of their data still needs a license and terms review. |

#### C. Cost optimisation (model budget)
Static scanning can be expensive if raw bundles reach the model, so the pipeline is **local-first, model-last**:

1. **Fetch once, dedupe by content hash.** Every asset is stored once by sha256. The same bundle on 200 pages is scanned once. A cache in `.navsentry/cache/assets/<sha256>.json` holds **findings only, not content**. Its key includes the detector version, so a rule change invalidates it; otherwise it is reused across runs until the hash changes. The cache is cleaned by `workspace clean`, and its age limit is configurable.
2. **Size and type gates.** Fonts, images and media are skipped by content type. Each asset is limited to 5 MiB, and anything larger is recorded as `skipped: size`. Known vendor chunks, identified by a stable hash across runs or a library banner, are scanned only by STA-LIBVULN and STA-SECRET.
3. **Fast regex prefilter, then precise check.** A single pass over the file uses combined anchored patterns. Only candidate spans (±200 chars) go to the entropy and format validators. The whole bundle never goes anywhere.
4. **Source maps:** read the `sources[]` names first; only scan `sourcesContent` when STA-SOURCEMAP already applies.
5. **Console streams:** messages are deduplicated by normalised template (numbers and ids stripped), so a log printed 10 000 times is checked once and counted.
6. **The model sees only a summary**, `client-findings.json`, which has a fixed schema: case ID, asset display URL, `line:col`, masked preview, count and template hash. It is capped at 200 entries, and the rest are counted as `truncated`. The model's job is to triage and write the report wording, not to scan.
7. **Budget accounting.** `run.json → analyzer.cost` records the bytes scanned locally, `agentVisibleBytes` and the cache hit ratio, so the optimisation can be measured. `agentVisibleBytes` is the size of the artifacts meant for the agent (page models and `client-findings.json`), with a target below 1 % of the scanned bytes. NavSentry has no model API, so it measures what it hands over, not what an agent chooses to read.

- **Engine:** the §6.4 detectors are regex, entropy and format validators. They run on Node built-ins (`RegExp`, `node:crypto`) and need no HTML parser, so they need no Python. This is the primary engine for §6.4, not a fallback, and it is reported as `engine: node-detector`.

## 7. Folder layout and workspace hygiene (G7, G8)

### 7.1 Persistent categories
```
<project>/navsentry/                 # tracked, owner-reviewed inputs (folder name: §12 D1)
  manifest.json
  flows/
    approved/   <id>.flow.md         # hash-pinned, owner-approved; the only flows used in production
    drafts/     <id>.flow.md         # analyzer output or hand-written, awaiting review
  analyzer/extractors/  *.json       # owner-promoted extractor specs (§5.4)
<project>/.navsentry/                # untracked; holds its own .gitignore containing "*"
  runs/<run-id>/                     # reports, as today: run.json, REPORT*.md, TEST-REPORT*.md, junit.xml,
                                     # report.sarif, flows.json, page-models/ (redacted), compare.md
  work/<run-id>/                     # EPHEMERAL: raw captures, screenshots, extractor drafts, session.json, lock
  cache/assets/                      # findings-only asset cache (§6.4-C)
  inventory.json                     # every file NavSentry created under navsentry/ and .navsentry/
```
- These are the only two paths NavSentry writes in a consumer project. The layout is the default that the skill and docs recommend; commands that take `--out` still write where they are told.
- Reports stay in `.navsentry/runs/`, which is today's default. They describe vulnerabilities, so they are not written into a tracked folder by default: the consumer repository may be public. Keeping a report in the repository is the owner's explicit choice (`--out`).
- NavSentry never edits the consumer's root `.gitignore`. The first time it creates `.navsentry/`, it writes `.navsentry/.gitignore` containing `*`, which makes git ignore the whole directory without touching any other file.
- `.navsentry/inventory.json` lists every file NavSentry created. `clean` deletes only files that appear in this inventory or that are under `.navsentry/work/`. The inventory is untracked; if it is lost, `clean` deletes nothing outside `work/`, which is the safe default.

### 7.2 Lifecycle of ephemeral files
1. Each run creates `.navsentry/work/<run-id>/` with a `lock` file (process ID, start time, host) and writes all intermediate files there.
2. When the run exits, the run deletes its work directory. This covers success, failure, SIGINT and SIGTERM. Signals need their own handlers, because Node does not run `finally` blocks when a signal ends the process.
3. At start, every run sweeps any `work/*` directory whose lock names a process that is no longer running, whatever its age. A directory without a readable lock is swept after 24 h. The directory of a live run is never touched, so concurrent runs are safe. A SIGKILL or a power loss is handled by the next run's sweep.
4. Deletion is containment-checked. NavSentry resolves real paths and refuses to delete anything whose real path is outside `.navsentry/work/` or the inventory. It never follows symlinks or Windows junctions; it removes the link itself.
5. Only redacted artifacts are **promoted** into `.navsentry/runs/<run-id>/`. Promotion runs the Redactor and the artifact leak scan from 0.1.2.
6. `WORKSPACE_DIRTY` (exit 4) makes G8 a check in code, not a promise:
   - Before the run, NavSentry takes a recursive snapshot of the project tree (relative path, size, mtime). It excludes `.git/`, `node_modules/`, `navsentry/`, `.navsentry/` and the manifest's `workspace.ignore` globs, which are meant for output that a running dev server writes (for example `.next/**`).
   - After cleanup it takes a second snapshot. Any path that was created or modified in between is listed, and the run exits 4.
   - If the tree has more than 200 000 entries, the check is `NOT_TESTED` with that reason, never PASS.
   - Limitation: the check sees changes made during the run by any process, not only by NavSentry. The report says so.
7. `navsentry workspace status` lists the persistent categories, any leftover work directories, and files not in the inventory. `workspace clean [--dry-run]` deletes leftovers under the rules in step 4.

### 7.3 Inside the NavSentry repository (maintainers)
- The same rule applies to maintainers. Development scripts and edit helpers go to the OS temp directory or the agent scratchpad, never into the repository tree.
- New gate check **GATE-09 Workspace hygiene**:
  - Before GATE-02 runs the tests, the gate records `git status --porcelain=v1 --ignored --untracked-files=all`, and it records it again afterwards. Any path that is new in the second listing and lies outside `dist/` and `.navsentry/` fails the gate. Comparing before and after keeps the maintainer's own ignored files (`.env`, `runs/`, `*.log`, `.claude/launch.json`) from failing it.
  - Independently, any **untracked** `*.cjs`, `*.py`, `*.ps1`, `*.sh` or `tmp*` file in the tree fails the gate. Tracked files, such as the shipped `analyzer/*.py`, are not affected.

## 8. Report additions
- Header: `environment`, profile, `mode`, `engine`, and for the production profile the authorization reference.
- A **Coverage by template** table (for spider).
- A **Redirect chains** table (production).
- **Analyzer**: the page models produced, the drafts proposed, and extractor spec hashes with the note "deleted".
- **Workspace**: files promoted, the result of the leftover check, and the cleanup status.

## 9. Safety invariants (testable)
| ID | Invariant |
|---|---|
| S1 | Every engine's network action passes through ScopeGate and Budget. For Computer Use this is a cooperative contract: the host calls `scope check` and `budget take`, and an action-log entry with no matching check makes the run `FAILED`. |
| S2 | In the production profile, only approved flows run, only observe methods are used, and the run stays inside the authorization window. Otherwise the run refuses to start (exit 3). |
| S3 | No raw page content reaches agent-facing artifacts. Only the redacted, size-capped page model does. |
| S4 | NavSentry never executes model-generated code. Extractor specs are data, validated against a strict schema. Shipped scripts run with `-I -S -B`, a scrubbed environment, and an interpreter from a trusted absolute path. |
| S5 | After every run, nothing new exists outside `navsentry/` and `.navsentry/`; otherwise the run reports `WORKSPACE_DIRTY` (exit 4). A tree too large to snapshot gives `NOT_TESTED`, never PASS. |
| S6 | An unavailable engine is reported `NOT_TESTED` with its reason, and NavSentry never falls back to another engine silently. |
| S7 | The spider never submits forms and never mutates parameters. |
| S8 | Raw console messages and asset content never appear in persisted artifacts or in agent-facing input. Only masked previews and hashes do. |
| S9 | Debug toggles (`?debug=1`, `localStorage.debug`) are detected statically and are never activated on a target. |
| S10 | A profile never adds origins. Loopback and private addresses need `network.allow_private` in every profile. |
| S11 | Cleanup never deletes outside `.navsentry/work/` and the inventory, and never follows a symlink or junction. |

## 10. Acceptance tests (fixture only, 127.0.0.1)
1. `page`+`http` on the vulnerable fixture: same findings as the seed scan.
2. `spider` (development): a fixture with 50 `/item/{id}` pages of one template and 3 other templates, and no findings on the items.
   - The run visits 3 pages per pattern, records 47 pages as `skipped: duplicate template`, and makes ≤ 15 requests in total.
   - A pattern whose pages have two different shapes is split into two groups.
3. `spider` hostile fixture: an off-scope link, a `javascript:` link, and a redirect loop. None of them is followed, and each is recorded.
4. Production guard (127.0.0.1 with `environment: production` and an `allow_private` approval, because production cannot be exercised for real in tests). Each of these exits 3 before any request:
   - a draft flow;
   - a run outside the authorization window;
   - a missing `authorization.reference`;
   - `--env development` against this manifest.
5. Profile scope: a development manifest without `allow_private` for 127.0.0.1 gets the loopback request denied. The profile adds nothing.
6. Analyzer (needs approved Python; otherwise the test is skipped with the reason, and the QA report records it as not run):
   - the page model contains no fixture token or field value;
   - the shape hash is stable across 2 instances of a page;
   - the drafts pass `flow lint`;
   - the run leaves no `__pycache__` in the package.
7. Extractor specs: a spec with an unknown key, a secret-like field name or an oversized regex is rejected. NavSentry refuses to run a `.py` file from `.navsentry/work/`.
8. Chains: in chain A→B, if A fails, B is `NOT_TESTED` with the dependency reason. A cycle is rejected by lint. Editing A invalidates B's approval.
9. Hygiene:
   - kill the run mid-way, and the next run removes the stale work directory at once (its lock owner is gone);
   - the work directory of a concurrent live run is left alone;
   - planting a file at the root during a run gives exit 4;
   - a symlink or junction inside the work directory that points outside survives cleanup with its target intact;
   - GATE-09 fails when an untracked `tmp.cjs` is left in the repository, and passes with the maintainer's existing ignored files.
10. Computer Use contract: when an action-log entry has no matching `scope check`, the run is `FAILED`; when the host capability is absent, the result is `NOT_TESTED`.
11. Static assets (vulnerable vs secure fixture):
    - The vulnerable fixture serves a bundle with a test token, a public `.map` with `sourcesContent`, `/env.js` with a non-public key, and an internal hostname. These produce NSC-INFO-007, NSC-INFO-008, NSC-CONF-009 and NSC-INFO-003.
    - The secure fixture keeps the same bundle contract without those values. It produces PASS and no contract drift.
    - A path that returns the single-page-app HTML with 200 for `/.env` gives no NSC-CONF-009 finding.
    - No raw token appears in any artifact.
12. Cost: a bundle referenced by 50 pages is fetched and scanned once. A second run gets 100 % cache hits for unchanged assets, and a detector version change invalidates the cache. Agent-visible bytes are below 1 % of the bytes scanned.
13. Console (needs `playwright`; otherwise skipped with the reason):
    - A fixture page logs a test token. That gives NSC-INFO-006 VALIDATED with a masked preview only.
    - A page logs while `console: "silent"` is declared. That gives a FAIL.
    - A bundle with a `console.log = ()=>{}` override and `?debug` toggle code gives NSC-INFO-006 SUSPECTED, and the toggle is never set.
    - With the `http` engine, the console checks are reported `NOT_TESTED` with the reason "no JS runtime".

## 11. Milestones
| Step | Content | Blocked by |
|---|---|---|
| 0.1.3-a | `scan`, profiles and production guards, the `--env` assertion, redirect-chain records, open-redirect observation (NSC-AC-008), `spider` (http, Node grouping), workspace layout, lock-based cleanup, exit 4, GATE-09 | — |
| 0.1.3-f | Chained flows (`requires`/`imports`, §5.5) | — |
| 0.1.3-s | Static asset scan (§6.4-B) with the Node detector, hash cache and cost accounting; NSC-INFO-007, NSC-INFO-008, NSC-CONF-009 | — (STA-LIBVULN / NSC-SUPPLY-002 only: a governance entry for the advisory data source) |
| 0.1.3-d | Development code inventory (§4.1): local OpenAPI JSON into draft flows, route and test file inventory | — |
| 0.1.3-b | Page-model analyzer (shipped scripts, page model, extractor specs) | CPython governance entry and ADR-0007, or the pure-Node choice (§12 D3) |
| 0.1.3-k | Runtime console checks (§6.4-A), NSC-INFO-006 | M1b Playwright, or 0.1.3-c |
| 0.1.3-c | Computer Use host contract (`session`, `scope check`, `budget take`, action log, `console ingest`) | owner decision on the host agent's terms; a governance entry (visual providers are `NOT_ADOPTED`) |
| M1b | Playwright engine for `flow` (development) | Playwright governance entry, now `PENDING_REVIEW` (PRM-GOV-003) |

Docs to update with the implementation: DEV-PLAN (live discovery moves from M1b to 0.1.3-a), README and CLI HELP (`scan`, `workspace`, exit 4), ARCHITECTURE, THREAT-MODEL (analyzer subprocess, the cooperative Computer Use contract, workspace deletion), FLOWS.md (`requires`/`imports`), the consumer SKILL.md (never open `.navsentry/work/`), CHANGELOG, and the catalog with regenerated docs.

## 12. Owner decisions
| # | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | Default consumer folder | `navsentry/`; `tests/security/`; other | `navsentry/`: it is separate from the project's own tests and easy to find. |
| D2 | Spider representatives per pattern | 3 in development and 2 in production; other numbers | 3 and 2, as drafted. |
| D3 | Page-model runtime | (a) CPython after a governance entry and ADR-0007; (b) pure Node | **(b)**, unless Node parsing proves insufficient. The spider already needs a Node tag tokenizer for `shape_hash` (§6.2), and the page model can reuse it. (b) meets the intent of G6 (local analysis, the model sees only redacted summaries) with no new runtime; it differs only from G6's literal "Python". (a) gets `html.parser`, but adds a runtime to govern and an ADR. |
| D4 | Profile for `staging` | production profile; development profile | Production profile: staging is a real, shared domain. |
| D5 | Site-specific extractors | (a) declarative JSON specs only; (b) execute model-generated Python | **(a)**. (b) cannot be confined with what is approved today (§5.4). It would need its own sandbox design and authorization. |
| D6 | Production budget numbers | defaults that the manifest can raise; hard ceilings | Defaults. `plan` shows the effective values before any run. |
| D7 | `playwright` for `page` and `spider` (development) | add it, which allows console checks without a host agent; keep G1/G2 as written | Add it once M1b governance is done. |
| D8 | Exit code for a dirty workspace | new exit 4; reuse exit 2 | 4: a dirty tree is a hygiene breach, not an incomplete test. |

## 13. Review log

### Round 1 — 2026-11-02 (Claude)
| # | Section | Problem in the first draft | Change |
|---|---|---|---|
| 1 | §4 | It added `environment: "development" \| "production"`, which conflicts with the existing required enum `local \| dev \| staging \| production`. | Keep the field and derive a profile from it. `--env` became an assertion. |
| 2 | §4 | Development allowed loopback, `*.localhost` and `*.test` automatically, which would widen ScopeGate (today loopback needs `network.allow_private`). | Origins are exactly the manifest origins in every profile (S10, test 5). |
| 3 | §4 | New authorization fields duplicated existing ones (`owner_confirmed` against `acknowledged`, `not_after` against `expires_at`). Development defaults raised the budget (500 requests and 4 rps against today's 200 and 2). | Reuse the existing fields and add only `not_before` and `allow_live_tokens`. Development defaults are unchanged. |
| 4 | §2, §3 | `analyzer` was listed as an engine, but it fetches nothing. `navsentry analyze --from <capture-dir>` could not work, because captures are deleted at the end of the run. `--manifest` differed from `--config`. | Engines map to the existing transports. Analysis is `--analyze` inside the run, and `flow analyze` reads the persisted page models. |
| 5 | §6.2, §11 | The spider grouped pages by a `template_id` that only the Python analyzer produced (0.1.3-b, blocked), yet the spider sat in unblocked 0.1.3-a. Skipping 47 pages without fetching them needed grouping before any fetch. | Two-stage grouping in Node: `path_pattern` before fetching, then `shape_hash`. |
| 6 | §6.4 | `NSC-CLI-*` and `NSC-STA-*` do not follow the catalog scheme, and they overlapped CONF-005, ERR-001, INFO-003, INFO-004 and PRIV-001. Status cells mixed check, lifecycle and severity words, plus `INVALID` and `INFO`, which the model does not have. | Detectors map to existing cases, and new cases are proposed with the next free IDs. Results use the model's own words (§2). |
| 7 | §6.4 | A provider-format match gave VALIDATED, and any `console.log` in production gave FAIL. | A format match gives SUSPECTED with high confidence. A bare count is only an observation. |
| 8 | §6.4-B | `/*.js.map` is a glob, not a fixed path. `/manifest.json` is public by design. A single-page-app fallback would make `/.env` look exposed. STA-006 relied on advisory data that has no governance entry. | `<bundle>.map` siblings and the `SourceMap` header instead. The format must match before a finding. NSC-SUPPLY-002 is marked blocked. |
| 9 | §5.3, §5.4 | Generated Python had to "write only inside the run directory, enforced by a path check in the wrapper", which the wrapper cannot see. Import greps can be bypassed. Python came from `PATH`, and `.pth` files and `__pycache__` were not handled. | No generated code at all: declarative extractor specs instead. Trusted absolute interpreter path, `-I -S -B`, and `scrubbedEnv()`. |
| 10 | §5.6 | Only a governance entry was named, but ADR-0001 also limits the core to Node built-ins. §12 said pure Node "works against G6". | ADR-0007 is required. D3 states that pure Node meets G6's intent. |
| 11 | §5.5, §7.1 | Chains broke the 0.1.2 rule "variables never cross flows" without saying so, there were two chain mechanisms (header keys and `chains/*.chain.json`), and the approval did not cover dependencies. | One mechanism (header keys), with an explicit supersede and its constraints. The dependency hashes are part of the dependent flow's hash. |
| 12 | §7 | Reports went into a tracked folder in the consumer repository, which may be public. Editing the root `.gitignore` conflicted with the dirty check. The inventory name was close to `manifest.json`. | Reports stay in `.navsentry/runs/`. A self-ignoring `.navsentry/.gitignore`. `.navsentry/inventory.json`. |
| 13 | §7.2 | `finally` does not run on signals. The 24 h sweep contradicted test 8. Concurrent runs could delete each other's work. A top-level listing missed nested files. Exit 4 was not part of the CLI contract. Deletion could follow junctions. | Lock-based sweep, signal handlers, a recursive snapshot with ignore globs, the exit 4 contract with precedence, and containment-checked deletion (S11). |
| 14 | §7.3 | `git status --ignored` lists the maintainer's legitimate ignored files, and the `*.py` rule would fail on the shipped `analyzer/*.py`. | Compare before and after, and apply the extension rule only to untracked files. |
| 15 | §6.3 | Separate `scope check` and `budget take` CLI calls cannot share the in-process Budget, and the contract was presented as enforcement. | Session state file, the cooperative contract stated honestly, and `FAILED` instead of `INVALID`. |

### Round 2
Pending.
