# SPEC 0.1.3 — Scan modes, environments, analyzer scripts and workspace hygiene

- Status: **ACCEPTED** · Drafted: 2026-11-02 · Review: rounds 1–3 done 2026-11-02 ([§13](#13-review-log)) · Owner decisions D1–D10: decided 2026-11-02 with the recommended options ([§12](#12-owner-decisions)) · Implementation: milestones 0.1.3-a1, a2, f, s and v (framework) done ([ADR-0007](../adr/0007-scan-modes-profiles-and-workspace.md)); later milestones open ([§14](#14-implementation-readiness-checklist))
- Builds on: [SPEC-0.1.2](SPEC-0.1.2-FLOW-TEST-CASES.md), [ADR-0001](../adr/0001-typescript-node-stack.md), [ADR-0003](../adr/0003-zero-runtime-dependencies.md), [ADR-0004](../adr/0004-scope-enforcement-at-transport.md), [ADR-0006](../adr/0006-flow-files-and-test-levels.md) · Baseline: 0.1.2 (`feat/flows-0.1.2` @ `318825c`, not yet on `main`)
- Security is still the primary purpose. Functional results come along with it; they never replace it.
- Compatibility: existing flow files, report paths and development manifests keep working. Three changes are intentional: production-profile manifests need more authorization fields, exit code 4 is new, and `run.json` gains `scanMode` beside the existing `mode`. See §3.1.

## 0. สรุปสำหรับเจ้าของงาน

**เป้าหมาย:** เพิ่มโหมดสแกน 3 แบบ ได้แก่ `page` (หน้าเดียว), `spider` (หลายหน้า โดยจัดกลุ่มหน้าที่ใช้ template เดียวกันแล้วตรวจแค่ตัวแทน) และ `flow` (เล่นตาม Flow) แยกโปรไฟล์ development กับ production ให้ชัด วิเคราะห์หน้าเว็บบนเครื่อง (โมเดลเห็นแค่สรุปที่ redact แล้ว) ตรวจ console และไฟล์ static ที่ส่งถึงเบราว์เซอร์ รองรับไฟล์ขนาดใหญ่ด้วยการอ่านแบบ stream มีตาราง vulnerability ตาม product/version ที่เสนออัปเดตเองเมื่อค้นเจอข้อมูลใหม่ และบังคับด้วยโค้ดว่าไม่มีไฟล์ชั่วคราวค้างในโปรเจกต์

**ทำได้โดยไม่ติด governance (เรียงตามลำดับใน §11):**
1. ฐานราก: ค่า config ใหม่, โปรไฟล์และ guard ของ production, `scanMode`, การดึงข้อมูลแบบ stream, แก้ Budget, workspace/cleanup/exit 4/GATE-09
2. `spider` ผ่าน HTTP และการบันทึก redirect ทีละ hop
3. Flow แบบต่อกัน (chain)
4. สแกนไฟล์ static (ยกเว้นการเทียบ library กับ advisory)
5. ตาราง vulnerability ในเครื่องพร้อมข้อเสนออัปเดตอัตโนมัติ (ตัวระบบ ยังไม่มีข้อมูล CVE จริง)
6. inventory จากโค้ดของโปรเจกต์ (development)

**ยังติดอยู่ (รายงานเป็น `NOT_TESTED` พร้อมเหตุผล และไม่มีการสลับไปใช้ engine อื่นแบบเงียบ ๆ):**
- Page-model analyzer: ถ้าใช้ Python ต้องมี governance entry ของ CPython และ ADR-0007 (หรือเลือก Node ล้วนตาม D3)
- Playwright และการตรวจ console ขณะรัน: governance ยังเป็น `PENDING_REVIEW` และต้องพิสูจน์ S1 ก่อน
- Computer Use: **เลื่อนออกจาก 0.1.3** เพราะ NavSentry บังคับ ScopeGate ในเบราว์เซอร์ของ host ไม่ได้
- การ import ข้อมูล advisory จริง: แหล่งข้อมูลต้องผ่าน governance ก่อน

**กระทบของเดิม:** manifest ที่ใช้โปรไฟล์ production ต้องมี `authorization.reference` และ `expires_at`, exit code 4 เป็นของใหม่, และ `run.json` มี `scanMode` แยกจาก `mode` (ซึ่งยังหมายถึง safety mode)

**ต้องการการตัดสินใจจากเจ้าของงาน:** D1–D10 ใน [§12](#12-owner-decisions) จากนั้นทำ checklist ใน [§14](#14-implementation-readiness-checklist) ก่อนเริ่มเขียนโค้ด

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
| G10 | An extensible **Markdown vulnerability table** of product/version CVEs and verified aliases, used during scans, with automatic sourced update proposals whenever research finds additions or corrections (owner addition after review round 2; §6.6) |

The goals are recorded as the owner stated them. Where the design maps a goal differently, the section says so: the `analyzer` engine in G1/G2 (§2), Computer Use in G1–G4 (§6.3), the limits of G6 (§5.1), and generated scripts in G7 (§5.4).

## 2. Capability matrix (honest status)

An **engine** fetches pages or drives a browser. Each engine maps to a transport that already exists in `transports.order`. **Analysis** is a separate local stage that runs on what an engine captured (`--analyze`). It never fetches anything, so it is not an engine. `--engine analyzer` is accepted as shorthand for `--engine http --analyze`, to match G1/G2.

| Engine | Transport (`transports.order`) | Status on 2026-11-02 |
|---|---|---|
| `http` | `direct-http` | USABLE (large bodies need the streamed capture of §6.5 first) |
| `playwright` | `playwright-browser` | BLOCKED: governance entry is `PENDING_REVIEW` (PRM-GOV-003), and S1 enforcement must be demonstrated (§6.3); scheduled for M1b |
| `computer-use` | `visual-computer-use`, and the manifest needs `transports.visual_computer_use: true` | DEFERRED beyond 0.1.3: S1 cannot be enforced in a host-owned browser (§6.3); visual providers are also `NOT_ADOPTED` |

| Mode \ Engine | `http` | `playwright` | `computer-use` | `--analyze` (local) | Production profile |
|---|---|---|---|---|---|
| `page` (single page) | USABLE as `test` (seed scan); `scan` PLANNED | — (not in G1; §12 D7) | DEFERRED | BLOCKED: page-model runtime (§5.6) | yes, observe |
| `spider` (multi-page) | PLANNED | — (not in G2; §12 D7) | DEFERRED | BLOCKED (as above) | yes, observe with strict budget |
| `flow` (follow flow) | USABLE (0.1.2, `test --flows`) | BLOCKED; development only | DEFERRED | — | `http` only, approved flows only |

Static asset checks (§6.4-B) run on whatever `http` fetched. They use the Node detector, so they do not wait for the page-model decision.

Rules:
- An engine that is not USABLE is shown in `doctor` as detected or unavailable, with its reason. Checks that a run requested from it are `NOT_TESTED` in the run report. NavSentry never falls back silently to another engine.
- Hard rule 5 applies: an engine is never marked USABLE before its adapter, its governance entry and its S1 enforcement exist.
- Status words come from the existing wire model. Transport probes are the existing `{id, available, usable, reason, version?}` object, displayed as `USABLE | DETECTED | UNAVAILABLE`. Checks are `PASS | FAIL | INCONCLUSIVE | NOT_TESTED | ERROR`. Findings are `SUSPECTED | VALIDATED | NEEDS_REVIEW | DISMISSED`. Runs are `executionStatus: COMPLETE | PARTIAL | FAILED`.
- This spec adds exactly two enums, both in §6.6 and both separate from the statuses above: knowledge applicability (`affected | not-affected | unknown | not-applicable`) and knowledge record state (`candidate | reviewed | needs-review | superseded | withdrawn`). `BLOCKED`, `PLANNED` and `DEFERRED` appear only in the matrix above. Skip reasons such as `sampled-out` are reason strings, not statuses.

## 3. CLI surface

```
navsentry scan  --config <manifest.json>  --mode page|spider|flow  [--engine http|playwright]
                [--analyze] [--env development|production] [--url <in-scope URL>] [--flows <path>] [--out <dir>]
navsentry flow analyze --config <manifest.json> --from-run <run.json> --out <dir>   # 0.1.2; also reads page-models/ beside run.json
navsentry workspace status|clean [--project <dir>] [--dry-run]                     # §7
navsentry knowledge status | lookup --product <id> [--version <v>] | propose --input <file.json>   # §6.6
```

- `--config`, as in every existing command. `--engine` defaults to `http`. `--engine computer-use` exits 3 with "deferred beyond 0.1.3 (S1)".
- `test`, `flow`, `plan` and `discover --dry-run` keep their 0.1.2 behaviour. `test` is not deprecated in 0.1.3.
  - `scan --mode page --engine http` without `--url` selects the same seed targets and checks as `test`.
  - `scan --mode flow --flows <path>` is the same as `test --flows <path> --flows-only`.
  - Live `discover` is refused today ("scheduled for M1b"). It becomes `scan --mode spider`. `discover --dry-run` stays the zero-network plan.
- There is no separate `navsentry analyze`. Raw captures are deleted when the run ends (§7.2), so analysis has to happen inside the run (`--analyze`). The run persists only the redacted `page-models/`, and `flow analyze` turns the run and its page models into draft flows.
- `--env` is an optional safety assertion. If it is given and differs from the manifest's profile (§4), the run exits 3 before any network activity. It never overrides the manifest.
- A mode and engine pair marked `—` in §2 exits 3. A pair marked BLOCKED runs nothing on that engine and reports `NOT_TESTED` with the reason (exit 2, incomplete).
- Exit codes: 0–3 as today, plus **4 = `WORKSPACE_DIRTY`** (§7.2). When several apply, the precedence is 3 > 4 > 1 > 2 > 0. HELP, README and the header comment of `src/cli.ts` list the new code.

### 3.1 Compatibility and executable contracts
- **Guards apply everywhere.** Production-profile guards apply to every execution entry point, including the legacy `test` and `test --flows`. Changing commands must not bypass them. Whether `staging` gets the production profile is D4; the rest of this spec assumes the recommended answer. A legacy manifest in the production profile without the required authorization is rejected before network activity, with migration guidance. Development manifests keep their current defaults.
- **Wire model.** `run.json.mode` stays the `SafetyMode` (`observe | safe-validate | active-approved`) from `src/types.ts`. A separate optional `scanMode: page | spider | flow` is added, plus optional `profile`, `engine`, `analyzer`, `workspace` and `knowledge` sections. The existing field is never overwritten with a scan mode. New readers accept 0.1.2 reports; absent coverage is unknown, never PASS. Validators, renderers and `compare` are extended together. An incompatible change needs a `REPORT_SCHEMA_VERSION` bump.
- **Flag validation.** `scan` requires `--mode`. `--url` applies only to `page`, `--flows` is required for `flow`, and `--analyze` applies only to `page` and `spider`. Invalid combinations exit 3 before any I/O. An explicit engine must also be allowed by `transports.order`; a flag never overrides manifest policy. `--engine analyzer` is validated exactly like `--engine http --analyze`.
- **Plan first.** The zero-network `plan` gains the mode and engine options. It reports the effective profile, budgets, optional checks, unavailable capabilities and the exposure probes it would send. Unavailable analysis never silently disappears: HTTP capture may complete, but the requested analysis is `NOT_TESTED` and the run is incomplete (exit 2 unless a higher-precedence code applies).

### 3.2 New manifest keys
All keys below are new and additive; a 0.1.2 build rejects them as unknown keys, which is the safe failure. Every value is validated in `src/config.ts` with the ranges shown. The profile supplies its defaults **before** parsing; omission is never inferred by comparing a parsed value with today's default. Values follow owner decisions D2, D6 and D9 (2026-11-02) and may be tuned after the large-fixture measurements.

| Key | Type and range | development default | production default |
|---|---|---|---|
| `authorization.reference` (existing) | string 1–100; in the production profile it may not contain `.`, `/` or `:`, so it cannot carry a hostname or URL | optional | **required** |
| `authorization.expires_at` (existing) | ISO date | optional | **required** |
| `authorization.not_before` | ISO date, before `expires_at` | — | — |
| `authorization.allow_live_tokens` | boolean | `false` | `false` |
| `safety.max_requests` (existing) | 1–5000 | 200 | 100 |
| `safety.max_requests_per_second` (existing) | 0.1–20 | 2 | 1 |
| `safety.max_depth` | integer 1–10 | 4 | 2 |
| `safety.representatives_per_pattern` | integer 1–10 | 3 | 2 |
| `safety.max_frontier` | integer 10–100 000 (URLs queued or recorded) | 5 000 | 1 000 |
| `capture.max_response_bytes` | safe integer ≥ 64 KiB; decoded bytes per response | 256 MiB | 256 MiB |
| `capture.max_run_bytes` | safe integer ≥ `max_response_bytes`; decoded bytes per run | 2 GiB | 2 GiB |
| `capture.max_wire_bytes` | safe integer ≥ 1 MiB; bytes on the wire per run | 2 GiB | 2 GiB |
| `capture.max_work_bytes` | safe integer ≥ `max_response_bytes`; on-disk spool per run | 2 GiB | 2 GiB |
| `capture.memory_buffer_bytes` | 64 KiB – 256 MiB and ≤ `max_response_bytes`; buffered input per active pipeline | 8 MiB | 8 MiB |
| `capture.max_console_messages` | integer 1–1 000 000 | 10 000 | 10 000 |
| `capture.max_console_bytes` | 64 KiB – `max_run_bytes` | 16 MiB | 16 MiB |
| `capture.cache_max_age_days` | integer 0–365; 0 means never reuse | 30 | 30 |
| `analyzer.timeout_seconds` | integer 1–3600, per document, within `max_duration_seconds` | 120 | 120 |
| `analyzer.include_text` | boolean; opt-in for titles and headings in page models (§5.2) | `false` | `false` |
| `workspace.ignore` | ≤ 50 relative globs, no `..`, no absolute or drive paths | `[]` | `[]` |

- Capture budgets are resource budgets, not format or product ceilings: owners may raise them for larger applications. There is no "unlimited" value. `plan` shows the effective values and the projected concurrent buffering.
- Production keeps its own request-rate and authorization-window controls on top of these budgets.

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
| Sources of evidence | code (static: routes, OpenAPI, test files; §4.1), localhost runs, integration tests, Playwright (when approved) | HTTP responses and redirect chains |
| Methods | observe: GET/HEAD/OPTIONS (already the only methods allowed in this release) | observe only; `safety.mode` is already forced to `observe` for production. Redirects are followed hop by hop, and every hop passes ScopeGate (already true for seeds, up to `MAX_REDIRECTS` = 5). |
| Flows | drafts with `--include-drafts`; their findings stay SUSPECTED (0.1.2) | **approved flows only** (hash-pinned). `--include-drafts` is refused, as in 0.1.2. |
| Budgets | §3.2 development defaults (today's request defaults are unchanged) | §3.2 production defaults; ≤ 2N pages per pattern including spread checks |
| Authorization | `authorization.acknowledged: true` and `owner`, as today | as development, plus the required `reference` and `expires_at` and the optional `not_before`. Outside `[not_before, expires_at]` the run refuses to start (exit 3). A run that reaches `expires_at` cancels in-flight work, and the result is `PARTIAL`. |
| Credentials | `*_env` variables, test values | `*_env` variables only. A token with a recognised live-key prefix (for example `sk_live_`) is refused unless `authorization.allow_live_tokens: true`. |

Explicit manifest values win over profile defaults, within the §3.2 ranges (§12 D6).

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
Raw page content stays on the machine. A local analysis script reduces it to a **structured page model**. The model (LLM) receives only that page model, which is redacted and size-capped. It uses the page model to propose flows. The page model is the only artifact allowed to cross from the analyzer to the model.

```
engine capture (http body / playwright DOM)
   → .navsentry/work/<run-id>/raw/                 (ephemeral, deleted when the run ends)
   → page-model analyzer (§5.6: Python -I -S -B, or Node per D3) → page model on stdout (≤ 64 KiB per page)
   → promoted to <run dir>/page-models/            (Redactor + artifact leak scan, §7.2)
   → `flow analyze --from-run` and/or the agent read the page models → navsentry/flows/drafts/*.flow.md
   → navsentry flow lint → owner approval → navsentry/flows/approved/
```

**Limit of this guarantee.** NavSentry has no model API (no SaaS; see governance). "The model" is the host agent, and the agent can read any file it has access to. NavSentry guarantees only this: raw captures exist only in `.navsentry/work/` while the run is going, they are deleted at the end, and they never appear in reports or in the agent-facing artifacts. The consumer skill tells the agent not to open `.navsentry/work/`. NavSentry cannot stop an agent from opening a file during a run. G6 is therefore met by design and by skill instruction, not by isolation.

### 5.2 Page model (wire format, JSON)
`{ url(display), template{path_pattern, shape_hash}, forms[{action(display), method, fields[{name,type,required}]}], links[{href(display), rel, same_template}], scripts{inline_count, external_origins[]}, security{csp, frames, cookies[flags only], mixed_content}, hashes{text}, text?{title, landmarks[≤ 20]} }`

- Field values, cookie values, tokens, emails and bodies are **never** included. Only names, types and flags are recorded.
- **Free text is omitted by default** (§6.5-D). `text` (the title and up to 20 headings) appears only with `analyzer.include_text: true`; it then passes through the Redactor before being cut to 120 characters per item, and the report says that pattern redaction cannot prove free text free of PII.
- `template` is computed in the Node core (§6.2), so the spider does not depend on the analyzer.
- Unknown fields are rejected when a page model is read back. Page models are data, never instructions.

### 5.3 Scripts shipped by NavSentry (not generated)
If D3 picks Python, the analyzer scripts are versioned **source** files in `analyzer/` inside the NavSentry package, and `package.json → files` gains `analyzer/`.
- They use the Python standard library only (`html.parser`, `json`, `hashlib`, `re`, `pathlib`). No pip installs. Each script is a single file, because `-I` removes the script's own directory from `sys.path` and sibling imports would fail.
- **Interpreter:** an absolute path from fixed trusted locations (the doctor probe), or an absolute path the owner sets. Never a bare `python` from `PATH`. This is the same rule as `TRUSTED_CURL`, and on Windows it also avoids the Microsoft Store alias stub. The version is checked (≥ 3.12).
- **Spawn:** `-I -S -B`: isolated mode; no `site`, so no `.pth` file can run code; and no `__pycache__` is written into the package, which would itself be a leftover (G8). Also `shell: false`, `scrubbedEnv()`, and the work directory as `cwd`. The input path is passed as an argument, and output goes to stdout as size-capped JSON, so the script writes no files.
- **Network:** there is no OS-level network sandbox. None is available without a new governed tool. Shipped scripts are kept network-free by review. A gate check helps that review: it allowlists the imports in `analyzer/*.py` and bans `__import__`, `importlib`, `exec`, `eval`, `compile`, `ctypes`, `socket`, `subprocess` and `os.system`. This is a review aid for reviewed code, not a sandbox.
- **Resources (either runtime):** input size follows the capture budgets (§3.2), not a fixed page limit. Parse incrementally from the capture stream or the owned spool file; never load the whole page into memory. Time is limited by `analyzer.timeout_seconds` and is interruptible. Agent-facing page models stay capped at 64 KiB whatever the input size. An overrun makes that page's analysis incomplete with a specific reason; partial output is never evidence of absence, and truncated output records how much was omitted.

### 5.4 Site-specific extractors (declarative, never generated code)
When the model needs a site-specific extractor, it writes a **declarative extractor spec** in JSON, not a script. The shipped analyzer interprets it.
- Schema: `{ "extractor": "1", "id", "match": {"path_pattern"}, "fields": [{"name", "select", "attr", "predicate"?, "max_items"}] }`. Unknown keys are rejected, and field names that look like secrets are rejected, as in manifests.
  - `select`: a selector subset only: `tag`, `tag[attr]`, `tag[attr=value]` and the descendant combinator, at most 8 levels deep. No pseudo-classes, no text selectors.
  - `attr`: one of `href`, `src`, `action`, `method`, `name`, `type`, `rel`, `role`, `id`. `value` and text content cannot be extracted, so form values and body text never leave the analyzer.
  - `predicate`: one of `present`, `nonempty`, `numeric`, `same_origin_url`, `matches_path_pattern`. There is no user regex: a length limit does not bound regex run time. A new predicate is a reviewed code change.
  - `max_items`: 1–50.
- Extracted values pass through the Redactor. Specs are written only to `.navsentry/work/<run-id>/extractors/` and are deleted with the run directory (§7). Their sha256 is kept in `run.json → analyzer.extractors[]`, so the run stays auditable.
- To keep an extractor, the owner must move it explicitly into `navsentry/analyzer/extractors/` under review. It is never promoted automatically.
- **NavSentry never executes model-generated code.** A generated script cannot be confined with what is approved today: a path check in the wrapper cannot see writes made inside the Python process, and an import check can be bypassed. Running generated code would need its own sandbox design and separate owner authorization, like `active-approved`. It is out of scope for 0.1.3 (§12 D5).

### 5.5 Analyzer outputs for flows
- A **self-contained flow** has one entry point, does not depend on another flow, and needs no state from a previous flow.
- A **chained flow** declares `requires: ["<flowId>"]` and `imports: {"<var>": "<flowId>.<var>"}` in its header. These are new additive keys, and a 0.1.2 parser rejects them. Chains **supersede** the 0.1.2 rule "variables never cross flows" (SPEC-0.1.2 §5.8), under these constraints:
  - **Graph.** Flow IDs resolve only within the selected flow root. Duplicate IDs, missing flows, undeclared dependencies, missing exports, cycles and collisions between local and imported names are lint errors, reported before any I/O. The runner orders flows topologically, and a shared dependency (for example in a diamond) runs once per selected graph, under the one run Budget.
  - **Values.** Only a variable that the source flow extracted in a `PASS` step can be imported. Values stay in memory. The 0.1.2 runtime value rule, substitution rule and Redactor registration still apply. Passing a value across an actor or origin boundary is rejected unless the reviewed flow contract declares it.
  - **Outcome.** If a required flow is not `PASS`, the dependent flow is `NOT_TESTED` with the reason "dependency <id> is <status>". It is never FAIL and never PASS.
  - **Hash and approval.** A dependent flow's `content_sha256` adds the sorted `(flowId, recursive content hash)` pairs of its dependencies, excluding review metadata. Flows without dependencies keep their 0.1.2 hash. Lint, approval and execution compute the same hash. Approval covers the whole dependency closure, so editing a required flow invalidates every flow that depends on it, and drafts are never approved automatically.
- Chains are declared only in flow headers. There is no separate chain file, because two sources of truth would drift.
- Every generated flow starts as `review.status: draft` with `provenance: {kind: "analyzer", from_run, template: "<path_pattern>"}`. The existing `provenance` object gains the `template` key.

### 5.6 Page-model runtime (blocking for 0.1.3-b)
- **If D3 picks Python:** Python is a new runtime binary, so hard rule 2 applies. Before any code that spawns Python is merged, `governance/third-party.json` needs an APPROVED entry for **CPython ≥ 3.12 (PSF License)**, covering provenance (python.org or the OS package), the advisory check, and the need (standard-library HTML parsing outside the Node process). ADR-0001 says the core uses only Node built-ins, so spawning Python also needs ADR-0007 to amend it for the optional analyzer. Python 3.13.14 is present on the maintainer machine (observed 2026-11-02); being present does not make it approved.
- **If D3 picks Node:** the analyzer reuses the bounded tag tokenizer that the spider needs for `shape_hash` (§6.2). No governance entry or ADR is needed.
- Until one of these exists, `doctor` shows the analyzer as unavailable with the reason, and `--analyze` gives `NOT_TESTED`. Neither runtime is substituted for the other silently.

## 6. Modes

### 6.1 `page`
- Fetches one in-scope URL (`--url`) or, without `--url`, the manifest `seed_paths` (the same targets as today's `test`). It runs every observe-mode check on them and, with `--analyze`, writes their page models.
- Output: a normal `run.json`/`REPORT.md` plus `page-models/` (redacted) in the run directory.

### 6.2 `spider` (template-aware crawler)
- BFS from `seed_paths`, up to `safety.max_depth`. Relative links and `<base>` are resolved first; a link is queued only when the static `ScopeGate.checkRequest` allows it, and the runtime check stays authoritative. `javascript:`, `data:` and `mailto:` links are recorded and never followed. The frontier is capped by `safety.max_frontier`; overflow makes the run `PARTIAL`.
- **Grouping key:** `(origin, actor, path_pattern, sorted query-key set)`. The `path_pattern` replaces numeric, UUID, hash-like and long-slug path segments with `{id}`, for example `/product/1…/product/9999` → `/product/{id}`. URL identity keeps query values in memory and drops fragments; a request is never rewritten into a different URL, and actors are never merged.
- **Sampling.** For each group, the spider fetches **N representatives** (`safety.representatives_per_pattern`) and records the rest as `skipped: sampled-out` without requesting them. Unvisited pages are `NOT_TESTED` with that reason. They are never confirmed duplicates and never inherit a PASS.
- **Shape check.** After fetching, a `shape_hash` (sha256 of the tag skeleton: tag names and nesting, with no text, ids, classes or attribute values, and with script and style bodies ignored) is compared across the representatives. Different hashes mark the group `mixed-shape` in the report. A split says nothing about the shapes of unvisited pages. The shape hash is a grouping heuristic only, never evidence for a finding.
- **Spread.** A finding on a representative leads to up to N more pages of the same group, to confirm the finding and measure how far it spreads. All fetches for one original group, including mixed-shape follow-ups, stay ≤ 2N.
- `safety.max_pages`, `targets.denied_paths`, the depth limit and `Budget` are hard limits. No form submission, no query fuzzing, and no parameter mutation (hard rule 6).
- **`robots.txt`** (RFC 9309), fetched once per origin through ScopeGate and the run Budget, with the NavSentry `User-Agent`:
  - Group selection uses the product token `NavSentry` (case-insensitive), otherwise `*`. Matching follows RFC 9309: the longest matching rule wins, `allow` wins a tie, and `*` and `$` are supported. At most 500 KiB is parsed, and up to 5 redirects are followed, each through ScopeGate.
  - Status: a 2xx text body is parsed. 404, 410 and other 4xx mean no policy. 401 and 403 are treated as unreachable, a conservative deviation from RFC 9309. 5xx, network errors, scope denials and budget exhaustion are unreachable. A 2xx body that is not a text policy (for example a single-page-app HTML fallback) follows §12 D10.
  - Production honours the policy (it is read, never overridden), and an unreachable policy blocks crawling that origin with incomplete coverage. Development records the policy without enforcing it.
  - Robots permission never expands manifest scope. The fixed exposure probes in §6.4-B are a separate bounded check set, not crawler links.
- Report: a coverage table per group (pattern, representatives, shape hashes, `mixed-shape`, sampled-out count), a list of skipped pages with reasons (budget, robots, out of scope, sampled-out, depth, frontier), and findings grouped by pattern.

### 6.3 `flow` and browser engines
- `http`: the 0.1.2 replay behaviour, with the shared profile guards of §3.1.
- `playwright` (development only; blocked until M1b): the UI steps `click`/`fill`/`see` run in a headless browser. ScopeGate is applied through `context.route('**')` with deny by default, and service workers are blocked (`serviceWorkers: 'block'`).
  - The adapter already declares the channels that `route()` cannot see: WebSocket frames after the upgrade, and browser-internal requests. `route()` also gives no connect-time check (ADR-0004).
  - M1b must demonstrate pre-request, connect-time and per-request budget enforcement for every enabled channel (S1). A forward proxy is only a design candidate: CONNECT authorizes a tunnel, not each HTTP path, method or WebSocket frame inside it, so proxy configuration alone is no evidence. Channels that cannot be enforced must be disabled and verified, or execution stays unavailable.
- `computer-use`: **deferred beyond 0.1.3.** The host's browser opens its own connections, so NavSentry cannot enforce pre-request or connect-time checks there, and it cannot block a request the host never asks about (the adapter already lists this channel as unenforceable). That fails hard rule 4. Governance approval, per-run consent, a clean action log or a SUSPECTED finding cap do not waive it, and this spec authorizes no change to the maintainer safety rules.
  - Results: no host capability → `NOT_TESTED` "host capability absent"; host present → `NOT_TESTED` "computer-use enforcement not demonstrated (S1)".
  - Candidate audit protocol, kept as input for a future design that must first satisfy S1 (not built in 0.1.3): `session start | scope check | budget take | session end` sharing one state file in the run's work directory, an action log where an unchecked action makes the run `FAILED`, consent recorded as a timestamp and actor label (never a name), findings capped at SUSPECTED unless an `http` re-check confirms them, and screenshots kept only in `.navsentry/work/`.

### 6.4 Client console and static asset checks (G9, owner request 2026-11-02)

The aim is to find sensitive values that leak to the client. There are two sources:

- **runtime console:** `console.*` output and uncaught errors;
- **static assets:** JS bundles, source maps and config files served to the browser.

Both are checked locally. The model never reads bundles or logs.

**Catalog rule.** Case IDs follow `NSC-<CATEGORY>-NNN` (`src/catalog.ts`). A detector whose root cause matches an existing case adds a new *evidence source* to that case; it does not create a parallel case. New cases are proposed only for new root causes. The proposed numbers are the next free ones on 2026-11-02 (`NSC-INFO-002` is reserved and never reused). They become final only when they are added to the catalog with complete entries (FACT, EVIDENCE, ACCEPTANCE, webRecheck, fix, regressionGuard) and verified mappings; the CWE IDs below are candidates to verify then. Detector labels such as `CON-SECRET` are internal names. `CheckResult.ruleId` is always the case ID, so `checks.disabled` keeps working. Detectors reuse the Redactor's patterns (`src/redact.ts`), so there is one definition of each secret shape. What every result below may claim is limited by §6.5-E.

#### A. Runtime console (needs a browser engine)
- **Capture:** with `playwright` (`flow`, development), attach `page.on('console')`, `page.on('pageerror')` and `requestfailed` to every page and flow step. With `http` only, these checks are `NOT_TESTED` with the reason "no JS runtime". `page` and `spider` have no browser engine in G1/G2 (§12 D7), and Computer Use is deferred (§6.3).
- **Raw data stays ephemeral:** messages are written only to `.navsentry/work/<run-id>/console/`, within `capture.max_console_messages` and `capture.max_console_bytes`. Every bounded message is inspected before normalising and deduplicating, so a secret in a later message cannot hide behind an earlier harmless message of the same shape. Dropped messages are counted, and the coverage is incomplete.
- **Report entry:** level, source `file:line`, case ID, template hash and a masked preview in the §6.5-D format, such as `[jwt,len=412]`. No hash of the raw message is kept.
- **Detectors:**

| Detector | Detects | Case | Result |
|---|---|---|---|
| CON-SECRET | Secrets or tokens in console output: JWT, `Bearer`, API-key and provider key shapes, private-key headers, and exact matches of in-scope cookie values or `*_env` actor tokens | proposed **NSC-INFO-006** Sensitive data written to the browser console (candidate CWE-532) | VALIDATED only on an exact match with a known test token or in-scope cookie value (a deterministic assertion); otherwise SUSPECTED |
| CON-PII | Email, phone or national-ID shapes (the Thai ID with its checksum) | existing NSC-INFO-004 (email) and NSC-PRIV-001 (personal identifier) | SUSPECTED |
| CON-DEBUG | Runtime markers that development features are running in a production build: an `[HMR]` or `webpack-dev-server` client connecting, framework dev-mode warnings | existing NSC-CONF-005 Debug mode / development features enabled | production profile: check FAIL, finding SUSPECTED. Development: observation only. State-store dumps count only as NSC-INFO-006 evidence when they hold sensitive data. A plain count of `console.log` calls is an observation, never a FAIL. |
| CON-TRACE | Stack traces, absolute file paths, internal hostnames or IPs in `pageerror` or console output | existing NSC-ERR-001 and NSC-INFO-003 | SUSPECTED |
| CON-ECHO | API response bodies echoed to the console, detected by the shape of JSON objects with keys such as `password\|token\|secret\|ssn` | proposed NSC-INFO-006 | SUSPECTED, with field names only |

- **"Disabled but still found":**
  - A flow can declare `console: "silent"` in its header (new, additive). Any console output during that flow then fails the new functional assertion kind `console_silent`, with the count. That is a functional FAIL; it becomes a security finding only when the output also carries sensitive data (NSC-INFO-006).
  - The static side is searched for logging that was only *hidden*: `console.log = () => {}` overrides with the original calls left in the bundle, logger levels toggled through `localStorage` or query flags such as `?debug=1`, and minified bundles without a detectable `drop_console` effect. These are observations. They support NSC-INFO-006 SUSPECTED only when the retained `console.` calls carry sensitive-looking arguments.
  - Debug toggles are detected from the static bundle only. NavSentry never sets them on any target (S9).

#### B. Static asset scan (http engine, no browser needed)
- **Inventory:**
  - JS and CSS URLs come from the HTML that the page or spider already fetched.
  - Source maps come from `//# sourceMappingURL` comments and the `SourceMap`/`X-SourceMap` response headers. For each discovered bundle, the `<bundle>.map` sibling is probed once.
  - A fixed list of well-known exposure paths is probed once per origin: `/.env`, `/.git/HEAD`, `/config.js`, `/env.js`, `/__ENV.js`, and `/asset-manifest.json` (used as an inventory source, not as a finding). `/manifest.json` is not probed, because a web app manifest is public by design. Each path gets a HEAD, and a GET follows only when the HEAD returns 2xx or 405.
  - These are GET-only observations from a fixed list (hard rule 6); they are not fuzzing. Every probe goes through ScopeGate and the run Budget. A path outside `allowed_paths` or inside `denied_paths` is `NOT_TESTED`, never forced. `plan` lists the probes it would send.
- **Bodies of exposed files** are processed only in memory and in the work directory. Only key names and masked values are kept (S8).
- **Detectors:**

| Detector | Detects | Case | Result |
|---|---|---|---|
| STA-SECRET | Secrets in bundles: provider key shapes, private keys, high-entropy strings near `key\|secret\|token\|password` | proposed **NSC-INFO-007** Secrets embedded in client-side assets (candidates CWE-540, CWE-798); the runtime counterpart of NSC-AUTH-001, which is `sast-only` | VALIDATED only on an exact match with a known test token. An exact provider format gives SUSPECTED with high confidence: a format match does not prove that a key is live, and NavSentry never calls the provider to test it. |
| STA-SOURCEMAP | Source maps reachable with `sourcesContent` included | proposed **NSC-INFO-008** Source maps with source content served publicly (candidate CWE-540) | Fetched as `anonymous` in the production profile: check FAIL, finding VALIDATED (the map was fetched and `sourcesContent` is not empty). Reachable only by an authenticated actor: SUSPECTED, stated as authenticated-only exposure. Development: observation only. |
| STA-EXPOSED | Exposed config, env or VCS files (`/.env`, `env.js` with non-public keys, `/.git/HEAD`) | proposed **NSC-CONF-009** Configuration or VCS files publicly reachable (candidates CWE-538, CWE-527) | VALIDATED only when the body matches the file's format, for example `ref: refs/` for `.git/HEAD` or `KEY=` lines for `.env`, and the evidence names the actor. A 200 response with HTML (a single-page-app fallback) is not a finding. |
| STA-INTERNAL | Internal endpoints or hosts embedded in bundles (RFC1918, `*.internal`, `localhost:*`, staging-looking hostnames) | existing NSC-INFO-003 | SUSPECTED |
| STA-DEVBUILD | Dev build indicators: unminified bundle, dev-mode framework flags, `sourceMappingURL` pointing to `file://` | existing NSC-CONF-005 | Observation, unless the evidence shows debug behaviour enabled or a declared policy violation; then, in the production profile, check FAIL, finding SUSPECTED |
| STA-LIBVULN | Vulnerable client libraries, identified from version banners such as `jQuery v1.x` and matched against the §6.6 knowledge base (no SaaS lookup, no second advisory snapshot) | proposed **NSC-SUPPLY-002** Client-side library with known vulnerabilities (candidate CWE-1395) | SUSPECTED, with version and advisory ID. Usable only once reviewed advisory records exist, which needs a governed advisory source (§6.6-A). A banner never suppresses another detector. |

#### C. Cost optimisation (model budget)
Static scanning can be expensive if raw bundles reach the model, so the pipeline is **local-first, model-last**:

1. **Fetch once per run and request identity; dedupe analysis by content hash.** Request identity is the canonical URL, the actor and the headers that change the representation; raw credentials are never persisted as keys. A content hash is known only after the complete bytes are fetched, so a cross-run cache hit saves analysis, not the request.
2. **Cache facts, not verdicts.** `.navsentry/cache/assets/` stores redacted detector facts only: never content, PASS or VALIDATED verdicts, request IDs or token-derived hashes. The cache key covers the content hash, detector version, configuration and redaction-policy version. Profile-dependent findings and known-token matches are re-evaluated in the current run with current evidence, so a development verdict is never reused in production. Entries expire after `capture.cache_max_age_days`, and deletion follows §7.2.
3. **Size and type gates.** Fonts, images and media are skipped by content type. Large bundles and maps are streamed and spooled within the capture budgets (§3.2, §6.5-A). Input that hits a budget or is truncated is incomplete, never a clean scan. A stable hash or a library banner is not proof of trusted vendor provenance and never suppresses a detector.
4. **Fast regex prefilter, then precise check.** A single pass over each stream uses combined anchored patterns. Only candidate spans (±200 chars) go to the entropy and format validators. The whole bundle never goes anywhere.
5. **Source maps:** read the `sources[]` names first; only scan `sourcesContent` when STA-SOURCEMAP already applies.
6. **The model sees only a summary**, `client-findings.json`, which has a fixed schema: case ID, asset display URL, `line:col`, masked preview, count and template hash. It is capped at 200 entries, and the rest are counted as `truncated`. The model's job is to triage and write the report wording, not to scan.
7. **Budget accounting.** `run.json → analyzer.cost` records the bytes scanned locally, `agentVisibleBytes` and the cache hit ratio (§6.5-E says how to read them). `agentVisibleBytes` is the size of the artifacts meant for the agent (page models and `client-findings.json`). NavSentry has no model API, so it measures what it hands over, not what an agent chooses to read.

- **Engine:** the §6.4 detectors are regex, entropy and format validators. They run on Node built-ins (`RegExp`, `node:crypto`) and need no HTML parser, so they need no Python. This is the primary engine for §6.4, not a fallback, and it is reported as `engine: node-detector`.

### 6.5 Capture, budget and evidence requirements (prerequisite, milestone 0.1.3-a1)

#### A. Streamed capture
- **Owner clarification, 2026-11-02:** modern projects need bodies substantially larger than 2–5 MiB. Fixed input caps of that size are withdrawn; the configurable budgets in §3.2 replace them.
- **Current code (verified 2026-11-02):** `src/transports/direct-http.ts` keeps at most `MAX_BODY_BYTES` (1 MiB), destroys the response beyond that, and resolves on `close` as well as `end` with `Buffer.concat`. A truncated body therefore comes back without any truncation flag. Before large-input support is claimed, this becomes streamed capture with backpressure, incremental hashing and detection, completion metadata (`complete | truncated | aborted`), and separate counters for wire, decoded, spooled and analyzed bytes.
- Existing small-response consumers may use a bounded buffer adapter. Larger responses never pass through an unbounded `Buffer.concat`, string conversion or whole-document `JSON.parse`.
- HTML, bundles and source-map entries are streamed without materializing the whole DOM, map or `sourcesContent` array. Detectors keep bounded parser state and overlap, so a chunk boundary cannot hide a token. A detector that needs a bounded parser NavSentry does not have reports unsupported input; it never silently scans only a prefix.
- Raw bytes are spooled only inside the run's own work directory, with restrictive permissions and the cleanup rules of §7.
- Budgets are enforced on observed bytes, never on a trusted `Content-Length`. Compression expansion, premature close, unsupported encoding, parse failures and exhausted budgets never become PASS. Free-disk exhaustion is handled explicitly, even below the configured budget. No new parser or decompressor dependency is authorized here.
- `capture.memory_buffer_bytes` is not a promise about total process memory; parser state and worker concurrency need their own measured bounds.

#### B. Request budget and deadline
- Every robots fetch, HEAD/GET probe, redirect, asset fetch and spread check draws on the one run Budget. None gets a separate allowance.
- `Budget.acquire()` currently checks its limits before the rate-limit wait (`src/budget.ts`). The budget and the authorization deadline must be re-checked after the wait and before each connection and redirect, and in-flight work is cancelled at `expires_at`. Reservations are serialized when `concurrency` > 1. Tests cover concurrent acquisition and expiry during a wait.

#### C. Coverage claims
- Sampling proves coverage only for the fetched representatives (§6.2). A rejected reference never enters the request queue.
- Negative outcomes cover only successfully scanned evidence. Anything not scanned completely is incomplete, with its reason.

#### D. Agent-facing evidence
- Pattern redaction cannot prove arbitrary text free of PII. Titles, headings, field names, source paths, headers and extractor values are all untrusted. Default agent artifacts use allowlisted structural fields and omit free text (§5.2). Form values, cookie values and arbitrary body text are never extracted.
- Display URLs drop fragments and userinfo and mask query values and identifier-like path segments.
- Renderers escape Markdown, HTML and control characters. Page models and advisory text are data, never instructions.
- Redaction runs before truncation. Known-token exact matching runs on the full bounded input before generic masking.
- **Masked preview format:** `[<kind>,len=<n>]`, optionally with a fixed public provider marker taken from the detector definition, for example `[jwt,len=412]` or `[stripe-live-key,len=107]`. A preview never contains characters from the value itself, and no artifact keeps a hash of a low-entropy value.
- Analyzers in either runtime have interruptible time and memory limits. There is no user regex in 0.1.3 (§5.4).

#### E. What a result may claim
- Debug toggles, a console override, an unminified bundle or a missing `drop_console` effect are observations on their own. A FAIL needs sensitive-data evidence or a deterministic, declared policy violation.
- Exposure findings name the actor. Anonymous reachability is public exposure; reachability only for an authenticated actor is reported as such.
- The cache hit ratio counts reuse among complete, cache-eligible captures. The < 1 % agent-visible target is a benchmark for the large-bundle fixture, not a pass criterion for small pages; with a zero denominator, the ratio is undefined and absolute bytes are reported.

### 6.6 Vulnerability knowledge base and automatic proposals (G10)

**Owner requirement, 2026-11-02:** keep an extensible Markdown vulnerability table, including product/version-specific advisories (for example Node.js, PHP, framework and library CVEs) and verified aliases. Use it during scans. Whenever authorized research finds new or changed information, prepare a sourced update proposal automatically, without waiting for another instruction. This is a required workflow, not a suggestion the user must remember.

#### A. Data and generated Markdown
- `src/catalog.ts` stays authoritative for NSC cases. The advisory dataset is a typed data module, `src/knowledge/advisories.ts`, like the catalog, so it is type-checked and ships in `dist/`.
- `npm run docs:catalog` generates **`docs/knowledge/VULNERABILITY-KB.md`**, split by ecosystem with a stable index once it grows, and GATE-03 checks it for drift. `package.json → files` gains `docs/knowledge/`, and AGENTS.md lists it as generated (never hand-edited).
- Advisories link to existing cases instead of creating parallel ones: server-side components to NSC-SUPPLY-001, client-side libraries to NSC-SUPPLY-002 (STA-LIBVULN reads this dataset).
- Records have a stable ID, a revision, `supersedes`, and a record state (`candidate | reviewed | needs-review | superseded | withdrawn`). Corrections and withdrawals keep their history.
- An informal name such as `php2shell` is an **unresolved alias until verified**. This spec does not assert an official advisory or guess a CVE mapping for it. An ambiguous alias returns candidates and a research-needed status, never the nearest-sounding vulnerability.
- This design change adds no real CVE records. The first import verifies primary advisories and needs an approved governance entry for its source (the OSV, NVD and GitHub Advisory APIs are `NOT_ADOPTED`; an offline copy of their data still needs a license and terms review). Fixtures use clearly synthetic records. Generic CWE/OWASP taxonomy does not replace affected-version information.

#### B. Required Markdown columns
Long evidence notes may use linked record headings in the same Markdown collection.

| Column | Contract |
|---|---|
| Record ID / revision | Stable identity, plus supersedes and withdrawal metadata |
| Product / ecosystem / component | Exact identity; runtime versus bundled dependency, upstream versus distribution package |
| CVE / advisory / aliases | Verified identifiers; unresolved aliases stay proposals |
| Affected / fixed versions | Explicit ranges, version scheme, release branches, exclusions and backport caveats; unknown stays unknown |
| Preconditions / surface | Platform, configuration, module, build flags, exposure and affected feature |
| Severity / source | Attributed upstream severity, vector and scoring version, separate from local risk |
| Safe evidence | What inventory or passive evidence establishes, and what stays unknown |
| NSC / detector / capability | The existing case and the implemented detector, or an explicit unavailable reason |
| Fix / regression guard | The vendor-supported fix or mitigation, and the legitimate behaviour to preserve |
| Sources / freshness | Primary links, publication and update dates, verification date, next-review date, and a source digest where permitted |
| Record state | `candidate`, `reviewed`, `needs-review`, `superseded`, `withdrawn`; separate from check and finding statuses |

#### C. Scan behaviour
1. At plan and run start, load the packaged snapshot and record its version, hash, verification date and stale-record count. Reviewed local knowledge is used first, also offline. An offline snapshot cannot prove that no newer CVE exists, and the report says so.
2. Product and version evidence comes only from authorized sources. Development may read manifests, lockfiles and runtime or container descriptors as data, without executing project code. Production uses allowed passive evidence, such as the headers NSC-INFO-001 already observes. The server's Node.js or PHP version is never inferred from the agent's own runtime, a browser's JavaScript behaviour or a client-library banner. No discovery request is added outside the plan and scope.
3. Matching is explicit about ecosystem and component, version scheme, affected and fixed ranges, and preconditions, including prereleases, distribution backports and incomplete identities. An unsupported version scheme or an unknown server version or configuration gives `unknown` applicability, never an assumed affected range or a PASS.
4. Applicability (`affected | not-affected | unknown | not-applicable`) is reported separately from check and finding statuses. A reliable affected-version match supports a SUSPECTED vulnerability, not validated remote exploitability. A deterministic installed-version assertion can be conclusive only about that inventory claim. An HTTP banner is weaker evidence, and its provenance and caveats are kept. Missing evidence maps to `INCONCLUSIVE` or `NOT_TESTED` for the relevant check.
5. Only implemented, reviewed observe-mode detectors run, through ScopeGate and Budget. Advisory rows and links are untrusted data, never commands or payloads. NavSentry never downloads or runs a PoC, never tests RCE, and never activates a check only because a CVE or alias matched. Unimplemented detectors stay `NOT_TESTED`, while the remediation guidance in the table stays visible.
6. Run reports have two Markdown tables, **Known vulnerability applicability** and **Knowledge gaps / proposed updates**, and record the snapshot they used. A later knowledge update never rewrites a historical result; re-evaluation is a new run with new provenance.

#### D. Automatic proposal lifecycle
- **Commands (offline, no network):** `knowledge status` (snapshot identity, freshness, stale count), `knowledge lookup` (bounded local search by product, version, advisory ID or alias, so the agent need not read every row or search the web on every run), and `knowledge propose --input <file.json>` (validates a sourced proposal against a strict schema, deduplicates it and writes the Markdown).
- **Triggers in 0.1.3:**
  1. Every `plan` and `scan` turns its own gaps (an unknown product, a stale record, an unresolved alias, unmapped evidence) into research-needed proposals, without claiming a new public vulnerability.
  2. The consumer skill requires the agent, after any authorized research that touches a product, version or advisory, to call `knowledge propose` with the sourced facts, without waiting for the user. New advisories, verified aliases, changed ranges, new mitigations, corrections, withdrawals and conflicting or stale evidence all qualify.
  3. NavSentry itself fetches no advisory source in 0.1.3. Source URLs in a proposal are untrusted data: they are validated as `https:` URLs and never fetched by NavSentry.
- **Storage:** `.navsentry/knowledge/proposals/<stable-id>.md` plus `INDEX.md`. Each proposal holds the candidate Markdown row, the field diff against the current record, primary source links and dates, confidence, duplicate and alias links, missing facts, governance status, affected cases, and the detector and test work still needed. The run report links and summarizes new and changed proposals.
- **Deduplication:** by advisory and product identity and revision, with provisional IDs for unresolved aliases. Identical research creates no duplicate and no repeated notification. Writes are atomic and locked against concurrent runs. A correction supersedes an earlier proposal without losing its history. Proposals are persistent artifacts, never default cleanup targets (§7.1).
- **Authority:** the standing owner instruction authorizes local proposals during authorized scan or research work. It does not authorize publication, merge, a new provider, or live exploit validation. Consumer runs never edit the installed package and never enable candidates silently. No hosted automation or background polling service is introduced.
- **Promotion (maintainers only):** a reviewed proposal changes `src/knowledge/advisories.ts`, and the Markdown is regenerated, after source verification, fixture tests, the governance and publication gates, and independent review before merge. Reusable knowledge carries no target URLs, customer identifiers, source paths, raw findings, tokens or PII; it uses generic descriptions and SRC-x references where needed.
- **Missing research capability:** a gap stays a visible research-needed entry. When approved research capability is available, the agent researches with product and advisory identifiers only, never consumer secrets or target identifiers. A failed refresh keeps the usable local knowledge and marks freshness incomplete. Zero matches never means a comprehensive absence of vulnerabilities.
- **Host hooks: deferred.** No host hook API is added in 0.1.3. A future hook must call `knowledge propose` with the same validation, with a versioned schema, bounded payloads, idempotency keys, timeouts and safe failure. Markdown never triggers shell commands, and no hook carries raw bodies or tokens or bypasses ScopeGate, governance or redaction. Without hooks, local lookup and reporting work unchanged.

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
  work/<run-id>/                     # EPHEMERAL: raw captures, spool, extractor drafts, console, lock
  cache/assets/                      # facts-only asset cache (§6.4-C)
  knowledge/proposals/               # persistent sanitized Markdown proposals + INDEX.md (§6.6)
  inventory.json                     # files NavSentry created: category, path, run, content hash
```
- These are the only two paths NavSentry writes in a consumer project. The layout is the default that the skill and docs recommend; commands that take `--out` still write where they are told.
- Reports stay in `.navsentry/runs/`, which is today's default. They describe vulnerabilities, so they are not written into a tracked folder by default: the consumer repository may be public. Keeping a report in the repository is the owner's explicit choice (`--out`).
- NavSentry never edits the consumer's root `.gitignore`. The first time it creates `.navsentry/`, it writes `.navsentry/.gitignore` containing `*`, which makes git ignore the whole directory without touching any other file.
- `inventory.json` is untrusted metadata, never deletion authority. Default `clean` removes only proven stale work directories and expired cache entries. It never deletes manifests, flows, extractors, reports, proposals, user-modified files or unknown files merely because they appear in the inventory. 0.1.3 adds no command that deletes persistent inputs or reports.

### 7.2 Lifecycle of ephemeral files
1. **Create.** Before any capture, a run creates `.navsentry/work/<run-id>/` exclusively, with an unpredictable ID and an exclusive ownership lock. The lock holds a nonce, the host identity, the process-start identity and the PID; a PID alone cannot detect reuse. All intermediate files go there.
2. **Exit.** When the run exits, it deletes its work directory. This covers success, failure, SIGINT and SIGTERM. Signals need their own handlers, because Node does not run `finally` blocks when a signal ends the process.
3. **Sweep.** At start, under a cleanup lock, a run sweeps only same-host work directories whose ownership is proven stale. Unknown identity, unreadable locks, permission failures and foreign hosts are reported and preserved; age alone never authorizes deletion. Recovery after SIGKILL or power loss is best effort on the next run, not guaranteed immediate erasure.
4. **Contain.** Deletion is limited to the canonical work and cache roots, resolved from one explicit project root, never to arbitrary inventory paths. Traversal, absolute, drive and UNC entries are rejected, and so are linked roots and ancestors. Containment and ownership are verified again just before each mutation. Symlinks and Windows junctions are never followed recursively; a verified owned link is unlinked without touching its target. If a concurrent path replacement cannot be ruled out, cleanup fails closed and reports itself incomplete. A tampered inventory cannot authorize deletion elsewhere.
5. **Promote.** Only redacted artifacts are promoted into `.navsentry/runs/<run-id>/`. Promotion runs the Redactor and the artifact leak scan from 0.1.2.
6. **Check (`WORKSPACE_DIRTY`, exit 4).** This makes G8 a check in code, not a promise.
   - Before the run, NavSentry takes a recursive snapshot of the project tree (relative path, size, mtime), never following links or junctions. It excludes `.git/`, `node_modules/`, `navsentry/`, `.navsentry/` and the manifest's `workspace.ignore` globs, which are meant for output that a running dev server writes (for example `.next/**`). Explicit `--out` files are recorded as authorized writes and excluded one by one, not by excluding their parent tree; they never become cleanup targets.
   - After cleanup it takes a second snapshot. Created, modified and deleted paths are listed as redacted display paths, and the run exits 4. A cleanup failure or a raw leftover also exits 4, with a sanitized diagnostic, even if promotion failed.
   - If the tree has more than 200 000 entries or cannot be read completely, the check is `NOT_TESTED` with that reason, and the run is incomplete (exit 2 unless a higher-precedence code applies), never PASS.
   - Limitations, stated in the report: metadata snapshots detect common changes but do not prove byte identity, and the check sees changes made by any process during the run, not only by NavSentry.
7. **Commands.** `navsentry workspace status|clean [--project <dir>] [--dry-run]` resolves one explicit project root (default: the current directory) and never guesses from parent repositories. `status` lists the persistent categories, leftover work directories and files not in the inventory, without deleting anything. `clean` follows steps 3–4 and the policy in §7.1. `--dry-run` changes nothing, including locks and the inventory.

### 7.3 Inside the NavSentry repository (maintainers)
- The same rule applies to maintainers. Development scripts and edit helpers go to the OS temp directory or the agent scratchpad, never into the repository tree.
- New gate check **GATE-09 Workspace hygiene**:
  - Before and after GATE-02, the gate records NUL-delimited Git status plus a bounded filesystem snapshot, excluding `.git/`, `node_modules/`, `dist/` and `.navsentry/`. Git status alone misses changes to an already-dirty path and can collapse ignored directories. Creations, modifications and deletions fail the gate; pre-existing, unchanged ignored files (`.env`, `runs/`, `*.log`, `.claude/launch.json`) are allowed. An enumeration failure makes the gate INCOMPLETE.
  - Independently, untracked helper scripts (`*.cjs`, `*.py`, `*.ps1`, `*.sh`, `tmp*`) outside those exclusions fail the gate. Tracked scripts, such as a shipped `analyzer/*.py`, are not affected. Dependencies and raw work directories are not scanned as maintainer helpers.

## 8. Report additions
- Header: `environment`, profile, `scanMode`, safety `mode`, engine, and for the production profile the authorization reference.
- **Coverage by template** (spider): groups, representatives, shape hashes, `mixed-shape`, sampled-out counts.
- **Redirect chains** (production).
- **Analyzer**: the page models produced, the drafts proposed, and extractor spec hashes with the note "deleted".
- **Capture**: wire, decoded, spooled and analyzed bytes, truncated or aborted captures, and dropped console messages.
- **Workspace**: files promoted, the result of the leftover check, and the cleanup status.
- **Knowledge**: snapshot identity and freshness, the **Known vulnerability applicability** and **Knowledge gaps / proposed updates** tables, and links to the proposals (§6.6).

## 9. Safety invariants (testable)
| ID | Invariant |
|---|---|
| S1 | Every executable engine enforces ScopeGate before requests and at connect time, plus the shared Budget. A cooperative host log cannot satisfy this invariant; an engine that cannot demonstrate it stays unavailable. |
| S2 | In the production profile, only approved flows run, only observe methods are used, and the run stays inside the authorization window. Otherwise the run refuses to start (exit 3). |
| S3 | No raw page content reaches agent-facing artifacts. Only the redacted, size-capped page model does, without free text unless `analyzer.include_text` is set. |
| S4 | NavSentry never executes model-generated code. Extractor specs are data, validated against a strict schema with no user regex. Shipped Python scripts, if any, run with `-I -S -B`, a scrubbed environment, and an interpreter from a trusted absolute path. |
| S5 | After every run, no unexpected creation, modification or deletion is detected outside approved write paths (§7.2); otherwise the run reports `WORKSPACE_DIRTY` (exit 4). A tree too large or unreadable to snapshot gives `NOT_TESTED`, never PASS. |
| S6 | A check requested from an unavailable engine or analyzer is `NOT_TESTED` with its reason, and NavSentry never falls back to another engine or runtime silently. |
| S7 | The spider never submits forms and never mutates parameters. |
| S8 | Raw console messages and asset content never appear in persisted artifacts or in agent-facing input. Only masked previews in the §6.5-D format and template hashes do. |
| S9 | Debug toggles (`?debug=1`, `localStorage.debug`) are detected statically and are never activated on a target. |
| S10 | A profile never adds origins. Loopback and private addresses need `network.allow_private` in every profile. |
| S11 | Automatic cleanup deletes only owned stale work and expired cache within validated roots, never persistent inputs, reports, proposals or arbitrary inventory paths, and never follows a symlink or junction. |
| S12 | Knowledge lookup and proposal ingestion cause zero target or network actions, and advisory content never becomes a command. |

## 10. Acceptance tests (fixture only, 127.0.0.1)
Tests that need an unavailable engine or runtime are skipped with the reason, and the QA report records them as not run.

1. `page`+`http` on the vulnerable fixture: same findings as the seed scan.
2. `spider` (development, exposure probes disabled explicitly): a fixture with 50 `/item/{id}` pages of one template and 3 other templates, and no findings on the items.
   - The run visits 3 pages per pattern, records 47 pages as `skipped: sampled-out`, and makes ≤ 15 requests in total, counting `robots.txt`.
   - A pattern whose pages have two different shapes is reported `mixed-shape`, within 2N fetches.
3. `spider` hostile fixture: an off-scope link, a `javascript:` link, and a redirect loop. None of them is followed, and each is recorded.
4. Production guard (127.0.0.1 with `environment: production` and an `allow_private` approval, because production cannot be exercised for real in tests). Each of these exits 3 before any request, through both `test` and `scan`:
   - a draft flow;
   - a run outside the authorization window;
   - a missing `authorization.reference` or `expires_at`, with migration guidance;
   - `--env development` against this manifest.
5. Profile scope: a development manifest without `allow_private` for 127.0.0.1 gets the loopback request denied. The profile adds nothing.
6. Page-model analyzer (whichever runtime D3 picks):
   - the page model contains no fixture token or field value, and no free text by default;
   - the shape hash is stable across 2 instances of a page;
   - the drafts pass `flow lint`;
   - with Python, the run leaves no `__pycache__` in the package.
7. Extractor specs: unknown keys, secret-like field names, a `value` attribute, text selectors and any regex are rejected. NavSentry refuses to run a `.py` file from `.navsentry/work/`. Fixed predicates and selectors obey the time, depth and output limits.
8. Chains: in chain A→B, if A fails, B is `NOT_TESTED` with the dependency reason. A cycle, a duplicate ID and an undeclared import are rejected by lint. A diamond dependency runs once. Editing A invalidates B's approval, transitively. An undeclared actor-boundary transfer is rejected.
9. Hygiene:
   - kill the run mid-way, and the next run removes its work directory only after proving same-host ownership is stale;
   - the work directory of a concurrent live run is left alone;
   - planting a file at the root during a run gives exit 4;
   - an owned symlink or junction inside the work directory is unlinked with its external target intact; a linked root or ancestor is refused;
   - GATE-09 fails when an untracked `tmp.cjs` is left in the repository, and passes with the maintainer's existing ignored files.
10. Browser availability: governance approval or host presence alone never enables execution. Until S1 is demonstrated, no browser is launched and the requested checks are `NOT_TESTED`. `--engine computer-use` exits 3.
11. Static assets (vulnerable vs secure fixture):
    - The vulnerable fixture serves a bundle with a test token, a public `.map` with `sourcesContent`, `/env.js` with a non-public key, and an internal hostname. These produce NSC-INFO-007, NSC-INFO-008, NSC-CONF-009 and NSC-INFO-003.
    - The secure fixture keeps the same bundle contract without those values. It produces PASS and no contract drift.
    - A path that returns the single-page-app HTML with 200 for `/.env` gives no NSC-CONF-009 finding.
    - A source map reachable only by an authenticated actor is reported as authenticated-only exposure.
    - No raw token appears in any artifact.
12. Cost: a bundle referenced by 50 pages with the same request identity is fetched and scanned once. A second run fetches the complete current bytes and reuses eligible detector facts for unchanged assets; a detector, configuration or redaction-policy change invalidates reuse. Known-token and profile verdicts are recomputed. Agent-visible bytes are below 1 % on the large-bundle benchmark; tiny or empty inputs report absolute bytes without failing that target.
13. Console (needs `playwright`):
    - A fixture page logs a test token. That gives NSC-INFO-006 VALIDATED with a masked preview only.
    - A flow with `console: "silent"` logs something harmless. That gives a functional FAIL (`console_silent`) and no security finding.
    - A harmless bundle with a `console.log = ()=>{}` override and a `?debug` toggle is an observation only, and the toggle is never set.
    - A harmless message followed by a same-template message carrying a secret: the secret is still detected.
    - With the `http` engine, the console checks are reported `NOT_TESTED` with the reason "no JS runtime".
14. Compatibility: 0.1.2 development manifests, reports and unchained approvals remain readable. `mode` keeps its safety meaning, and `scanMode` round-trips separately. Invalid flag pairs and forbidden engines make zero requests.
15. Coverage and budgets: robots deny, 401/403, 5xx and unavailable cases; the same path on two origins and two actors; query variants; mixed shapes; and an unsampled vulnerable page that never inherits PASS. All robots, redirect, HEAD/GET and asset requests are counted. An oversized frontier, request exhaustion, deadline expiry during a rate wait and concurrent reservations all end within limits with incomplete reasons.
16. Capture and cache:
    - Generated 16 MiB and 128 MiB bodies and maps with synthetic secrets after the first 5 MiB, at the end, and across chunk boundaries: all detected without whole-body buffering.
    - With a raised `capture.max_response_bytes`, a generated 300 MiB asset is scanned, which proves 256 MiB is not a hard ceiling. Fixtures are generated on demand, never committed as blobs.
    - Working memory stays bounded as input grows. Cancellation, spool cleanup, disk-full errors, wire and decoded byte accounting, and exact-limit and limit-plus-one behaviour are verified.
    - Premature close, unsupported encoding, budget-exceeded input and malformed maps never become PASS.
    - A development-to-production or actor/token change never reuses an obsolete verdict. A vendor banner never suppresses a source-map or config detector.
17. Workspace: tampered inventory traversal and absolute paths, PID reuse, foreign-host and unreadable locks, concurrent cleaners, ancestor junctions, modified persistent flows and explicit `--out` files all leave unrelated files intact. A cleanup failure returns 4, an incomplete snapshot returns 2. GATE-09 detects changes to already-dirty files and nested ignored directories without traversing dependencies.
18. Evidence: fixture secrets in titles, headings, field names, URL fragments, path segments, source filenames and extractor values never appear in any generated artifact by default. Prompt-injection text stays data and renderers escape it. Sensitive prefixes and low-entropy hashes are withheld.
19. Knowledge base (synthetic records only):
    - offline lookup of a known advisory; affected, unaffected and unknown versions; server-runtime ambiguity; prerelease and backport handling;
    - an unresolved named alias returns candidates and research-needed, never a guessed CVE;
    - an unavailable detector stays `NOT_TESTED` while the remediation guidance shows;
    - malicious instructions inside advisory text are ignored;
    - new, changed and withdrawn advisories create proposals without another user instruction; repeated and concurrent proposals are deduplicated; an interrupted write is recovered;
    - forbidden identifiers are withheld from proposals; stale and offline status is visible;
    - GATE-03 rejects drift in the generated Markdown;
    - proposal ingestion causes zero target or network actions (S12).

## 11. Milestones
Implementation order, top to bottom. Each step needs its own fixture acceptance (§10) and a passing local gate.

| Step | Content | Depends on | Blocked by |
|---|---|---|---|
| 0.1.3-a1 | Foundations: §3.2 config keys, profiles and production guards on every entry point, the `--env` assertion, `scanMode` and the other wire additions, streamed capture and capture budgets (§6.5-A), Budget deadline and serialization fixes (§6.5-B), workspace layout, lock-based cleanup, exit 4, GATE-09 | — | §12 D1, D4, D6, D8, D9 |
| 0.1.3-a2 | `scan --mode page\|spider` over `http`, Node grouping and shape hash, robots handling, redirect-chain records, open-redirect observation (NSC-AC-008) | a1 | §12 D2 |
| 0.1.3-f | Chained flows (`requires`/`imports`, §5.5) | a1 | — |
| 0.1.3-s | Static asset scan (§6.4-B) with the Node detector, facts cache and cost accounting; NSC-INFO-007, NSC-INFO-008, NSC-CONF-009 | a1 (a2 for spider-fed inventory) | — |
| 0.1.3-v | Knowledge base framework: typed dataset, generated Markdown, `knowledge status\|lookup\|propose`, applicability matching, report tables, skill trigger (§6.6) | a1 | Real advisory records and STA-LIBVULN: an approved advisory source |
| 0.1.3-d | Development code inventory (§4.1): local OpenAPI JSON into draft flows, route and test file inventory | a1 | — |
| 0.1.3-b | Page-model analyzer (page model, extractor specs) | a2 | §12 D3, D5; with Python also the CPython governance entry and ADR-0007 |
| 0.1.3-k | Runtime console checks (§6.4-A), NSC-INFO-006 | M1b | — |
| M1b | Playwright engine for `flow` (development) | a1 | Playwright governance entry (`PENDING_REVIEW`, PRM-GOV-003) and demonstrated S1 enforcement |
| Deferred | Computer Use engine (§6.3) | — | A design that satisfies S1 in a host-owned browser, a governance entry and an owner decision on the host agent's terms |

Docs to update with the implementation: DEV-PLAN (live discovery moves from M1b to 0.1.3-a2; Computer Use deferred), README and CLI HELP (`scan`, `workspace`, `knowledge`, exit 4), ARCHITECTURE, THREAT-MODEL (analyzer subprocess, Computer Use deferral, workspace deletion, knowledge ingestion), FLOWS.md (`requires`/`imports`, `console: silent`), AGENTS.md (the generated knowledge Markdown), the consumer SKILL.md (never open `.navsentry/work/`; call `knowledge propose` after research), CHANGELOG, and the catalog with regenerated docs.

## 12. Owner decisions
| # | Decision | Options | Recommendation (all adopted by the owner on 2026-11-02) |
|---|---|---|---|
| D1 | Default consumer folder | `navsentry/`; `tests/security/`; other | `navsentry/`: it is separate from the project's own tests and easy to find. |
| D2 | Spider representatives per pattern | 3 in development and 2 in production; other numbers | 3 and 2, as drafted. |
| D3 | Page-model runtime | (a) CPython after a governance entry and ADR-0007; (b) pure Node | **(b)**, unless Node parsing proves insufficient. The spider already needs a Node tag tokenizer for `shape_hash` (§6.2), and the page model can reuse it. (b) meets the intent of G6 (local analysis, the model sees only redacted summaries) with no new runtime; it differs only from G6's literal "Python". (a) gets `html.parser`, but adds a runtime to govern and an ADR. |
| D4 | Profile for `staging` | production profile; development profile | Production profile: staging is a real, shared domain. Existing staging manifests then need `reference` and `expires_at`. |
| D5 | Site-specific extractors | (a) declarative JSON specs only; (b) execute model-generated Python | **(a)**. (b) cannot be confined with what is approved today (§5.4). It would need its own sandbox design and authorization. |
| D6 | Production budget numbers | defaults that the manifest can raise; hard ceilings | Defaults. `plan` shows the effective values before any run. |
| D7 | `playwright` for `page` and `spider` (development) | add it, which allows console checks without a host agent; keep G1/G2 as written | Add it once M1b governance and S1 are done. |
| D8 | Exit code for a dirty workspace | new exit 4; reuse exit 2 | 4: a dirty tree is a hygiene breach, not an incomplete test. |
| D9 | Initial capture budgets (large-input support itself is owner-required) | the §3.2 proposed values; values tuned after large-fixture measurements | Start with the §3.2 values (256 MiB per response, 2 GiB per run for decoded, wire and spool bytes, 8 MiB buffer per pipeline) and tune them after the 16/128/300 MiB fixtures. They are recommendations, not owner-approved limits. |
| D10 | Production `robots.txt` answered with a 2xx body that is not a text policy (often a single-page-app HTML fallback) | (a) no policy, recorded, as RFC 9309 parsing implies; (b) unreachable, so crawling that origin is blocked, as round 2 proposed for malformed policies | **(a)**: the site has no robots policy, and blocking would make the spider useless on many single-page apps. The observation stays in the report. Choose (b) if the owner prefers the most conservative reading. |

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

### Round 2 — 2026-11-02 (Codex)
Repository/spec review against the 0.1.2 implementation on this branch. **Verdict: sound direction, but not ready to implement unchanged.** The requirements below are design corrections, not evidence of implemented capabilities or owner approval of §12 choices. References are local repository evidence; no live target was scanned.

| Priority | Finding and repository evidence | Required correction added |
|---|---|---|
| Blocker | Cooperative Computer Use and a CONNECT proxy cannot establish hard rule 4 / ADR-0004; optional adapters already declare unenforceable channels (`src/transports/optional.ts`). | §6.3/S1 keep execution unavailable until enforcement is demonstrated; consent is insufficient. |
| High | Inventory-based cleanup could delete approved flows/reports, and PID-only locks do not prove ownership. | §7 restricts deletion to owned stale work/expired cache, distrusts inventory, handles uncertain locks conservatively and adds adversarial tests. |
| High | Claimed additive compatibility conflicts with new production requirements; `RunResult.mode` already means safety mode (`src/types.ts`, `src/config.ts`, `src/cli.ts`). | §3.1 defines migration, shared guards, `scanMode`, status wire shape and reader/CLI contracts. |
| High | Proposed input limits exceed the 1 MiB transport cap; close/end handling does not expose completeness (`src/transports/direct-http.ts`). Budget checks precede rate waiting (`src/budget.ts`). | §6.5 requires bounded complete capture, deadline cancellation and serialized reservations before crawler expansion. |
| High | Pattern sampling cannot prove unvisited pages share a shape or are secure. | §6.5 records sampled-out coverage, separates origin/actor/query identity and keeps an original-pattern request ceiling. |
| High | Content-only cache can reuse stale actor/profile verdicts; console template deduplication can hide later secrets. | §6.4-C caches detector facts with context invalidation and inspects bounded messages before deduplication. |
| High | Pattern redaction is not arbitrary-PII isolation (`src/redact.ts`); short arbitrary regex can still exhaust analysis time. | §6.5 omits unsafe free text, forbids arbitrary extractor regex and requires bounded, escaped artifacts. |
| Medium | Debug markers/vendor banners alone do not establish leaks or trusted provenance. | §6.4/§6.5 remove detector suppression and require evidence for failure/public-exposure claims. |
| Medium | Chain imports lack deterministic identity/hash/actor rules (`src/flow/parse.ts`, `lint.ts`, `execute.ts`). | §5.5 defines graph validation, recursive hashing and restricted runtime value transfer. |
| Medium | Git status alone misses already-dirty modifications; `--out` conflicts with blanket hygiene restrictions (`scripts/local-gate.ts`, `src/cli.ts`). | §7 adds bounded snapshots, exact authorized-write exclusions, explicit root and cleanup-failure semantics. |
| Owner requirement | Body limits of 2–5 MiB are too small for growing applications. | §5.3/§6.4/§6.5 replace fixed caps with streaming/spooling, independently bounded memory and adjustable capture budgets; test 16/128 MiB plus a configured 300 MiB response. D9 records proposed defaults for later tuning. |

Owner addition after round 2: G10/§6.6 add product/version vulnerability knowledge (including Node.js/PHP advisories and verified aliases), generated Markdown tables, offline applicability matching and automatic persistent Markdown update proposals. This is specified behavior, not a claim that advisory lookup or host hooks are implemented. `php2shell` is recorded only as an example of an unresolved alias requiring verification.

### Round 3 — 2026-11-02 (Claude, consistency pass before implementation)
No requirement from rounds 1–2 was removed. This pass resolved contradictions between the round-2 additions and older text, and filled the gaps that blocked implementation.

| # | Section | Problem | Change |
|---|---|---|---|
| 1 | §1, §2 | G10 sat outside the goals table. §2 said "this spec adds no status words", but §6.6 adds applicability and record-state enums. | G10 is a table row. §2 names the two new enums and keeps them separate from check and finding statuses. |
| 2 | §3.1, §3.2 | §3.1 stated the `staging` profile as decided while D4 was open. It required new limits "specified before implementation" without naming them. | §3.1 refers to D4. §3.2 is a table of every new key with type, range and per-profile default, marking proposed values. |
| 3 | §2, §6.3, §6.4-A, §11 | Computer Use was a release blocker, yet §6.3 still described a runnable protocol, §6.4-A used `console ingest`, and 0.1.3-c was a milestone. | Computer Use is DEFERRED beyond 0.1.3 everywhere; `--engine computer-use` exits 3. The protocol is kept only as a candidate design. |
| 4 | §5.2, §6.5 | The page model carried the title and headings by default, while §6.5 required free text to be omitted by default. It also duplicated `dom_shape` and `template.shape_hash`. | Free text is opt-in (`analyzer.include_text`). The duplicate hash is removed. |
| 5 | §5.4 | `predicate` was a "fixed reviewed enum" that was never listed, `select` had no grammar, and `attr` could read `value`. | Selector subset, attribute allowlist (no `value`, no text) and a five-item predicate set. |
| 6 | §6.2, §6.5 | The report still listed "duplicate template". "Each new group gets its own representatives" contradicted the 2N cap. Robots rules were split across two sections and left undefined. | `sampled-out` and `mixed-shape` throughout, one grouping key, a 2N cap including follow-ups, and robots rules based on RFC 9309 in one place. Round 2's "malformed policy blocks crawling" conflicts with RFC parsing for HTML fallbacks, so it became D10. |
| 7 | §6.4-A | Static "hidden logging" evidence was SUSPECTED, which contradicted §6.5 and test 13. The manifest key `checks.console` had no functional result that it could fail. | `console: "silent"` lives only in flow headers, as the functional assertion `console_silent`. Static evidence is an observation unless the calls carry sensitive arguments. |
| 8 | §6.4-A | CON-DEBUG failed on state dumps and dev warnings alike, against §6.5-E. | FAIL only for runtime markers of running development features. |
| 9 | §6.4, §6.5, S8 | The preview `eyJ…` conflicted with "no token prefixes", and reports kept raw-message hashes. | One preview format (`[kind,len=n]` plus a fixed public provider marker). Reports keep template hashes only. |
| 10 | §6.4-B | Source-map and config results did not apply round 2's anonymous-versus-authenticated rule. STA-LIBVULN kept its own "pinned advisory snapshot" next to the §6.6 dataset. | Actor-specific results. One advisory dataset (§6.6). |
| 11 | §6.6 | A JSON file in `src/` is not copied to `dist/` by `tsc`. The "automatic" proposal path had no command an agent could call. The hook events had no defined interface, and the §6.6 acceptance lived outside §10. | Typed data module `src/knowledge/advisories.ts`, `knowledge status\|lookup\|propose`, explicit triggers through `plan`/`scan` and the skill, hooks deferred behind `propose`, acceptance as test 19, invariant S12. |
| 12 | §6.5, §11 | Streamed capture was an "implementation prerequisite" that sat in no milestone, and milestones had no order. | Milestone 0.1.3-a1 (foundations) and an ordered table with dependencies. §6.5 split into subsections A–E. |
| 13 | §3, §8, §9, §10 | The `workspace` synopsis lacked `--project`. The report header showed `mode` where `scanMode` was meant. S6 contradicted the round-2 doctor rule. Test 6 assumed Python. The probe note for test 2 sat in test 15. | Aligned. |

## 14. Implementation readiness checklist
Implementation of a milestone starts only when every item it depends on is done.

- [x] Owner answers D1–D10 (§12): recommended options adopted 2026-11-02. Milestone 0.1.3-a1 needs D1, D4, D6, D8 and D9; 0.1.3-a2 needs D2 and D10; 0.1.3-b needs D3 and D5.
- [x] §3.2 values confirmed (D9 values) and every "proposed" mark removed.
- [ ] Catalog entries drafted for NSC-AC-008, NSC-INFO-006, NSC-INFO-007, NSC-INFO-008, NSC-CONF-009 and NSC-SUPPLY-002, with CWE mappings verified (§6.4).
- [x] An ADR for scan modes and profiles ([ADR-0007](../adr/0007-scan-modes-profiles-and-workspace.md); D3 picked Node), and the threat-model update (TM-21 to TM-24).
- [ ] Governance: nothing new is needed for 0.1.3-a1, a2, f, s, v (framework) and d. A CPython entry is needed only if D3 picks Python. An advisory-source entry is needed before any real advisory record is imported.
- [x] The 0.1.2 baseline: owner chose to stack 0.1.3 on it and merge both to `main` together.
- [ ] One branch per milestone, tests written with the change, vulnerable and secure fixture variants for every new check, CHANGELOG under Unreleased, `npm run gate` PASS, and independent review before merge.

Milestone 0.1.3-a1 is covered by `test/a1.test.ts` (parts of tests 4, 5, 9, 10, 14, 15, 16 and 17) and GATE-09. Milestone 0.1.3-a2 is covered by `test/a2.test.ts` (tests 2, 3 and the spider parts of 15). Milestone 0.1.3-f is covered by `test/chain.test.ts` (test 8). Milestone 0.1.3-v is covered by `test/knowledge.test.ts` (test 19, synthetic records only). Milestone 0.1.3-s is covered by `test/assets.test.ts` (tests 11, 12 and the static-asset parts of 16, with generated 16 MiB and 300 MiB bundles; the 128 MiB size is not run separately). The other numbered tests are requirements of later milestones and are not claimed to pass yet. Within a1, streamed capture keeps a bounded in-memory prefix rather than spooling to disk; spooling arrives with the detectors that need it (0.1.3-s).
