# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- [SPEC-0.3.0](docs/specs/SPEC-0.3.0-AGENT-FIRST-AND-RECORDER.md): agent-first use, self-contained reports, a Computer Use middle path and a flow recorder. Accepted 2026-11-06 with owner decisions D1–D10 (recommended options).
- Replay timeline: `scan --mode flow --engine playwright` takes a viewport screenshot of the headless browser right after every browser step (navigate, click, see, fill, select, submit).
  - The PNGs go to `<run>/shots/`, which has its own `.gitignore`. At most 60 per run.
  - TEST-REPORT.md gets a "Replay timeline" section with each step's status and screenshot. A FAIL step shows what was expected, what was observed and the page at that moment.
  - `flows.json` steps carry `screenshot`.
  - A failed screenshot never changes a step's result. The screenshots add no requests.
- `navsentry doctor` has an "Agent launch (MCP)" section: it says whether `navsentry` is on PATH and prints a `claude mcp add` command. Without PATH, the command uses absolute paths. A missing PATH entry was why MCP hosts reported `CONNECTION_CLOSED`. `doctor --json` includes it as `launch`. README documents `npm link` for source checkouts.
- Report verdict: the Summary of every REPORT.md and REPORT.html starts with a one-line answer to "Do I need to fix something now?".
  - 🔴 fix now: an IMMEDIATE or CAUTION finding, or test objects left behind.
  - 🟡 schedule it: PLANNED findings only.
  - 🟢 no fix needed in the tested scope, which is not proof of security.
  - ⚪ can't tell: an incomplete run, or flows that failed or did not run, when nothing needs a fix now. Never shown as no-fix.
  - `scan` prints the verdict and `Open in a browser: …/REPORT.html`. `scan --json` adds `verdict`.
- `navsentry report --out <file>` writes the rendered report and never overwrites one. `--format html` on a terminal without `--out` is refused with a pointer to the REPORT.html that scan already wrote, instead of filling the screen with HTML.
- 0.3.0-f NavSentry Recorder (SPEC-0.3.0 §7, owner decisions D7 and D10). A Chrome/Edge MV3 extension in `extension/`, loaded unpacked and shipped in the package. It records clicks, field changes and submits with a screenshot per step.
  - **What it never records:** typed values, and screenshots of password fields.
  - **Scope:** taken from an imported `navsentry.json` (`targets.origins`). Host access is asked one origin at a time.
  - **No network:** no network APIs, and CSP `connect-src 'none'`.
  - **Review before saving:** delete steps, mark where the flow ends, and add reviewer notes. Save writes a `.navrec.zip`.
  - **Import:** `flow from-recording` also accepts `.navrec.zip` and writes the draft flow, `<id>.RECORDING.md` with screenshots and notes, and a git-ignored `<id>.shots/`. The archive goes through a strict reader: name allowlist, no traversal, duplicates, symlinks or encryption, size limits, CRC, and a sha256 per screenshot. Password fills use a `*_PASSWORD` env variable.
  - **Governance:** store distribution is recorded as NOT_ADOPTED. `doctor` checks the extension manifest version. Threat model TM-40.
  - **Not yet verified in a browser:** the extension needs a headed browser, which is pending governance. Its static safety properties and the whole import path are tested.
- 0.3.0-e recorder import (SPEC-0.3.0 §6): `navsentry flow from-recording --input <recording.json> --out <dir>` turns a Chrome/Edge DevTools Recorder JSON export into one draft E2E flow plus `<id>.IMPORT.md`. Zero network; the file is read as data.
  - `navigate`, `click`, `change` and `waitForElement` become navigate, click, fill and see steps, located by accessible-name selectors.
  - Recorded values are dropped: each input becomes an env-backed variable.
  - Out-of-scope URLs, a second origin, CSS/XPath-only selectors, keys, scrolls and hovers are listed, never guessed.
  - At most 200 steps (owner decision D10). An existing flow is never overwritten.
  - MCP tool `navsentry_flow_from_recording`. A sample recording ships in `examples/demo/recordings/`, documented in FLOWS.md and the tour.
- 0.3.0-d visual driver middle path (SPEC-0.3.0 §5, owner decisions D5 and D6). Every request still goes through ScopeGate and the Budget.
  - **`browse snapshot`:** lists the page's interactive elements with refs (e1, e2…), roles, accessible names and an in-scope flag for links. It never includes field values, and names are redacted.
  - **`browse click --ref <ref>`:** clicks by ref; coordinates still work. The role and name of the clicked element are logged.
  - **`browse type --ref <ref>`:** fills a text field, with `--env <VAR>` (the value is read in the session and treated as a known secret) or with `--text` (short, non-secret).
    - Literal text is refused in password fields and when it looks like a secret or personal data.
    - Values are never logged; the log keeps the env name, the length, and a sha256 prefix for literal text.
    - A POST submit is still refused.
  - **`browse key --key`:** presses one key from an allowlist (Enter, Tab, Escape, Backspace, arrows, PageUp, PageDown, Home, End).
  - **`browse end --save-flow <dir>`:** writes a draft E2E flow from the action log. Typed inputs become env variables. The draft is parsed before writing and never overwrites a file.
  - **MCP tools:** `navsentry_browse_snapshot`, `navsentry_browse_type` and `navsentry_browse_key` are new; `navsentry_browse_click` accepts `ref`; `navsentry_browse_end` accepts `save_flow`.
  - **`--headed` is refused for now.** It needs the full Chromium build, which is recorded as PENDING_REVIEW in `governance/third-party.json`; only the headless shell is approved (hard rule 2). Human-action logging for headed sessions comes with that approval.
  - Threat model TM-39.
- 0.3.0-b agent-first use (SPEC-0.3.0 §3.2, owner decision D1):
  - **`--json`:** `test`, `scan` and `compare` accept `--json` and print a machine-readable summary: report paths, counts by action level, gaps and next commands.
  - **`navsentry next --run <dir>`:** lists actions by level, gaps (NOT_TESTED, sampled-out pages, incomplete flows) and the next commands, with zero network. Each command is marked as sending traffic or not, and owner decisions are marked as such.
  - **`navsentry mcp`:** a local MCP server over stdio, with no dependency and no listener. Its tools cover doctor, plan, scan, next, compare, flow analyze/lint, knowledge lookup and the visual driver; screenshots come back as images.
    - Every tool runs the CLI as a child process, so all refusals and safety gates apply.
    - There is no tool for init, flow approval, workspace cleanup, installation updates or manifest edits.
    - Threat model TM-38.
  - **Agent loop in the consumer skill:** after one go-ahead, the agent runs plan → scan → next → explore → draft flows → report.
- 0.3.0-a (SPEC-0.3.0 §3.1, §8): `navsentry init <url>` writes `navsentry.json` after you confirm authorization and name an owner on an interactive terminal (refused without a TTY, so an agent cannot answer for you). Staging and production also ask for the reference and expiry, loopback and private hosts need a separate approval, and cloud metadata addresses are refused. An existing manifest is never overwritten.
- Commands use `./navsentry.json` when `--config` is omitted, and say so on stderr.
- `navsentry scan` without `--mode` scans the seed page; `scan --deep` is spider with `--analyze`.
- Demo v2: `node dist/scripts/demo.js serve [--variant vulnerable|secure]` serves a linked demo shop (products, search, sign-in form) on one origin, so before/after compare shows only real changes. `examples/demo/` has a manifest and two approved flows, and [docs/TOUR.md](docs/TOUR.md) walks through every mode.
- 0.3.0-c readable reports (SPEC-0.3.0 §4).
  - **Fixed sections:** every REPORT.md has the same twelve sections in the same order: Summary, Findings, Fix verification, Known vulnerabilities, Coverage, Not tested and limitations, Transports and engine, Requests refused before sending, Redirect chains, Client assets and browser, Knowledge gaps, Run details. A section without data says why.
  - **Finding cards:** one card per case lists every affected target. Each card says why the problem matters, how to fix it, how to recheck it, when it counts as fixed and what must not break.
  - **Before/after examples:** every automated case has fix examples for nginx, Express, ASP.NET Core, Spring or front-end builds (`src/fixes.ts`). Reports label them as not executed by NavSentry.
  - **Self-contained reports:** reports no longer link into NavSentry's catalog docs.
  - **Action levels:** IMMEDIATE / CAUTION / PLANNED / OPTIONAL / INFO, with colour markers, derived from severity and priority. run.json is unchanged. The summary lists what to do first.
  - **CVSS:** known vulnerabilities show the advisory's CVSS score, vector and source.
  - **HTML report:** `REPORT.html` is written beside REPORT.md, as one offline file built from the same Markdown.
    - Colours by status and level, a level filter, Export Markdown and Print / PDF.
    - All run text is escaped, and a CSP allows only the file's own hashed style and script.
    - `navsentry report --format html` renders it from a saved run.
  - **Terminal colour:** run summaries and `compare` output are coloured, only on a TTY. `NO_COLOR` or `--no-color` turns it off.

### Fixed
- Docs out of step with 0.2.0: case counts (57 cases, 26 automated), coverage classes, the transport table and Computer Use boundary, M2 status, exit code 4 in the flow exit table, the test-suite list, GATE-09/10 and report artifacts.
- The consumer skill says that loopback targets need an owner-confirmed `network.allow_private` entry, and exit codes are a readable list.
- README gains *Scan modes at a glance*, *Computer Use (visual driver)* and *Try it locally*, written for the demo shop v2 in `examples/demo/`.

### Changed
- **Approve once (breaking):** `flow approve` needs an interactive terminal, like `init`. Without one it is refused, even with `--by`. That stops pipes and agent shell tools; the consumer skill also forbids agents from running it, because a pseudo-terminal could still type. Unapproved flows that a selected flow requires join the same decision.
  - `--flows` takes a folder. Every draft or stale approval in it is listed with its steps, requests and state-changing steps, and approved with one name and one yes. Valid approvals are left alone.
  - `--by` is optional: the approver is asked for, with the manifest owner as the default.
  - `navsentry next` suggests the single folder command, and the consumer skill asks the user to run it.
- **Breaking (development only):** `browse type --env` accepts only `NAVSENTRY_*` variable names. Before, any name was accepted, so a page that told an agent to type, for example, `AWS_SECRET_ACCESS_KEY` could send that host secret to the target (hard rule 7, independent review). Rename the variable, for example `NAVSENTRY_LOGIN_PASSWORD`.
- `navsentry init` safety and defaults:
  - It refuses to write inside a NavSentry source checkout, which is a public repository.
  - It warns and asks again when `local` or `dev` is chosen for a host that is not loopback or private.
  - On the development profile it lists `playwright-browser` in `transports.order`, so `--engine playwright` works without editing the manifest.
  - `.gitignore` now ignores a root `navsentry.json` and `navsentry/`.
- `flow from-recording` usability:
  - Without a manifest, the error explains that the recording carries none and that every recorded URL is checked against the owner's scope. It names `navsentry init <origin>` with the origin from the recording.
  - Control and invisible formatting characters (C1, zero-width, bidi marks, BOM, soft hyphen) are removed from targets.
  - Targets that look cut (an ellipsis, or a short file-name end such as `TS.md`) are listed under "Targets to check".
- `serve` now starts one demo shop on port 4173 instead of two fixtures on 4173 and 4174.
- The lint warning for E2E flows with UI steps points to `--engine playwright` instead of saying the browser transport does not exist.
- `compare` matches requests by method, path and actor. A changed origin is reported once, instead of listing every request as missing.
- The sample reports in `docs/samples/` are regenerated in the new format, with HTML versions.

## [0.2.0] - 2026-11-05

### Fixed
- safe-validate review fixes: a `logout` step on a fixture `cleanup_actor` is now refused at runtime as well as by lint, so cleanup always keeps its session. Lint now requires `fixture_create` to run as the fixture `owner_actor` (previously only a runtime ERROR). Browser login flows now stop on the first signal like other flows.
- Threat model IDs were duplicated: the console-output and visual-driver rows reused TM-30 and TM-31 from the analyzer rows. They are now TM-36 and TM-37.
- The local gate gave the test suite only 5 minutes; the suite now takes about 4, so a slow or busy machine turned GATE-02 into a FAIL with `pass=?`. The limit is 15 minutes, and a timeout is reported as such.
- `safety.mode: safe-validate` was accepted for `environment: staging`, because the check compared the environment name instead of the profile. Every production-profile environment (staging, production, unrecognized) is now limited to observe.

### Added
- `fixture_verify_gone` flow step (SPEC-0.2.0 §4.2, safe-validate): a mid-flow check, through the fixture's `verify_gone` as `cleanup_actor`, that an object this run created is gone. Gone is PASS, still present is FAIL. Cleanup still runs afterwards.
- safe-validate milestone 0.2.0-d (SPEC-0.2.0, development profile only).
  - **NSC-BIZ-001** moves to `flow` automation. Fixtures may declare `invariants` (JSON pointer with `>=`, `<=`, `==`, `!=` or `in`) and `forbidden_transitions` (pointer, from, to). They are evaluated on each object through `exists` before cleanup. A violation is FAIL; without declared rules the case is NOT_TESTED. Observed values are never recorded.
  - **NSC-INJ-004:** run marker reflections inside an HTML attribute or `<script>` element are recorded in the new `run.json → observations` and listed in REPORT.md. The case stays NOT_TESTED ("needs an injection payload (active-approved)").
  - A fill step may use `{{marker}}`.
- safe-validate milestone 0.2.0-c (SPEC-0.2.0, development profile only). Three cases move to `flow` automation:
  - **NSC-AC-003 modification:** a declared fixture mutation with `object_owner` and `access: denied`, judged against the owner's own mutation.
  - **NSC-AC-006 CSRF:** a new `check: "csrf"` mutation step and a `csrf` key on `allowed_mutations` entries. The step sends a token-less probe, a probe from the reserved origin `https://navsentry-csrf-probe.invalid`, and a same-origin control. Cookie-session actors only.
  - **NSC-AUTH-002:** a new `logout` step reads, logs out through `auth_endpoints.logout`, and re-reads with the pre-logout session. The actor is logged out afterwards, and logging out a `cleanup_actor` is a lint error.

  Fixture mutations may also be form-encoded (`content_type: application/x-www-form-urlencoded`). Vulnerable and secure fixture variants cover SPEC tests 8–10.
- safe-validate milestone 0.2.0-b (SPEC-0.2.0, development profile only). Login actors: `actors.<name>.login` is either `{"http": "login", "body": {"json": ...}}`, which sends one declared request to `auth_endpoints.login`, or `{"flow": "<id>"}`, a browser login flow on `--engine playwright` whose cookies become the session. Cookie-session actors use `cookie_env`, which is refused in the production profile. A failed login makes that actor's steps NOT_TESTED "login failed", and that actor creates nothing. Credentials and session cookie values are known secrets and never appear in artifacts. In safe-validate, the playwright engine runs `fill`, `select` and `submit`. A non-observe browser request (form or page JavaScript) is sent only when `checkMutation` matches a declared `allowed_mutations`, `login` or `logout` entry with the same content type, within `max_body_bytes`. Redirect hops are matched again, and the visual driver stays observe-only. **Approval change:** a flow that uses a fixture or a login actor now includes the referenced manifest entries and login flow in its approval hash. Editing them invalidates the approval, and `flow approve` needs `--config` for flows that use fixtures. Flows that use neither keep their hash.
- safe-validate milestone 0.2.0-a (SPEC-0.2.0, development profile only): manifest `fixtures` and `auth_endpoints`, plus `safety.max_mutations` (default 20, at most 200) and `safety.cleanup_window_seconds` (default 30). There is still no general mutation switch: a non-observe request is sent only when `ScopeGate.checkMutation` matches a declared entry (S13). New flow step `fixture_create`; http steps may send POST/PUT/PATCH/DELETE with a JSON body when they are bound to a fixture. Ids are validated before a URL is built, and mutations never follow redirects. Each create reserves its cleanup cost in the Budget and writes an fsynced intent to `fixtures.pending.json` before it is sent. Cleanup runs in reverse order as `cleanup_actor` (one retry on a network error or 5xx), including after a failing step, after the limits are exhausted and on the first SIGINT/SIGTERM. A second signal skips cleanup and keeps the pending file, and the next sweep reports it without deleting anything. run.json gains `marker`, `fixtures` and `mutations` (body sha256 only); REPORT.md gains *Fixtures and cleanup* and *Mutations*. **New FAILED cause:** a run with any leftover, or with a create whose outcome is unknown, is `executionStatus: FAILED` (exit 2), and the report lists the exact manual action. Login actors, browser mutations and the new security checks follow in 0.2.0-b to 0.2.0-d. Documented in [ADR-0010](docs/adr/0010-safe-validate-fixtures.md), threat model TM-32 to TM-35, FLOWS.md and the consumer skill.
- Design spec [SPEC-0.2.0](docs/specs/SPEC-0.2.0-M2-SAFE-VALIDATE.md) for M2 safe-validate (fixture mutations with tracked cleanup, login and cookie-session actors, CSRF, session-after-logout, business invariants). Accepted 2026-11-04 with owner decisions D1–D9; no behaviour changes until milestone 0.2.0-a.
- Computer Use as a visual driver on a NavSentry-owned browser ([ADR-0009](docs/adr/0009-visual-driver-on-owned-browser.md)): `navsentry browse start|screenshot|click|scroll|status|end` (development profile, `transports.visual_computer_use: true`). The agent sees screenshots and sends coordinates; every request the page makes still goes through ScopeGate and the Budget (S1). Commands use a token-protected local pipe, every action is logged, sessions end on `end`, idle timeout, deadline, budget or action limit, and screenshots are deleted with the work directory. Writes `VISUAL-SESSION.md` and `session.json`. No typing until M2. `scan --engine computer-use` still exits 3 and points to `browse`.
- STA-LIBVULN detector (SPEC-0.1.3 §6.4-B): the jQuery licence banner in a served bundle is matched against reviewed advisory records; an affected version is NSC-SUPPLY-002 SUSPECTED with the CVE and GHSA IDs and a client-finding preview `[jquery,v=<version>,<GHSA>]`. Outside the ranges, unknown, or only candidate records → NOT_TESTED with the reason. A plugin that only mentions jQuery is not a match, and a banner never suppresses another detector. Detector version 3 invalidates cached facts. NSC-SUPPLY-002 is now `auto`.

### Changed
- The three jQuery advisory records are promoted to `reviewed` (revision 2) after an independent, fresh-context review against the GHSA pages, the NVD API and the jQuery 3.4.0/3.5.0 release notes (2026-11-04).

### Fixed
- `npm run build` (and so `test`, `gate`, `docs:catalog`, `release:pack`) deletes `dist/` first. `tsc` never removes outputs whose sources are gone, so after a branch switch the gate could run stale compiled tests.
- An unrecognized `environment` (for example `development`) still fails safe to the production profile, but the authorization errors no longer claim the manifest said `"staging"`; they explain the fallback and name `local`/`dev`.

### Added
- Knowledge base: first real records from the GitHub Advisory Database (CC-BY 4.0): GHSA-gxr4-xjj5-5px2 (CVE-2020-11022), GHSA-jpcq-cgw6-v4j6 (CVE-2020-11023) and GHSA-6c3j-c64m-qhgq (CVE-2019-11358) for npm `jquery`, state `candidate` until independent review. STA-LIBVULN is not implemented yet, so they apply through `knowledge lookup` and owner-provided versions only. The generated KB carries the CC-BY attribution.
- 0.1.3-k runtime console checks (playwright engine): every console message and uncaught page error is inspected in memory on arrival and never written. New case NSC-INFO-006 (CWE-532): VALIDATED on an exact match with a known in-scope value, otherwise SUSPECTED; PII, stack traces and internal addresses map to NSC-INFO-004, NSC-PRIV-001, NSC-ERR-001 and NSC-INFO-003; dev-runtime markers are observations in development. REPORT.md gains a Browser console section; run.json gains `console`. With the http engine the checks are NOT_TESTED ("no JS runtime").
- Flow header `console: "silent"` and the functional assertion `console_silent`.
- Static detector STA-HIDDENLOG: `console.*` overrides and `?debug`/localStorage toggles in bundles are observations (NSC-INFO-006 NOT_TESTED); toggles are never set (S9). Detector version 2 invalidates cached asset facts.
- Authorization header credentials are also known without their scheme, so an exact match works on the bare token.
- M1b Playwright engine: `scan --mode flow --engine playwright` (development profile) runs `navigate`, `click`, `see` and `wait_for` in the Chromium headless shell. Every browser request is fulfilled through direct-http (ScopeGate before the request and at connect time, Budget, redaction); non-observe methods are refused, WebSocket is closed, service workers are blocked, and Chromium launches against a dead proxy ([ADR-0008](docs/adr/0008-playwright-engine-s1.md)). `fill`, `select` and `submit` stay NOT_TESTED until M2. Without the browser, UI steps are NOT_TESTED with no http fallback.
- `playwright-core` 1.64.1 as a dev and optional peer dependency (owner approved 2026-11-03). Install the browser yourself with `npx playwright-core install --only-shell chromium`; NavSentry never downloads it.
- GATE-02 reports how many tests were skipped.
- GATE-10 dependency-audit self-test (QA-AT-10): `npm audit --package-lock-only` must flag the known-vulnerable fixture lockfile `test/fixtures/sca/` (lockfile only, never installed); offline is INCOMPLETE.

### Changed
- Governance: Playwright moves from PENDING_REVIEW to approved (Chromium headless shell only); the GitHub Advisory Database is approved as the advisory source; OSV.dev is recorded as not adopted.

### Added
- Page-model analyzer, milestone 0.1.3-b (SPEC-0.1.3 §5; pure Node per owner decision D3, no Python):
  - `scan --mode page|spider --analyze` (or `--engine analyzer`) builds one redacted page model per fetched HTML page in `page-models/` beside `run.json`: display URL, template (path pattern, shape hash), forms (action, method, field names, types, required flags), links, script counts and external origins, CSP meta, frames, cookie flags, mixed-content count and a whole-page text hash. Field values, cookie values, tokens, emails and body text are never included; secret-looking field names are withheld. Titles and headings appear only with `analyzer.include_text: true`, redacted and cut to 120 characters. Each model is capped at 64 KiB with omitted counts, bounded by `analyzer.timeout_seconds`, and passes an artifact leak scan before it is written.
  - Declarative extractor specs (owner decision D5): JSON with a selector subset (tag, `tag[attr]`, `tag[attr=value]`, descendant, ≤ 8 levels), an attribute allowlist without `value` or text, five fixed predicates and no user regex. Owner-promoted specs live in `navsentry/analyzer/extractors/`; `--extractors <dir>` drafts are copied into the run's work directory and deleted with it. Non-JSON files (for example `.py`) are refused: NavSentry never executes model-generated code. `run.json → analyzer` records spec hashes.
  - `flow analyze --from-run` reads the page models beside `run.json` and adds a *Templates and forms* section to ANALYSIS.md.
  - REPORT.md gains an *Analyzer* section.

### Changed
- `--analyze` is no longer reported as NOT_TESTED: the analyzer runs.

### Added
- Development code inventory, milestone 0.1.3-d (SPEC-0.1.3 §4.1):
  - `navsentry flow import --openapi <spec.json> --config <manifest> --out <dir>`: a local OpenAPI 3.x or Swagger 2.0 JSON document becomes draft integration flows. GET operations without a body become steps; protected operations get an allowed step for an authenticated actor plus an anonymous `access: denied` step (NSC-AC-002). Path and required query parameters become `*_env` variables. Mutations, GETs with side-effect names, out-of-scope paths and non-plain templates are listed in IMPORT.md, not encoded. Step titles are generated; spec text never reaches the drafts. Existing drafts are never overwritten. YAML is not supported (ADR-0003).
  - `navsentry inventory --config <manifest> [--project <dir>] [--out <dir>]` (development profile only): a read-only, zero-network inventory of route declarations (Express-style, Next.js file routes, Python decorators, ASP.NET attributes, Spring mappings, Laravel routes), OpenAPI documents, test files and lockfile packages (`package-lock.json`, `composer.lock`). Links and junctions are never followed, dependency and build folders are skipped, and only validated route strings, relative paths, line numbers and package identities are kept. Lockfile packages are matched against the knowledge snapshot. Writes `code-inventory.json` and `CODE-INVENTORY.md`; the run is wrapped in the workspace check, so a change to the project exits 4.

### Added
- Vulnerability knowledge base framework, milestone 0.1.3-v (SPEC-0.1.3 §6.6):
  - Typed offline snapshot in `src/knowledge/advisories.ts` with records (identity, verified identifiers, affected/fixed ranges, preconditions, severity source, safe evidence, linked case, fix, regression guard, sources and freshness, record state) and aliases. It ships with **no real CVE records**: importing them needs an approved advisory source in governance.
  - Generated `docs/knowledge/VULNERABILITY-KB.md` (`npm run docs:catalog`, checked by GATE-03).
  - Explicit applicability (`affected | not-affected | unknown | not-applicable`) with semver precedence; unknown or partial versions, unsupported schemes and distribution packages (backports) give `unknown`, never an assumed range.
  - `navsentry knowledge status | lookup | propose`, all offline. `lookup` accepts a product and version or a CVE, advisory ID or alias; an unresolved alias returns candidates and "research needed", never a guessed mapping.
  - `knowledge propose --input <file.json>` validates a strict schema (https sources only, never fetched; no secrets, addresses, personal data or, with `--config`, target hosts), deduplicates by a stable ID, and writes `.navsentry/knowledge/proposals/<id>.md` plus `INDEX.md` atomically under a lock. Repeats are `unchanged`; corrections revise and keep history.
  - Every run records the snapshot identity and freshness and evaluates passive banner evidence (Server, X-Powered-By). REPORT.md gains *Known vulnerability applicability* and *Knowledge gaps / proposed updates* tables. An affected match is NSC-SUPPLY-001 SUSPECTED; anything else is NOT_TESTED with its reason. Unrecognised banner names are withheld. `scan` writes research-needed proposals for its gaps.
  - The consumer skill asks the agent to call `knowledge propose` after authorized research that touches a product, version or advisory.

### Added
- Static asset scan, milestone 0.1.3-s (SPEC-0.1.3 §6.4-B/C), on by default for `scan --mode page|spider`:
  - Inventory from fetched HTML (scripts, stylesheets, script/style preloads) and `/asset-manifest.json`; images, fonts and media are skipped. Each asset is fetched once per run and actor.
  - Bodies are streamed into an owned spool file in the run's work directory (bounded by `capture.max_work_bytes`) and scanned in chunks with an overlap, so values across chunk boundaries are found without buffering the body. Asset requests keep no body excerpt.
  - Fixed exposure probes once per origin as anonymous: `/.env`, `/.git/HEAD`, `/config.js`, `/env.js`, `/__ENV.js` (HEAD, then GET on 2xx/405); `/asset-manifest.json` for inventory. `checks.disabled: ["NSC-CONF-009"]` turns the probes off. A 200 SPA fallback page is not a finding: the file format must match.
  - Source maps from `sourceMappingURL`, the `SourceMap`/`X-SourceMap` headers or one `<bundle>.map` probe.
  - New cases **NSC-INFO-007** Secrets in client-side assets (exact known-token match VALIDATED, format match SUSPECTED), **NSC-INFO-008** Source maps with source content (anonymous in production VALIDATED, authenticated-only SUSPECTED, development observation only), **NSC-CONF-009** Configuration or VCS files publicly reachable, and **NSC-SUPPLY-002** Client-side library with known vulnerabilities (planned; needs an approved advisory source). Internal hosts in assets add evidence to NSC-INFO-003; development-server client code in a production bundle to NSC-CONF-005.
  - Facts-only cache in `.navsentry/cache/assets/`, keyed by content hash, detector version and redaction-policy version; it never stores values, verdicts or known-token matches, which are recomputed each run. `capture.cache_max_age_days: 0` disables reuse; `workspace clean --cache-max-age-days <n>` removes expired entries.
  - `client-findings.json` beside `run.json`: the agent-facing summary (case, asset display URL, line:col, masked `[kind,len=n]` preview, count, content-hash prefix), capped at 200 entries. `run.json → assets.cost` records bytes scanned locally, agent-visible bytes and the cache hit ratio. REPORT.md gains a *Client assets* section.
  - Provider key shapes (AWS, Stripe, GitHub, Slack, Google API) are shared by the Redactor and the detectors.

### Added
- Chained flows, milestone 0.1.3-f (SPEC-0.1.3 §5.5, docs/FLOWS.md): flow headers gain `requires` and `imports`. Lint rejects missing flows, cycles, undeclared imports, missing exports, name collisions and undeclared actor or origin transfers before any request. Flows run in dependency order and a shared dependency runs once. A dependent of a flow that is not PASS is NOT_TESTED with the dependency reason. Only values extracted in PASS steps are imported. A dependent's content hash covers its dependency closure, so editing a required flow invalidates dependent approvals; unchained flows keep their 0.1.2 hash.
- `flow approve --root <dir>` (default: the file's directory) so approval hashes include dependencies. `provenance.template` is accepted in flow headers.
- `--only` and `--level` selections pull in eligible required flows.

### Added
- Milestone 0.1.3-a2 (SPEC-0.1.3 §6.2, §4.2):
  - `navsentry scan --mode spider`: a template-aware crawl from the seed paths up to `safety.max_depth`. Pages are grouped by (origin, actor, path pattern, query-key set); `safety.representatives_per_pattern` pages per group are fetched and the rest are recorded as `sampled-out` (NOT_TESTED, never an inherited PASS). A shape hash of the tag skeleton marks `mixed-shape` groups. A finding or a mixed shape leads to more pages of that group, never more than 2N. Links pass the static ScopeGate before they are queued; `javascript:`, `mailto:`, `data:`, off-scope and denied links are recorded, never followed. Frontier, page, depth and request limits are hard limits; no forms are submitted and no parameters changed.
  - `robots.txt` per RFC 9309, fetched once per origin through ScopeGate and the run Budget: the `NavSentry` group or `*`, longest match, `allow` wins ties, `*` and `$`. Production enforces the policy and blocks an origin whose policy is unreachable (401/403, 5xx, errors); development records it. A 2xx HTML body (SPA fallback) means no policy (D10).
  - `scan --mode page --url <URL>`: one in-scope URL instead of the seed paths; an out-of-scope URL exits 3 before any request.
  - Redirect chains are recorded hop by hop (status, masked `Location`, scope decision, security-header changes) and redirect loops are stopped.
  - New case **NSC-AC-008 Open redirect** (CWE-601): observes query parameters already present in seed or crawled URLs and never injects a destination; findings are SUSPECTED.
  - REPORT.md: *Coverage by template*, robots.txt, skipped pages and *Redirect chains* sections. `run.json` gains optional `spider` and `redirectChains`.

### Changed
- Live `discover` now points to `scan --mode spider`; `discover --dry-run` is unchanged.

## [0.1.3] - 2026-11-02

### Added
- Scan modes and profiles, milestone 0.1.3-a1 ([SPEC-0.1.3](docs/specs/SPEC-0.1.3-SCAN-MODES-AND-WORKSPACE.md), [ADR-0007](docs/adr/0007-scan-modes-profiles-and-workspace.md)):
  - `navsentry scan --mode page|spider|flow [--engine http|playwright|analyzer] [--analyze] [--env …]`. `page` without `--url` is the seed scan of `test`; `flow` is `test --flows <path> --flows-only`. `spider` and `page --url` exit 3 with "scheduled for 0.1.3-a2". `--engine computer-use` exits 3 (deferred beyond 0.1.3). A blocked engine (`playwright`) runs nothing and exits 2; unavailable `--analyze` is reported NOT_TESTED (exit 2). Nothing ever falls back to another engine.
  - Profiles derived from `environment`: `local`/`dev` → `development`, `staging`/`production` → `production`, with per-profile defaults applied before parsing.
  - `--env development|production` on `test`, `scan` and `plan`: a safety assertion that exits 3 before any request when it differs from the manifest profile.
  - New manifest keys: `authorization.not_before`, `authorization.allow_live_tokens`, `safety.max_depth`, `safety.representatives_per_pattern`, `safety.max_frontier`, `capture.*`, `analyzer.timeout_seconds`, `analyzer.include_text`, `workspace.ignore`.
  - Streamed HTTP capture: every byte is counted and hashed, a bounded prefix (`capture.memory_buffer_bytes`, 8 MiB) is kept for checks, and each response records `complete | truncated | aborted` (`ObservedRequest.capture`). Per-response and per-run byte budgets replace the fixed 1 MiB cap. Truncated, aborted, partially inspected or non-identity-encoded bodies make the run PARTIAL, and flow body assertions on them are INCONCLUSIVE.
  - Workspace hygiene: NavSentry writes only `<project>/.navsentry/` (with its own `.gitignore` containing `*`) and explicit `--out` files. Each run uses a locked `.navsentry/work/<run-id>/` that is deleted on exit, SIGINT and SIGTERM; stale directories are swept only when same-host ownership is proven stale. Before/after snapshots of the project report unexpected changes as **exit 4 `WORKSPACE_DIRTY`** (precedence 3 > 4 > 1 > 2 > 0). `--project <dir>` selects the project root.
  - `navsentry workspace status|clean [--project <dir>] [--dry-run]`.
  - `run.json` gains optional `scanMode`, `profile`, `engine`, `authorizationReference`, `capture` and `workspace`; `mode` keeps its safety meaning and schema version 1 is unchanged. REPORT.md shows them, with Capture and Workspace sections.
  - GATE-09 (maintainers): the local gate fails on files created, modified or deleted during the tests, and on untracked helper scripts (`*.cjs`, `*.py`, `*.ps1`, `*.sh`, `tmp*`).

### Changed
- Budget reservations are serialized, and the request, duration and authorization-deadline limits are re-checked after the rate-limit wait. Reaching `expires_at` cancels in-flight requests and the run becomes PARTIAL.
- `--include-drafts` is refused for the whole production profile (now including `staging`).
- Origins containing `*` are rejected when the manifest loads.

### Migration
- **Staging and production manifests** now use the production profile. They need `authorization.reference` (1–100 characters, no `.`, `/` or `:`) and `authorization.expires_at`, and default to 100 requests at 1 request per second. Development manifests (`local`, `dev`) keep their 0.1.2 defaults.
- Scripts that treat any non-zero exit as failure are unaffected; scripts that map exit codes should add 4.

## [0.1.2] - 2026-11-01

### Added
- Story flows: one `*.flow.md` file per user story, with strict JSON blocks (`navsentry-flow`, `navsentry-step`) inside Markdown. See `docs/FLOWS.md` and ADR-0006.
- Deterministic test levels: a flow is Integration (API steps only) or E2E (any `navigate` or UI step), with reasons. A declared level that disagrees is a lint error.
- `navsentry flow init | analyze | lint | approve | show`. `flow analyze` drafts flows and `ANALYSIS.md` from an earlier `run.json` without network access. `flow approve` pins approval to a content hash.
- `navsentry test --flows <path>` (`--flows-only`, `--include-drafts`, `--only`, `--level`, `--junit`) replays flows through the same ScopeGate, Budget and Redactor. Every flow exchange also runs the security checks. Outputs: `flows.json`, `TEST-REPORT.md` (en/th), optional `junit.xml`, and a Flows section in `REPORT.md`.
- `navsentry plan --flows` lists each flow step with its scope decision and the estimated number of requests.
- Access expectations (`access: allowed|denied` with a positive control) and a new automation class `flow`. NSC-AC-002 and NSC-AC-003 (read access) are now checked through flows. New case NSC-AC-007 *Missing function-level authorization*.
- `compare` reads `flows.json` beside each `run.json` (directories are accepted) and reports functional regressions (new verdict `FUNCTIONAL_REGRESSION`).
- Example flows and manifest (`examples/flows/`, `examples/manifest.flows.example.json`) and a `MANUAL-REPLAY` template.

### Changed
- `executeTest` returns the run together with the flow result. The run JSON gains the optional fields `ObservedRequest.flow`, `CheckResult.basis` and `RunResult.flowSet`; schema version 1 is unchanged.
- Exit code 1 now also covers a failed flow. Exit code 2 now also covers incomplete flows: in this release that includes every E2E flow with UI steps, because UI steps are not executed yet.

## [0.1.0] - 2026-10-31

### Added
- Agent plugins from this repository: Claude Code plugin and marketplace, Codex plugin and marketplace (pinned to the release tag), Gemini CLI extension and Antigravity plugin, all shipping the `navsentry` and `navsentry-doctor` skills.
- `navsentry doctor` version management: CLI and package location, version consistency of every bundled manifest and skill, NavSentry plugin/skill installations per host (`CURRENT`/`OUTDATED`/`NEWER`/`UNKNOWN`), host update commands, `--host`, `--project`, `--json`. Reads local files only.
- `navsentry doctor update --host <host> --scope user|project [--dry-run]` copies the skills into a host skills folder, backing up the previous copy outside it and refusing foreign folders.
- Release tarball (`npm run release:pack`) installable with `npm install -g`.
- Codex repository skill discovery and explicit fallback loading, checkout-relative resource resolution and interruption recovery guidance.
- CLI: `doctor`, `integrations`, `validate`, `plan`, `discover --dry-run`, `test`, `report`, `compare`, `catalog`.
- Strict JSON manifest (authorization acknowledgement, origin/path allow/deny lists, safe methods, budgets, env-referenced actors; plaintext secrets rejected).
- `ScopeGate` with pre-request checks and connect-time DNS validation (private/loopback/link-local/CGNAT/NAT64/IPv4-mapped; cloud metadata always blocked; explicit private-network approvals).
- `direct-http` transport (node:http/https), redirect re-check per hop, bounded bodies, request budget and rate limiting.
- TLS handshake probe (TLS 1.0–1.3 acceptance, certificate key size/validity/chain).
- 20 deterministic observe-mode checks mapped to Case Catalog IDs.
- Redaction (known secrets, JWT, bearer/basic, secret assignments, email, Thai national ID with checksum, Luhn-valid card numbers, private IPs); binary bodies withheld.
- Response contracts and `compare` (security status transitions + legitimate-response drift).
- Reports: JSON schema v1, Markdown (en/th), SARIF 2.1.0.
- Case Catalog with 50 cases in 13 categories, OWASP Top 10 2021 + 2025, CWE, WSTG, ASVS 5.0 chapter mapping; generated catalog with VERIFY/FIX/RECHECK agent prompts and ISSUE/CVE matrix.
- Optional transport probes (Playwright, curl, PowerShell, visual, ZAP) reporting honest availability; tested safe argv builders for curl/PowerShell.
- Local release gate (8 gates) replacing hosted CI; third-party decision register; local demo fixture app.
- Computer Use is documented as unavailable as a scan transport; manual browser evidence cannot silently become automated PASS results.
- Documentation set, ADRs 0001–0005, consumer skill, delivery reports (issue register, fix report, QA report, Thai human summary).

### Fixed
- The CLI entry check resolves symlinks, so a globally installed `navsentry` runs on Linux and macOS.
