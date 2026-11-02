# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

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
