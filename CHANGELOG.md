# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.2] - Unreleased (pending owner release authorization)

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
