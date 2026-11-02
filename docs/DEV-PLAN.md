# Development plan (แผนการพัฒนา)

Principle: each milestone ships working, tested behavior — never empty interfaces. Third-party governance and the local gate apply from M0. No hosted CI at any stage.

| Milestone | Scope | Status | Exit criteria |
|---|---|---|---|
| **M0** Foundations | ADRs, docs, threat model, manifest + validation, dry-run plan, catalog, local gate | ✅ done (v0.1.0) | gate PASS; dry-run zero network |
| **M1-core** HTTP observe | ScopeGate (+DNS), budget, redaction, direct-http, TLS probe, 20 checks, JSON/MD/SARIF, compare, fixture app | ✅ done (v0.1.0) | 30 tests; demo compare IMPROVED_NO_DRIFT |
| **M1-flows** Story flows (v0.1.2) | Flow Markdown v1, lint, E2E/Integration classification, replay through ScopeGate/Budget with security checks, access expectations (`flow` class: NSC-AC-002/003/007), `flow analyze`, TEST-REPORT/flows.json/JUnit, functional regressions in `compare` | ✅ done (v0.1.2) | flow tests pass; gate PASS |
| **0.1.3-a1** Scan modes foundations | Profiles and production guards on every entry point, `--env`, new manifest keys, `scan --mode page\|flow`, `scanMode` wire field, streamed capture with byte budgets, Budget deadline and serialization, workspace lock/cleanup/snapshots, exit 4, `workspace status\|clean`, GATE-09 | ✅ done (0.1.3) | a1 acceptance tests; gate PASS |
| **0.1.3-a2** Spider | `scan --mode spider` (template grouping, shape hash, 2N spread), RFC 9309 robots.txt, `page --url`, redirect-chain records, NSC-AC-008 | ✅ done | a2 acceptance tests; gate PASS |
| **0.1.3-f** Chained flows | `requires`/`imports`, graph lint, dependency-ordered replay, closure hashes for approval | ✅ done | chain tests; gate PASS |
| **0.1.3-s … b** Static assets, knowledge base, code inventory, page analyzer | See [SPEC-0.1.3 §11](specs/SPEC-0.1.3-SCAN-MODES-AND-WORKSPACE.md#11-milestones). Live discovery moves here from M1b. Computer Use is deferred beyond 0.1.3. | ⏳ next | per-milestone acceptance in SPEC-0.1.3 §10 |
| **M1b** Browser + discovery | Playwright adapter (headless/headful), deny-by-default routing via ScopeGate, `serviceWorkers:'block'`, popup/WebSocket checks, DOM checks (CSP violations, cookie visibility, framing), bounded same-origin discovery (`discover`), YAML manifests (governed dependency) | ⏳ next | QA-AT-04 passes on Linux headless; out-of-scope subresource blocked test |
| **M2** Authenticated validation | Login flows from env credentials, per-actor isolated contexts, scenarios as flow-format extensions (login actions, safe-validate mutation steps with cleanup, `session-lifecycle`, `csrf`, `reflected-marker`), fixtures with positive/negative controls, cleanup | ⏳ | NSC-AC-002/003/006, NSC-AUTH-002, NSC-INJ-004 automated; QA-AT-07 passes |
| **M3** CLI transports | curl and PowerShell execution (7 and 5.1), parity tests vs direct-http, Windows + Linux runs, visual provider interface contract (still unavailable by default) | ⏳ | identical findings across transports on the fixture; PRM-SAFE-001 closed |
| **M4** Reporting & interop | HTML report, resumable large runs with integrity manifest, ASVS 5.0 requirement IDs verified, DevSift correlation adapter (versioned, read-only) | ⏳ | schema v1 stable; correlation sample |
| **M5** Hardening & imports | SCA fixture self-test (QA-AT-10), OpenAPI/Postman import → reviewed manifests (no script execution; Newman only after terms review), optional ZAP passive (self-hosted, terms reviewed), `active-approved` design document (not implementation) | ⏳ | gate self-test FAIL on fixture lockfile |

## Immediate next steps (ordered)
1. Owner: remove `workflow` scope from the GitHub CLI token; enable private vulnerability reporting in repository settings.
2. Run `npm test` on Linux and Node 22/24; update [TESTING.md](TESTING.md#platform-matrix).
3. Complete the Playwright browser-binary terms review → add the optional dependency → M1b.
4. QA-AT-10 SCA fixture self-test (small, independent).
5. M2 scenario schema design review before code.

## Risks
| Risk | Mitigation |
|---|---|
| Scope creep from the master prompt | Milestone exit criteria; honest NOT_TESTED |
| Browser cannot be fully constrained | Declare unenforceable channels; block service workers; refuse unsafe runs |
| False positives erode trust | SUSPECTED lifecycle; caveats; owner-recorded exceptions |
| Platform policy risk (GitHub) | No automation; no customer data; AUP-reviewed content |
