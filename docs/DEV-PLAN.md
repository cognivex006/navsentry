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
| **0.1.3-s** Static asset scan | Inventory, spool-backed streamed detectors, exposure probes, source maps, facts cache, `client-findings.json`, NSC-INFO-007/008, NSC-CONF-009 | ✅ done | asset tests; gate PASS |
| **0.1.3-v** Knowledge base framework | Typed snapshot, generated KB Markdown, applicability matching, `knowledge status\|lookup\|propose`, run tables and research-needed proposals | ✅ done; first real records (3 jQuery GHSA advisories, `candidate`) added 2026-11-03 after the GitHub Advisory Database was approved | knowledge tests; gate PASS |
| **0.1.3-d** Code inventory | `flow import --openapi` (local JSON → drafts), read-only `inventory` of routes, OpenAPI files, tests and lockfiles | ✅ done | inventory tests; gate PASS |
| **0.1.3-b** Page analyzer | Pure-Node page models (`--analyze`), declarative extractor specs, page models in `flow analyze` | ✅ done | analyzer tests; gate PASS |
| **M1b (0.1.3)** Playwright engine | `scan --mode flow --engine playwright` (development): `navigate`/`click`/`see`/`wait_for` in the Chromium headless shell; every request fulfilled through direct-http (ScopeGate + Budget); WebSocket and service workers disabled; dead-proxy launch ([ADR-0008](adr/0008-playwright-engine-s1.md)) | ✅ done | browser tests; gate PASS |
| **0.1.3-k** Console checks | Runtime console capture on the playwright engine, NSC-INFO-006 (CON-SECRET/ECHO), CON-PII/TRACE/DEBUG mapped to existing cases, `console: "silent"`, static hidden-logging observations (STA-HIDDENLOG) | ✅ done | console tests; gate PASS |
| **Visual driver** Computer Use | `navsentry browse` on a NavSentry-owned browser: screenshot/click/scroll over a token-protected local pipe, audit log, idle/deadline/budget ends, no typing ([ADR-0009](adr/0009-visual-driver-on-owned-browser.md)) | ✅ done | visual tests; gate PASS |
| **M1b+** Browser follow-ups | Headful mode, DOM checks (CSP violations, cookie visibility, framing), YAML manifests (governed dependency); live discovery moved to 0.1.3-a2 | ⏳ | QA-AT-04 passes on Linux headless; out-of-scope subresource blocked test |
| **0.2.0-a** safe-validate foundations | Fixture and auth-endpoint config, `checkMutation`, id rules, Budget cleanup reserve and window, pending intents, cleanup and leftovers, signal coordinator, http mutation steps, reports ([ADR-0010](adr/0010-safe-validate-fixtures.md)) | ✅ done (feat/0.2.0-a) | SPEC-0.2.0 tests 1–7; gate PASS |
| **0.2.0-b** Logins and browser mutations | http and browser login actors, `cookie_env`, browser `postData` matching through `checkMutation`, `fill`/`select`/`submit` in safe-validate, approval hashing of fixture/auth/login entries | ✅ done (feat/0.2.0-b) | SPEC-0.2.0 tests 2, 12, 13, 15; gate PASS |
| **0.2.0-c** Safe-validate security checks | NSC-AC-003 modification, NSC-AC-006 CSRF (`check: "csrf"`, reserved probe origin), NSC-AUTH-002 (`logout` step), form-encoded fixture mutations | ✅ done (feat/0.2.0-c) | SPEC-0.2.0 tests 8–10; gate PASS |
| **M2** Authenticated validation | Login flows from env credentials, per-actor isolated contexts, scenarios as flow-format extensions (login actions, safe-validate mutation steps with cleanup, `session-lifecycle`, `csrf`, `reflected-marker`), fixtures with positive/negative controls, cleanup | ⏳ | NSC-AC-002/003/006, NSC-AUTH-002, NSC-INJ-004 automated; QA-AT-07 passes |
| **M3** CLI transports | curl and PowerShell execution (7 and 5.1), parity tests vs direct-http, Windows + Linux runs, visual provider interface contract (still unavailable by default) | ⏳ | identical findings across transports on the fixture; PRM-SAFE-001 closed |
| **M4** Reporting & interop | HTML report, resumable large runs with integrity manifest, ASVS 5.0 requirement IDs verified, DevSift correlation adapter (versioned, read-only) | ⏳ | schema v1 stable; correlation sample |
| **M5** Hardening & imports | SCA fixture self-test (QA-AT-10, ✅ done as GATE-10), OpenAPI/Postman import → reviewed manifests (no script execution; Newman only after terms review), optional ZAP passive (self-hosted, terms reviewed), `active-approved` design document (not implementation) | ⏳ | gate self-test FAIL on fixture lockfile |

## Immediate next steps (ordered)
1. Owner: remove `workflow` scope from the GitHub CLI token; enable private vulnerability reporting in repository settings.
2. Run `npm test` on Linux and Node 22/24; update [TESTING.md](TESTING.md#platform-matrix).
3. More reviewed client-library records (STA-LIBVULN recognises jQuery banners today) and other library banners, each with primary-source verification and independent review.
4. M2: [SPEC-0.2.0](specs/SPEC-0.2.0-M2-SAFE-VALIDATE.md) ACCEPTED 2026-11-04; 0.2.0-a, 0.2.0-b and 0.2.0-c done. Next: 0.2.0-d (NSC-BIZ-001 owner-declared invariants, NSC-INJ-004 marker reflection as an observation; tests 11 and 14).

## Risks
| Risk | Mitigation |
|---|---|
| Scope creep from the master prompt | Milestone exit criteria; honest NOT_TESTED |
| Browser cannot be fully constrained | Declare unenforceable channels; block service workers; refuse unsafe runs |
| False positives erode trust | SUSPECTED lifecycle; caveats; owner-recorded exceptions |
| Platform policy risk (GitHub) | No automation; no customer data; AUP-reviewed content |
