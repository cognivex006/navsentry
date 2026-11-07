# Testing

## Suites (`npm test`)
| File | Proves |
|---|---|
| `test/config.test.ts` | safe defaults; authorization required; plaintext secrets/unknown keys rejected without echo; unsafe modes/methods/origins refused |
| `test/scope.test.ts` | origin/scheme/port/credential/method denial; deny-wins globs; encoded traversal; address classification incl. metadata, IPv4-mapped, NAT64; DNS-rebinding rule |
| `test/redact.test.ts` | checksum validators; secrets/PII removed; headers/URLs; binary withheld |
| `test/e2e.test.ts` | zero-network dry-run; vulnerable fixture FAILs; secure fixture PASSes; compare no-drift and drift detection; redirect escape; connect-time denial (0 bytes sent); budget → PARTIAL; unreachable → never PASS; SARIF structure |
| `test/flow.test.ts` | flow parser strictness (unknown keys, block typos, nested fences, limits, no values in messages); lint/plan zero network and scope/secret/level rules; deterministic classification; vulnerable fixture → NSC-AC-002/003/007 FAIL (SUSPECTED for drafts, VALIDATED when approved); secure fixture PASS; UI steps NOT_TESTED and E2E never PASS; hostile extracted values never leave scope; budget exhaustion; approval hash; analyzer zero network, deterministic, no errors/values encoded; compare functional regressions; CLI outputs and exit codes; no network imports in `src/flow`; shipped examples lint |
| `test/visual.test.ts` | ADR-0009 visual driver: preconditions refuse with zero requests; clicks navigate in scope; an off-scope click never reaches the canary and is a denial; WebSocket/service worker/POST blocked; every app request is a recorded exchange; forged token refused; Budget and idle timeout end the session; work directory and screenshots deleted; CLI start/status/end |
| `test/console.test.ts` | 0.1.3-k: a known test token in console output is NSC-INFO-006 VALIDATED with a masked preview and no message text in artifacts; `console: "silent"` is a functional FAIL only; a later same-template message with a secret is still found; a console.log override and `?debug` toggle are observations and the toggle is never requested (S9); http engine → NOT_TESTED "no JS runtime"; bounded capture counts dropped messages |
| `test/browser.test.ts` | M1b / S1: browser steps pass and fail honestly; off-scope subresources never reach a canary origin; no WebSocket upgrade, service worker fetch or POST reaches the app; every request the app saw is a recorded direct-http exchange; Budget bounds the browser; no http fallback without the engine; launch flags alone block a direct connection. Needs the Chromium headless shell (see below), otherwise skipped with the reason |
| `test/a1.test.ts` | 0.1.3-a1: profiles from `environment`, production authorization window, manifest key ranges, scan modes, streamed capture, workspace lock and exit 4 |
| `test/a2.test.ts` | 0.1.3-a2 spider: path patterns and shape hash, tag scan, RFC 9309 robots.txt, per-template sampling within the request budget, redirect chains |
| `test/chain.test.ts` | chained flows: `requires`/`imports`, dependency order, graph lint, transitive approval hashes |
| `test/assets.test.ts` | 0.1.3-s static asset scan: chunk-boundary secrets with masked facts only, exposure probes, source maps, facts cache; vulnerable and secure fixtures |
| `test/libvuln.test.ts` | STA-LIBVULN: jQuery banner → NSC-SUPPLY-002 against reviewed advisories; secure version, candidate-only records and non-banner mentions |
| `test/knowledge.test.ts` | 0.1.3-v knowledge base: semver applicability, offline lookup, packaged snapshot, strict proposal schema |
| `test/inventory.test.ts` | 0.1.3-d: OpenAPI import to linted drafts, code inventory of routes, tests, OpenAPI files and lockfiles; read-only, development only |
| `test/analyzer.test.ts` | 0.1.3-b page models: structure only, stable shape hash, strict declarative extractors, redaction |
| `test/safe-validate.test.ts` | SPEC-0.2.0 tests 1–7: safe-validate config refusals, S13 declared entries only, id rules, cleanup, leftovers and signals |
| `test/safe-validate-b.test.ts` | SPEC-0.2.0 tests 2, 12, 13, 15: login actors (http, browser, cookie session), browser mutation matching, approval hashing |
| `test/safe-validate-c.test.ts` | SPEC-0.2.0 tests 8–10: NSC-AC-003 modification, NSC-AC-006 CSRF, NSC-AUTH-002 session after logout |
| `test/safe-validate-d.test.ts` | SPEC-0.2.0 tests 11, 14: NSC-BIZ-001 invariants and forbidden transitions, NSC-INJ-004 marker observations |
| `test/doctor.test.ts` | version doctor: packaging versions, statuses, installation discovery, skill update with backup |
| `test/skill-discovery.test.ts` | Codex entrypoint resolves the canonical skill; skill front matter shape |
| `test/transports.test.ts` | curl/PowerShell argv safety; scrubbed env; honest optional adapters; router never substitutes; catalog integrity and anonymization |

Fixture app: `test/fixtures/demo-server.ts` — binds 127.0.0.1, synthetic data, `vulnerable` and `secure` variants with identical response contracts for legitimate callers. Flow routes: `/api/me` (AC-002), `/api/orders` and `/api/orders/:id` (AC-003), `/api/admin/stats` (AC-007), `/app/profile` and `/login` (E2E), `/api/hostile-ids` (NavSentry extraction-safety fixture). Fixture flows: `test/fixtures/flows/`, `test/fixtures/flows-hostile/`.

Browser tests: install the approved build once, outside the repository, and point the tests at it. GATE-02 shows the skip count when it is missing.

```bash
PLAYWRIGHT_BROWSERS_PATH=<dir outside the repo> npx playwright-core install --only-shell chromium
```

## Local gate (`npm run gate`)
GATE-01 no workflows · GATE-02 tests · GATE-03 generated docs · GATE-04 npm audit · GATE-05 lockfile provenance · GATE-06 terms decisions · GATE-07 SBOM · GATE-08 publication safety · GATE-09 workspace hygiene · GATE-10 dependency-audit self-test. PASS / FAIL / INCOMPLETE; exit 0 only when all PASS.

## Platform matrix
| Platform | Node | Executed | Result |
|---|---|---|---|
| Windows 11 Pro 10.0.26300 x64 | 26.13.0 | ✅ 2026-11-05 | 156/156 tests, gate PASS |
| Windows | 22.x / 24.x | ❌ not executed | — |
| Linux (container/WSL) | 22/24/26 | ❌ not executed | — |
| macOS | any | ❌ not executed | — |

Unexecuted rows are not claims of support. Run `npm test` there and update this table with the real result.
