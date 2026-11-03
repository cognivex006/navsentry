# Testing

## Suites (`npm test`)
| File | Proves |
|---|---|
| `test/config.test.ts` | safe defaults; authorization required; plaintext secrets/unknown keys rejected without echo; unsafe modes/methods/origins refused |
| `test/scope.test.ts` | origin/scheme/port/credential/method denial; deny-wins globs; encoded traversal; address classification incl. metadata, IPv4-mapped, NAT64; DNS-rebinding rule |
| `test/redact.test.ts` | checksum validators; secrets/PII removed; headers/URLs; binary withheld |
| `test/e2e.test.ts` | zero-network dry-run; vulnerable fixture FAILs; secure fixture PASSes; compare no-drift and drift detection; redirect escape; connect-time denial (0 bytes sent); budget → PARTIAL; unreachable → never PASS; SARIF structure |
| `test/flow.test.ts` | flow parser strictness (unknown keys, block typos, nested fences, limits, no values in messages); lint/plan zero network and scope/secret/level rules; deterministic classification; vulnerable fixture → NSC-AC-002/003/007 FAIL (SUSPECTED for drafts, VALIDATED when approved); secure fixture PASS; UI steps NOT_TESTED and E2E never PASS; hostile extracted values never leave scope; budget exhaustion; approval hash; analyzer zero network, deterministic, no errors/values encoded; compare functional regressions; CLI outputs and exit codes; no network imports in `src/flow`; shipped examples lint |
| `test/browser.test.ts` | M1b / S1: browser steps pass and fail honestly; off-scope subresources never reach a canary origin; no WebSocket upgrade, service worker fetch or POST reaches the app; every request the app saw is a recorded direct-http exchange; Budget bounds the browser; no http fallback without the engine; launch flags alone block a direct connection. Needs the Chromium headless shell (see below), otherwise skipped with the reason |
| `test/transports.test.ts` | curl/PowerShell argv safety; scrubbed env; honest optional adapters; router never substitutes; catalog integrity and anonymization |

Fixture app: `test/fixtures/demo-server.ts` — binds 127.0.0.1, synthetic data, `vulnerable` and `secure` variants with identical response contracts for legitimate callers. Flow routes: `/api/me` (AC-002), `/api/orders` and `/api/orders/:id` (AC-003), `/api/admin/stats` (AC-007), `/app/profile` and `/login` (E2E), `/api/hostile-ids` (NavSentry extraction-safety fixture). Fixture flows: `test/fixtures/flows/`, `test/fixtures/flows-hostile/`.

Browser tests: install the approved build once, outside the repository, and point the tests at it. GATE-02 shows the skip count when it is missing.

```bash
PLAYWRIGHT_BROWSERS_PATH=<dir outside the repo> npx playwright-core install --only-shell chromium
```

## Local gate (`npm run gate`)
GATE-01 no workflows · GATE-02 tests · GATE-03 generated docs · GATE-04 npm audit · GATE-05 lockfile provenance · GATE-06 terms decisions · GATE-07 SBOM · GATE-08 publication safety. PASS / FAIL / INCOMPLETE; exit 0 only when all PASS.

## Platform matrix
| Platform | Node | Executed | Result |
|---|---|---|---|
| Windows 11 Pro 10.0.26300 x64 | 26.13.0 | ✅ 2026-10-31 | 30/30 tests, gate PASS |
| Windows | 22.x / 24.x | ❌ not executed | — |
| Linux (container/WSL) | 22/24/26 | ❌ not executed | — |
| macOS | any | ❌ not executed | — |

Unexecuted rows are not claims of support. Run `npm test` there and update this table with the real result.
