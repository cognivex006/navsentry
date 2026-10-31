# Testing

## Suites (`npm test`)
| File | Proves |
|---|---|
| `test/config.test.ts` | safe defaults; authorization required; plaintext secrets/unknown keys rejected without echo; unsafe modes/methods/origins refused |
| `test/scope.test.ts` | origin/scheme/port/credential/method denial; deny-wins globs; encoded traversal; address classification incl. metadata, IPv4-mapped, NAT64; DNS-rebinding rule |
| `test/redact.test.ts` | checksum validators; secrets/PII removed; headers/URLs; binary withheld |
| `test/e2e.test.ts` | zero-network dry-run; vulnerable fixture FAILs; secure fixture PASSes; compare no-drift and drift detection; redirect escape; connect-time denial (0 bytes sent); budget → PARTIAL; unreachable → never PASS; SARIF structure |
| `test/transports.test.ts` | curl/PowerShell argv safety; scrubbed env; honest optional adapters; router never substitutes; catalog integrity and anonymization |

Fixture app: `test/fixtures/demo-server.ts` — binds 127.0.0.1, synthetic data, `vulnerable` and `secure` variants with identical response contracts.

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
