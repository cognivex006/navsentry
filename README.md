# NavSentry

**Navigate. Validate. Secure.**

AI-assisted browser-based E2E security testing for web applications, with automated vulnerability validation and evidence-based reporting.

> ⚠️ **Authorized targets only.** NavSentry refuses to run without an explicit authorization acknowledgement and an origin allowlist. It never crawls the Internet, never sends injection/DoS payloads, and defaults to passive `observe` mode.

## Status — v0.1.0 (M0 + M1-core)

| Capability | State |
|---|---|
| Manifest validation, scope & authorization gate (origins, paths, methods, DNS-rebinding/metadata protection, redirect re-check) | ✅ implemented, tested |
| `direct-http` transport (node:http/https, zero dependencies) | ✅ usable |
| TLS handshake probe (protocol versions, certificate) | ✅ usable (legacy versions may be INCONCLUSIVE) |
| 20 deterministic observe-mode checks (headers, cookies, CORS, methods, cache, disclosure, PII, JWT, HTTPS redirect) | ✅ |
| Reports: JSON (schema v1), Markdown (en/th), SARIF 2.1.0 | ✅ |
| `compare`: before/after security status + **legitimate-response contract drift** | ✅ |
| Case Catalog: 50 cases, permanent IDs, OWASP 2021+2025 / CWE / WSTG / ASVS 5.0 mapping, agent prompts | ✅ |
| Local release gate (no hosted CI) | ✅ |
| `playwright-browser`, `curl-cli`, `powershell-http` execution | ⏳ M1b / M3 (probe only today; never faked) |
| Cross-role IDOR, CSRF, session lifecycle scenarios | ⏳ M2 |
| Visual computer-use, ZAP passive, OpenAPI/Postman import, DevSift bridge | ⏳ M3–M5 |

See [docs/DEV-PLAN.md](docs/DEV-PLAN.md) and [docs/COVERAGE.md](docs/COVERAGE.md).

## Quickstart

Requires Node.js ≥ 22.12 (tested on 26.13.0, Windows 11).

```bash
npm ci --ignore-scripts
```

```bash
npm run build
```

```bash
node dist/src/cli.js doctor
```

```bash
node dist/src/cli.js validate --config examples/manifest.example.json
```

```bash
node dist/src/cli.js plan --config examples/manifest.example.json
```

```bash
node dist/src/cli.js test --config my-manifest.json --out runs/before
```

```bash
node dist/src/cli.js compare --before runs/before/run.json --after runs/after/run.json
```

Try it safely against the bundled local demo (127.0.0.1 only, synthetic data):

```bash
node dist/scripts/demo.js run
```

It writes [docs/samples/before/REPORT.md](docs/samples/before/REPORT.md), [docs/samples/after/REPORT.md](docs/samples/after/REPORT.md) and [docs/samples/compare.md](docs/samples/compare.md).

## Architecture

```
Agent / CLI ─► Planner ─► Authorization & Scope Gate ─► Transport Router
                                │ (pre-request + connect-time DNS check)      │
                                ▼                                             ▼
                           Budget (rate/volume/duration)      direct-http · tls-probe · [browser · curl · pwsh · visual · zap]
                                                                              │
                         deterministic checks ◄───────────────────────────────┘
                                │
                     redaction ─► findings / coverage / response contracts ─► JSON · Markdown · SARIF · compare
```

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · Threat model: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)

## Results vocabulary

- Check status: `PASS` `FAIL` `INCONCLUSIVE` `NOT_TESTED` `ERROR` — missing evidence is never PASS.
- Finding lifecycle: `SUSPECTED` `VALIDATED` `NEEDS_REVIEW` `DISMISSED`; severity is separate from confidence.
- Priority: `IMMEDIATE` (fix now) · `PLANNED` (can wait) · `CAUTION` (fix carefully: may affect legitimate users).
- CLI exit: `0` no findings in tested scope · `1` findings · `2` incomplete · `3` usage/config error.

## Documentation

| For | Read |
|---|---|
| Users / consumer agents | [skills/navsentry/SKILL.md](skills/navsentry/SKILL.md), [docs/AGENT-INTEGRATIONS.md](docs/AGENT-INTEGRATIONS.md), [docs/REPORTING.md](docs/REPORTING.md) |
| Case knowledge base | [docs/cases/CASE-CATALOG.md](docs/cases/CASE-CATALOG.md), [docs/ISSUE-CVE-MATRIX.md](docs/ISSUE-CVE-MATRIX.md) |
| Maintainers | [AGENTS.md](AGENTS.md), [DEVELOPMENT.md](DEVELOPMENT.md), [docs/TESTING.md](docs/TESTING.md), [docs/THIRD-PARTY-GOVERNANCE.md](docs/THIRD-PARTY-GOVERNANCE.md), [docs/adr/](docs/adr/) |
| Review of this delivery | [docs/reports/HUMAN-SUMMARY.md](docs/reports/HUMAN-SUMMARY.md) (Thai), [01 issues](docs/reports/01-ISSUE-REGISTER.md), [02 fixes](docs/reports/02-FIX-REPORT.md), [03 QA](docs/reports/03-QA-REPORT.md) |

## Limitations

- Zero findings ≠ secure. Most injection, access-control and business-logic classes need M2 scenarios or authorized manual testing.
- No hosted CI by policy; quality gates run locally with `npm run gate`.
- Linux/macOS and Node 22/24 have not been executed yet ([TESTING.md](docs/TESTING.md#platform-matrix)).

## License

Apache-2.0 — see [LICENSE](LICENSE). Security reports: [SECURITY.md](SECURITY.md).
