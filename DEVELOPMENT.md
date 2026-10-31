# Development

## Setup

```bash
npm ci --ignore-scripts
```

`.npmrc` enforces `ignore-scripts=true` and `save-exact=true`. There are **no runtime dependencies**; dev dependencies are TypeScript 6.0.3 and @types/node 22.20.5.

## Commands

| Command | Purpose |
|---|---|
| `npm run build` | Compile `src/`, `test/`, `scripts/` to `dist/` |
| `npm test` | Build + run all tests (`node:test`, sequential) |
| `npm run docs:catalog` | Regenerate `docs/cases/CASE-CATALOG.md` and `docs/ISSUE-CVE-MATRIX.md` from `src/catalog.ts` |
| `npm run gate` | Local release/PR gate (replaces hosted CI) → `.navsentry/gate/GATE-REPORT.md` |
| `node dist/scripts/demo.js run` | Regenerate `docs/samples/` from the local fixture app |
| `node dist/scripts/demo.js serve` | Serve vulnerable (:4173) and secure (:4174) fixtures for browser rechecks |

## Layout

```
src/
  cli.ts            command surface and exit codes
  config.ts         strict manifest parsing (unknown keys rejected)
  scope.ts          ScopeGate: origin/path/method + address classification
  budget.ts         request volume / rate / duration
  redact.ts         redaction before persistence
  contract.ts       response-contract fingerprints
  catalog.ts        Case Catalog (single source of truth)
  checks/           passive.ts (per-exchange), tls.ts (handshake probe)
  transports/       direct-http, optional adapters, router
  report/render.ts  JSON / Markdown / SARIF
  runner.ts         plan (no network) and execute
  compare.ts        before/after verdict + contract drift
scripts/            gate, doc generator, demo
test/               unit + fixture E2E (demo-server.ts)
governance/         third-party decisions
```

## Coding conventions
- TypeScript strict, ES modules, Node built-ins only in `src/`.
- No `child_process` with `shell: true`; executables only from fixed system paths with argv arrays.
- Errors shown to users must not echo request data or secrets (`safeError`).
- Checks read raw responses in memory but emit only redacted, value-free observations.

## Branches, reviews, releases
- `main` is protected by convention: work on `feat/*`, `fix/*`, `docs/*`; Conventional Commits.
- Before pushing: `npm run gate` must PASS. Optional local hook: `git config core.hooksPath scripts/hooks` (create your own `pre-push` that runs the gate; nothing is installed automatically).
- Releases: owner authorization, `CHANGELOG.md` section, tag `vX.Y.Z`. No package publication is configured.

## Dependency updates
No Dependabot/Renovate (hosted automation is prohibited). Manual procedure:
1. `npm outdated` — list candidates.
2. Prefer versions published ≥ 14 days ago; read release notes and advisories for the exact version.
3. Review license and terms; update `governance/third-party.json` (version, reviewed, review_due, decision).
4. `npm install --save-exact --ignore-scripts <pkg>@<version>`
5. `npm run gate` must PASS (audit, lockfile provenance, decisions, SBOM).
6. Commit lockfile + register together with a `chore(deps):` message explaining why.

## Adding a check
1. Add/extend the case in `src/catalog.ts` (see the matrix "Adding a case" section).
2. Implement in `src/checks/` returning `CheckResult` with redacted observations.
3. Wire it in `runner.ts` (`PER_EXCHANGE` or a dedicated probe step) and in `planRun`.
4. Add vulnerable + secure routes in `test/fixtures/demo-server.ts` (secure keeps the response contract) and assertions in `test/e2e.test.ts`.
5. `npm run docs:catalog && npm run gate`.
