# ADR-0001: TypeScript on Node.js, built-ins first

- Status: Accepted · Date: 2026-10-31

## Context
The master prompt recommends TypeScript and Playwright. Supply-chain risk and terms review cost grow with each dependency.

## Decision
TypeScript (strict, ES modules) on Node.js ≥ 22.12. The core uses only Node built-ins (`node:http/https/tls/dns/crypto/test`). TypeScript 6.0.3 (pure JS) is the only build tool; tests use `node:test`.

## Consequences
+ Zero runtime dependencies; tiny audit surface. − Some conveniences (YAML, schema validators) are hand-written or deferred.
