# ADR-0005: Response contracts protect legitimate callers during remediation

- Status: Accepted · Date: 2026-10-31

## Context
Owner requirement: security fixes must not change the responses that legitimate requesters depend on.

## Decision
Every observed request stores a contract: status, media type, non-volatile non-security header names, JSON key/type skeleton hash (array order/length-insensitive) and body-size bucket. `navsentry compare` reports per-case transitions and contract drift; security headers are excluded because they are expected to change. Every catalog case carries a `regressionGuard`. CLI exits 1 on drift or regression.

## Consequences
Fixes like "hide the stack trace" must keep the same status and JSON keys. Value changes inside a field (e.g. masking) are allowed; key/type changes require explicit owner approval.
