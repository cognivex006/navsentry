# ADR-0003: Zero runtime dependencies; JSON manifests in v0.1

- Status: Accepted · Date: 2026-10-31

## Decision
v0.1 ships without runtime dependencies. Manifests are JSON validated by hand-written strict code (unknown keys rejected). YAML support needs a governed dependency and safe-load review (M1b). Playwright will be an optional peer dependency that NavSentry never installs automatically.

## Consequences
Users write JSON for now; validation errors are precise and never echo secret values.
