# ADR-0004: Scope enforcement in the transport, including connect-time DNS checks

- Status: Accepted · Date: 2026-10-31

## Decision
`ScopeGate.checkRequest` runs before any I/O; `ScopeGate.checkResolvedAddress` runs inside the socket `lookup` for every resolved address. Redirects are never auto-followed; each hop is re-checked. Cloud metadata addresses are always blocked; other non-public addresses require a named approval (host, approver, reason). Node's global `fetch` is not used because it cannot enforce connect-time checks without an extra dependency.

## Consequences
DNS rebinding and redirect escapes are blocked and tested. Browser transports must route every request through the same gate and declare channels they cannot constrain; the playwright engine does this by fulfilling every request through direct-http ([ADR-0008](0008-playwright-engine-s1.md)).
