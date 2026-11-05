# ADR-0010: safe-validate with declared fixtures, `checkMutation` and tracked cleanup

- Status: Accepted (SPEC-0.2.0, owner decisions D1–D9, 2026-11-04) · Date: 2026-11-05 · Builds on [ADR-0004](0004-scope-enforcement-at-transport.md), [ADR-0006](0006-flow-files-and-test-levels.md)

## Context
Several M2 cases cannot be tested in observe mode, because each one needs the target to change state: modifying another user's object (NSC-AC-003), CSRF (NSC-AC-006), the session after logout (NSC-AUTH-002) and business invariants (NSC-BIZ-001). Until now the only safety was "observe methods only". A single `allow_mutations` switch would turn every in-scope path into a write target and leave test data behind with no record. [SPEC-0.2.0](../specs/SPEC-0.2.0-M2-SAFE-VALIDATE.md) designs a narrower permission model. This ADR records the parts built in milestone 0.2.0-a.

## Decision
1. **Development profile only (D1).** `safety.mode: safe-validate` and the `fixtures`/`auth_endpoints` keys are refused at config time (exit 3) for staging, production and any unrecognized environment. `allow_mutations` stays rejected, and `allowed_methods` stays observe-only.
2. **Permission exists only as declared entries.** A fixture declares its `create`, `exists`, `cleanup`, optional `verify_gone` and `allowed_mutations`. Each entry has an exact method and a path template whose only placeholder is `{{id}}`, as a whole segment. Every declared path must be inside `allowed_paths` and outside `denied_paths` at config time.
3. **A separate gate method, `ScopeGate.checkMutation(url, method, entry)` (S13).** It runs the same origin, scheme, credential, encoded-separator, glob and literal-address checks as `checkRequest`. It then requires the method to equal the entry's method, and the *normalised* pathname to match the template with one id-shaped segment per placeholder. `checkRequest` keeps refusing every non-observe method, so the observe paths cannot widen. direct-http calls `checkMutation` only when the request carries its entry, and the connect-time address check is unchanged.
4. **Ids are validated before a URL is built.** An id must be a string or non-negative integer matching `^[A-Za-z0-9_-]{1,128}$`. `fillTemplate` throws on anything else.
5. **Mutations never follow redirects.** A 3xx is a result. A step that is bound to a fixture sends a JSON body that is built only from the declared template, run variables and the run marker. A placeholder must be a whole string value. Only the body's sha256 is recorded.
6. **Cleanup is reserved and recorded before a create is sent (S14).**
   - A create holds `2 × (1 + verify_gone)` Budget slots, which ordinary requests cannot use.
   - Creates stop when less than `cleanup_window_seconds` is left before the earlier of the run deadline and `authorization.expires_at`. Nothing is sent after that window (D9).
   - An intent is written and fsynced to `fixtures.pending.json` in the work directory before the create.
   - `max_mutations` (D2: default 20, maximum 200) limits non-observe requests. Cleanup is paid from the reserve, not from this limit.
7. **Cleanup by extracted id only.** Objects are cleaned in reverse creation order, as `cleanup_actor`. `cleanup` and `verify_gone` are retried once after a network error or 5xx, and a 404 on cleanup counts as done. Creates and mutations are never retried. Nothing is ever deleted by search, by marker or by type.
8. **Leftovers fail the run (S15, D3).**
   - A run is `executionStatus: FAILED` (exit 2) if an object is not cleaned and verified gone, or if a create's outcome is unknown (reset, truncated or unparseable response, or a rejected id).
   - The report lists each leftover with the exact manual action.
   - The agent never improvises a delete.
9. **Signals.** safe-validate runs replace the immediate exit in `beginRun` with a `SignalCoordinator`.
   - The first SIGINT/SIGTERM stops new requests and lets cleanup run for at most 30 s; then the reports are written.
   - A second signal skips cleanup, lists leftovers on stderr and exits, and keeps the pending file.
   - The next run's sweep reads pending files from stale work directories and reports them in `fixtures.pendingFromPreviousRuns`. It never acts on them.
10. **A run marker.** Each run gets a random `nsv-<16 hex>` marker. It is recorded in run.json and is available to body templates as `{{marker}}`.

## Evidence
`test/safe-validate.test.ts` runs SPEC-0.2.0 acceptance tests 1–7 against a fixture API on 127.0.0.1 (`test/fixtures/fixture-server.ts`). The tests cover:
- the config refusals;
- the `checkMutation` and lint refusals, and a 307 that is never followed;
- id rejection with no DELETE sent;
- cleanup at the normal end, after a failing step, at the mutation limit and on a first signal;
- the second signal and the pending file it keeps;
- reserve and window refusals, and the authorization deadline on reserve slots;
- lost creates, which are never retried;
- a refused DELETE with its retry, an object still present after cleanup, and pending intents from a killed run.

## Consequences
- Plus: write access is as narrow as the owner's declarations, and every write is in run.json with its entry, actor, status and body hash.
- Plus: a run cannot report COMPLETE while test data may still exist.
- Minus: a mis-declared fixture endpoint can still touch real data (TM-32). Side effects such as emails, webhooks and audit rows are not cleaned (TM-33).
- Not in this milestone: login and cookie-session actors, browser mutations, `fill`/`select`/`submit`, approval hashing of fixture entries (0.2.0-b), and the new security checks (0.2.0-c/d). `fixture_verify_gone` is not implemented yet.
