# ADR-0009: Computer Use as a visual driver on a NavSentry-owned browser

- Status: Accepted (owner request 2026-11-04) · Date: 2026-11-04 · Builds on [ADR-0008](0008-playwright-engine-s1.md)

## Context
SPEC-0.1.3 §6.3 deferred `computer-use` because a browser owned by the host opens its own connections. NavSentry cannot enforce ScopeGate before a request or at connect time there, so S1 and hard rule 4 fail. The owner asked how Computer Use could still be supported. Three options were weighed:
1. the agent drives a browser that NavSentry owns;
2. the host provides an interception API;
3. the host's browser runs in a VM behind a TLS-terminating proxy.

Option 2 needs a host capability that has not been verified. Option 3 needs a trusted CA and a VM that has to be maintained. Option 1 reuses the M1b engine, which already demonstrates S1.

## Decision
1. **NavSentry owns the browser.** `navsentry browse start` launches the M1b playwright engine and keeps it, with the run's ScopeGate, Budget and Redactor, in one long-lived session process. The host agent never opens a browser of its own. It looks at screenshots and sends coordinates.
2. **The network layer is unchanged.** Every request the page makes is fulfilled through direct-http (ScopeGate before the request and at connect time, Budget, redaction) or aborted, so S1 holds wherever the agent clicks.
3. **Actions are observe only:** `screenshot`, `click x y` and `scroll dx dy` in a fixed 1280×800 viewport. There is no typing or key press; that needs safe-validate (M2). Non-observe browser requests are refused, as in M1b.
4. **The local control channel** is a named pipe on Windows and a Unix socket elsewhere, never a TCP port. Every command must carry a 256-bit random token. The token is stored with mode 0600 in the run's work directory, and it is published only after the pipe is listening. Requests are capped at 4 KiB.
5. **An audit log with no unlogged path.** Commands run one at a time, and each is logged (sequence, time, action, coordinates, display URL, request IDs) before its result is returned. The log holds no page content.
6. **Lifecycle.** The session ends on `browse end`, after an idle timeout (default 300 s), at the run deadline (`safety.max_duration_seconds`), when the Budget is exhausted, or after 500 actions. It runs inside the managed workspace, so the work directory and every screenshot are deleted when it ends, and leftovers give exit 4. A killed session is swept by the next run.
7. **Consent and where data goes.** NavSentry calls no model provider. Screenshots leave NavSentry only when the host agent reads them, and they reach that agent's model provider. `transports.visual_computer_use: true` in the manifest records the owner's consent, and the order must also list `visual-computer-use` and `playwright-browser`. The visual driver is for the development profile only.
8. **Evidence.** `VISUAL-SESSION.md` and `session.json` contain the action log, requests, denials and passive checks on loaded documents. Findings follow the usual lifecycle rules. Screenshots are never kept.
9. **`scan --engine computer-use` still exits 3**, now pointing to `browse`. Batch scans do not drive a visual session.

## Evidence
`test/visual.test.ts`, on 127.0.0.1 fixtures only, shows:
- every missing precondition is refused before any browser starts or any request is sent;
- clicking the in-scope link navigates;
- clicking the off-scope link never reaches the canary origin and is recorded as a denial;
- the page's off-scope image and fetch, its WebSocket, its service worker and its POST are all blocked;
- every request the app saw is a recorded direct-http exchange;
- a forged token is refused;
- out-of-viewport coordinates are logged as errors;
- the Budget and the idle timeout end the session;
- the work directory and screenshots are deleted, and the workspace check passes;
- the CLI runs `start`, `status` and `end` end to end.

## Consequences
- Plus: Computer Use works without weakening S1. Prompt-injected text on a page can steer clicks, but it cannot steer the network.
- Plus: the host's model only ever sees screenshots, never raw responses.
- Minus: no typing until M2.
- Minus: screenshots of the target reach the host's model provider, so the owner must consent per manifest and the provider's terms apply to the host, not to NavSentry.
- Minus: pages that depend on WebSocket or service workers behave differently.
- Minus: one session process per run.
