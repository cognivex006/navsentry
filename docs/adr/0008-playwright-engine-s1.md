# ADR-0008: Playwright engine and S1 enforcement

- Status: Accepted (owner approval of Playwright 2026-11-03) · Date: 2026-11-03

## Context
SPEC-0.1.3 §6.3 and invariant S1 allow a browser engine only if every enabled channel gets ScopeGate checks before the request and at connect time, plus the shared Budget. `context.route()` sees HTTP(S) requests, but it gives no connect-time check, it does not see WebSocket frames after the upgrade, and it does not see the browser's own background traffic (ADR-0004). A forward proxy is not evidence either: a CONNECT tunnel authorizes a host, not each path, method or frame inside it.

## Decision
1. **The browser never connects on its own.** Every request the page makes is intercepted by `context.route('**')` and either fulfilled from NavSentry's `direct-http` transport or aborted. `route.continue()` is never called. `direct-http` already applies ScopeGate before the request, the connect-time DNS check and the Budget, so the browser inherits all three, along with redaction, capture limits and request records.
2. **Observe methods only.** A browser request other than GET, HEAD or OPTIONS is refused before it is sent and recorded as a denial, because NavSentry cannot vet its body. `fill`, `select` and `submit` steps stay NOT_TESTED until safe-validate (M2).
3. **Disabled, not enforced.** WebSocket is closed with `routeWebSocket` before it connects. Service workers are blocked per context. A partial or undecoded body is never rendered: the request is aborted.
4. **Defence in depth.** Chromium is launched against a dead proxy (including loopback) with host resolution mapped to NOTFOUND and background networking switched off. A request that escaped routing would fail instead of reaching the network. A test launches with these flags and no routing at all, and shows that the off-scope canary gets no hit.
5. **Approved build only.** This uses playwright-core 1.64.1 (no install scripts, zero dependencies) as a dev and optional peer dependency, with the Chromium headless shell, which `headless: true` selects. Branded channels, Firefox and WebKit are not approved. NavSentry never downloads a browser; the user runs `npx playwright-core install --only-shell chromium`.
6. **Development profile only, `flow` mode only.** This keeps D7 and §6.3 as written. One isolated browser context per actor, so cookies never cross actors.

## Evidence
`test/browser.test.ts`, on 127.0.0.1 fixtures only, shows:
- off-scope subresources and fetches never reach a canary origin and are recorded as denials;
- the app sees no WebSocket upgrade, no service worker fetch and no POST;
- every request the app saw is a recorded `direct-http` exchange, counted against the Budget;
- a Budget of 2 bounds the browser to at most 2 requests;
- an unavailable engine leaves UI steps NOT_TESTED with no http fallback.

## Consequences
+ UI journeys (`navigate`, `click`, `see`, `wait_for`) run under the same safety controls as API steps. + Console capture becomes possible (0.1.3-k). − Every subresource is a budgeted request, so pages with many assets need a larger `max_requests`. − Pages that depend on WebSocket or service workers behave differently than in a normal browser; affected checks must say so. − Chromium launch flags are an implementation detail of Chromium and are re-verified by the defence-in-depth test on every upgrade.
