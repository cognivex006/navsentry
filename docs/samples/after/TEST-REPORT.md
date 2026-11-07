# NavSentry Test Report — demo-after (local)

- Run ID: `1ffc3457-161c-46f9-ac69-20c7d1a591b3` · Tool: navsentry 0.2.0 · Node 26.13.0 · Mode: `observe`
- Flow set: 2 flows, 11 steps · `6f94a62dbe77497f`
- **Security result: FINDINGS** (11 findings) — Read the security report first: [REPORT.md](REPORT.md)
- **Functional result: INCOMPLETE**

## Summary

| Level | PASS | FAIL | INCOMPLETE | ERROR | NOT_TESTED |
|---|---|---|---|---|---|
| Integration (API/service) | 1 | 0 | 0 | 0 | 0 |
| E2E (user journey) | 0 | 0 | 1 | 0 | 0 |

> A flow PASS means the asserted behaviour matched in the tested scope; it does not prove the feature correct or secure. HTTP-level page checks see server-rendered HTML only.

## Flows

### orders-access — Orders access control

- Status: **PASS** · Level: **Integration (API/service)** · Executability: full · Review: draft
- Story: A reader opens their own order; another reader and an anonymous visitor cannot; only admins see stats.
- Level reasons: all steps are API requests
- File: `orders-access.flow.md`

| Step | Actor | Action | Request (template) | Status | Assertions | Security case |
|---|---|---|---|---|---|---|
| S1 S1 — Reader A lists orders | reader_a | http | `GET /api/orders` | PASS | 3/3 | — |
| S2 S2 — Reader A opens own order (positive control) | reader_a | http | `GET /api/orders/{{orderA}}` | PASS | 4/4 | — |
| S3 S3 — Reader B must not open Reader A's order | reader_b | http | `GET /api/orders/{{orderA}}` | PASS | 1/1 | NSC-AC-003 |
| S4 S4 — Reader A profile (positive control) | reader_a | http | `GET /api/me` | PASS | 2/2 | — |
| S5 S5 — Anonymous must not read a profile | anonymous | http | `GET /api/me` | PASS | 1/1 | NSC-AC-002 |
| S6 S6 — Admin sees stats (positive control) | admin | http | `GET /api/admin/stats` | PASS | 2/2 | — |
| S7 S7 — Reader must not see admin stats | reader_a | http | `GET /api/admin/stats` | PASS | 1/1 | NSC-AC-007 |

**Security findings raised during this flow:**
- `3585c95db6c6d12721e0affe` (REPORT.md)
- `74c1939329689193ff67afab` (REPORT.md)
- `fc8f24db6bc1fbad7593d749` (REPORT.md)
- `91750bce609f47a4105f2edb` (REPORT.md)

### profile-journey — Reader profile journey

- Status: **INCOMPLETE** · Level: **E2E (HTTP-level only)** · Executability: partial · Review: draft
- Story: A signed-in reader opens the profile page and navigates to order history; visitors are sent to login.
- Level reasons: S2 click needs a browser; S3 see needs a browser
- File: `profile-journey.flow.md`

| Step | Actor | Action | Request (template) | Status | Assertions | Security case |
|---|---|---|---|---|---|---|
| S1 S1 — Profile page loads | reader_a | navigate | `GET /app/profile` | PASS | 4/4 | — |
| S2 S2 — Open order history | reader_a | click | — | NOT_TESTED | — | — |
| S3 S3 — History is visible | reader_a | see | — | NOT_TESTED | — | — |
| S4 S4 — Visitor is sent to login | anonymous | navigate | `GET /app/profile` | PASS | 1/1 | NSC-AC-002 |

**Steps not executed:**
- S2 NOT_TESTED: click requires the playwright-browser transport (M1b), which is not usable in this release
- S3 NOT_TESTED: see requires the playwright-browser transport (M1b), which is not usable in this release

**Security findings raised during this flow:**
- `ef51e0debbf6974b84b21ba4` (REPORT.md)

**Manual replay checklist:**
> These steps need a transport that is not usable in this release. Record a manual replay separately in MANUAL-REPLAY.md (docs/reports/templates); it never changes flows.json.
1. S2 — as reader_a: click link “Orders”
2. S3 — as reader_a: check that you can see text “Order history”

## Limitations

- A flow PASS means the asserted behaviour matched in the tested scope; it does not prove the feature correct or secure. HTTP-level page checks see server-rendered HTML only.
