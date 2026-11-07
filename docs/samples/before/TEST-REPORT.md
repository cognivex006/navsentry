# NavSentry Test Report — demo-before (local)

- Run ID: `0858cfcf-c21b-49f2-9ae1-4207ddb50e1d` · Tool: navsentry 0.2.0 · Node 26.13.0 · Mode: `observe`
- Flow set: 2 flows, 11 steps · `6f94a62dbe77497f`
- **Security result: FINDINGS** (58 findings) — Read the security report first: [REPORT.md](REPORT.md)
- **Functional result: FAIL**

## Summary

| Level | PASS | FAIL | INCOMPLETE | ERROR | NOT_TESTED |
|---|---|---|---|---|---|
| Integration (API/service) | 0 | 1 | 0 | 0 | 0 |
| E2E (user journey) | 0 | 1 | 0 | 0 | 0 |

> A flow PASS means the asserted behaviour matched in the tested scope; it does not prove the feature correct or secure. HTTP-level page checks see server-rendered HTML only.

## Flows

### orders-access — Orders access control

- Status: **FAIL** · Level: **Integration (API/service)** · Executability: full · Review: draft
- Story: A reader opens their own order; another reader and an anonymous visitor cannot; only admins see stats.
- Level reasons: all steps are API requests
- File: `orders-access.flow.md`

| Step | Actor | Action | Request (template) | Status | Assertions | Security case |
|---|---|---|---|---|---|---|
| S1 S1 — Reader A lists orders | reader_a | http | `GET /api/orders` | PASS | 3/3 | — |
| S2 S2 — Reader A opens own order (positive control) | reader_a | http | `GET /api/orders/{{orderA}}` | PASS | 4/4 | — |
| S3 S3 — Reader B must not open Reader A's order | reader_b | http | `GET /api/orders/{{orderA}}` | FAIL | 0/1 | NSC-AC-003 |
| S4 S4 — Reader A profile (positive control) | reader_a | http | `GET /api/me` | PASS | 2/2 | — |
| S5 S5 — Anonymous must not read a profile | anonymous | http | `GET /api/me` | FAIL | 0/1 | NSC-AC-002 |
| S6 S6 — Admin sees stats (positive control) | admin | http | `GET /api/admin/stats` | PASS | 2/2 | — |
| S7 S7 — Reader must not see admin stats | reader_a | http | `GET /api/admin/stats` | FAIL | 0/1 | NSC-AC-007 |

**Failed or inconclusive assertions:**
- S3 access: expected denied · observed status 200, same contract as positive control S2 → **FAIL**
- S5 access: expected denied · observed status 200, same contract as positive control S4 → **FAIL**
- S7 access: expected denied · observed status 200, same contract as positive control S6 → **FAIL**

**Security findings raised during this flow:**
- `2ed31545305ed6fa20e0a163` (REPORT.md)
- `3eef519c1454dd179dcdf801` (REPORT.md)
- `4394e9188345a42229ec9d40` (REPORT.md)
- `fee4e2b13b1a34242abf2210` (REPORT.md)
- `2f0c13798b3f6290b328e559` (REPORT.md)
- `7c6bc49d2e83bb56b8b62a1f` (REPORT.md)
- `410d1fcc3d4bf29a8b41f77d` (REPORT.md)
- `8abac78f653ee5b014e2f490` (REPORT.md)
- `887c9e474229a3f22403e9f7` (REPORT.md)
- `6b1e8104436e4050b9e69aea` (REPORT.md)
- `b8fb462c3914484b16461887` (REPORT.md)
- `b6438cdb4cfb8485c2c39cb4` (REPORT.md)
- `10818924dc8a1a6ca8a01ce1` (REPORT.md)
- `557b65c1e49e747d5e8b1ff7` (REPORT.md)
- `f3e727a639f1686ee83fcfde` (REPORT.md)

### profile-journey — Reader profile journey

- Status: **FAIL** · Level: **E2E (HTTP-level only)** · Executability: partial · Review: draft
- Story: A signed-in reader opens the profile page and navigates to order history; visitors are sent to login.
- Level reasons: S2 click needs a browser; S3 see needs a browser
- File: `profile-journey.flow.md`

| Step | Actor | Action | Request (template) | Status | Assertions | Security case |
|---|---|---|---|---|---|---|
| S1 S1 — Profile page loads | reader_a | navigate | `GET /app/profile` | PASS | 4/4 | — |
| S2 S2 — Open order history | reader_a | click | — | NOT_TESTED | — | — |
| S3 S3 — History is visible | reader_a | see | — | NOT_TESTED | — | — |
| S4 S4 — Visitor is sent to login | anonymous | navigate | `GET /app/profile` | FAIL | 0/1 | NSC-AC-002 |

**Failed or inconclusive assertions:**
- S4 access: expected denied · observed status 200, same contract as positive control S1 → **FAIL**

**Steps not executed:**
- S2 NOT_TESTED: click requires the playwright-browser transport (M1b), which is not usable in this release
- S3 NOT_TESTED: see requires the playwright-browser transport (M1b), which is not usable in this release

**Security findings raised during this flow:**
- `fee0a4fff083aa2abb24c113` (REPORT.md)
- `86733b9437764e1560fc2e38` (REPORT.md)
- `0e1ff75fa30e8a236884445c` (REPORT.md)
- `537cf1850c28c8f706b2ddec` (REPORT.md)
- `61ef9ac144885a9aee7c1d64` (REPORT.md)
- `82c6f694fc9f9f46f387b272` (REPORT.md)
- `4bab2545a1262edeea8cda03` (REPORT.md)

**Manual replay checklist:**
> These steps need a transport that is not usable in this release. Record a manual replay separately in MANUAL-REPLAY.md (docs/reports/templates); it never changes flows.json.
1. S2 — as reader_a: click link “Orders”
2. S3 — as reader_a: check that you can see text “Order history”

## Limitations

- A flow PASS means the asserted behaviour matched in the tested scope; it does not prove the feature correct or secure. HTTP-level page checks see server-rendered HTML only.
