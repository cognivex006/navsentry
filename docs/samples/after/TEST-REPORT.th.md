# รายงานการทดสอบ NavSentry — demo-after (local)

- Run ID: `841daba1-525d-487c-9413-a747e421e45b` · Tool: navsentry 0.1.2 · Node 26.13.0 · Mode: `observe`
- Flow set: 2 flows, 11 steps · `6f94a62dbe77497f`
- **ผลด้านความปลอดภัย: FINDINGS** (11 findings) — อ่านรายงานความปลอดภัยก่อน: [REPORT.md](REPORT.md)
- **ผลการทดสอบการทำงาน: INCOMPLETE**

## สรุป

| ระดับ | PASS | FAIL | INCOMPLETE | ERROR | NOT_TESTED |
|---|---|---|---|---|---|
| Integration (ระดับ API/บริการ) | 1 | 0 | 0 | 0 | 0 |
| E2E (เส้นทางผู้ใช้ตั้งแต่ต้นจนจบ) | 0 | 0 | 1 | 0 | 0 |

> ผล PASS ของโฟลว์หมายถึงพฤติกรรมที่ระบุตรงตามที่คาดในขอบเขตที่ทดสอบเท่านั้น ไม่ได้รับรองว่าฟีเจอร์ถูกต้องทั้งหมดหรือปลอดภัย การตรวจหน้าเว็บระดับ HTTP เห็นเฉพาะ HTML ที่ server ส่งมา

## โฟลว์

### orders-access — Orders access control

- สถานะ: **PASS** · ระดับ: **Integration (ระดับ API/บริการ)** · ความสามารถในการรัน: full · สถานะการอนุมัติ: draft
- เรื่องราวผู้ใช้: A reader opens their own order; another reader and an anonymous visitor cannot; only admins see stats.
- เหตุผลของการจัดระดับ: all steps are API requests
- File: `orders-access.flow.md`

| ขั้นตอน | Actor | Action | Request (template) | สถานะ | ผลการตรวจ | เคสความปลอดภัย |
|---|---|---|---|---|---|---|
| S1 S1 — Reader A lists orders | reader_a | http | `GET /api/orders` | PASS | 3/3 | — |
| S2 S2 — Reader A opens own order (positive control) | reader_a | http | `GET /api/orders/{{orderA}}` | PASS | 4/4 | — |
| S3 S3 — Reader B must not open Reader A's order | reader_b | http | `GET /api/orders/{{orderA}}` | PASS | 1/1 | NSC-AC-003 |
| S4 S4 — Reader A profile (positive control) | reader_a | http | `GET /api/me` | PASS | 2/2 | — |
| S5 S5 — Anonymous must not read a profile | anonymous | http | `GET /api/me` | PASS | 1/1 | NSC-AC-002 |
| S6 S6 — Admin sees stats (positive control) | admin | http | `GET /api/admin/stats` | PASS | 2/2 | — |
| S7 S7 — Reader must not see admin stats | reader_a | http | `GET /api/admin/stats` | PASS | 1/1 | NSC-AC-007 |

**ช่องโหว่ที่พบระหว่างโฟลว์นี้:**
- `3585c95db6c6d12721e0affe` (REPORT.md)
- `74c1939329689193ff67afab` (REPORT.md)
- `fc8f24db6bc1fbad7593d749` (REPORT.md)
- `91750bce609f47a4105f2edb` (REPORT.md)

### profile-journey — Reader profile journey

- สถานะ: **INCOMPLETE** · ระดับ: **E2E (ทดสอบได้เฉพาะระดับ HTTP)** · ความสามารถในการรัน: partial · สถานะการอนุมัติ: draft
- เรื่องราวผู้ใช้: A signed-in reader opens the profile page and navigates to order history; visitors are sent to login.
- เหตุผลของการจัดระดับ: S2 click needs a browser; S3 see needs a browser
- File: `profile-journey.flow.md`

| ขั้นตอน | Actor | Action | Request (template) | สถานะ | ผลการตรวจ | เคสความปลอดภัย |
|---|---|---|---|---|---|---|
| S1 S1 — Profile page loads | reader_a | navigate | `GET /app/profile` | PASS | 4/4 | — |
| S2 S2 — Open order history | reader_a | click | — | NOT_TESTED | — | — |
| S3 S3 — History is visible | reader_a | see | — | NOT_TESTED | — | — |
| S4 S4 — Visitor is sent to login | anonymous | navigate | `GET /app/profile` | PASS | 1/1 | NSC-AC-002 |

**ขั้นตอนที่ไม่ได้รัน:**
- S2 NOT_TESTED: click requires the playwright-browser transport (M1b), which is not usable in this release
- S3 NOT_TESTED: see requires the playwright-browser transport (M1b), which is not usable in this release

**ช่องโหว่ที่พบระหว่างโฟลว์นี้:**
- `ef51e0debbf6974b84b21ba4` (REPORT.md)

**รายการทดสอบซ้ำด้วยมือ:**
> ขั้นตอนเหล่านี้ต้องใช้ transport ที่รุ่นนี้ยังไม่รองรับ ให้บันทึกผลการทดสอบด้วยมือแยกไว้ใน MANUAL-REPLAY.md (docs/reports/templates) ผลนี้ไม่เปลี่ยน flows.json
1. S2 — as reader_a: click link “Orders”
2. S3 — as reader_a: check that you can see text “Order history”

## ข้อจำกัด

- ผล PASS ของโฟลว์หมายถึงพฤติกรรมที่ระบุตรงตามที่คาดในขอบเขตที่ทดสอบเท่านั้น ไม่ได้รับรองว่าฟีเจอร์ถูกต้องทั้งหมดหรือปลอดภัย การตรวจหน้าเว็บระดับ HTTP เห็นเฉพาะ HTML ที่ server ส่งมา
