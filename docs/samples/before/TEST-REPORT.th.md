# รายงานการทดสอบ NavSentry — demo-before (local)

- Run ID: `07cab76a-5f94-418d-b373-720b3ca0c67f` · Tool: navsentry 0.1.2 · Node 26.13.0 · Mode: `observe`
- Flow set: 2 flows, 11 steps · `6f94a62dbe77497f`
- **ผลด้านความปลอดภัย: FINDINGS** (58 findings) — อ่านรายงานความปลอดภัยก่อน: [REPORT.md](REPORT.md)
- **ผลการทดสอบการทำงาน: FAIL**

## สรุป

| ระดับ | PASS | FAIL | INCOMPLETE | ERROR | NOT_TESTED |
|---|---|---|---|---|---|
| Integration (ระดับ API/บริการ) | 0 | 1 | 0 | 0 | 0 |
| E2E (เส้นทางผู้ใช้ตั้งแต่ต้นจนจบ) | 0 | 1 | 0 | 0 | 0 |

> ผล PASS ของโฟลว์หมายถึงพฤติกรรมที่ระบุตรงตามที่คาดในขอบเขตที่ทดสอบเท่านั้น ไม่ได้รับรองว่าฟีเจอร์ถูกต้องทั้งหมดหรือปลอดภัย การตรวจหน้าเว็บระดับ HTTP เห็นเฉพาะ HTML ที่ server ส่งมา

## โฟลว์

### orders-access — Orders access control

- สถานะ: **FAIL** · ระดับ: **Integration (ระดับ API/บริการ)** · ความสามารถในการรัน: full · สถานะการอนุมัติ: draft
- เรื่องราวผู้ใช้: A reader opens their own order; another reader and an anonymous visitor cannot; only admins see stats.
- เหตุผลของการจัดระดับ: all steps are API requests
- File: `orders-access.flow.md`

| ขั้นตอน | Actor | Action | Request (template) | สถานะ | ผลการตรวจ | เคสความปลอดภัย |
|---|---|---|---|---|---|---|
| S1 S1 — Reader A lists orders | reader_a | http | `GET /api/orders` | PASS | 3/3 | — |
| S2 S2 — Reader A opens own order (positive control) | reader_a | http | `GET /api/orders/{{orderA}}` | PASS | 4/4 | — |
| S3 S3 — Reader B must not open Reader A's order | reader_b | http | `GET /api/orders/{{orderA}}` | FAIL | 0/1 | NSC-AC-003 |
| S4 S4 — Reader A profile (positive control) | reader_a | http | `GET /api/me` | PASS | 2/2 | — |
| S5 S5 — Anonymous must not read a profile | anonymous | http | `GET /api/me` | FAIL | 0/1 | NSC-AC-002 |
| S6 S6 — Admin sees stats (positive control) | admin | http | `GET /api/admin/stats` | PASS | 2/2 | — |
| S7 S7 — Reader must not see admin stats | reader_a | http | `GET /api/admin/stats` | FAIL | 0/1 | NSC-AC-007 |

**ผลตรวจที่ไม่ผ่านหรือสรุปไม่ได้:**
- S3 access: expected denied · observed status 200, same contract as positive control S2 → **FAIL**
- S5 access: expected denied · observed status 200, same contract as positive control S4 → **FAIL**
- S7 access: expected denied · observed status 200, same contract as positive control S6 → **FAIL**

**ช่องโหว่ที่พบระหว่างโฟลว์นี้:**
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

- สถานะ: **FAIL** · ระดับ: **E2E (ทดสอบได้เฉพาะระดับ HTTP)** · ความสามารถในการรัน: partial · สถานะการอนุมัติ: draft
- เรื่องราวผู้ใช้: A signed-in reader opens the profile page and navigates to order history; visitors are sent to login.
- เหตุผลของการจัดระดับ: S2 click needs a browser; S3 see needs a browser
- File: `profile-journey.flow.md`

| ขั้นตอน | Actor | Action | Request (template) | สถานะ | ผลการตรวจ | เคสความปลอดภัย |
|---|---|---|---|---|---|---|
| S1 S1 — Profile page loads | reader_a | navigate | `GET /app/profile` | PASS | 4/4 | — |
| S2 S2 — Open order history | reader_a | click | — | NOT_TESTED | — | — |
| S3 S3 — History is visible | reader_a | see | — | NOT_TESTED | — | — |
| S4 S4 — Visitor is sent to login | anonymous | navigate | `GET /app/profile` | FAIL | 0/1 | NSC-AC-002 |

**ผลตรวจที่ไม่ผ่านหรือสรุปไม่ได้:**
- S4 access: expected denied · observed status 200, same contract as positive control S1 → **FAIL**

**ขั้นตอนที่ไม่ได้รัน:**
- S2 NOT_TESTED: click requires the playwright-browser transport (M1b), which is not usable in this release
- S3 NOT_TESTED: see requires the playwright-browser transport (M1b), which is not usable in this release

**ช่องโหว่ที่พบระหว่างโฟลว์นี้:**
- `fee0a4fff083aa2abb24c113` (REPORT.md)
- `86733b9437764e1560fc2e38` (REPORT.md)
- `0e1ff75fa30e8a236884445c` (REPORT.md)
- `537cf1850c28c8f706b2ddec` (REPORT.md)
- `61ef9ac144885a9aee7c1d64` (REPORT.md)
- `82c6f694fc9f9f46f387b272` (REPORT.md)
- `4bab2545a1262edeea8cda03` (REPORT.md)

**รายการทดสอบซ้ำด้วยมือ:**
> ขั้นตอนเหล่านี้ต้องใช้ transport ที่รุ่นนี้ยังไม่รองรับ ให้บันทึกผลการทดสอบด้วยมือแยกไว้ใน MANUAL-REPLAY.md (docs/reports/templates) ผลนี้ไม่เปลี่ยน flows.json
1. S2 — as reader_a: click link “Orders”
2. S3 — as reader_a: check that you can see text “Order history”

## ข้อจำกัด

- ผล PASS ของโฟลว์หมายถึงพฤติกรรมที่ระบุตรงตามที่คาดในขอบเขตที่ทดสอบเท่านั้น ไม่ได้รับรองว่าฟีเจอร์ถูกต้องทั้งหมดหรือปลอดภัย การตรวจหน้าเว็บระดับ HTTP เห็นเฉพาะ HTML ที่ server ส่งมา
