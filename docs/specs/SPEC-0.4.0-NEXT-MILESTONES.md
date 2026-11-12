# SPEC 0.4.0 — What can be built now, and what moves to the next phase

- Status: **DRAFT** · Drafted: 2026-11-12 · Owner instruction 2026-11-12: build everything that is not blocked now; move every blocked item, and every item that must come before or after a blocked item, to the next phase.
- Covers DEV-PLAN milestones M1b+, M3, M4 and M5. Related: [DEV-PLAN](../DEV-PLAN.md) · [governance/third-party.json](../../governance/third-party.json) · AGENTS.md hard rules 2, 4, 5, 6.
- §3 is implemented under that instruction. Every other section is a plan, not an accepted design.

## 0. สรุปสำหรับเจ้าของงาน

| งาน | phase นี้ | phase หน้า | เหตุผล |
|---|---|---|---|
| M4 integrity manifest + `navsentry verify` | ✅ ทำแล้ว (§3) | | ไม่ต้องใช้ของภายนอก ไม่มี network ไม่ติดอะไร |
| M4 resumable runs | | ✅ | ต้องตัดสินว่า Budget และ approval ข้ามการ resume อย่างไร (กฎข้อ 4) และต่อยอดจาก manifest (§4) |
| M4 ASVS 5.0 IDs | | ✅ | ต้องตรวจทีละข้อจากเอกสาร OWASP ต้นฉบับ และต้องมีคนรีวิวแยก (§5) |
| M4 DevSift adapter | | ✅ | ต้องรู้ก่อนว่า DevSift ต้องมี entry ใน governance หรือไม่ (D3) |
| M1b+ DOM checks (CSP, cookie, framing) | | ✅ | ใช้ Chromium headless shell ซึ่งเป็น Chrome for Testing ที่รอเจ้าของยืนยัน terms ใหม่ (D1) |
| M1b+ YAML manifests | | ✅ | ต้องเพิ่ม dependency (กฎข้อ 2) |
| M3 CLI transports (curl, PowerShell) | | ✅ ทั้งชุด | curl และ PowerShell เป็น binary ภายนอก ต้องอนุมัติก่อน (D2); interface และ parity test มีไว้เพื่อ transport เหล่านี้เท่านั้น จึงย้ายไปด้วยกัน; การรันบน Linux ทำในเครื่องนี้ไม่ได้ |
| M5 Postman/Newman, ZAP | | ✅ | ต้องรีวิว terms ก่อน |
| M5 `active-approved` | | ✅ | ต้องมีการออกแบบและอนุมัติแยก (กฎข้อ 6) |

## 1. Rule used to split the work
An item moves to the next phase when it needs something not yet allowed: a dependency, binary or service without a dated APPROVED entry, an owner decision on safety, a primary-source review, or a platform this machine does not have. An item that only exists to serve a moved item moves with it, and so does an item that has to wait for one.

## 2. Blockers and the owner decisions they need
| ID | Decision | Unblocks |
|---|---|---|
| D1 | Re-confirm or reject the Chrome for Testing terms for the headless shell; decide the full build (review due 2026-12-11) | M1b+ DOM checks; headed driver |
| D2 | Approve, or reject, curl and PowerShell (7 and 5.1) as governed binaries | M3 |
| D3 | Is DevSift a third party for governance purposes? | M4 DevSift adapter |
| D4 | Resume semantics: does a resumed run share the original Budget, deadline and approval hashes, or start a new run that references the old one? | M4 resumable runs |
| D5 | A YAML parser dependency, or no YAML | M1b+ YAML manifests |
| D6 | Terms review for Newman and ZAP, and whether `active-approved` is designed at all | M5 |

## 3. Integrity manifest and `navsentry verify` (implemented)
- After `scan` or `test` writes its reports, it writes `MANIFEST.json` in the run folder: `kind: navsentry-run-manifest`, `schemaVersion: "1"`, `runId`, `toolVersion`, `algorithm: sha256`, and one entry (`path`, `bytes`, `sha256`) per file **this run wrote**. Files the owner already had in `--out` are not listed.
- `navsentry verify --run <dir|run.json> [--json]` lists files that were modified, are missing, or were added (symbolic links count as added and are never followed). It exits 0 on PASS and 1 on any change. Without a manifest it errors; it never passes.
- A manifest entry whose path is absolute, has a drive letter or backslash, or contains `..` or an empty segment is refused.
- **Limitation, stated in every result:** the manifest is not signed. It catches accidental or partial changes, not a deliberate edit that also rewrites the manifest. Signing would need key management, which is a separate decision.
- No network, no new dependency. Tests: `test/integrity.test.ts`.

## 4. Resumable runs (next phase)
Needs D4. A resume must never send more requests than the original Budget allowed, never outlive the authorization window, and never reuse an approval hash for flows that changed. A resumed run would check the earlier run folder with `verify` before it trusts anything in it.

## 5. ASVS 5.0 requirement IDs (next phase)
Each case's ASVS mapping must be checked against the OWASP ASVS 5.0 source text, recorded with the source and date, and reviewed by someone else before `catalog.ts` marks it verified. Unverified mappings stay unverified.

## 6. Out of scope for this phase
Everything in the table marked phase หน้า. Nothing in this spec makes an unavailable capability usable.
