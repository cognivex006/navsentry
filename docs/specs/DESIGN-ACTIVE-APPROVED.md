# Design: `active-approved` mode (design only, not implemented)

- Status: **DRAFT design** · Written 2026-11-13 under owner decision D6 ([SPEC-0.4.0](SPEC-0.4.0-NEXT-MILESTONES.md#21-owner-decisions-2026-11-13)): "write the `active-approved` design document (design only, no active payloads)".
- AGENTS.md hard rule 6 still applies in full: observe and safe-validate send **no** active payloads. Nothing here changes code. Building this mode needs a separate owner authorization, this design ACCEPTED, and a threat-model update.

## 0. สรุปสำหรับเจ้าของงาน
`active-approved` คือโหมดที่จะยอมให้ส่ง payload ทดสอบ (เช่น ตรวจว่า input ถูก encode ก่อนแสดงผลหรือไม่) แต่**เฉพาะ**เมื่อเจ้าของระบบเป้าหมายอนุมัติเป็นลายลักษณ์อักษรต่อ run, ต่อ origin, ต่อกลุ่ม payload และภายในช่วงเวลาที่กำหนด เอกสารนี้เป็นแค่แบบ ยังไม่มีโค้ด สิ่งที่ห้ามตลอดไปแม้ในโหมดนี้: DoS, request smuggling/desync, brute force, การลบหรือแก้ข้อมูลจริง และ payload ที่ไม่อยู่ในแคตตาล็อกที่รีวิวแล้ว

## 1. Goals and non-goals
- Goal: turn cases that are NOT_TESTED today because they need a payload (NSC-INJ-001…006 output and input handling, NSC-AC-005 SSRF) into tested results, without leaving the safety model.
- Never, in any mode: denial of service or load, request smuggling or desync (NSC-CONF-008 stays passive), brute force or credential stuffing, destructive writes, payloads that try to execute code on the server, or payloads that reach a third party.

## 2. Authorization (separate from the manifest's `authorization`)
- A per-run approval file, `navsentry/active-approvals/<id>.json`, written by the owner with an interactive command (TTY only, like `flow approve`). It records: target origins, allowed payload classes, maximum payload requests, the time window (at most 24 h), a named approver, a reference (ticket or contract), and the SHA-256 of the manifest and payload catalog it approves.
- The run refuses unless the approval matches the manifest hash, the catalog hash and the current time. A flag never creates or widens an approval. Production also needs `authorization.reference`, as today.

## 3. Payload catalog
- A reviewed, versioned catalog in the repository (`src/active/catalog.ts`). Every payload has an ID, class, case, expected safe and unsafe responses, and a reason it is non-destructive. The tests carry vulnerable and secure fixtures for each payload.
- Initial classes are proposals for the owner, not decisions:
  - `reflect-marker`: inert markers that show output encoding. This is NSC-INJ-004 today, as observations only.
  - `syntax-probe`: a single quote or bracket to see whether a parser error leaks (NSC-ERR-001, NSC-INJ-001/002/003). There is no union, no time delay and no stacked query.
  - `path-probe`: `../` against a declared file parameter, reading only a canary file the fixture owns (NSC-INJ-006).
  - `ssrf-canary`: a URL pointing at a NavSentry-owned `.invalid` canary that is never resolvable. The result comes from the target's error behavior, never from a real outbound call (NSC-AC-005).
- Adding a payload follows the knowledge-base promotion rule: primary source, fixture tests and independent review.

## 4. Enforcement (rule 4: safety is code)
- Payloads are sent only through ScopeGate and the Budget, plus a third gate, `ActiveGate`. It checks the approval, the payload class, a separate payload counter and the declared parameter.
- Payloads go only into parameters the owner declared in the manifest (`active.parameters`), never into discovered ones.
- There is one payload request at a time, with a minimum interval. The run stops on the first 5xx burst, a timeout spike, or a response that looks like data changed.
- Every payload request is logged with its payload ID and the SHA-256 of the full request. Payload text is never copied into reports beyond its catalog ID.

## 5. Results
- A finding from a payload needs the catalog's unsafe response for VALIDATED. Anything weaker is SUSPECTED. A missing response is INCONCLUSIVE, never PASS.
- Reports name the approval ID and window.

## 6. Owner decisions needed before implementation
| ID | Decision |
|---|---|
| A1 | Build `active-approved` at all, and in which milestone |
| A2 | Which payload classes from §3 to allow first |
| A3 | Whether production may ever use it, or development and staging only |
| A4 | The default per-run payload limit and minimum interval |
| A5 | Who may act as approver (the manifest owner only, or a named second person) |
