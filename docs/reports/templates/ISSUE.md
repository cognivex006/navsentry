# ISSUE-<CASE_ID>-<SEQ>

| Field | Value |
|---|---|
| Case ID | NSC-XXX-000 (see docs/cases/CASE-CATALOG.md) |
| Project code | (code name only — no customer name/host/IP in shared copies) |
| Target | METHOD URL (query redacted) |
| Fingerprint | from run.json |
| Status | PASS / FAIL / INCONCLUSIVE / NOT_TESTED / ERROR |
| Lifecycle | SUSPECTED / VALIDATED / NEEDS_REVIEW / DISMISSED |
| Severity · Confidence | |
| Priority | IMMEDIATE (แก้ทันที) / PLANNED (รอได้) / CAUTION (แก้แล้วกระทบ ต้องระวัง) |
| Run | runs/<id>/run.json |

**FACT:** what was observed, one or two sentences, no secrets.

**EVIDENCE:**
- coverage row: `...`
- observations (redacted): `...`
- manual/browser check: `...`

**Reason for status:** (mandatory for anything other than PASS/FAIL)

**Checklist**
- [ ] Target is in the authorized manifest scope
- [ ] run.json attached; coverage row quoted
- [ ] Evidence redacted
- [ ] Occurrence row appended to docs/ISSUE-CVE-MATRIX.md §8 (private copy if project-specific)
