# NavSentry compare — verdict: **IMPROVED_NO_DRIFT**

## Fixed (FAIL → PASS)
- NSC-CONF-002
- NSC-CONF-003
- NSC-CONF-004
- NSC-CONF-006
- NSC-INFO-001
- NSC-INFO-003
- NSC-INFO-004
- NSC-ERR-001
- NSC-PRIV-001
- NSC-SESS-002
- NSC-SESS-003
- NSC-SESS-004
- NSC-AC-002
- NSC-AC-003
- NSC-AC-007
- NSC-AC-004

## Regressed (PASS → FAIL)
- none

## Still failing / not proven fixed
- NSC-CONF-007
- NSC-CRYPT-006

## Legitimate-response contract drift
- none (status, content type, non-security headers and JSON shape unchanged)

## Requests missing in the after-run
- none

## User stories (flows)
### Functional regressions (PASS → FAIL/ERROR)
- none

### Fixed (FAIL → PASS)
- orders-access/S3
- orders-access/S5
- orders-access/S7
- profile-journey/S4

### Not comparable
- none
