# FIX-<CASE_ID>-<SEQ>

| Field | Value |
|---|---|
| Closes | ISSUE-<CASE_ID>-<SEQ> |
| Repository · branch · commit | |
| Changed files | |
| Deployed to | staging environment name, date |
| Before run | runs/before/run.json |
| After run | runs/after/run.json |
| Compare verdict | IMPROVED_NO_DRIFT / IMPROVED_WITH_DRIFT / ... |

**Change summary:** configuration/code change in 2–4 lines.

**Legitimate-caller protection:** what was kept identical (status codes, JSON keys, headers) and how it was proven.

**Contract drift (if any):** each row from `navsentry compare` + owner approval reference.

**Acceptance criteria** (copy from the case, tick with evidence)
- [ ] ...
- [ ] compare: case in "Fixed", no unexplained drift
- [ ] automated test added/updated in the application repository
