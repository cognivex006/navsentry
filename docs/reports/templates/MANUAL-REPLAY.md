# MANUAL-REPLAY — <flow id> (<run label>)

Manual replay of flow steps that NavSentry could not execute (for example UI steps that need the browser transport). This record is **separate from `flows.json`**: it never changes a step to PASS there.

| Field | Value |
|---|---|
| Flow / steps | `<flowId>` S2–S3 |
| Target environment | <staging / local> (must be in the authorized manifest) |
| Performed by / date (UTC) | <name> / <timestamp> |
| Browser and version | <browser> |
| Authorization reference | <manifest authorization.reference> |

| Step | Instruction (from TEST-REPORT.md) | Observed | Result (OBSERVED_OK / OBSERVED_DIFFERENT / NOT_DONE) |
|---|---|---|---|
| S2 | | | |

## Limitations
- A screenshot or visual check does not prove response headers, cookie flags or network enforcement.
- No tokens, cookies, passwords or personal data in this file.
