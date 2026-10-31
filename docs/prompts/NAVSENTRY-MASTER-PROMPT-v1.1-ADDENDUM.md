# NavSentry Master Prompt — v1.1 Addendum (overrides v1.0 where they conflict)

Use this addendum **together with** Master Prompt v1.0. Each item names the PRM issue it resolves ([01-ISSUE-REGISTER](../reports/01-ISSUE-REGISTER.md)).

```text
NAVSENTRY v1.1 OVERRIDES — read before acting

1. NO HOSTED AUTOMATION (PRM-GOV-001/002)
   Do not create .github/workflows, Dependabot, Renovate, GitHub Apps, scheduled cloud jobs or
   bulk GitHub API automation. Every "CI", "PR check", "scheduled scan" or "pinned workflow action"
   requirement in v1.0 is satisfied by the local gate `npm run gate` and manual, reviewed updates.

2. SAAS / THIRD-PARTY TERMS FIRST (PRM-GOV-003)
   Before using any SaaS, API, browser binary or tool: read its current license, ToS, AUP, API
   terms and data-sharing rules; record URL, date, findings and decision in
   governance/third-party.json. Default decision is NOT_ADOPTED. Never send target data to a
   SaaS without the target owner's approval.

3. PUBLIC REPOSITORY HYGIENE (PRM-DATA-001)
   Never commit customer names, hostnames, IP addresses, source paths, report excerpts, tokens or
   PII. Refer to assessment inputs as SRC-<letter>. Keep owner-specific forbidden terms in the
   untracked .navsentry/forbidden-terms.txt; GATE-08 must PASS.

4. CLI TRANSPORT SAFETY (PRM-SAFE-001)
   curl: "-q" first, --max-redirs 0, --proto =http,https, --noproxy '*', argv only, fixed path.
   PowerShell: fixed script, values as parameters, -NoProfile, -UseBasicParsing,
   -MaximumRedirection 0; handle Windows PowerShell 5.1 (no -SkipHttpErrorCheck) explicitly.

5. CONNECT-TIME SCOPE (PRM-SAFE-002, PRM-ARCH-002)
   Validate every resolved address at socket connect (DNS rebinding). Browser transports must
   block service workers, route every request through the same gate, and declare channels they
   cannot constrain (WebSocket frames, browser-internal traffic).

6. ACTIVE CLASSES ARE MANUAL (PRM-SAFE-003)
   SQLi, script/template injection, LDAPi, LFI, request smuggling and DoS are catalogued as
   manual-active and reported NOT_TESTED with a reason. No payloads in code.

7. STANDARDS (PRM-MAP-001)
   Map every case to OWASP Top 10:2021 AND Top 10:2025, CWE and WSTG. Map ASVS 5.0.0 at chapter
   level until requirement IDs are verified against the official text. Never invent IDs.

8. PROTECT LEGITIMATE CALLERS (PRM-RPT-001)
   Every fix must keep status codes, content types, non-security headers and JSON key/type shape
   for valid requests. Prove it with `navsentry compare` (IMPROVED_NO_DRIFT) or obtain explicit
   owner approval for each drift row.

9. CASE IDS AND REPORTS (PRM-RPT-002/003)
   Use permanent IDs NSC-<CAT>-<NNN> from src/catalog.ts; log occurrences in
   docs/ISSUE-CVE-MATRIX.md. Deliver: (1) issue register, (2) fix report with evidence,
   (3) QA report with PASS/FAIL and mandatory improvement criteria for every non-PASS,
   (4) a short human summary. Every issue/fix/QA item has a checklist an agent can re-run and
   copy-ready VERIFY / FIX / RECHECK prompts with FACT / EVIDENCE / ACCEPTANCE CRITERIA and a
   real-browser recheck.

10. SOURCE FINDINGS (PRM-SRC-001/002/003)
   Separate DAST, SAST and infrastructure findings; count root causes, not lines; treat scanner
   output as SUSPECTED until confirmed; do not implement deprecated controls (e.g. HPKP) to
   satisfy a scanner.

11. DELIVERY (PRM-ARCH-001, PRM-PROC-001)
   Ship working vertical slices per milestone (docs/DEV-PLAN.md); unavailable capabilities are
   reported honestly. After the owner-authorized bootstrap commit, use scoped branches and
   reviewed merges.
```
