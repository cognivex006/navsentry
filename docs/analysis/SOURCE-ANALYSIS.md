# Source analysis — separating vulnerabilities from the assessment documents

Six documents were provided. They are **anonymized** here (public repository). Raw files stay with the owner.

| Source | Type | Tool family | What it can prove | What it cannot |
|---|---|---|---|---|
| SRC-A | DAST (black-box web scan), 2022, 19 alerts | commercial web scanner | TLS/protocol, headers, cookies, error pages as observed over HTTP | code-level cause; whether a finding is exploitable in context |
| SRC-B/C/D | SAST developer workbooks, 2023, 515 / 513 / 51 issues | commercial SAST (Go) | code patterns (source → sink) | runtime reachability; framework mitigations (e.g. Go rejects CR/LF in outgoing header values) |
| SRC-E | VA + web application assessment with remediation status, 2024 (Thai) | network VA + web scanner + manual review | host/network hardening; web findings with Fixed / Exception / Waiting status and retest | — |
| SRC-F | OWASP Top 10:2021 explanation (Thai) | reference | taxonomy | (no findings) |

## Separation into categories

| Category | From sources | Runtime-testable by NavSentry? |
|---|---|---|
| Transport & crypto (CRYPT) | SSLv3/POODLE, TLS 1.0/1.1, Sweet32, Logjam, weak/static ciphers, key reuse, key size, HPKP, hardcoded key | Protocol/cert: yes (probe). Cipher enumeration: assisted. Hardcoded key: SAST only |
| Misconfiguration & headers (CONF) | HSTS, CSP, clickjacking, content-type, debug mode, methods/override, cache policy, request smuggling | Headers/methods/cache: yes. Debug: assisted. Smuggling: manual-active |
| Information disclosure (INFO/ERR) | version disclosure, error messages, unhandled exception, server error message, internal IP, email | yes (pattern + deterministic) |
| Privacy (PRIV) | national-ID disclosure, sensitive data in GET | yes, SUSPECTED until confirmed |
| Session (SESS) | cookie Secure/HttpOnly/SameSite, JWT claims | yes |
| Access control / auth (AC/AUTH) | authorization bypass via test login, missing authentication, hardcoded API credentials | M2 scenarios; credentials SAST only |
| Injection (INJ) | SQLi, server-side script injection, LDAPi, reflected XSS, LFI, header manipulation | No in observe (manual-active / M2 benign marker / SAST) |
| Components (SUPPLY) | unpatched web-server connector / HTTP stack | assisted (inventory evidence required) |
| Infrastructure (INFRA) | ICMP timestamp/redirect, umask/home perms, SSH MAC, FTP plaintext, DB ports, OS package CVEs, package repository | out of web scope |

Full per-case detail: [CASE-CATALOG](../cases/CASE-CATALOG.md); counts and CVEs: [ISSUE-CVE-MATRIX](../ISSUE-CVE-MATRIX.md).

## Lessons that make the rules application-agnostic
1. **One root cause, many instances.** 1,077 header-manipulation hits came from shared forwarding helpers → fix the helper with an allowlist; count occurrences per case, not per line.
2. **Scanner ≠ truth.** Three SRC-E Exceptions were justified (internal 13-digit ID, product not deployed, OPTIONS needed for CORS). NavSentry encodes this as SUSPECTED lifecycle, checksum validation and narrower rules.
3. **Some recommended fixes are harmful** (HPKP). The catalog says when *not* to fix.
4. **Remediation must keep legitimate behavior.** The SRC-E SQLi retest judged success by a `success:false` response — the same envelope must stay for valid errors. NavSentry's `compare` checks status + JSON shape.
5. **Severity vocabularies differ** (Critical/High/Medium/Low/Info vs Severe/Critical). Catalog severity is NavSentry's own default; source severity is kept only as provenance.
