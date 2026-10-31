# Security Policy

## Supported versions
| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Reporting a vulnerability in NavSentry
Please use GitHub **private vulnerability reporting** for this repository (Security → Report a vulnerability). Do not open public issues for vulnerabilities. Include affected version, impact and a minimal reproduction against the bundled fixture app — never data from a real target. We aim to acknowledge within 7 days and agree on a disclosure timeline (default 90 days).

## Safe and lawful use
- Use NavSentry only on systems you own or are **explicitly authorized in writing** to test. The manifest's `authorization` block records that acknowledgement; it does not create permission.
- Default mode `observe` sends only GET/HEAD/OPTIONS and TLS handshakes within the allowlist, rate-limited. Production targets are limited to `observe`.
- NavSentry contains no exploit payloads, password guessing, rate-limit bypass, WAF evasion or DoS functionality, and must not be modified to add them in this repository.
- Do not upload target data, reports or evidence to third-party services without the target owner's approval.

## Restrictions on contributions
- No customer data, real hostnames, IP addresses or credentials in issues, PRs, fixtures or docs.
- New dependencies or services require a terms/license review ([docs/THIRD-PARTY-GOVERNANCE.md](docs/THIRD-PARTY-GOVERNANCE.md)).

## If sensitive data is published by mistake
Treat it as an incident: remove it, rotate any credential involved, notify the data owner, and record the event. Rewriting Git history alone is not sufficient once data has been pushed.
