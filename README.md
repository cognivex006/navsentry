# NavSentry

**Navigate. Validate. Secure.**

AI-assisted security testing for web applications, with automated vulnerability validation and evidence-based reporting.

> ⚠️ **Authorized targets only.** NavSentry refuses to run without an explicit authorization acknowledgement and an origin allowlist. It never crawls the Internet, never sends injection or DoS payloads, and defaults to passive `observe` mode.

## Features

- **Scope and authorization gate**: origin, path and method allowlists, checked before each request and again at connect time. It blocks DNS rebinding, private and metadata addresses, and out-of-scope redirects.
- **Request budget**: limits on request volume, rate and run duration.
- **20 observe-mode checks**: security headers, cookies, CORS, HTTP methods, caching, information disclosure, PII exposure, JWT handling, HTTPS redirect, plus a TLS handshake probe for protocol versions and certificates.
- **Evidence-based reports**: JSON, Markdown (English and Thai) and SARIF 2.1.0. Secrets and personal data are redacted before anything is written.
- **Story flows (test cases)**: one Markdown file per user story, replayed through the same safety pipeline. Each flow is classified as Integration or E2E automatically. `flow analyze` drafts flows from an earlier run. Owner-declared access expectations check missing authentication, IDOR and missing function-level authorization. See [docs/FLOWS.md](docs/FLOWS.md).
- **Fix verification**: `compare` shows which issues were fixed, which still fail, any change a legitimate user would notice (contract drift), and any story step that stopped working (functional regression).
- **Case catalog**: 50 cases mapped to OWASP Top 10 2021 and 2025, CWE, WSTG and ASVS 5.0, each with VERIFY, FIX and RECHECK prompts for AI agents.
- **Agent plugins** for Claude Code, Codex, Gemini CLI and Antigravity, plus a portable skill for other agents.
- **Version doctor**: checks the CLI, plugins and skill copies on every host and shows how to update anything out of date.

## Install

Requires Node.js 22.12 or newer.

Install the CLI from the release tarball:

```bash
npm install -g https://github.com/cognivex006/navsentry/releases/download/v0.2.0/navsentry-0.2.0.tgz
```

```bash
navsentry doctor
```

### Agent plugins

Each plugin adds the `navsentry` skill and the `navsentry-doctor` skill. The plugins call the CLI, so install the CLI first.

**Claude Code**

```bash
claude plugin marketplace add cognivex006/navsentry
```

```bash
claude plugin install navsentry@navsentry
```

**Codex**

```bash
codex plugin marketplace add cognivex006/navsentry
```

```bash
codex plugin add navsentry@navsentry
```

**Gemini CLI**

```bash
gemini extensions install https://github.com/cognivex006/navsentry
```

**Antigravity (`agy`)**

```bash
agy plugin install https://github.com/cognivex006/navsentry
```

**Skills without a plugin**: `doctor update` copies both skills into a host's skills folder, for one project or for your user:

```bash
navsentry doctor update --host codex --scope project --project /path/to/your/app
```

**Other agents**: any agent that reads `SKILL.md` files can use the `skills/navsentry/` and `skills/navsentry-doctor/` folders. `navsentry doctor` prints the package folder that contains them. See [docs/AGENT-INTEGRATIONS.md](docs/AGENT-INTEGRATIONS.md) for details.

## Quick start

```bash
navsentry init https://staging.example.test/
```

`init` asks you to confirm that you own the target or have written authorization, then writes `navsentry.json`. Every command finds that file, so no `--config` is needed:

```bash
navsentry plan
```

```bash
navsentry scan
```

```bash
navsentry scan --deep
```

`scan` checks one page; `scan --deep` follows links and samples pages by template. To try every mode on the bundled demo shop without a real target, follow the [10-minute tour](docs/TOUR.md).

## Usage

1. Describe the target in a manifest. Start from [examples/manifest.example.json](examples/manifest.example.json). Credentials are referenced by environment variable names only.
2. Validate the manifest and review the plan. Neither step sends any network traffic.

   ```bash
   navsentry validate --config my-manifest.json
   ```

   ```bash
   navsentry plan --config my-manifest.json
   ```

3. Run the checks:

   ```bash
   navsentry test --config my-manifest.json --out runs/before
   ```

   Open `runs/before/REPORT.html` in a browser, or `REPORT.md`; both have the same content. Every report has the same twelve sections. Each finding gets one card per case with the fix, before/after code examples for common stacks, how to recheck and when it counts as fixed. Each card has an action level:
   - 🔴 `IMMEDIATE`: fix now.
   - 🟠 `CAUTION`: fix carefully; may affect legitimate users.
   - 🟡 `PLANNED`: schedule it.
   - 🔵 `OPTIONAL`: hardening; may be skipped with a recorded reason.
   - ⚪ `INFO`: observation only.

   The HTML report filters by level, exports Markdown and prints to PDF. Terminal output is coloured when it goes to a terminal; set `NO_COLOR` or pass `--no-color` to turn colour off.
4. After a fix, run again and compare:

   ```bash
   navsentry test --config my-manifest.json --out runs/after
   ```

   ```bash
   navsentry compare --before runs/before/run.json --after runs/after/run.json
   ```

5. Render a report in another format or language:

   ```bash
   navsentry report --input runs/after/run.json --format sarif
   ```

   ```bash
   navsentry report --input runs/after/run.json --format markdown --lang th
   ```

### Story flows

Draft flows from a run, review them, then replay them with the security checks. None of these commands except `test` sends network traffic.

```bash
navsentry flow analyze --config my-manifest.json --from-run runs/before/run.json --out navsentry/flows
```

```bash
navsentry flow lint --config my-manifest.json --flows navsentry/flows
```

```bash
navsentry flow approve --flows navsentry/flows/orders-access.flow.md --by "<owner name>"
```

```bash
navsentry test --config my-manifest.json --flows navsentry/flows --out runs/before
```

Open `REPORT.md` (security) and `TEST-REPORT.md` (functional). In this release, UI steps (`click`, `fill`, …) are not executed. An E2E flow that contains them is reported `INCOMPLETE`, with a manual replay checklist.

Browse the case catalog:

```bash
navsentry catalog --category CONF
```

Example reports: [before](docs/samples/before/REPORT.md) ([HTML](docs/samples/before/REPORT.html)), [after](docs/samples/after/REPORT.md) ([HTML](docs/samples/after/REPORT.html)), [compare](docs/samples/compare.md).

### With an AI agent

Ask in the agent chat, for example:

- "Use navsentry to scan our app and tell me what to fix first."
- "Explore the site with the navsentry visual driver and summarize what you find."
- "Compare the before and after navsentry runs and list any contract drift."
- "Check my navsentry installation and versions."

The agent runs the whole loop itself: plan, scan, read the summary, explore, draft flows, and report. It asks you once before sending traffic, and leaves authorization, flow approval and manifest changes to you.

For the smoothest loop, register the local MCP server once. It gives the agent NavSentry tools directly and returns screenshots as images.

```bash
claude mcp add navsentry -- navsentry mcp
```

For Codex, see [docs/AGENT-INTEGRATIONS.md](docs/AGENT-INTEGRATIONS.md#mcp-server-claude-code-codex-and-other-mcp-hosts). Without MCP, `navsentry scan --json` and `navsentry next --run <dir>` give agents the same information.

## Version doctor

```bash
navsentry doctor
```

Shows the CLI version, its package location, the version of every bundled plugin manifest and skill, and every NavSentry plugin or skill installed for Claude Code, Codex, Gemini CLI and Antigravity. Each entry is `CURRENT`, `OUTDATED`, `NEWER` or `UNKNOWN`. Doctor reads local files only, makes no network requests and changes nothing.

| Option | Effect |
|---|---|
| `--host claude\|codex\|gemini\|antigravity` | Check one host (`agy` = `antigravity`) |
| `--project <dir>` | Project whose skill folders are checked (default: current directory) |
| `--json` | Machine-readable output |

Update skill copies for one host:

```bash
navsentry doctor update --host claude --scope user --dry-run
```

```bash
navsentry doctor update --host claude --scope user
```

The previous copy is backed up outside the skills folder. Plugins are owned by their host: doctor prints the host's own update command (for example `claude plugin update navsentry@navsentry`) instead of editing the host's files.

## Commands

| Command | Purpose |
|---|---|
| `navsentry doctor` | Versions, installations and available transports |
| `navsentry integrations` | Available transports only |
| `navsentry init <url>` | Write `navsentry.json` after you confirm authorization (interactive terminal only) |
| `navsentry validate --config <m>` | Check a manifest |
| `navsentry plan --config <m>` | Show planned requests and skipped cases (no network) |
| `navsentry test --config <m> [--out <dir>] [--env <profile>] [--project <dir>]` | Run observe-mode checks and write reports |
| `navsentry scan [--config <m>] [--mode page\|spider\|flow] [--deep] [--url <URL>] [--engine http\|playwright\|analyzer] [--env <profile>]` | Scan one page (default), crawl by template (`--deep` = spider with page models), or replay flows |
| `navsentry workspace status\|clean [--project <dir>] [--dry-run]` | Show or remove NavSentry leftovers in a project |
| `navsentry inventory --config <m> [--project <dir>]` | Read-only code inventory of a development project (routes, OpenAPI, tests, lockfiles) |
| `navsentry flow import --openapi <spec.json> --config <m> --out <dir>` | Draft flows from a local OpenAPI JSON document |
| `navsentry knowledge status\|lookup\|propose` | Offline vulnerability knowledge base and update proposals |
| `navsentry report --input <run.json> --format markdown\|html\|json\|sarif [--lang en\|th]` | Render a saved run |
| `navsentry compare --before <run.json> --after <run.json>` | Before/after verdict and contract drift |
| `navsentry catalog [--category <CODE>]` | List catalog cases |

Exit codes: `0` no findings in tested scope · `1` findings · `2` incomplete run · `3` usage or configuration error · `4` workspace dirty (a leftover or unexpected change in the project, or a cleanup failure). When several apply: 3 > 4 > 1 > 2 > 0.

Profiles: `local` and `dev` manifests use the `development` profile; `staging` and `production` use the `production` profile, which requires `authorization.reference` and `authorization.expires_at` and refuses to run outside that window.

## Results

- Check status: `PASS`, `FAIL`, `INCONCLUSIVE`, `NOT_TESTED`, `ERROR`. Missing evidence is never `PASS`.
- Finding status: `SUSPECTED`, `VALIDATED`, `NEEDS_REVIEW`, `DISMISSED`. Severity is reported separately from confidence.

## Limitations

- Zero findings does not mean the application is secure. Injection, access control and business-logic issues need authorized manual testing.
- Checks run over HTTP and TLS. Browser-based (DOM and visual) checks are reported as `NOT_TESTED`.
- `safe-validate` (development profile only, 0.2.0-a) changes state only through fixtures that the owner declares, and cleans them up by id. Login actors (http or browser) and cookie sessions take credentials from env vars only (0.2.0-b). Side effects such as emails or webhooks are not undone, and a run that leaves data behind is `FAILED`. See [docs/FLOWS.md](docs/FLOWS.md#fixtures-and-mutations-safe-validate-020-a).

## More

- [Case catalog](docs/cases/CASE-CATALOG.md) · [Issue/CVE matrix](docs/ISSUE-CVE-MATRIX.md)
- [Reading reports](docs/REPORTING.md) · [Agent integrations](docs/AGENT-INTEGRATIONS.md)
- [Threat model](docs/THREAT-MODEL.md) · [Security policy](SECURITY.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
