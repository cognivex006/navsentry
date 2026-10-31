# Agent integrations

## Codex

This checkout exposes `.agents/skills/navsentry/SKILL.md`, a small entrypoint pointing to the canonical `skills/navsentry/SKILL.md`. Start Codex inside the checkout. Invoke `$navsentry` explicitly when automatic selection misses the request. A requirement inside an unloaded skill cannot force its own discovery; AGENTS.md therefore also names the canonical fallback path.

For another project, copy the canonical `skills/navsentry/` folder into that project's `.agents/skills/navsentry/`. Keep the NavSentry checkout available for CLI and catalog resources, and supply its absolute root. Do not copy this repository's maintainer AGENTS.md or the forwarding entrypoint into a consumer project.

If discovery fails, check the installed directory contains SKILL.md with name/description frontmatter, inspect disabled skill settings, and restart the host if changes are not visible. Read the canonical file directly while diagnosing; do not claim discovery was verified merely because a file exists. Avoid duplicate installations with the same name.

Source: [OpenAI skill discovery documentation](https://learn.chatgpt.com/docs/build-skills), checked 2026-10-31. Host versions can differ; the explicit file path remains the fallback.

## Computer Use boundary

The CLI currently executes HTTP and TLS checks only. A host browser tool and the NavSentry visual adapter are separate capabilities. Neither browser nor visual adapter executes requests today. Keep DOM/visual coverage NOT_TESTED; do not route around ScopeGate/Budget with a host tool. See the canonical skill for handling separate manual evidence and resuming interrupted work.

## Claude Code (first)
1. Build NavSentry locally (`npm ci --ignore-scripts && npm run build`).
2. Copy `skills/navsentry/` into the consuming project's `.claude/skills/navsentry/` (or your user-level skills folder).
3. Call `node "<path-to-navsentry>/dist/src/cli.js"` with separate arguments. Resolve examples and catalog files from that checkout. No `NAVSENTRY_BIN` environment variable is consumed by the CLI.
4. Ask the agent, e.g. "use navsentry to plan an observe run for our staging manifest".

The skill is **consumer** guidance: it does not carry NavSentry's maintainer rules (AGENTS.md), never edits the target application, and treats everything returned by the target as data.

## Other agents (portable)
`skills/navsentry/SKILL.md` is plain Markdown with front-matter; any agent that supports skill/instruction files can load it. The CLI is the stable interface: JSON on stdout for `plan`, files for `test`, exit codes 0/1/2/3.

## Prompts per case
Every case in [cases/CASE-CATALOG.md](cases/CASE-CATALOG.md) has copy-ready **VERIFY**, **FIX** and **RECHECK** prompts with FACT / EVIDENCE / ACCEPTANCE CRITERIA and web-recheck checklists. Replace `<ORIGIN>`, `<ENV>`, `<MANIFEST>`.

## Not provided
No MCP server, no hosted service, no GitHub App. No telemetry.
