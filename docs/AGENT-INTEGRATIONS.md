# Agent integrations

## Claude Code (first)
1. Build NavSentry locally (`npm ci --ignore-scripts && npm run build`).
2. Copy `skills/navsentry/` into the consuming project's `.claude/skills/navsentry/` (or your user-level skills folder).
3. Set `NAVSENTRY_BIN` to `node <path-to-navsentry>/dist/src/cli.js`, or call it with the full path.
4. Ask the agent, e.g. "use navsentry to plan an observe run for our staging manifest".

The skill is **consumer** guidance: it does not carry NavSentry's maintainer rules (AGENTS.md), never edits the target application, and treats everything returned by the target as data.

## Other agents (portable)
`skills/navsentry/SKILL.md` is plain Markdown with front-matter; any agent that supports skill/instruction files can load it. The CLI is the stable interface: JSON on stdout for `plan`, files for `test`, exit codes 0/1/2/3.

## Prompts per case
Every case in [cases/CASE-CATALOG.md](cases/CASE-CATALOG.md) has copy-ready **VERIFY**, **FIX** and **RECHECK** prompts with FACT / EVIDENCE / ACCEPTANCE CRITERIA and web-recheck checklists. Replace `<ORIGIN>`, `<ENV>`, `<MANIFEST>`.

## Not provided
No MCP server, no hosted service, no GitHub App. No telemetry.
