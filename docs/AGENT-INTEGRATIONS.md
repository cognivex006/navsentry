# Agent integrations

Every integration ships the same two skills: `navsentry` (plan, run, report, compare) and `navsentry-doctor` (versions and updates). Both call the CLI, so install the CLI first (see the [README](../README.md#install)). Run `navsentry doctor` after any install or update; it reports each installation as `CURRENT`, `OUTDATED`, `NEWER` or `UNKNOWN`.

| Host | Package files | Install | Update | Doctor `--host` |
|---|---|---|---|---|
| Claude Code | `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json` | `claude plugin marketplace add cognivex006/navsentry` then `claude plugin install navsentry@navsentry` | `claude plugin marketplace update navsentry` then `claude plugin update navsentry@navsentry` | `claude` |
| Codex | `.codex-plugin/plugin.json`, `.agents/plugins/marketplace.json` | `codex plugin marketplace add cognivex006/navsentry` then `codex plugin add navsentry@navsentry` | `codex plugin marketplace upgrade navsentry` then `codex plugin add navsentry@navsentry` | `codex` |
| Gemini CLI | `gemini-extension.json` | `gemini extensions install https://github.com/cognivex006/navsentry` | `gemini extensions update navsentry` | `gemini` |
| Antigravity (`agy`) | `.antigravity-plugin/plugin.json` | `agy plugin install https://github.com/cognivex006/navsentry` | `agy plugin uninstall navsentry` then install again | `antigravity` or `agy` |

The Codex marketplace entry pins the plugin to the release tag (`ref: v0.3.0`), so the installed plugin always matches a released CLI. Antigravity documents no update subcommand; check `agy plugin --help` on your version first.

## Skills without a plugin

`navsentry doctor update` copies both skills into one host's skills folder. Preview the change with `--dry-run`:

```bash
navsentry doctor update --host claude --scope project --project /path/to/app --dry-run
```

| Host | `--scope user` | `--scope project` |
|---|---|---|
| Claude Code | `~/.claude/skills/` | `<project>/.claude/skills/` |
| Codex | `~/.agents/skills/` (also reads `~/.codex/skills/`) | `<project>/.agents/skills/` |
| Gemini CLI | `~/.gemini/skills/` | `<project>/.gemini/skills/` |
| Antigravity | `~/.gemini/config/skills/` (also reads `~/.gemini/antigravity-cli/skills/`) | `<project>/.agents/skills/` |

An existing copy is backed up to a temporary folder outside the skills directory, so the host never loads two skills with the same name. Doctor refuses to overwrite a folder that holds a different skill. Restart the host session afterwards.

## Other agents

`skills/navsentry/SKILL.md` and `skills/navsentry-doctor/SKILL.md` are plain Markdown with `name`, `description` and `metadata.version` front matter. Any agent that supports skill or instruction files can load them. `navsentry doctor --json` returns `packageRoot`, the folder that contains these skills, the case catalog and the example manifest. The CLI is the stable interface: JSON on stdout for `plan` and `browse`, files for `test` and `scan`, exit codes 0/1/2/3/4 (see the README).

## Using a NavSentry checkout with Codex

A checkout exposes `.agents/skills/navsentry/SKILL.md`, a small entrypoint pointing to the canonical `skills/navsentry/SKILL.md`. Invoke `$navsentry` explicitly when automatic selection misses the request. Do not copy that forwarding entrypoint or the checkout's AGENTS.md into another project.

If discovery fails, check that the installed folder contains SKILL.md with name/description front matter, inspect disabled skill settings, and restart the host. Avoid duplicate installations with the same name; `navsentry doctor` lists them.

## Computer Use boundary

A host's own Computer Use or browser tool must never be pointed at the target: NavSentry cannot enforce scope or the Budget there. Use the NavSentry visual driver instead ([ADR-0009](adr/0009-visual-driver-on-owned-browser.md)): `navsentry browse start` launches a browser that NavSentry owns, and the agent drives it with `browse screenshot`, `click`, `scroll` and `end`. Every request the page makes still goes through ScopeGate and the Budget.

Requirements: development profile (`local` or `dev`), `transports.visual_computer_use: true`, `visual-computer-use` and `playwright-browser` in `transports.order`, and the Chromium headless shell (`navsentry doctor` shows `visual-computer-use USABLE`). The driver is observe-only: no typing. DOM checks inside the browser (CSP violations, cookie visibility, framing) are not implemented yet and stay NOT_TESTED. See the canonical skill for handling separate manual evidence and resuming interrupted work.

### Tips for Claude Code and Codex

- Run `browse start` as a background command; it stays alive until `browse end`, the idle timeout or the deadline. Read the `SESSION:` line from its output.
- `browse screenshot` returns JSON with a `path` to a PNG. Claude Code reads it with its file-read tool; in Codex, attach it with the `view_image` tool. Coordinates are pixels in the 1280x800 image.
- If the agent does not pick the skill automatically, name it: "use the navsentry skill" (Claude Code) or `$navsentry` (Codex).

## Prompts per case

Every case in [cases/CASE-CATALOG.md](cases/CASE-CATALOG.md) has copy-ready **VERIFY**, **FIX** and **RECHECK** prompts with FACT / EVIDENCE / ACCEPTANCE CRITERIA and web-recheck checklists. Replace `<ORIGIN>`, `<ENV>`, `<MANIFEST>`.

## Not provided

No hosted service, no GitHub App, no telemetry. `navsentry doctor` makes no network requests. The MCP server below is local and stdio only.

## MCP server (Claude Code, Codex and other MCP hosts)

`navsentry mcp` is a local MCP server over stdio. It has no dependencies and no network listener. It lets the agent call NavSentry as tools instead of composing command lines, and it returns visual-driver screenshots as images.

| Tool | Sends traffic | What it does |
|---|---|---|
| `navsentry_doctor` | no | Versions and usable transports |
| `navsentry_plan` | no | The plan for a run |
| `navsentry_scan` | **yes** | page (default), `deep` spider, or `mode: flow`; returns a JSON summary |
| `navsentry_next` | no | Actions by level, gaps, next commands |
| `navsentry_compare` | no | Before/after verdict |
| `navsentry_flow_analyze`, `navsentry_flow_lint` | no | Draft and check flows |
| `navsentry_flow_from_recording` | no | Draft a flow from a DevTools Recorder export |
| `navsentry_knowledge_lookup` | no | Offline advisory lookup |
| `navsentry_browse_start`, `_click`, `_key`, `_scroll` | **yes** | Visual driver on NavSentry's own browser; click by snapshot ref or by coordinates |
| `navsentry_browse_snapshot` | no | Interactive elements with refs, roles, names and scope flags (no values) |
| `navsentry_browse_type` | no | Fill a field: `env` for secrets, `text` for short non-secret input; values are never logged |
| `navsentry_browse_screenshot`, `_end` | no | Screenshot as an image; end the session, optionally `save_flow` to a draft flow |

There is no tool to create or edit a manifest, approve a flow, clean a workspace or update an installation; those stay with the person. Each tool runs the CLI, so every refusal and safety gate applies.

Register it once, from the project folder that holds `navsentry.json`.

Claude Code:

```bash
claude mcp add navsentry -- navsentry mcp
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.navsentry]
command = "navsentry"
args = ["mcp"]
```

If the host reports `CONNECTION_CLOSED`, `navsentry` is usually not on PATH (the CLI was never installed with `npm install -g` or `npm link`). Run `navsentry doctor` (or `node <checkout>/dist/src/cli.js doctor`): its "Agent launch (MCP)" section says whether `navsentry` was found and prints a register command with the absolute path of Node and of `dist/src/cli.js`, which works without PATH.

Codex starts the server in the folder where you start Codex. To scan another project, pass `cwd` in the tool call.

Without MCP, agents use the same loop through the CLI: `navsentry scan --json` and `navsentry next --run <dir> --json` print machine-readable summaries.

Sources (checked 2026-10-31): [Claude Code plugin marketplaces](https://code.claude.com/docs/en/plugin-marketplaces), [Gemini CLI extension reference](https://geminicli.com/docs/extensions/reference), [Antigravity plugins](https://antigravity.google/docs/build-plugins), [Antigravity skills](https://antigravity.google/docs/skills). The Codex format follows Codex CLI 0.166.0 (`codex plugin --help`). Host versions differ; the explicit file path remains the fallback.
