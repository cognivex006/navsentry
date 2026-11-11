---
name: navsentry-doctor
description: Check NavSentry CLI, plugin and skill versions across Claude Code, Codex, Gemini CLI and Antigravity, report outdated or mismatched installations, and update a selected host's NavSentry skills when the user asks. Use for NavSentry install, update, version or doctor requests.
metadata:
  version: "0.3.1"
---

# NavSentry doctor

Read-only by default. Only an explicit user request to update authorizes changing an installation, and only for the host and scope the user selected.

## Status (read-only)
1. Run `navsentry doctor` (or `node "<NAVSENTRY_ROOT>/dist/src/cli.js" doctor` with separate arguments). Add `--host claude|codex|gemini|antigravity` (`agy` is an alias) to narrow it and `--json` when you need fields such as `packageRoot`.
2. If the command is not found, say the CLI is not installed. Show the install command from the NavSentry README or release notes and wait for the user; never install it yourself.
3. Report separately: CLI version, package root, packaging consistency, and each installation with host, kind, scope, path and status (`CURRENT`, `OUTDATED`, `NEWER`, `UNKNOWN`). `UNKNOWN` means no version could be read; never report it as current.
4. Do not print the contents of host configuration files, tokens or credentials.

## Update (only when asked)
- Skill copies (`kind: skill`): `navsentry doctor update --host <host> --scope user|project [--project <dir>]`. Run with `--dry-run` first and show the plan. The command backs up the previous copy outside the skills directory and refuses targets that are not NavSentry skills.
- Plugins and extensions (`kind: plugin`): the host owns them. Show the update commands that `doctor` prints and let the user run them; do not edit host plugin caches or configuration.
- After any update, run `navsentry doctor` again and report the new status. A host may need a restart before it loads the new version; say so instead of claiming it is active.

## Boundaries
- Doctor makes no network requests. Checking for newer releases means the user looks at the project's releases page.
- Never uninstall another product, change host security settings, or update a host the user did not select.
