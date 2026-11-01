#!/usr/bin/env node
/**
 * NavSentry CLI. Exit codes (CLI status is separate from the security result):
 *   0 = completed, no findings in tested scope   1 = completed with findings
 *   2 = incomplete run (gaps/errors)              3 = usage / configuration error
 */
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { CASES, CATEGORIES } from "./catalog.js";
import { compareRuns, renderCompareMarkdown } from "./compare.js";
import { ConfigError, loadManifest } from "./config.js";
import { DoctorError, HOSTS, applySkillUpdate, doctorReport, normalizeHost, planSkillUpdate, pluginCommands, type Host } from "./doctor.js";
import { renderJson, renderMarkdown, renderSarif, securityResult, validateRunResult } from "./report/render.js";
import { executeRun, planRun } from "./runner.js";
import { allAdapters } from "./transports/registry.js";
import { TOOL_VERSION } from "./types.js";

const HELP = `navsentry ${TOOL_VERSION} — Navigate. Validate. Secure.
Authorized targets only. Default mode is observe (GET/HEAD/OPTIONS + TLS handshake).

Usage:
  navsentry doctor [--host claude|codex|gemini|antigravity|agy] [--project <dir>] [--json]
  navsentry doctor update --host <host> --scope user|project [--project <dir>] [--dry-run]
  navsentry integrations
  navsentry validate --config <manifest.json>
  navsentry plan --config <manifest.json>            (zero network)
  navsentry discover --config <manifest.json> --dry-run
  navsentry test --config <manifest.json> [--out <dir>] [--profile safe]
  navsentry report --input <run.json> --format markdown|json|sarif [--lang en|th]
  navsentry compare --before <run.json> --after <run.json>
  navsentry catalog [--category <CODE>]

Exit: 0 no findings · 1 findings · 2 incomplete · 3 usage/config error`;

function arg(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : undefined;
}

function need(argv: string[], name: string): string {
  const v = arg(argv, name);
  if (!v || v.startsWith("--")) throw new UsageError(`missing ${name}`);
  return v;
}

class UsageError extends Error {}

const print = (s: string) => process.stdout.write(s.endsWith("\n") ? s : s + "\n");

export async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  try {
    switch (cmd) {
      case undefined:
      case "help":
      case "--help":
      case "-h":
        print(HELP);
        return cmd === undefined ? 3 : 0;
      case "--version":
        print(TOOL_VERSION);
        return 0;
      case "doctor":
        return await doctor(rest);
      case "integrations": {
        const st = await Promise.all(allAdapters().map((a) => a.probe()));
        print(`navsentry ${TOOL_VERSION} · node ${process.versions.node} · ${process.platform}-${process.arch}`);
        for (const s of st) print(`${s.usable ? "USABLE     " : s.available ? "DETECTED   " : "UNAVAILABLE"} ${s.id.padEnd(20)} ${s.version ?? ""}  ${s.reason}`);
        return 0;
      }
      case "validate": {
        const m = loadManifest(need(rest, "--config"));
        print(`OK manifest: project=${m.project} environment=${m.environment} mode=${m.safety.mode} origins=${m.targets.origins.join(",")}`);
        return 0;
      }
      case "plan":
      case "discover": {
        if (cmd === "discover" && !rest.includes("--dry-run")) throw new UsageError("live discovery (crawling) is scheduled for milestone M1b; use --dry-run or `plan`");
        const m = loadManifest(need(rest, "--config"));
        const plan = planRun(m, process.env);
        print(JSON.stringify(plan, null, 2));
        return 0;
      }
      case "test": {
        const profile = arg(rest, "--profile");
        if (profile && profile !== "safe") throw new UsageError("only --profile safe is supported");
        const m = loadManifest(need(rest, "--config"));
        const r = await executeRun(m);
        const out = resolve(arg(rest, "--out") ?? join(".navsentry", "runs", r.runId));
        mkdirSync(out, { recursive: true });
        writeFileSync(join(out, "run.json"), renderJson(r));
        if (m.report.formats.includes("markdown")) writeFileSync(join(out, "REPORT.md"), renderMarkdown(r, m.report.language));
        if (m.report.formats.includes("sarif")) writeFileSync(join(out, "report.sarif"), JSON.stringify(renderSarif(r), null, 2));
        const sec = securityResult(r);
        print(`execution=${r.executionStatus} security=${sec} findings=${r.findings.length} requests=${r.budget.requestsUsed}`);
        print(`REPORT: ${join(out, "REPORT.md")}`);
        return r.findings.length ? 1 : sec === "INCOMPLETE" || r.executionStatus !== "COMPLETE" ? 2 : 0;
      }
      case "report": {
        const r = validateRunResult(JSON.parse(readFileSync(need(rest, "--input"), "utf8")));
        const fmt = arg(rest, "--format") ?? "markdown";
        const lang = (arg(rest, "--lang") ?? "en") as "en" | "th";
        if (fmt === "markdown") print(renderMarkdown(r, lang));
        else if (fmt === "json") print(renderJson(r));
        else if (fmt === "sarif") print(JSON.stringify(renderSarif(r), null, 2));
        else throw new UsageError("format must be markdown|json|sarif (html is planned for M4)");
        return 0;
      }
      case "compare": {
        const b = validateRunResult(JSON.parse(readFileSync(need(rest, "--before"), "utf8")));
        const a = validateRunResult(JSON.parse(readFileSync(need(rest, "--after"), "utf8")));
        const c = compareRuns(b, a);
        print(renderCompareMarkdown(c));
        return c.verdict === "REGRESSED" || c.verdict === "IMPROVED_WITH_DRIFT" || c.verdict === "DRIFT_ONLY" ? 1 : 0;
      }
      case "catalog": {
        const cat = arg(rest, "--category");
        if (cat && !(cat in CATEGORIES)) throw new UsageError(`unknown category; one of ${Object.keys(CATEGORIES).join(", ")}`);
        for (const c of CASES.filter((x) => !cat || x.category === cat)) print(`${c.id.padEnd(16)} ${c.automation.padEnd(13)} ${c.priority.padEnd(9)} ${c.severity.padEnd(8)} ${c.titleEn}`);
        return 0;
      }
      default:
        throw new UsageError(`unknown command ${cmd}`);
    }
  } catch (e) {
    if (e instanceof ConfigError || e instanceof UsageError || e instanceof DoctorError) {
      process.stderr.write(`${e.message}\n`);
      return 3;
    }
    if (e instanceof SyntaxError) {
      process.stderr.write("input is not valid JSON\n");
      return 3;
    }
    process.stderr.write(`error: ${(e as Error).message}\n`);
    return 3;
  }
}

async function doctor(argv: string[]): Promise<number> {
  const update = argv[0] === "update";
  const hostArg = arg(argv, "--host");
  const host = hostArg ? normalizeHost(hostArg) : undefined;
  if (hostArg && !host) throw new UsageError(`unknown host; one of ${HOSTS.join(", ")} (agy = antigravity)`);
  const project = resolve(arg(argv, "--project") ?? process.cwd());
  if (update) {
    const scope = arg(argv, "--scope");
    if (!host) throw new UsageError("doctor update needs --host");
    if (scope !== "user" && scope !== "project") throw new UsageError("doctor update needs --scope user|project");
    const plan = planSkillUpdate(host, scope, undefined, project);
    for (const c of plan.copies) print(`${c.replaces === null ? "INSTALL" : "REPLACE"} ${c.skill} ${c.replaces ?? ""}${c.replaces === null ? "" : " -> "}${TOOL_VERSION}  ${c.to}`);
    if (argv.includes("--dry-run")) { print("dry run: nothing was changed"); return 0; }
    const backup = applySkillUpdate(plan);
    print(backup ? `previous copies backed up to ${backup}` : "no previous copies");
    print("Restart the host session so it loads the new skills. Plugins are updated with the host's own commands (see `navsentry doctor`).");
    return 0;
  }
  const hosts: readonly Host[] = host ? [host] : HOSTS;
  const r = doctorReport(hosts, undefined, project);
  const transports = await Promise.all(allAdapters().map((a) => a.probe()));
  if (argv.includes("--json")) { print(JSON.stringify({ ...r, node: process.versions.node, platform: `${process.platform}-${process.arch}`, transports }, null, 2)); return 0; }
  print(`navsentry ${TOOL_VERSION} · node ${process.versions.node} · ${process.platform}-${process.arch}`);
  print(`package: ${r.packageRoot}`);
  print("\nTransports");
  for (const s of transports) print(`  ${s.usable ? "USABLE     " : s.available ? "DETECTED   " : "UNAVAILABLE"} ${s.id.padEnd(20)} ${s.version ?? ""}  ${s.reason}`);
  print("\nPackage versions");
  for (const m of r.manifests) print(`  ${m.status.padEnd(9)} ${(m.version ?? "-").padEnd(9)} ${m.file}`);
  print("\nInstallations");
  if (!r.installations.length) print("  none found");
  for (const i of r.installations) print(`  ${i.status.padEnd(9)} ${(i.version ?? "-").padEnd(9)} ${i.host.padEnd(12)} ${i.kind.padEnd(6)} ${i.scope.padEnd(7)} ${i.path}`);
  for (const h of hosts) {
    const mine = r.installations.filter((i) => i.host === h);
    const cmds = pluginCommands(h);
    if (!mine.length) print(`\n${h}: not installed. Install: ${cmds.install.join(" && ")}`);
    else if (mine.some((i) => i.kind === "plugin" && i.status !== "CURRENT")) print(`\n${h}: plugin not current. Update: ${cmds.update.join(" && ")}`);
    if (mine.some((i) => i.kind === "skill" && i.status !== "CURRENT")) print(`\n${h}: skill copy not current. Update: navsentry doctor update --host ${h} --scope <user|project>`);
  }
  print("\nNothing was installed or changed. Doctor makes no network requests.");
  return r.manifests.some((m) => m.status !== "CURRENT") ? 2 : 0;
}

// realpath: npm links the bin on Linux/macOS, so argv[1] may be the symlink, not this file.
const entry = (() => { try { return realpathSync(process.argv[1] ?? ""); } catch { return ""; } })();
const invokedDirectly = entry.replace(/\\/g, "/").endsWith("dist/src/cli.js");
if (invokedDirectly) main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
