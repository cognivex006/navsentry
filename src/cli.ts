#!/usr/bin/env node
/**
 * NavSentry CLI. Exit codes (CLI status is separate from the security result):
 *   0 = completed, no findings in tested scope   1 = completed with findings
 *   2 = incomplete run (gaps/errors)              3 = usage / configuration error
 */
import { existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { CASES, CATEGORIES } from "./catalog.js";
import { compareRuns, renderCompareMarkdown } from "./compare.js";
import { ConfigError, loadManifest } from "./config.js";
import { DoctorError, HOSTS, applySkillUpdate, doctorReport, normalizeHost, planSkillUpdate, pluginCommands, type Host } from "./doctor.js";
import { renderJson, renderMarkdown, renderSarif, securityResult, validateRunResult } from "./report/render.js";
import { executeTest, planRun } from "./runner.js";
import { analyzeRun } from "./flow/analyze.js";
import { approveText, initTemplate } from "./flow/author.js";
import { classify } from "./flow/classify.js";
import { manualLine } from "./flow/execute.js";
import { lintFlows } from "./flow/lint.js";
import { FLOW_ID, FlowError, loadFlowFiles, type FlowDoc } from "./flow/parse.js";
import { renderFlowSection, renderJunit, renderTestMarkdown, validateFlowRunResult } from "./report/flow-render.js";
import type { Manifest } from "./config.js";
import type { FlowRunResult } from "./types.js";
import { allAdapters } from "./transports/registry.js";
import { TOOL_VERSION } from "./types.js";

const HELP = `navsentry ${TOOL_VERSION} — Navigate. Validate. Secure.
Authorized targets only. Default mode is observe (GET/HEAD/OPTIONS + TLS handshake).

Usage:
  navsentry doctor [--host claude|codex|gemini|antigravity|agy] [--project <dir>] [--json]
  navsentry doctor update --host <host> --scope user|project [--project <dir>] [--dry-run]
  navsentry integrations
  navsentry validate --config <manifest.json>
  navsentry plan --config <manifest.json> [--flows <path>] [--flows-only] [--include-drafts]   (zero network)
  navsentry discover --config <manifest.json> --dry-run
  navsentry test --config <manifest.json> [--out <dir>] [--profile safe]
                 [--flows <path>] [--flows-only] [--include-drafts] [--only <id,...>] [--level integration|e2e] [--junit]
  navsentry report --input <run.json|flows.json> --format markdown|json|sarif|junit [--lang en|th]
  navsentry compare --before <dir|run.json> --after <dir|run.json>   (reads flows.json beside run.json)
  navsentry catalog [--category <CODE>]

Story flows (Markdown test cases; zero network):
  navsentry flow init --id <id> --title <title> [--story <text>] [--level auto|integration|e2e] --out <dir>
  navsentry flow analyze --config <manifest.json> --from-run <run.json> --out <dir> [--lang en|th]
  navsentry flow lint --config <manifest.json> --flows <path>
  navsentry flow approve --flows <file> --by <name> [--reference <ref>]   (owner action)
  navsentry flow show --flows <file>

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
      case "flow":
        return await flowCommand(rest);
      case "plan":
      case "discover": {
        if (cmd === "discover" && !rest.includes("--dry-run")) throw new UsageError("live discovery (crawling) is scheduled for milestone M1b; use --dry-run or `plan`");
        const m = loadManifest(need(rest, "--config"));
        const sel = arg(rest, "--flows") ? selectFlows(m, rest) : undefined;
        const plan = planRun(m, process.env, sel ? { flows: sel.docs, flowsOnly: rest.includes("--flows-only"), warnings: sel.warnings } : {});
        print(JSON.stringify(plan, null, 2));
        return 0;
      }
      case "test": {
        const profile = arg(rest, "--profile");
        if (profile && profile !== "safe") throw new UsageError("only --profile safe is supported");
        const m = loadManifest(need(rest, "--config"));
        if (rest.includes("--flows-only") && !arg(rest, "--flows")) throw new UsageError("--flows-only needs --flows");
        const sel = arg(rest, "--flows") ? selectFlows(m, rest) : undefined;
        for (const w of sel?.warnings ?? []) process.stderr.write(`warning: ${w}\n`);
        const { run: r, flowRun } = await executeTest(m, sel ? { flows: sel.docs, flowsOnly: rest.includes("--flows-only") } : {});
        const out = resolve(arg(rest, "--out") ?? join(".navsentry", "runs", r.runId));
        mkdirSync(out, { recursive: true });
        writeFileSync(join(out, "run.json"), renderJson(r));
        const lang = m.report.language;
        if (m.report.formats.includes("markdown")) writeFileSync(join(out, "REPORT.md"), renderMarkdown(r, lang) + (flowRun ? "\n" + renderFlowSection(flowRun, r, lang) : ""));
        if (m.report.formats.includes("sarif")) writeFileSync(join(out, "report.sarif"), JSON.stringify(renderSarif(r), null, 2));
        if (flowRun) {
          writeFileSync(join(out, "flows.json"), JSON.stringify(flowRun, null, 2) + "\n");
          writeFileSync(join(out, "TEST-REPORT.md"), renderTestMarkdown(flowRun, r, lang));
          if (rest.includes("--junit")) writeFileSync(join(out, "junit.xml"), renderJunit(flowRun));
        }
        const sec = securityResult(r);
        print(`execution=${r.executionStatus} security=${sec} findings=${r.findings.length} requests=${r.budget.requestsUsed}${flowRun ? ` functional=${flowRun.functionalResult} flows=${flowRun.flows.length}` : ""}`);
        print(`REPORT: ${join(out, "REPORT.md")}`);
        if (flowRun) print(`TEST-REPORT: ${join(out, "TEST-REPORT.md")}`);
        const func = flowRun?.functionalResult;
        return r.findings.length || func === "FAIL" ? 1 : sec === "INCOMPLETE" || r.executionStatus !== "COMPLETE" || func === "INCOMPLETE" ? 2 : 0;
      }
      case "report": {
        const input = JSON.parse(readFileSync(need(rest, "--input"), "utf8")) as { kind?: string };
        const fmt = arg(rest, "--format") ?? "markdown";
        const lang = (arg(rest, "--lang") ?? "en") as "en" | "th";
        if (input?.kind === "navsentry-flow-result") {
          const fr = validateFlowRunResult(input);
          if (fmt === "markdown") print(renderTestMarkdown(fr, undefined, lang));
          else if (fmt === "json") print(JSON.stringify(fr, null, 2));
          else if (fmt === "junit") print(renderJunit(fr));
          else throw new UsageError("flow results render as markdown|json|junit");
          return 0;
        }
        const r = validateRunResult(input);
        if (fmt === "markdown") print(renderMarkdown(r, lang));
        else if (fmt === "json") print(renderJson(r));
        else if (fmt === "sarif") print(JSON.stringify(renderSarif(r), null, 2));
        else throw new UsageError("format must be markdown|json|sarif (html is planned for M4)");
        return 0;
      }
      case "compare": {
        const runPath = (p: string) => (statSync(p).isDirectory() ? join(p, "run.json") : p);
        const bp = runPath(need(rest, "--before")), ap = runPath(need(rest, "--after"));
        const b = validateRunResult(JSON.parse(readFileSync(bp, "utf8")));
        const a = validateRunResult(JSON.parse(readFileSync(ap, "utf8")));
        const fb = join(dirname(bp), "flows.json"), fa = join(dirname(ap), "flows.json");
        const flows = existsSync(fb) && existsSync(fa) ? { before: validateFlowRunResult(JSON.parse(readFileSync(fb, "utf8"))), after: validateFlowRunResult(JSON.parse(readFileSync(fa, "utf8"))) } : undefined;
        const c = compareRuns(b, a, flows);
        print(renderCompareMarkdown(c));
        return c.verdict === "REGRESSED" || c.verdict === "IMPROVED_WITH_DRIFT" || c.verdict === "DRIFT_ONLY" || c.verdict === "FUNCTIONAL_REGRESSION" ? 1 : 0;
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
    if (e instanceof ConfigError || e instanceof UsageError || e instanceof DoctorError || e instanceof FlowError) {
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

/** Loads, lints and selects flows. Any lint error stops the command before network activity. */
function loadLinted(m: Manifest, path: string): { docs: FlowDoc[]; warnings: string[] } {
  const { docs, problems } = loadFlowFiles(resolve(path));
  if (problems.length) throw new FlowError(problems);
  const { errors, warnings } = lintFlows(docs, m);
  if (errors.length) throw new FlowError(errors);
  return { docs, warnings };
}

function selectFlows(m: Manifest, argv: string[]): { docs: FlowDoc[]; warnings: string[] } {
  const { docs, warnings } = loadLinted(m, need(argv, "--flows"));
  const drafts = argv.includes("--include-drafts");
  if (drafts && m.environment === "production") throw new UsageError("--include-drafts is refused for production targets; approve the flows first");
  const only = arg(argv, "--only")?.split(",").map((x) => x.trim()).filter(Boolean);
  const level = arg(argv, "--level");
  if (level && level !== "integration" && level !== "e2e") throw new UsageError("--level must be integration or e2e");
  const picked = docs.filter((d) => (drafts || d.header.review.status === "approved") && (!only || only.includes(d.header.id)) && (!level || classify(d).level === level));
  const skippedDrafts = docs.filter((d) => d.header.review.status !== "approved" && !drafts).length;
  if (skippedDrafts) warnings.push(`${skippedDrafts} draft flow(s) skipped; approve them or pass --include-drafts (non-production only)`);
  if (!picked.length) throw new UsageError("no flows selected (drafts need --include-drafts; check --only / --level)");
  return { docs: picked, warnings };
}

async function flowCommand(argv: string[]): Promise<number> {
  const [sub, ...rest] = argv;
  switch (sub) {
    case "init": {
      const id = need(rest, "--id");
      if (!FLOW_ID.test(id)) throw new UsageError("--id must match ^[a-z0-9][a-z0-9-]{1,62}$");
      const title = need(rest, "--title");
      const level = arg(rest, "--level") ?? "auto";
      if (!["auto", "integration", "e2e"].includes(level)) throw new UsageError("--level must be auto, integration or e2e");
      const dir = resolve(need(rest, "--out"));
      const file = join(dir, `${id}.flow.md`);
      if (existsSync(file)) throw new UsageError(`${id}.flow.md already exists; not modified`);
      mkdirSync(dir, { recursive: true });
      writeFileSync(file, initTemplate(id, title.slice(0, 120), (arg(rest, "--story") ?? title).slice(0, 1000), level as "auto"));
      print(`written ${file} (draft)`);
      return 0;
    }
    case "lint": {
      const m = loadManifest(need(rest, "--config"));
      const { docs, warnings } = loadLinted(m, need(rest, "--flows"));
      for (const w of warnings) print(`warning: ${w}`);
      for (const d of docs) {
        const c = classify(d);
        print(`OK ${d.header.id.padEnd(32)} ${c.level.padEnd(11)} ${c.executability.padEnd(7)} ${d.header.review.status.padEnd(8)} ${d.steps.length} steps  (${c.levelReasons.join("; ")})`);
      }
      return 0;
    }
    case "analyze": {
      const m = loadManifest(need(rest, "--config"));
      const run = validateRunResult(JSON.parse(readFileSync(need(rest, "--from-run"), "utf8")));
      if (run.scope.origins.some((o) => !m.targets.origins.includes(o))) throw new UsageError("run is for a different target (its origins are not all in the manifest)");
      const dir = resolve(need(rest, "--out"));
      mkdirSync(dir, { recursive: true });
      const existing = existsSync(dir) ? loadFlowFiles(dir).docs.map((d) => d.header.id) : [];
      const lang = (arg(rest, "--lang") ?? m.report.language) as "en" | "th";
      const outp = analyzeRun(run, m, new Set(existing), lang);
      let written = 0;
      for (const [name, content] of outp.files) {
        const f = join(dir, name);
        if (name !== "ANALYSIS.md" && existsSync(f)) { outp.skippedExisting.push(name); continue; }
        writeFileSync(f, content);
        if (name !== "ANALYSIS.md") written++;
      }
      print(`draft flows written: ${written}; existing, not modified: ${outp.skippedExisting.length ? outp.skippedExisting.join(", ") : "none"}`);
      print(`ANALYSIS: ${join(dir, "ANALYSIS.md")}`);
      return 0;
    }
    case "approve": {
      const path = resolve(need(rest, "--flows"));
      const by = need(rest, "--by").trim();
      if (!by || by.length > 100) throw new UsageError("--by needs the approver's name (1-100 characters)");
      const { docs, problems } = loadFlowFiles(path);
      if (problems.length) throw new FlowError(problems);
      if (docs.length !== 1 || statSync(path).isDirectory()) throw new UsageError("--flows must name exactly one .flow.md file");
      const doc = docs[0]!;
      const ref = arg(rest, "--reference");
      writeFileSync(path, approveText(doc, by, new Date().toISOString().slice(0, 10), ref));
      print(`approved ${doc.header.id} by ${by}; editing the flow invalidates this approval`);
      return 0;
    }
    case "show": {
      const { docs, problems } = loadFlowFiles(resolve(need(rest, "--flows")));
      if (problems.length) throw new FlowError(problems);
      for (const d of docs) {
        const c = classify(d);
        print(`# ${d.header.id} — ${d.header.title}`, );
        print(`Level: ${c.level} (${c.levelReasons.join("; ")}) · executability ${c.executability} · ${d.header.review.status}`);
        print(`Story: ${d.header.story}\n`);
        d.steps.forEach((s, i) => {
          const e = s.expect;
          const exp = e ? [e.access && `access ${e.access}`, e.status && `status ${Array.isArray(e.status) ? e.status.join("|") : e.status}`, e.content_type, e.redirect_to && `redirect to ${e.redirect_to}`, e.json && `${e.json.length} JSON checks`, e.text_present && `${e.text_present.length} text markers`].filter(Boolean).join(", ") : "";
          print(`${i + 1}. ${s.request ? `${s.id} — as ${s.actor}: ${s.action === "navigate" ? "open" : "request"} ${s.request.method} ${s.request.path}` : manualLine(s)}${exp ? ` → expect ${exp}` : ""}`);
        });
        print("");
      }
      return 0;
    }
    default:
      throw new UsageError("flow needs a subcommand: init | analyze | lint | approve | show");
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
