#!/usr/bin/env node
/**
 * NavSentry CLI. Exit codes (CLI status is separate from the security result):
 *   0 = completed, no findings in tested scope   1 = completed with findings
 *   2 = incomplete run (gaps/errors)              3 = usage / configuration error
 *   4 = WORKSPACE_DIRTY (leftover, unexpected project change, or cleanup failure; 0.1.3)
 * When several apply, precedence is 3 > 4 > 1 > 2 > 0.
 */
import { randomUUID } from "node:crypto";
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
import type { Engine, FlowRunResult, RunResult, ScanMode } from "./types.js";
import { WorkspaceError, authorize, beginRun, endRun, projectRoot, releaseWorkDir, sweepStale, workspaceStatus } from "./workspace.js";
import { allAdapters } from "./transports/registry.js";
import { ScopeGate } from "./scope.js";
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
  navsentry test --config <manifest.json> [--out <dir>] [--profile safe] [--env development|production] [--project <dir>]
                 [--flows <path>] [--flows-only] [--include-drafts] [--only <id,...>] [--level integration|e2e] [--junit]
  navsentry scan --config <manifest.json> --mode page|spider|flow [--engine http|playwright|analyzer] [--analyze]
                 [--env development|production] [--url <in-scope URL>] [--flows <path>] [--out <dir>] [--project <dir>]
                 page without --url scans the seed paths, like test; flow equals test --flows <path> --flows-only.
                 spider crawls from the seed paths, grouping pages by template; computer-use is deferred beyond 0.1.3.
  navsentry workspace status|clean [--project <dir>] [--dry-run]
  navsentry report --input <run.json|flows.json> --format markdown|json|sarif|junit [--lang en|th]
  navsentry compare --before <dir|run.json> --after <dir|run.json>   (reads flows.json beside run.json)
  navsentry catalog [--category <CODE>]

Story flows (Markdown test cases; zero network):
  navsentry flow init --id <id> --title <title> [--story <text>] [--level auto|integration|e2e] --out <dir>
  navsentry flow analyze --config <manifest.json> --from-run <run.json> --out <dir> [--lang en|th]
  navsentry flow lint --config <manifest.json> --flows <path>
  navsentry flow approve --flows <file> --by <name> [--reference <ref>]   (owner action)
  navsentry flow show --flows <file>

Exit: 0 no findings · 1 findings · 2 incomplete · 3 usage/config error · 4 workspace dirty
      (precedence 3 > 4 > 1 > 2 > 0)`;

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
        if (cmd === "discover" && !rest.includes("--dry-run")) throw new UsageError("live discovery is `navsentry scan --mode spider` (0.1.3); `discover --dry-run` stays the zero-network plan");
        const m = loadManifest(need(rest, "--config"));
        assertEnv(m, rest);
        const sel = arg(rest, "--flows") ? selectFlows(m, rest) : undefined;
        const plan = planRun(m, process.env, sel ? { flows: sel.docs, flowsOnly: rest.includes("--flows-only"), warnings: sel.warnings } : {});
        print(JSON.stringify(plan, null, 2));
        return 0;
      }
      case "test": {
        const profile = arg(rest, "--profile");
        if (profile && profile !== "safe") throw new UsageError("only --profile safe is supported");
        const m = loadManifest(need(rest, "--config"));
        assertEnv(m, rest);
        if (rest.includes("--flows-only") && !arg(rest, "--flows")) throw new UsageError("--flows-only needs --flows");
        const sel = arg(rest, "--flows") ? selectFlows(m, rest) : undefined;
        return await runAndReport(m, rest, sel ? { flows: sel.docs, flowsOnly: rest.includes("--flows-only"), warnings: sel.warnings } : {});
      }
      case "scan":
        return await scan(rest);
      case "workspace":
        return workspaceCommand(rest);
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
    if (e instanceof ConfigError || e instanceof UsageError || e instanceof DoctorError || e instanceof FlowError || e instanceof WorkspaceError) {
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

/** `--env` is a safety assertion against the manifest profile; it never overrides the manifest. */
function assertEnv(m: Manifest, argv: string[]): void {
  const env = arg(argv, "--env");
  if (env === undefined) return;
  if (env !== "development" && env !== "production") throw new UsageError("--env must be development or production");
  if (env !== m.profile) throw new UsageError(`--env ${env} does not match the manifest profile ${m.profile} (environment "${m.environment}"); nothing was sent`);
}

/** Exit precedence 3 > 4 > 1 > 2 > 0 (3 is raised as an exception before a run result exists). */
export function exitCode(r: RunResult, flowRun?: FlowRunResult): number {
  if (r.workspace?.status === "FAIL") return 4;
  const func = flowRun?.functionalResult;
  if (r.findings.length || func === "FAIL") return 1;
  if (securityResult(r) === "INCOMPLETE" || r.executionStatus !== "COMPLETE" || func === "INCOMPLETE" || r.workspace?.status === "NOT_TESTED") return 2;
  return 0;
}

interface RunOpts { urls?: string[]; spider?: boolean; flows?: FlowDoc[]; flowsOnly?: boolean; warnings?: string[]; scanMode?: ScanMode; engine?: RunResult["engine"]; notTested?: string[] }

/** Executes a run inside a managed workspace (SPEC-0.1.3 §7.2), writes the reports and returns the exit code. */
async function runAndReport(m: Manifest, argv: string[], o: RunOpts): Promise<number> {
  for (const w of o.warnings ?? []) process.stderr.write(`warning: ${w}\n`);
  const runId = randomUUID();
  const ws = beginRun(arg(argv, "--project") ?? process.cwd(), runId, m.workspace.ignore);
  let res: Awaited<ReturnType<typeof executeTest>>;
  try {
    res = await executeTest(m, { runId, ...(o.flows ? { flows: o.flows, flowsOnly: !!o.flowsOnly } : {}), ...(o.scanMode ? { scanMode: o.scanMode } : {}), ...(o.engine ? { engine: o.engine } : {}), ...(o.urls ? { urls: o.urls } : {}), ...(o.spider ? { spider: true } : {}) });
  } catch (e) {
    ws.dispose();
    try { releaseWorkDir(ws.work); } catch { /* reported by the next run's sweep */ }
    throw e;
  }
  const { run: r, flowRun } = res;
  if (o.notTested?.length) { r.incompleteReasons.push(...o.notTested); if (r.executionStatus === "COMPLETE") r.executionStatus = "PARTIAL"; }
  for (const p of ws.sweep.preserved) r.incompleteReasons.push(`work directory preserved during sweep: ${p.reason}`);
  const outArg = arg(argv, "--out");
  const out = outArg ? resolve(outArg) : join(ws.root, ".navsentry", "runs", r.runId);
  mkdirSync(out, { recursive: true });
  const lang = m.report.language;
  const write = (): number => {
    const files: [string, string][] = [["run.json", renderJson(r)]];
    if (m.report.formats.includes("markdown")) files.push(["REPORT.md", renderMarkdown(r, lang) + (flowRun ? "\n" + renderFlowSection(flowRun, r, lang) : "")]);
    if (m.report.formats.includes("sarif")) files.push(["report.sarif", JSON.stringify(renderSarif(r), null, 2)]);
    if (flowRun) {
      files.push(["flows.json", JSON.stringify(flowRun, null, 2) + "\n"]);
      files.push(["TEST-REPORT.md", renderTestMarkdown(flowRun, r, lang)]);
      if (argv.includes("--junit")) files.push(["junit.xml", renderJunit(flowRun)]);
    }
    for (const [n, c] of files) { authorize(ws, join(out, n)); writeFileSync(join(out, n), c); }
    return files.length;
  };
  // Reports are written first so the second snapshot sees them as authorized writes,
  // then rewritten with the workspace result.
  const promoted = write();
  r.workspace = endRun(ws, promoted);
  if (r.workspace.status !== "PASS") {
    r.incompleteReasons.push(`workspace check ${r.workspace.status}${r.workspace.reason ? `: ${r.workspace.reason}` : ""}`);
    if (r.executionStatus === "COMPLETE") r.executionStatus = "PARTIAL";
  }
  write();
  const sec = securityResult(r);
  print(`execution=${r.executionStatus} security=${sec} findings=${r.findings.length} requests=${r.budget.requestsUsed}${flowRun ? ` functional=${flowRun.functionalResult} flows=${flowRun.flows.length}` : ""} workspace=${r.workspace.status}`);
  if (r.workspace.status === "FAIL") process.stderr.write(`WORKSPACE_DIRTY: created=${r.workspace.created.length} modified=${r.workspace.modified.length} deleted=${r.workspace.deleted.length} cleanup=${r.workspace.cleanup}\n`);
  print(`REPORT: ${join(out, "REPORT.md")}`);
  if (flowRun) print(`TEST-REPORT: ${join(out, "TEST-REPORT.md")}`);
  return exitCode(r, flowRun);
}

const ENGINE_TRANSPORT: Record<Engine, string> = { http: "direct-http", playwright: "playwright-browser", "computer-use": "visual-computer-use" };

/** `scan` (SPEC-0.1.3 §3). Every invalid combination exits 3 before any I/O. */
async function scan(argv: string[]): Promise<number> {
  const mode = need(argv, "--mode");
  if (mode !== "page" && mode !== "spider" && mode !== "flow") throw new UsageError("--mode must be page, spider or flow");
  const rawEngine = arg(argv, "--engine") ?? "http";
  if (rawEngine === "computer-use") throw new UsageError("--engine computer-use is deferred beyond 0.1.3: ScopeGate cannot be enforced in a host-owned browser (S1)");
  if (rawEngine !== "http" && rawEngine !== "playwright" && rawEngine !== "analyzer") throw new UsageError("--engine must be http, playwright or analyzer");
  const analyze = argv.includes("--analyze") || rawEngine === "analyzer";
  const engine: Engine = rawEngine === "analyzer" ? "http" : rawEngine;
  if (arg(argv, "--url") !== undefined && mode !== "page") throw new UsageError("--url applies only to --mode page");
  if (arg(argv, "--flows") !== undefined && mode !== "flow") throw new UsageError("--flows applies only to --mode flow");
  if (mode === "flow" && !arg(argv, "--flows")) throw new UsageError("--mode flow needs --flows <path>");
  if (analyze && mode === "flow") throw new UsageError("--analyze applies only to --mode page and spider");
  if (engine === "playwright" && mode !== "flow") throw new UsageError(`--engine playwright is not offered for --mode ${mode} (SPEC-0.1.3 §2, owner decision D7)`);
  const m = loadManifest(need(argv, "--config"));
  assertEnv(m, argv);
  if (!m.transports.order.includes(ENGINE_TRANSPORT[engine])) throw new UsageError(`--engine ${rawEngine} needs transport ${ENGINE_TRANSPORT[engine]} in the manifest transports.order; a flag never overrides manifest policy`);
  if (engine === "playwright" && m.profile === "production") throw new UsageError("--engine playwright is development only");
  const url = arg(argv, "--url");
  let urls: string[] | undefined;
  if (url !== undefined) {
    let u: URL;
    try { u = new URL(need(argv, "--url")); } catch { throw new UsageError("--url must be an absolute http(s) URL"); }
    const d = new ScopeGate(m).checkRequest(u.toString(), "GET");
    if (!d.allowed) throw new UsageError(`--url is outside the manifest scope: ${d.reason}; nothing was sent`);
    urls = [u.toString()];
  }
  const eng: NonNullable<RunResult["engine"]> = { requested: rawEngine, used: engine, analyze };
  if (mode === "flow") {
    const sel = selectFlows(m, argv);
    if (engine === "playwright") {
      // BLOCKED engine: nothing runs on it and nothing falls back to http (S6).
      process.stderr.write(`${sel.docs.length} flow(s) NOT_TESTED: engine playwright is blocked (governance entry PENDING_REVIEW, S1 enforcement not demonstrated; milestone M1b)\n`);
      return 2;
    }
    return await runAndReport(m, argv, { flows: sel.docs, flowsOnly: true, warnings: sel.warnings, scanMode: "flow", engine: eng });
  }
  const notTested = analyze ? ["analysis NOT_TESTED: the page-model analyzer is not available yet (milestone 0.1.3-b)"] : [];
  return await runAndReport(m, argv, { scanMode: mode, engine: eng, notTested, ...(urls ? { urls } : {}), ...(mode === "spider" ? { spider: true } : {}) });
}

function workspaceCommand(argv: string[]): number {
  const [sub, ...rest] = argv;
  const project = arg(rest, "--project") ?? process.cwd();
  if (sub === "status") {
    const s = workspaceStatus(project);
    print(`project: ${s.root}`);
    for (const c of s.categories) print(`  ${c.present ? "present" : "absent "} ${String(c.entries).padStart(5)}  ${c.name}`);
    if (!s.work.length) print("work directories: none");
    for (const w of s.work) print(`  work ${w.dir}: ${w.stale ? "stale (removable by clean)" : `preserved: ${w.reason}`}`);
    print("Nothing was changed.");
    return s.work.some((w) => w.stale) ? 4 : 0;
  }
  if (sub === "clean") {
    const dry = rest.includes("--dry-run");
    const r = sweepStale(projectRoot(project), { dryRun: dry });
    for (const d of r.removed) print(`${dry ? "would remove" : "removed"} .navsentry/work/${d}`);
    for (const p of r.preserved) print(`preserved .navsentry/work/${p.dir}: ${p.reason}`);
    print(dry ? "dry run: nothing was changed" : `removed ${r.removed.length}; preserved ${r.preserved.length}. Manifests, flows, reports and proposals are never cleaned.`);
    return r.preserved.some((p) => p.reason.startsWith("cleanup failed")) ? 4 : 0;
  }
  throw new UsageError("workspace needs a subcommand: status | clean");
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
  if (drafts && m.profile === "production") throw new UsageError("--include-drafts is refused for production targets; approve the flows first");
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
