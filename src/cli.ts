#!/usr/bin/env node
/**
 * NavSentry CLI. Exit codes (CLI status is separate from the security result):
 *   0 = completed, no findings in tested scope   1 = completed with findings
 *   2 = incomplete run (gaps/errors)              3 = usage / configuration error
 *   4 = WORKSPACE_DIRTY (leftover, unexpected project change, or cleanup failure; 0.1.3)
 * When several apply, precedence is 3 > 4 > 1 > 2 > 0.
 */
import { randomUUID } from "node:crypto";
import { SNAPSHOT } from "./knowledge/advisories.js";
import { lookup, snapshotStatus } from "./knowledge/model.js";
import { ProposalError, parseProposal, propose } from "./knowledge/propose.js";
import { evaluateEvidence } from "./knowledge/evidence.js";
import { MAX_SPEC_BYTES, OpenApiError, importOpenApi, parseOpenApiText } from "./inventory/openapi.js";
import { inventoryTree } from "./inventory/tree.js";
import { parseExtractor, type ExtractorSpec } from "./analyzer/extractor.js";
import { validatePageModel } from "./analyzer/page-model.js";
import { Redactor } from "./redact.js";
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { CASES, CATEGORIES } from "./catalog.js";
import { compareRuns, renderCompareMarkdown } from "./compare.js";
import { ConfigError, loadManifest } from "./config.js";
import { DoctorError, HOSTS, applySkillUpdate, doctorReport, launchCheck, packageRoot, normalizeHost, planSkillUpdate, pluginCommands, type Host } from "./doctor.js";
import { renderJson, renderMarkdown, renderSarif, securityResult, validateRunResult, verdict, VERDICT_MARK } from "./report/render.js";
import { executeTest, planRun } from "./runner.js";
import { analyzeRun } from "./flow/analyze.js";
import { approveText, initTemplate } from "./flow/author.js";
import { ApproveError, confirmApproval, isApproved, selectForApproval, type ApprovePrompter } from "./flow/approve.js";
import { bindManifest, classify } from "./flow/classify.js";
import { manualLine } from "./flow/execute.js";
import { lintFlows } from "./flow/lint.js";
import { FLOW_ID, FlowError, loadFlowFiles, parseFlowText, type FlowDoc } from "./flow/parse.js";
import { LoginDraftError, loginFlowFromDraft, type LoginDraft } from "./flow/login.js";
import { renderFlowSection, renderJunit, renderTestMarkdown, validateFlowRunResult } from "./report/flow-render.js";
import type { Manifest } from "./config.js";
import type { AnalyzerResult, CodeInventory, Engine, FlowRunResult, RunResult, ScanMode } from "./types.js";
import type { FixtureLifecycle } from "./fixtures/lifecycle.js";
import { SignalCoordinator } from "./fixtures/signals.js";
import { WorkspaceError, authorize, cleanCache, beginRun, endRun, projectRoot, releaseWorkDir, sweepStale, workspaceStatus } from "./workspace.js";
import { allAdapters } from "./transports/registry.js";
import { ScopeGate } from "./scope.js";
import { TOOL_VERSION } from "./types.js";
import { SessionRefused, sendCommand, startSession } from "./visual/session.js";
import { renderVisualSession } from "./visual/report.js";
import { draftFlowFromSession } from "./visual/flow-draft.js";
import { MAX_RECORDING_BYTES, RecordingError, importRecording, recordingOrigin } from "./flow/recording.js";
import { MAX_NAVREC_BYTES, importNavrec, isZip } from "./flow/navrec.js";
import { renderHtml } from "./report/html.js";
import { paint } from "./report/color.js";
import { nextSteps, renderNext } from "./next.js";
import { runMcpServer } from "./mcp.js";
import { cliTransportCheck, type CliKind } from "./transports/cli-http.js";
import { MANIFEST_FILE, buildManifest, renderVerify, verifyRun } from "./integrity.js";
import { fileURLToPath } from "node:url";
import { DEFAULT_MANIFEST, INIT_ENVIRONMENTS, InitError, askInit, buildInitManifest, insideNavSentryCheckout, type InitEnvironment } from "./init.js";
import { createInterface } from "node:readline/promises";

const HELP = `navsentry ${TOOL_VERSION} — Navigate. Validate. Secure.
Authorized targets only. Default mode is observe (GET/HEAD/OPTIONS + TLS handshake).

Usage:
  navsentry doctor [--host claude|codex|gemini|antigravity|agy] [--project <dir>] [--json]
  navsentry doctor update --host <host> --scope user|project [--project <dir>] [--dry-run]
  navsentry integrations
  navsentry init <url> [--environment local|dev|staging|production] [--lang en|th] [--out <file>]
                 asks you (on a terminal) to confirm authorization, then writes navsentry.json.
                 Every command below uses ./navsentry.json when --config is omitted.
  navsentry validate --config <manifest.json>
  navsentry plan --config <manifest.json> [--flows <path>] [--flows-only] [--include-drafts]   (zero network)
  navsentry discover --config <manifest.json> --dry-run
  navsentry test --config <manifest.json> [--transport direct-http|curl-cli|powershell-http] [--out <dir>] [--profile safe] [--env development|production] [--project <dir>]
                 [--flows <path>] [--flows-only] [--include-drafts] [--only <id,...>] [--level integration|e2e] [--junit]
  navsentry scan [--config <manifest.json>] [--mode page|spider|flow] [--deep] [--engine http|playwright|analyzer] [--transport direct-http|curl-cli|powershell-http] [--analyze [--extractors <dir>]]
                 [--env development|production] [--url <in-scope URL>] [--flows <path>] [--out <dir>] [--project <dir>]
                 no --mode means page; --deep means spider with --analyze. page without --url scans the seed paths, like test; flow equals test --flows <path> --flows-only.
                 spider crawls from the seed paths, grouping pages by template; scan --engine computer-use exits 3: use browse.
  navsentry browse start [--config <manifest.json>] --url <in-scope URL> [--actor <name>] [--idle-seconds <n>] [--out <dir>] [--project <dir>] [--headed]
  navsentry browse screenshot|snapshot|status --session <id> [--project <dir>]
  navsentry browse click --ref <e12> | --x <px> --y <px> --session <id>      (refs come from snapshot)
  navsentry browse type --ref <e12> --env NAVSENTRY_<NAME> | --text <text> --session <id>   (no values in logs; no literal text in password fields)
  navsentry browse key --key Enter|Tab|Escape|Backspace|Arrow*|PageUp|PageDown|Home|End --session <id>
  navsentry browse scroll --dx <px> --dy <px> --session <id>
  navsentry browse end --session <id> [--save-flow <dir>]   (writes a draft flow from the action log)
                 visual driver (development only, transports.visual_computer_use: true): NavSentry owns the browser,
                 every request goes through ScopeGate and the Budget; start runs until end, idle timeout or deadline.
  navsentry workspace status|clean [--project <dir>] [--dry-run] [--cache-max-age-days <n>]
  navsentry knowledge status [--json]
  navsentry knowledge lookup --product <name> [--version <v>] | --id <CVE|advisory|alias> [--json]
  navsentry knowledge propose --input <file.json> [--config <manifest.json>] [--project <dir>]   (offline)
  navsentry report --input <run.json|flows.json> --format markdown|html|json|sarif|junit [--lang en|th] [--out <file>]   (--no-color on any command)
  navsentry verify --run <dir> [--json]   (checks the run folder against MANIFEST.json; exit 1 on any change)
  navsentry compare --before <dir|run.json> --after <dir|run.json>   (reads flows.json beside run.json)
  navsentry catalog [--category <CODE>]

For agents:
  navsentry next --run <dir|run.json> [--json]   (zero network: actions by level, gaps, next commands)
  navsentry mcp   local MCP server over stdio (no listener); tools run this CLI with every safety gate
  --json on test, scan and compare prints a machine-readable summary instead of text

Story flows (Markdown test cases; zero network):
  navsentry flow init --id <id> --title <title> [--story <text>] [--level auto|integration|e2e] --out <dir>
  navsentry flow analyze --config <manifest.json> --from-run <run.json> --out <dir> [--lang en|th]
  navsentry flow import --openapi <spec.json> --config <manifest.json> --out <dir>   (local OpenAPI JSON → drafts)
  navsentry flow from-recording --input <recording.json> [--config <manifest.json>] --out <dir>   (DevTools Recorder JSON or NavSentry Recorder .navrec.zip → draft)
  navsentry flow login-from-draft --flows <draft.flow.md> --actor <name> --out <dir>   (sign-in draft → login flow + manifest entries to add by hand; no network)
  navsentry inventory --config <manifest.json> [--project <dir>] [--out <dir>]   (development: read-only code inventory)
  navsentry flow lint --config <manifest.json> --flows <path>
  navsentry flow approve --flows <file|dir> [--by <name>] [--config <manifest>] [--reference <ref>] [--root <flows-dir>]   (owner only, interactive terminal: one summary and one yes for every draft)
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

/** `--config <m>`, or `./navsentry.json` when it exists (SPEC-0.3.0 §3.1, owner decision D2). */
function configPath(argv: string[]): string {
  if (argv.includes("--config")) return need(argv, "--config");
  const def = resolve(DEFAULT_MANIFEST);
  if (existsSync(def)) {
    process.stderr.write(`using ${DEFAULT_MANIFEST} in the current directory\n`);
    return def;
  }
  throw new UsageError(`missing --config (or create ${DEFAULT_MANIFEST} here with \`navsentry init <url>\`)`);
}

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
        const m = loadManifest(configPath(rest));
        print(`OK manifest: project=${m.project} environment=${m.environment} mode=${m.safety.mode} origins=${m.targets.origins.join(",")}`);
        return 0;
      }
      case "flow":
        return await flowCommand(rest);
      case "plan":
      case "discover": {
        if (cmd === "discover" && !rest.includes("--dry-run")) throw new UsageError("live discovery is `navsentry scan --mode spider` (0.1.3); `discover --dry-run` stays the zero-network plan");
        const m = loadManifest(configPath(rest));
        assertEnv(m, rest);
        const sel = arg(rest, "--flows") ? selectFlows(m, rest) : undefined;
        const plan = planRun(m, process.env, sel ? { flows: sel.docs, flowsOnly: rest.includes("--flows-only"), warnings: sel.warnings } : {});
        print(JSON.stringify(plan, null, 2));
        return 0;
      }
      case "test": {
        const profile = arg(rest, "--profile");
        if (profile && profile !== "safe") throw new UsageError("only --profile safe is supported");
        const m = loadManifest(configPath(rest));
        assertEnv(m, rest);
        if (rest.includes("--flows-only") && !arg(rest, "--flows")) throw new UsageError("--flows-only needs --flows");
        const sel = arg(rest, "--flows") ? selectFlows(m, rest) : undefined;
        return await runAndReport(m, rest, sel ? { flows: sel.docs, flowsOnly: rest.includes("--flows-only"), warnings: sel.warnings } : {});
      }
      case "scan":
        return await scan(rest);
      case "init":
        return await initCommand(rest);
      case "mcp":
        return await runMcpServer({ cliPath: fileURLToPath(import.meta.url) });
      case "next": {
        // Zero network: reads run.json (and flows.json beside it) and lists the next steps.
        const p = need(rest, "--run");
        const runFile = statSync(p).isDirectory() ? join(p, "run.json") : p;
        const r = validateRunResult(JSON.parse(readFileSync(runFile, "utf8")));
        const fp = join(dirname(runFile), "flows.json");
        const fr = existsSync(fp) ? validateFlowRunResult(JSON.parse(readFileSync(fp, "utf8"))) : undefined;
        const n = nextSteps(r, fr, dirname(resolve(runFile)), securityResult(r));
        print(rest.includes("--json") ? JSON.stringify(n, null, 2) : paint(renderNext(n)));
        return 0;
      }
      case "workspace":
        return workspaceCommand(rest);
      case "knowledge":
        return knowledgeCommand(rest);
      case "inventory":
        return inventoryCommand(rest);
      case "browse":
        return await browseCommand(rest);
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
        let body: string;
        if (fmt === "markdown") body = renderMarkdown(r, lang);
        else if (fmt === "html") body = renderHtml(renderMarkdown(r, lang), `NavSentry report — ${r.project}`, lang);
        else if (fmt === "json") body = renderJson(r);
        else if (fmt === "sarif") body = JSON.stringify(renderSarif(r), null, 2);
        else throw new UsageError("format must be markdown|html|json|sarif");
        const outFile = arg(rest, "--out");
        if (outFile) {
          // Never overwrite: the run directory already holds reports written by scan.
          if (existsSync(resolve(outFile))) throw new UsageError(`${resolve(outFile)} already exists; NavSentry never overwrites a report (choose another --out path)`);
          writeFileSync(resolve(outFile), body.endsWith("\n") ? body : body + "\n", { flag: "wx" });
          print(`Wrote ${resolve(outFile)}`);
        } else if (fmt === "html" && process.stdout.isTTY) {
          throw new UsageError("HTML is a file to open in a browser, not terminal output. Add --out <file>.html (scan already wrote REPORT.html in the run folder)");
        } else print(body);
        return 0;
      }
      case "verify": {
        const dir = need(rest, "--run");
        const v = verifyRun(statSync(dir).isDirectory() ? dir : dirname(dir));
        print(rest.includes("--json") ? JSON.stringify({ kind: "navsentry-verify", ...v }, null, 2) : renderVerify(v));
        return v.status === "PASS" ? 0 : 1;
      }
      case "compare": {
        const runPath = (p: string) => (statSync(p).isDirectory() ? join(p, "run.json") : p);
        const bp = runPath(need(rest, "--before")), ap = runPath(need(rest, "--after"));
        const b = validateRunResult(JSON.parse(readFileSync(bp, "utf8")));
        const a = validateRunResult(JSON.parse(readFileSync(ap, "utf8")));
        const fb = join(dirname(bp), "flows.json"), fa = join(dirname(ap), "flows.json");
        const flows = existsSync(fb) && existsSync(fa) ? { before: validateFlowRunResult(JSON.parse(readFileSync(fb, "utf8"))), after: validateFlowRunResult(JSON.parse(readFileSync(fa, "utf8"))) } : undefined;
        const c = compareRuns(b, a, flows);
        print(rest.includes("--json") ? JSON.stringify({ kind: "navsentry-compare", ...c }, null, 2) : paint(renderCompareMarkdown(c)));
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
    if (e instanceof ConfigError || e instanceof UsageError || e instanceof DoctorError || e instanceof FlowError || e instanceof WorkspaceError || e instanceof ProposalError || e instanceof OpenApiError || e instanceof RecordingError) {
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

interface RunOpts { analyze?: { extractors: string[]; draftsDir?: string }; assets?: boolean; urls?: string[]; spider?: boolean; flows?: FlowDoc[]; flowsOnly?: boolean; warnings?: string[]; scanMode?: ScanMode; engine?: RunResult["engine"]; notTested?: string[]; browser?: boolean }

/** Executes a run inside a managed workspace (SPEC-0.1.3 §7.2), writes the reports and returns the exit code. */
async function runAndReport(m: Manifest, argv: string[], o: RunOpts): Promise<number> {
  for (const w of o.warnings ?? []) process.stderr.write(`warning: ${w}\n`);
  // M3 (SPEC-0.4.0 D2): every request through curl or PowerShell instead of direct-http; refused before the run starts.
  const tArg = arg(argv, "--transport");
  let httpTransport: { kind: CliKind; file: string } | undefined;
  if (tArg && tArg !== "direct-http") {
    if (o.browser) throw new UsageError("--transport applies to the http engine; the playwright engine sends through direct-http");
    const c = cliTransportCheck(tArg, m.transports.order, m.safety.mode);
    if ("refused" in c) throw new UsageError(c.refused);
    httpTransport = { kind: tArg as CliKind, file: c.file };
  }
  const runId = randomUUID();
  // safe-validate: signals go through the coordinator so cleanup runs before the exit (SPEC-0.2.0 §6.2).
  const sv = m.safety.mode === "safe-validate";
  const ws = beginRun(arg(argv, "--project") ?? process.cwd(), runId, m.workspace.ignore, { coordinatedSignals: sv });
  const coord = sv ? new SignalCoordinator((code, lines) => { for (const l of lines) process.stderr.write(`${l}\n`); process.stderr.write("second signal: cleanup skipped; fixtures.pending.json kept for the next run's sweep\n"); process.exit(code); }).install() : undefined;
  let res: Awaited<ReturnType<typeof executeTest>>;
  // Replay timeline: step screenshots go to the run work dir first, then into <run>/shots/ (git-ignored).
  const shotsWork = join(ws.work.path, "shots");
  if (o.browser) mkdirSync(shotsWork, { recursive: true });
  const analyzer: AnalyzerResult | undefined = o.analyze ? { engine: "node-page-model", pages: 0, withheld: 0, incomplete: 0, includeText: m.analyzer.include_text, extractors: [], refused: [] } : undefined;
  let specs: ExtractorSpec[] = [];
  if (o.analyze && analyzer) specs = loadExtractors(ws.root, ws.work.path, o.analyze.draftsDir, analyzer);
  try {
    res = await executeTest(m, { ...(sv ? { fixtureWorkDir: ws.work.path, onFixtures: (l: FixtureLifecycle) => coord!.attach(l), pendingFromPreviousRuns: ws.sweep.pendingFixtures } : {}), ...(o.analyze ? { analyze: { extractors: specs } } : {}), runId, ...(o.flows ? { flows: o.flows, flowsOnly: !!o.flowsOnly } : {}), ...(o.scanMode ? { scanMode: o.scanMode } : {}), ...(o.engine ? { engine: o.engine } : {}), ...(o.urls ? { urls: o.urls } : {}), ...(o.spider ? { spider: true } : {}), ...(o.browser ? { browser: { shotsDir: shotsWork } } : {}), ...(httpTransport ? { httpTransport } : {}),
      ...(o.assets ? { assets: true, workDir: ws.work.path, cacheDir: join(ws.root, ".navsentry", "cache", "assets") } : {}) });
  } catch (e) {
    coord?.dispose();
    ws.dispose();
    try { releaseWorkDir(ws.work); } catch { /* reported by the next run's sweep */ }
    throw e;
  }
  const { run: r, flowRun, clientFindings, proposals, pageModels } = res;
  const shots = new Map<string, Buffer>();
  for (const s of flowRun?.flows.flatMap((f) => f.steps) ?? []) {
    if (!s.screenshot) continue;
    try { shots.set(s.screenshot, readFileSync(join(shotsWork, s.screenshot))); } catch { delete s.screenshot; }
  }
  // Page models are promoted only after the Redactor and the artifact leak scan (§7.2 step 5).
  const models: [string, string][] = [];
  if (analyzer && pageModels) {
    const leak = new Redactor(Object.values(process.env).filter((v): v is string => typeof v === "string" && v.length >= 12 && Object.values(m.actors).some((a) => [a.authorization_header_env, a.password_env, a.username_env].some((k) => k && process.env[k] === v))));
    pageModels.forEach((pm, i) => {
      const json = JSON.stringify(pm, null, 2) + "\n";
      if (leak.text(json).outcome.kinds.includes("known-secret")) { analyzer.withheld++; return; }
      models.push([`page-models/${String(i + 1).padStart(3, "0")}.json`, json]);
    });
    analyzer.pages = models.length;
    analyzer.incomplete = pageModels.filter((p) => p.incomplete).length;
    if (analyzer.withheld) r.incompleteReasons.push(`analyzer: ${analyzer.withheld} page model(s) withheld by the leak scan`);
    r.analyzer = analyzer;
    if (r.assets?.cost) r.assets.cost.agentVisibleBytes += models.reduce((a, [, c]) => a + Buffer.byteLength(c), 0);
  }
  // §6.6-D trigger 1: every scan turns its own knowledge gaps into local research-needed proposals.
  if (o.scanMode && proposals?.length && r.knowledge) {
    for (const p of proposals) {
      try {
        const out = propose(ws.root, p, SNAPSHOT);
        r.knowledge.proposals.push({ id: out.id, status: out.status });
      } catch (e) {
        r.incompleteReasons.push(`knowledge proposal not written: ${(e as Error).message.split("\n")[0]}`);
      }
    }
  }
  if (o.notTested?.length) { r.incompleteReasons.push(...o.notTested); if (r.executionStatus === "COMPLETE") r.executionStatus = "PARTIAL"; }
  for (const p of ws.sweep.preserved) r.incompleteReasons.push(`work directory preserved during sweep: ${p.reason}`);
  if (ws.sweep.pendingFixtures.length) r.incompleteReasons.push(`${ws.sweep.pendingFixtures.length} fixture intent(s) from an interrupted run may be leftovers (see run.json fixtures.pendingFromPreviousRuns); NavSentry deleted nothing`);
  const outArg = arg(argv, "--out");
  const out = outArg ? resolve(outArg) : join(ws.root, ".navsentry", "runs", r.runId);
  mkdirSync(out, { recursive: true });
  const lang = m.report.language;
  const written: string[] = [];
  const write = (): number => {
    written.length = 0;
    // The agent-facing summary is written first so its size is recorded in run.json (§6.4-C item 7).
    const cf = clientFindings ? JSON.stringify({ kind: "navsentry-client-findings", schemaVersion: "1", runId: r.runId, entries: clientFindings, truncated: r.assets?.clientFindings.truncated ?? 0 }, null, 2) + "\n" : undefined;
    if (cf && r.assets?.cost) r.assets.cost.agentVisibleBytes = Buffer.byteLength(cf);
    const files: [string, string][] = [["run.json", renderJson(r)]];
    if (cf) files.push(["client-findings.json", cf]);
    files.push(...models);
    if (m.report.formats.includes("markdown")) {
      const md = renderMarkdown(r, lang, flowRun?.functionalResult) + (flowRun ? "\n" + renderFlowSection(flowRun, r, lang) : "");
      files.push(["REPORT.md", md], ["REPORT.html", renderHtml(md, `NavSentry report — ${r.project}`, lang)]);
    }
    if (m.report.formats.includes("sarif")) files.push(["report.sarif", JSON.stringify(renderSarif(r), null, 2)]);
    if (flowRun) {
      files.push(["flows.json", JSON.stringify(flowRun, null, 2) + "\n"]);
      files.push(["TEST-REPORT.md", renderTestMarkdown(flowRun, r, lang)]);
      if (argv.includes("--junit")) files.push(["junit.xml", renderJunit(flowRun)]);
    }
    if (models.length) mkdirSync(join(out, "page-models"), { recursive: true });
    for (const [n, c] of files) { authorize(ws, join(out, n)); writeFileSync(join(out, n), c); written.push(n); }
    if (shots.size) {
      // Screenshots can show personal data from the page: kept beside the report, never committed.
      mkdirSync(join(out, "shots"), { recursive: true });
      authorize(ws, join(out, "shots", ".gitignore"));
      writeFileSync(join(out, "shots", ".gitignore"), "*\n");
      written.push("shots/.gitignore");
      for (const [n, b] of shots) { authorize(ws, join(out, "shots", n)); writeFileSync(join(out, "shots", n), b); written.push(`shots/${n}`); }
    }
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
  // Integrity manifest (SPEC-0.4.0 §3): sizes and SHA-256 of what this run wrote, checked by `navsentry verify`.
  writeFileSync(join(out, MANIFEST_FILE), JSON.stringify(buildManifest(out, r.runId, TOOL_VERSION, written), null, 2) + "\n");
  const sec = securityResult(r);
  if (r.workspace.status === "FAIL") process.stderr.write(`WORKSPACE_DIRTY: created=${r.workspace.created.length} modified=${r.workspace.modified.length} deleted=${r.workspace.deleted.length} cleanup=${r.workspace.cleanup}\n`);
  if (argv.includes("--json")) {
    // Machine-readable summary for agents (SPEC-0.3.0 §3.2): paths, counts by level, gaps and next commands.
    const n = nextSteps(r, flowRun, out, sec);
    const vd = verdict(r, lang, flowRun?.functionalResult);
    print(JSON.stringify({ ...n, kind: "navsentry-run-summary", verdict: { kind: vd.kind, count: vd.count, text: vd.text }, exitCode: exitCode(r, flowRun), findings: r.findings.length, requests: r.budget.requestsUsed, workspace: r.workspace.status, ...(flowRun ? { functionalResult: flowRun.functionalResult, flows: flowRun.flows.length, testReport: join(out, "TEST-REPORT.md") } : {}), runJson: join(out, "run.json") }, null, 2));
  } else {
    print(paint(`execution=${r.executionStatus} security=${sec} findings=${r.findings.length} requests=${r.budget.requestsUsed}${flowRun ? ` functional=${flowRun.functionalResult} flows=${flowRun.flows.length}` : ""} workspace=${r.workspace.status}`));
    const vd = verdict(r, lang, flowRun?.functionalResult);
    print(paint(`${VERDICT_MARK[vd.kind]} ${vd.text}`));
    print(paint(`REPORT: ${join(out, "REPORT.md")}`));
    if (m.report.formats.includes("markdown")) print(paint(`Open in a browser: ${join(out, "REPORT.html")}`));
    if (flowRun) print(`TEST-REPORT: ${join(out, "TEST-REPORT.md")}`);
  }
  for (const x of r.fixtures?.leftovers ?? []) process.stderr.write(`LEFTOVER ${x.fixture} ${x.displayId}: ${x.manualAction}\n`);
  coord?.dispose();
  if (coord?.signal) return coord.signal === "SIGINT" ? 130 : 143;
  return exitCode(r, flowRun);
}

const ENGINE_TRANSPORT: Record<Engine, string> = { http: "direct-http", playwright: "playwright-browser", "computer-use": "visual-computer-use" };

/** `scan` (SPEC-0.1.3 §3). Every invalid combination exits 3 before any I/O. */
async function scan(argvIn: string[]): Promise<number> {
  let argv = argvIn;
  const deep = argv.includes("--deep");
  if (deep && argv.includes("--mode") && arg(argv, "--mode") !== "spider") throw new UsageError("--deep means --mode spider --analyze; it cannot be combined with another mode");
  if (deep && !argv.includes("--analyze")) argv = [...argv, "--analyze"];
  const mode = argv.includes("--mode") ? need(argv, "--mode") : deep ? "spider" : "page";
  if (mode !== "page" && mode !== "spider" && mode !== "flow") throw new UsageError("--mode must be page, spider or flow");
  const rawEngine = arg(argv, "--engine") ?? "http";
  if (rawEngine === "computer-use") throw new UsageError("--engine computer-use does not drive a host-owned browser (S1 cannot be enforced there); use `navsentry browse start` (visual driver on the playwright engine, ADR-0009)");
  if (rawEngine !== "http" && rawEngine !== "playwright" && rawEngine !== "analyzer") throw new UsageError("--engine must be http, playwright or analyzer");
  const analyze = argv.includes("--analyze") || rawEngine === "analyzer";
  const engine: Engine = rawEngine === "analyzer" ? "http" : rawEngine;
  if (arg(argv, "--url") !== undefined && mode !== "page") throw new UsageError("--url applies only to --mode page");
  if (arg(argv, "--flows") !== undefined && mode !== "flow") throw new UsageError("--flows applies only to --mode flow");
  if (mode === "flow" && !arg(argv, "--flows")) throw new UsageError("--mode flow needs --flows <path>");
  if (analyze && mode === "flow") throw new UsageError("--analyze applies only to --mode page and spider");
  if (arg(argv, "--extractors") !== undefined && !analyze) throw new UsageError("--extractors needs --analyze");
  if (engine === "playwright" && mode !== "flow") throw new UsageError(`--engine playwright is not offered for --mode ${mode} (SPEC-0.1.3 §2, owner decision D7)`);
  const m = loadManifest(configPath(argv));
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
    return await runAndReport(m, argv, { flows: sel.docs, flowsOnly: true, warnings: sel.warnings, scanMode: "flow", engine: eng, ...(engine === "playwright" ? { browser: true } : {}) });
  }
  const drafts = arg(argv, "--extractors");
  return await runAndReport(m, argv, { scanMode: mode, engine: eng, assets: true, ...(analyze ? { analyze: { extractors: [], ...(drafts ? { draftsDir: resolve(need(argv, "--extractors")) } : {}) } } : {}), ...(urls ? { urls } : {}), ...(mode === "spider" ? { spider: true } : {}) });
}

/**
 * `browse` (ADR-0009): the visual driver. `start` holds the browser and the run's safety state until the
 * session ends; the other subcommands talk to it over a local pipe. Screenshot paths point into the run's
 * work directory, which is deleted when the session ends.
 */
async function browseCommand(argv: string[]): Promise<number> {
  const sub = argv[0];
  const rest = argv.slice(1);
  const project = arg(rest, "--project") ?? process.cwd();
  if (sub === "start") {
    const m = loadManifest(configPath(rest));
    assertEnv(m, rest);
    let url: string;
    try { url = new URL(need(rest, "--url")).toString(); } catch { throw new UsageError("--url must be an absolute http(s) URL"); }
    const idle = arg(rest, "--idle-seconds");
    const idleSeconds = idle === undefined ? 300 : Number(idle);
    if (!Number.isInteger(idleSeconds) || idleSeconds < 10 || idleSeconds > 3600) throw new UsageError("--idle-seconds must be an integer between 10 and 3600");
    let h: Awaited<ReturnType<typeof startSession>>;
    try {
      h = await startSession({ manifest: m, projectDir: project, url, idleSeconds, headed: rest.includes("--headed"), ...(arg(rest, "--actor") ? { actor: need(rest, "--actor") } : {}) });
    } catch (e) {
      if (e instanceof SessionRefused) throw new UsageError(e.message);
      throw e;
    }
    print(`SESSION: ${h.id}`);
    const { result, workspace, saveFlow } = await h.done;
    const outArg = arg(rest, "--out");
    const out = outArg ? resolve(outArg) : join(workspace.root, ".navsentry", "runs", `browse-${h.id}`);
    let flowFile: string | undefined;
    if (saveFlow) {
      // A draft flow from the action log; never overwrites, and it is an authorized write in the project.
      try {
        const d = draftFlowFromSession(result);
        mkdirSync(saveFlow, { recursive: true });
        flowFile = join(saveFlow, `${d.id}.flow.md`);
        if (existsSync(flowFile)) throw new Error(`${flowFile} already exists`);
        authorize(workspace, flowFile);
        writeFileSync(flowFile, d.text, { flag: "wx" });
        result.flowDraft = flowFile;
      } catch (e) {
        result.incompleteReasons.push(`--save-flow: ${(e as Error).message}`);
        flowFile = undefined;
      }
    }
    const write = () => {
      mkdirSync(out, { recursive: true });
      for (const [n, c] of [["session.json", JSON.stringify(result, null, 2)], ["VISUAL-SESSION.md", renderVisualSession(result)]] as const) { authorize(workspace, join(out, n)); writeFileSync(join(out, n), c); }
      return 2 + (flowFile ? 1 : 0);
    };
    const promoted = write();
    result.workspace = endRun(workspace, promoted);
    if (result.workspace.status !== "PASS") result.incompleteReasons.push(`workspace check ${result.workspace.status}`);
    write();
    print(`ended=${result.endReason} actions=${result.actions.length} requests=${result.requests.length} findings=${result.findings.length} workspace=${result.workspace.status}`);
    print(`REPORT: ${join(out, "VISUAL-SESSION.md")}`);
    if (flowFile) print(`FLOW: ${flowFile}`);
    if (result.workspace.status === "FAIL") return 4;
    if (result.findings.length) return 1;
    return result.executionStatus === "COMPLETE" ? 0 : 2;
  }
  const cmds = ["screenshot", "snapshot", "click", "type", "key", "scroll", "status", "end"] as const;
  if (!cmds.includes(sub as (typeof cmds)[number])) throw new UsageError("browse start|screenshot|snapshot|click|type|key|scroll|status|end");
  const id = need(rest, "--session");
  if (!/^[A-Za-z0-9-]{8,64}$/.test(id)) throw new UsageError("--session must be a session id printed by browse start");
  const num = (k: string) => { const v = Number(need(rest, k)); if (!Number.isInteger(v)) throw new UsageError(`${k} must be an integer`); return v; };
  let cmd: Parameters<typeof sendCommand>[1];
  if (sub === "click") cmd = rest.includes("--ref") ? { cmd: "click", ref: need(rest, "--ref") } : { cmd: "click", x: num("--x"), y: num("--y") };
  else if (sub === "scroll") cmd = { cmd: "scroll", dx: num("--dx"), dy: num("--dy") };
  else if (sub === "type") {
    // The value never travels on the command line for --env: only the variable name does.
    if (rest.includes("--env") === rest.includes("--text")) throw new UsageError("browse type needs --ref and exactly one of --env NAVSENTRY_<NAME> or --text <text>");
    const i = rest.indexOf("--text");
    if (i >= 0 && (rest[i + 1] === undefined || rest[i + 1]!.startsWith("--"))) throw new UsageError("--text needs a value that does not start with --");
    cmd ={ cmd: "type", ref: need(rest, "--ref"), ...(i >= 0 ? { text: rest[i + 1] ?? "" } : { env: need(rest, "--env") }) };
  } else if (sub === "key") cmd = { cmd: "key", key: need(rest, "--key") };
  else if (sub === "end") cmd = { cmd: "end", ...(rest.includes("--save-flow") ? { saveFlow: resolve(need(rest, "--save-flow")) } : {}) };
  else cmd = { cmd: sub as "screenshot" | "snapshot" | "status" };
  let res: Record<string, unknown>;
  try {
    res = await sendCommand(join(projectRoot(project), ".navsentry", "work", id), cmd);
  } catch (e) {
    if (e instanceof SessionRefused) throw new UsageError(e.message);
    throw e;
  }
  print(JSON.stringify(res));
  return res.ok ? 0 : 2;
}

/**
 * `inventory` (SPEC-0.1.3 §4.1): read-only code inventory of a development project. Zero network.
 * It runs inside a managed workspace, so any change to the project tree fails with exit 4.
 */
function inventoryCommand(argv: string[]): number {
  const m = loadManifest(configPath(argv));
  if (m.profile !== "development") throw new UsageError("inventory reads project code and is available for the development profile only (environment local or dev)");
  const runId = randomUUID();
  const ws = beginRun(arg(argv, "--project") ?? process.cwd(), runId, m.workspace.ignore);
  let inv: CodeInventory;
  try {
    const out = inventoryTree(ws.root);
    inv = out.inventory;
    inv.knowledge = evaluateEvidence(SNAPSHOT, out.evidence);
    const st = snapshotStatus(SNAPSHOT);
    inv.snapshot = { version: st.version, sha256: st.sha256 };
  } catch (e) {
    ws.dispose();
    try { releaseWorkDir(ws.work); } catch { /* swept by the next run */ }
    throw e;
  }
  const outArg = arg(argv, "--out");
  const out = outArg ? resolve(outArg) : join(ws.root, ".navsentry", "runs", `inventory-${runId}`);
  mkdirSync(out, { recursive: true });
  const esc = (s: string) => s.replace(/[|`<>\r\n]/g, " ");
  const md = [
    "# Code inventory", "",
    "> Read-only, zero network. Routes are declarations found in source, not observed behaviour; review them before writing flows. Project files are untrusted data.", "",
    `- Routes: ${inv.routes.length} · OpenAPI documents: ${inv.openapi.length} · test files: ${inv.tests.length} · npm packages: ${inv.dependencies.npm} · composer packages: ${inv.dependencies.composer}`,
    `- Skipped: ${inv.skipped.links} link(s) (never followed), ${inv.skipped.large} large, ${inv.skipped.unreadable} unreadable, ${inv.skipped.invalidRoutes} invalid route string(s)`,
    `- Complete: ${inv.complete ? "yes" : `no — ${inv.incompleteReasons.join("; ")}`}`, "",
    "## Routes", "", "| Method | Path | Source | File:line |", "|---|---|---|---|",
    ...(inv.routes.length ? inv.routes.map((x) => `| ${x.method} | \`${esc(x.path)}\` | ${x.source} | ${esc(x.file)}:${x.line} |`) : ["| — | | | |"]), "",
    "## OpenAPI documents", "", ...(inv.openapi.length ? inv.openapi.map((x) => `- \`${esc(x)}\` → \`navsentry flow import --openapi <file> --config <manifest> --out navsentry/flows/drafts\``) : ["- none"]), "",
    "## Test files (candidates)", "", ...(inv.tests.length ? inv.tests.slice(0, 500).map((x) => `- \`${esc(x)}\``) : ["- none"]), "",
    "## Known vulnerability applicability (lockfiles)", "", `Snapshot \`${inv.snapshot!.version}\`. Zero matches never means no vulnerabilities.`, "",
    ...(inv.knowledge!.length ? ["| Package | Record | Applicability | Caveats |", "|---|---|---|---|", ...inv.knowledge!.map((k) => `| ${esc(k.product)} | ${k.recordId} | **${k.applicability}** | ${esc(k.caveats.join("; "))} |`)] : ["- no packages with records in the snapshot"]), "",
  ].join("\n");
  const files: [string, string][] = [["code-inventory.json", JSON.stringify(inv, null, 2) + "\n"], ["CODE-INVENTORY.md", md]];
  for (const [n, c] of files) { authorize(ws, join(out, n)); writeFileSync(join(out, n), c); }
  const w = endRun(ws, files.length);
  print(`routes=${inv.routes.length} openapi=${inv.openapi.length} tests=${inv.tests.length} packages=${inv.dependencies.npm + inv.dependencies.composer} complete=${inv.complete} workspace=${w.status}`);
  print(`INVENTORY: ${join(out, "CODE-INVENTORY.md")}`);
  if (w.status === "FAIL") { process.stderr.write(`WORKSPACE_DIRTY: created=${w.created.length} modified=${w.modified.length} deleted=${w.deleted.length}\n`); return 4; }
  return inv.complete && w.status === "PASS" ? 0 : 2;
}

/**
 * Extractor specs (§5.4): owner-promoted specs from `<project>/navsentry/analyzer/extractors/` and
 * draft specs copied into the run's work directory (deleted with it). Only `.json` data files are
 * accepted; NavSentry never executes code from either place.
 */
function loadExtractors(root: string, work: string, draftsDir: string | undefined, out: AnalyzerResult): ExtractorSpec[] {
  const specs: ExtractorSpec[] = [];
  const read = (dir: string, source: "draft" | "promoted") => {
    let names: string[];
    try { names = readdirSync(dir).sort(); } catch { return; }
    const dest = join(work, "extractors");
    if (source === "draft") mkdirSync(dest, { recursive: true });
    for (const n of names.slice(0, 50)) {
      const p = join(dir, n);
      const st = lstatSync(p);
      if (st.isSymbolicLink() || !st.isFile()) { out.refused.push({ file: n, reason: "not a regular file" }); continue; }
      if (!n.endsWith(".json")) { out.refused.push({ file: n, reason: "refused: extractors are JSON data; NavSentry never executes code" }); continue; }
      try {
        let text = readFileSync(p, "utf8");
        if (source === "draft") { writeFileSync(join(dest, n), text, { flag: "wx", mode: 0o600 }); text = readFileSync(join(dest, n), "utf8"); }
        const s = parseExtractor(text);
        specs.push(s);
        out.extractors.push({ id: s.id, sha256: s.sha256, source, status: source === "draft" ? "deleted with the run" : "kept (owner-promoted)" });
      } catch (e) {
        out.refused.push({ file: n, reason: (e as Error).message.split("\n").slice(0, 3).join(" ") });
      }
    }
  };
  read(join(root, "navsentry", "analyzer", "extractors"), "promoted");
  if (draftsDir) read(draftsDir, "draft");
  return specs;
}

/** `knowledge status | lookup | propose` (SPEC-0.1.3 §6.6-D). Offline: zero network actions (S12). */
function knowledgeCommand(argv: string[]): number {
  const [sub, ...rest] = argv;
  if (sub === "status") {
    const s = snapshotStatus(SNAPSHOT);
    if (rest.includes("--json")) { print(JSON.stringify(s, null, 2)); return 0; }
    print(`snapshot ${s.version} · sha256 ${s.sha256.slice(0, 16)} · generated ${s.generatedAt}`);
    print(`records ${s.records} · reviewed ${s.reviewed} · stale ${s.stale}${s.verifiedAt ? ` · oldest verification ${s.verifiedAt}` : ""}`);
    print(s.note);
    if (!s.records) print("No advisory records yet: importing real records needs an approved advisory source (governance/third-party.json).");
    return 0;
  }
  if (sub === "lookup") {
    const product = arg(rest, "--product"), version = arg(rest, "--version"), id = arg(rest, "--id");
    if (!product && !id) throw new UsageError("knowledge lookup needs --product <name> or --id <CVE, advisory ID or alias>");
    const r = lookup(SNAPSHOT, { ...(product ? { product } : {}), ...(version ? { version } : {}), ...(id ? { id } : {}) });
    if (rest.includes("--json")) { print(JSON.stringify({ matches: r.matches.map((x) => ({ id: x.record.id, applicability: x.applicability, caveats: x.caveats })), ...(r.research ? { research: r.research } : {}) }, null, 2)); return 0; }
    if (r.research) print(`research needed: ${r.research.reason}${r.research.candidates.length ? ` (candidates: ${r.research.candidates.join(", ")})` : ""}`);
    for (const x of r.matches) print(`${x.record.id.padEnd(24)} ${x.applicability.padEnd(14)} ${[...x.record.identifiers.cve, ...x.record.identifiers.advisory].join(",")}  ${x.caveats.join("; ")}`);
    if (!r.matches.length && !r.research) print("no records in the local snapshot (not proof of absence)");
    return 0;
  }
  if (sub === "propose") {
    const input = JSON.parse(readFileSync(need(rest, "--input"), "utf8")) as unknown;
    const cfg = arg(rest, "--config");
    const forbidden = cfg ? loadManifest(cfg).targets.origins.map((o) => new RegExp(new URL(o).hostname.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i")) : [];
    const items = Array.isArray(input) ? input : [input];
    if (items.length > 50) throw new UsageError("at most 50 proposals per call");
    const parsed = items.map((x) => parseProposal(x, forbidden));
    const root = projectRoot(arg(rest, "--project") ?? process.cwd());
    for (const p of parsed) {
      const out = propose(root, p, SNAPSHOT);
      print(`${out.status.padEnd(9)} ${out.id} rev ${out.revision}  ${out.file}`);
    }
    print("Proposals are local and unreviewed. NavSentry fetched nothing; promotion into the snapshot is a reviewed maintainer change.");
    return 0;
  }
  throw new UsageError("knowledge needs a subcommand: status | lookup | propose");
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
    const root = projectRoot(project);
    const r = sweepStale(root, { dryRun: dry });
    const ageArg = arg(rest, "--cache-max-age-days");
    const age = ageArg === undefined ? 30 : Number(ageArg);
    if (!Number.isInteger(age) || age < 0 || age > 365) throw new UsageError("--cache-max-age-days must be an integer in [0, 365]");
    const cache = cleanCache(root, age, { dryRun: dry });
    print(`${dry ? "would remove" : "removed"} ${cache.removed} expired cache entr${cache.removed === 1 ? "y" : "ies"} (older than ${age} days)`);
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
  const eligible = (d: FlowDoc) => drafts || d.header.review.status === "approved";
  const picked = docs.filter((d) => eligible(d) && (!only || only.includes(d.header.id)) && (!level || classify(d).level === level));
  // Required flows join the selection when they are eligible; otherwise the dependent is NOT_TESTED.
  for (let i = 0; i < picked.length; i++) for (const dep of picked[i]!.deps ?? []) if (eligible(dep) && !picked.includes(dep)) picked.push(dep);
  const skippedDrafts = docs.filter((d) => d.header.review.status !== "approved" && !drafts).length;
  if (skippedDrafts) warnings.push(`${skippedDrafts} draft flow(s) skipped; approve them or pass --include-drafts (non-production only)`);
  if (!picked.length) throw new UsageError("no flows selected (drafts need --include-drafts; check --only / --level)");
  return { docs: picked, warnings };
}

/**
 * `flow approve --flows <file|dir>` (authorize once): one summary and one yes for every draft in
 * the selection. Interactive terminal only, like init: an agent cannot approve for the owner.
 * `prompter` is a test seam; the CLI passes none and builds one only on a TTY.
 */
export async function approveCommand(rest: string[], prompter?: ApprovePrompter): Promise<number> {
  const flowsArg = need(rest, "--flows");
  const target = resolve(flowsArg);
  if (!existsSync(target)) throw new UsageError(`--flows ${flowsArg} does not exist`);
  const isDir = statSync(target).isDirectory();
  // Load the whole flow root so the approval hash covers the dependency closure.
  const root = resolve(arg(rest, "--root") ?? (isDir ? target : dirname(target)));
  const { docs, problems } = loadFlowFiles(root);
  if (problems.length) throw new FlowError(problems);
  const inSel = (d: FlowDoc) => {
    const rel = relative(target, resolve(root, d.file));
    return isDir ? rel !== "" && rel !== ".." && !rel.startsWith(".." + sep) && !isAbsolute(rel) : rel === "";
  };
  if (!docs.some(inSel)) throw new UsageError(isDir ? `no .flow.md files in ${target}` : "--flows must be inside --root (default: its own directory)");
  // SPEC-0.2.0 §4.5: fixture and login entries are part of the approved content, so the manifest is
  // bound before anything is judged approved or stale.
  const cfgArg = arg(rest, "--config");
  const cfg = cfgArg ? resolve(cfgArg) : existsSync(resolve(DEFAULT_MANIFEST)) ? resolve(DEFAULT_MANIFEST) : undefined;
  const manifest = cfg ? loadManifest(cfg) : undefined;
  if (manifest) bindManifest(docs, manifest);
  const { todo, current } = selectForApproval(docs, inSel);
  // A dependent is never approved on top of a draft: unapproved dependencies join the same decision.
  const seen = new Set(todo.map((d) => d.header.id));
  const addDeps = (d: FlowDoc) => { for (const x of d.deps ?? []) if (!isApproved(x) && !seen.has(x.header.id)) { seen.add(x.header.id); todo.push(x); addDeps(x); } };
  for (const d of [...todo]) addDeps(d);
  // Checked over everything that will be approved, pulled-in dependencies included.
  for (const d of [...docs.filter(inSel), ...todo]) {
    const missing = d.header.requires.filter((id) => !d.deps?.some((x) => x.header.id === id));
    if (missing.length) throw new UsageError(`cannot approve ${d.header.id}: required flow(s) ${missing.join(", ")} not found in ${root}`);
  }
  if (!manifest && todo.some((d) => d.steps.some((s) => s.fixture))) throw new UsageError("this flow set uses fixtures: pass --config <manifest> so the approval covers the fixture entries");
  let p = prompter;
  let rl: ReturnType<typeof createInterface> | undefined;
  if (!p) {
    if (!process.stdin.isTTY || !process.stdout.isTTY) throw new UsageError(`flow approve is the owner's decision, so it runs only in an interactive terminal. Run it yourself: navsentry flow approve --flows ${flowsArg}`);
    rl = createInterface({ input: process.stdin, output: process.stdout });
    const r = rl;
    p = { ask: (q) => r.question(q), say: (l) => print(l) };
  }
  try {
    if (current.length) p.say(`already approved (unchanged): ${current.map((d) => d.header.id).join(", ")}`);
    if (!todo.length) { p.say("nothing to approve: every selected flow already has a valid approval"); return 0; }
    p.say(manifest ? `manifest: ${cfg}` : "manifest: none (no fixture or login entries are bound)");
    for (const d of todo) if (d.bindings) p.say(`  ${d.header.id} is approved together with manifest entries: ${Object.keys(JSON.parse(d.bindings)).join(", ")}`);
    for (const d of todo) if (!inSel(d)) p.say(`  ${d.header.id} is included because a selected flow requires it and it is not approved`);
    const by = await confirmApproval(p, todo, { ...(arg(rest, "--by") ? { by: arg(rest, "--by")! } : {}), ...(manifest ? { owner: manifest.authorization.owner } : {}) });
    const ref = arg(rest, "--reference");
    const today = new Date().toISOString().slice(0, 10);
    for (const d of todo) writeFileSync(resolve(root, d.file), approveText(d, by, today, ref));
    p.say(`approved ${todo.map((d) => d.header.id).join(", ")} by ${by}; editing a flow invalidates its approval`);
    return 0;
  } catch (e) {
    if (e instanceof ApproveError) throw new UsageError(e.message);
    throw e;
  } finally {
    rl?.close();
  }
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
      const m = loadManifest(configPath(rest));
      const { docs, warnings } = loadLinted(m, need(rest, "--flows"));
      for (const w of warnings) print(`warning: ${w}`);
      for (const d of docs) {
        const c = classify(d);
        print(`OK ${d.header.id.padEnd(32)} ${c.level.padEnd(11)} ${c.executability.padEnd(7)} ${d.header.review.status.padEnd(8)} ${d.steps.length} steps  (${c.levelReasons.join("; ")})`);
      }
      return 0;
    }
    case "analyze": {
      const m = loadManifest(configPath(rest));
      const run = validateRunResult(JSON.parse(readFileSync(need(rest, "--from-run"), "utf8")));
      if (run.scope.origins.some((o) => !m.targets.origins.includes(o))) throw new UsageError("run is for a different target (its origins are not all in the manifest)");
      const dir = resolve(need(rest, "--out"));
      mkdirSync(dir, { recursive: true });
      const existing = existsSync(dir) ? loadFlowFiles(dir).docs.map((d) => d.header.id) : [];
      const lang = (arg(rest, "--lang") ?? m.report.language) as "en" | "th";
      const outp = analyzeRun(run, m, new Set(existing), lang);
      // Page models beside run.json (redacted, structural) add a templates-and-forms section.
      const pmDir = join(dirname(resolve(need(rest, "--from-run"))), "page-models");
      if (existsSync(pmDir)) {
        const pms = readdirSync(pmDir).filter((n) => /^\d{3}\.json$/.test(n)).sort().map((n) => validatePageModel(JSON.parse(readFileSync(join(pmDir, n), "utf8"))));
        const md = outp.files.get("ANALYSIS.md") ?? "";
        const tpl = new Map<string, { pages: number; forms: number }>();
        for (const p of pms) { const t = tpl.get(p.template.path_pattern) ?? { pages: 0, forms: 0 }; t.pages++; t.forms += p.forms.length; tpl.set(p.template.path_pattern, t); }
        const forms = pms.flatMap((p) => p.forms.map((f) => `| \`${p.template.path_pattern.replace(/[`|]/g, "")}\` | ${f.method} | ${f.fields.map((x) => `${x.name.replace(/[`|]/g, "")}:${x.type}${x.required ? "*" : ""}`).join(", ") || "—"} |`));
        outp.files.set("ANALYSIS.md", `${md}\n## Templates and forms (page models)\n\nStructure only; field values and page text are never recorded. Forms need the browser transport (M1b) and, for submissions, safe-validate (M2).\n\n| Template | Pages | Forms |\n|---|---|---|\n${[...tpl].map(([k, v]) => `| \`${k.replace(/[`|]/g, "")}\` | ${v.pages} | ${v.forms} |`).join("\n") || "| — | | |"}\n\n| Template | Method | Fields (* required) |\n|---|---|---|\n${forms.join("\n") || "| — | | |"}\n`);
      }
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
    case "approve":
      return approveCommand(rest);
    case "import": {
      const m = loadManifest(configPath(rest));
      const spec = resolve(need(rest, "--openapi"));
      if (statSync(spec).size > MAX_SPEC_BYTES) throw new UsageError(`--openapi file is larger than ${MAX_SPEC_BYTES} bytes`);
      const doc = parseOpenApiText(readFileSync(spec, "utf8"));
      const dir = resolve(need(rest, "--out"));
      mkdirSync(dir, { recursive: true });
      const existing = loadFlowFiles(dir).docs.map((d) => d.header.id);
      const outp = importOpenApi(doc, m, new Set(existing));
      let written = 0;
      for (const [name, content] of outp.files) {
        const f = join(dir, name);
        if (name !== "IMPORT.md" && existsSync(f)) { outp.skippedExisting.push(name); continue; }
        writeFileSync(f, content);
        if (name !== "IMPORT.md") written++;
      }
      print(`operations=${outp.operations.length} encoded=${outp.operations.filter((o) => o.encoded).length} draft flows written: ${written}; existing, not modified: ${outp.skippedExisting.length ? outp.skippedExisting.join(", ") : "none"}`);
      print(`IMPORT: ${join(dir, "IMPORT.md")}`);
      return 0;
    }
    case "login-from-draft": {
      // Login helper: a recorded sign-in draft becomes a login flow; the manifest is never edited here.
      const path = resolve(need(rest, "--flows"));
      if (!existsSync(path) || statSync(path).isDirectory()) throw new UsageError("--flows must name one .flow.md draft");
      const parsed = parseFlowText(readFileSync(path, "utf8"), path.split(/[\\/]/).pop() ?? "draft.flow.md");
      if (!parsed.doc) throw new FlowError(parsed.problems);
      let ld: LoginDraft;
      try { ld = loginFlowFromDraft(parsed.doc, need(rest, "--actor")); } catch (e) { if (e instanceof LoginDraftError) throw new UsageError(e.message); throw e; }
      const dir = resolve(need(rest, "--out"));
      mkdirSync(dir, { recursive: true });
      const f = join(dir, `${ld.id}.flow.md`);
      if (existsSync(f)) throw new UsageError(`${f} already exists; NavSentry never overwrites a flow`);
      writeFileSync(f, ld.flow, { flag: "wx" });
      print(`FLOW: ${f} (draft)`);
      for (const m of ld.mapped) print(`  ${m.step} fills {{${m.to}}}`);
      for (const d of ld.dropped) print(`  ${d.step} dropped: ${d.reason}`);
      print("\nAdd these entries to navsentry.json yourself (owner decision: login actors need safe-validate on the development profile). Check auth_endpoints.login against the real sign-in request:");
      print(ld.manifestSnippet);
      const a = JSON.parse(ld.manifestSnippet).actors as Record<string, { username_env: string; password_env: string }>;
      const env = Object.values(a)[0]!;
      const actorName = Object.keys(a)[0]!;
      print(`\nThen set ${env.username_env} and ${env.password_env} in your shell, set "actor": "${actorName}" on the steps that need the session, and approve with: navsentry flow approve --flows ${f}`);
      return 0;
    }
    case "from-recording": {
      // DevTools Recorder JSON → one draft flow (SPEC-0.3.0 §6). Zero network; never overwrites.
      const input = resolve(need(rest, "--input"));
      if (!rest.includes("--config") && !existsSync(resolve(DEFAULT_MANIFEST))) {
        // The manifest is the owner's scope, not part of the recording: every recorded URL is checked against it.
        let origin: string | undefined;
        try { if (statSync(input).size <= MAX_RECORDING_BYTES && !isZip(readFileSync(input).subarray(0, 4))) origin = recordingOrigin(JSON.parse(readFileSync(input, "utf8"))); } catch { /* the import reports bad input */ }
        throw new UsageError(`missing --config. The recording does not carry a manifest: NavSentry needs your navsentry.json to check every recorded URL against the scope you authorized. Create one in your project folder with \`navsentry init ${origin ?? "<origin of the recorded site>"}\`, or pass --config <manifest.json>`);
      }
      const m = loadManifest(configPath(rest));
      const name = input.split(/[\\/]/).pop() ?? "recording";
      const head = readFileSync(input).subarray(0, 4);
      if (isZip(head)) {
        // NavSentry Recorder extension bundle (SPEC-0.3.0 §7): flow + RECORDING.md + screenshots in an ignored folder.
        if (statSync(input).size > MAX_NAVREC_BYTES) throw new UsageError(`--input is larger than ${MAX_NAVREC_BYTES} bytes`);
        const imp = importNavrec(readFileSync(input), m, name);
        const dir = resolve(need(rest, "--out"));
        mkdirSync(dir, { recursive: true });
        const f = join(dir, `${imp.id}.flow.md`);
        if (existsSync(f)) throw new UsageError(`${f} already exists; NavSentry never overwrites a flow`);
        writeFileSync(f, imp.flow, { flag: "wx" });
        writeFileSync(join(dir, `${imp.id}.RECORDING.md`), imp.recordingMd);
        if (imp.shots.size) {
          const sd = join(dir, `${imp.id}.shots`);
          mkdirSync(sd, { recursive: true });
          // Screenshots may show personal data: keep them out of version control.
          writeFileSync(join(sd, ".gitignore"), "*\n");
          for (const [n, b] of imp.shots) writeFileSync(join(sd, n), b, { flag: "wx" });
        }
        print(`encoded=${imp.encoded} not encoded=${imp.skipped.length} targets to check=${imp.warnings.length} screenshots=${imp.shots.size}`);
        print(`FLOW: ${f}`);
        print(`RECORDING: ${join(dir, `${imp.id}.RECORDING.md`)}`);
        return 0;
      }
      if (statSync(input).size > MAX_RECORDING_BYTES) throw new UsageError(`--input is larger than ${MAX_RECORDING_BYTES} bytes`);
      let raw: unknown;
      try { raw = JSON.parse(readFileSync(input, "utf8")); } catch { throw new UsageError("--input is not JSON; export the recording from DevTools as JSON"); }
      const imp = importRecording(raw, m, input.split(/[\\/]/).pop() ?? "recording.json");
      const dir = resolve(need(rest, "--out"));
      mkdirSync(dir, { recursive: true });
      const f = join(dir, `${imp.id}.flow.md`);
      if (existsSync(f)) throw new UsageError(`${f} already exists; NavSentry never overwrites a flow`);
      writeFileSync(f, imp.flow, { flag: "wx" });
      writeFileSync(join(dir, `${imp.id}.IMPORT.md`), imp.report);
      print(`encoded=${imp.encoded} listed for review=${imp.skipped.length} targets to check=${imp.warnings.length}`);
      print(`FLOW: ${f}`);
      print(`IMPORT: ${join(dir, `${imp.id}.IMPORT.md`)}`);
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
      throw new UsageError("flow needs a subcommand: init | analyze | import | from-recording | lint | approve | show");
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
  const launch = launchCheck();
  if (argv.includes("--json")) { print(JSON.stringify({ ...r, node: process.versions.node, platform: `${process.platform}-${process.arch}`, transports, launch }, null, 2)); return 0; }
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
  print("\nAgent launch (MCP)");
  if (launch.onPath) print(`  OK        navsentry on PATH: ${launch.onPath}`);
  else {
    print("  NOT_FOUND navsentry is not on PATH. An MCP host that runs `navsentry mcp` then fails with CONNECTION_CLOSED.");
    print("            Fix: npm install -g <release tarball>, or `npm link` in a NavSentry checkout, or register the server by absolute path:");
  }
  print(`  register: claude mcp add navsentry -- ${[launch.mcpCommand.command, ...launch.mcpCommand.args].map((a) => (/\s/.test(a) ? `"${a}"` : a)).join(" ")}`);
  print("\nNothing was installed or changed. Doctor makes no network requests.");
  return r.manifests.some((m) => m.status !== "CURRENT") ? 2 : 0;
}

// realpath: npm links the bin on Linux/macOS, so argv[1] may be the symlink, not this file.
const entry = (() => { try { return realpathSync(process.argv[1] ?? ""); } catch { return ""; } })();
const invokedDirectly = entry.replace(/\\/g, "/").endsWith("dist/src/cli.js");
if (invokedDirectly) main(process.argv.slice(2)).then((code) => { process.exitCode = code; });

/** `navsentry init <url>` (SPEC-0.3.0 §3.1). Interactive on purpose: authorization is the user's answer. */
async function initCommand(argv: string[]): Promise<number> {
  const url = argv[0];
  if (!url || url.startsWith("--")) throw new UsageError("usage: navsentry init <url> [--environment local|dev|staging|production] [--lang en|th] [--out <file>]");
  const env = arg(argv, "--environment");
  if (env !== undefined && !INIT_ENVIRONMENTS.includes(env as InitEnvironment)) throw new UsageError(`--environment must be one of ${INIT_ENVIRONMENTS.join(", ")}`);
  const lang = arg(argv, "--lang");
  if (lang !== undefined && lang !== "en" && lang !== "th") throw new UsageError("--lang must be en or th");
  const out = resolve(argv.includes("--out") ? need(argv, "--out") : DEFAULT_MANIFEST);
  if (existsSync(out)) throw new UsageError(`${out} already exists; NavSentry never overwrites a manifest (edit it, or choose --out)`);
  if (insideNavSentryCheckout(out, packageRoot())) throw new UsageError(`${out} is inside the NavSentry source checkout (a public repository). Run init from your own project folder, or pass --out <path outside the checkout>`);
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new UsageError("navsentry init asks you to confirm authorization, so it runs only in an interactive terminal. Run it yourself; an agent must not answer for you");
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answers = await askInit({ ask: (q) => rl.question(q), say: (l) => print(l) }, url, { ...(env ? { environment: env as InitEnvironment } : {}), ...(lang ? { language: lang as "en" | "th" } : {}) });
    const manifest = buildInitManifest(answers);
    writeFileSync(out, JSON.stringify(manifest, null, 2) + "\n", { flag: "wx" });
    print(`Wrote ${out}\nNext: navsentry plan   (no network)\n      navsentry scan   (one page)\n      navsentry scan --deep   (crawl by template, page models)`);
    return 0;
  } catch (e) {
    if (e instanceof InitError) throw new UsageError(e.message);
    throw e;
  } finally {
    rl.close();
  }
}
