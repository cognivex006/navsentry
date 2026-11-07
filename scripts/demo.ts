/**
 * Local demo against the disposable fixture app (127.0.0.1 only, synthetic data).
 *   node dist/scripts/demo.js run    -> writes docs/samples/{before,after}/ + compare.md
 *   node dist/scripts/demo.js serve [--variant vulnerable|secure] [--port 4173]  -> demo shop v2 on one origin
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { compareRuns, renderCompareMarkdown } from "../src/compare.js";
import { renderJson, renderMarkdown, renderSarif } from "../src/report/render.js";
import { loadFlowFiles } from "../src/flow/parse.js";
import { renderFlowSection, renderJunit, renderTestMarkdown } from "../src/report/flow-render.js";
import { executeTest } from "../src/runner.js";
import { FIXTURE_TOKENS, startDemo } from "../test/fixtures/demo-server.js";
import { startDemoSite } from "../test/fixtures/demo-site.js";
import { localManifest } from "../test/helpers.js";

const mode = process.argv[2] ?? "run";

if (mode === "serve") {
  // Demo v2 (SPEC-0.3.0 §8): one origin; restart with --variant secure for the after-run.
  const i = process.argv.indexOf("--variant");
  const variant = i > 0 ? process.argv[i + 1] : "vulnerable";
  if (variant !== "vulnerable" && variant !== "secure") throw new Error("--variant must be vulnerable or secure");
  const p = process.argv.indexOf("--port");
  const port = p > 0 ? Number(process.argv[p + 1]) : 4173;
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error("--port must be 1024-65535");
  const site = await startDemoSite(variant, port);
  console.log(`demo shop (${variant}): ${site.origin}/\n(Ctrl+C to stop; restart with --variant ${variant === "vulnerable" ? "secure" : "vulnerable"} to compare)`);
} else {
  const v = await startDemo("vulnerable", 4173);
  const s = await startDemo("secure", 4174);
  const seeds = ["/", "/api/profile", "/api/error", "/api/token", "/go-out"];
  // Story flows from the fixture set (synthetic, drafts) run together with the seeds.
  const flows = loadFlowFiles(join(process.cwd(), "test", "fixtures", "flows")).docs;
  const env = { NAVSENTRY_TEST_READER_A_AUTH: FIXTURE_TOKENS.reader_a, NAVSENTRY_TEST_READER_B_AUTH: FIXTURE_TOKENS.reader_b, NAVSENTRY_TEST_ADMIN_AUTH: FIXTURE_TOKENS.admin };
  const actors = { reader_a: { authorization_header_env: "NAVSENTRY_TEST_READER_A_AUTH" }, reader_b: { authorization_header_env: "NAVSENTRY_TEST_READER_B_AUTH" }, admin: { authorization_header_env: "NAVSENTRY_TEST_ADMIN_AUTH" } };
  const b = await executeTest(localManifest(v.origin, { project: "demo-before", actors, targets: { origins: [v.origin], seed_paths: seeds, denied_paths: ["/admin/**"] } }), { env, flows });
  const a = await executeTest(localManifest(s.origin, { project: "demo-after", actors, targets: { origins: [s.origin], seed_paths: seeds, denied_paths: ["/admin/**"] } }), { env, flows });
  const before = b.run, after = a.run;
  await v.close();
  await s.close();
  const root = join(process.cwd(), "docs", "samples");
  for (const [name, r, fr] of [["before", before, b.flowRun!], ["after", after, a.flowRun!]] as const) {
    const dir = join(root, name);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "run.json"), renderJson(r));
    writeFileSync(join(dir, "REPORT.md"), renderMarkdown(r, "en") + "\n" + renderFlowSection(fr, r, "en"));
    writeFileSync(join(dir, "REPORT.th.md"), renderMarkdown(r, "th") + "\n" + renderFlowSection(fr, r, "th"));
    writeFileSync(join(dir, "flows.json"), JSON.stringify(fr, null, 2) + "\n");
    writeFileSync(join(dir, "TEST-REPORT.md"), renderTestMarkdown(fr, r, "en"));
    writeFileSync(join(dir, "TEST-REPORT.th.md"), renderTestMarkdown(fr, r, "th"));
    writeFileSync(join(dir, "junit.xml"), renderJunit(fr));
    writeFileSync(join(dir, "report.sarif"), JSON.stringify(renderSarif(r), null, 2) + "\n");
    console.log(`${name}: execution=${r.executionStatus} findings=${r.findings.length} requests=${r.budget.requestsUsed} denials=${r.denials.length} functional=${fr.functionalResult}`);
  }
  // The two fixtures listen on different ports; align origins so legitimate requests pair up.
  const norm = (r: typeof before, o: string) => ({ ...r, requests: r.requests.map((q) => ({ ...q, url: q.url.replace(o, "http://demo") })) });
  const c = compareRuns(norm(before, v.origin), norm(after, s.origin), { before: b.flowRun!, after: a.flowRun! });
  writeFileSync(join(root, "compare.md"), renderCompareMarkdown(c));
  console.log(`compare verdict: ${c.verdict} fixed=${c.fixed.length} drift=${c.contractDrift.length}`);
}
