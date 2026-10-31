/**
 * Local demo against the disposable fixture app (127.0.0.1 only, synthetic data).
 *   node dist/scripts/demo.js run    -> writes docs/samples/{before,after}/ + compare.md
 *   node dist/scripts/demo.js serve  -> serves vulnerable on :4173 and secure on :4174 for browser rechecks
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { compareRuns, renderCompareMarkdown } from "../src/compare.js";
import { renderJson, renderMarkdown, renderSarif } from "../src/report/render.js";
import { executeRun } from "../src/runner.js";
import { startDemo } from "../test/fixtures/demo-server.js";
import { localManifest } from "../test/helpers.js";

const mode = process.argv[2] ?? "run";

if (mode === "serve") {
  const v = await startDemo("vulnerable", 4173);
  const s = await startDemo("secure", 4174);
  console.log(`vulnerable: ${v.origin}\nsecure:     ${s.origin}\n(Ctrl+C to stop)`);
} else {
  const v = await startDemo("vulnerable", 4173);
  const s = await startDemo("secure", 4174);
  const seeds = ["/", "/api/profile", "/api/error", "/api/token", "/go-out"];
  const before = await executeRun(localManifest(v.origin, { project: "demo-before", targets: { origins: [v.origin], seed_paths: seeds, denied_paths: ["/admin/**"] } }));
  const after = await executeRun(localManifest(s.origin, { project: "demo-after", targets: { origins: [s.origin], seed_paths: seeds, denied_paths: ["/admin/**"] } }));
  await v.close();
  await s.close();
  const root = join(process.cwd(), "docs", "samples");
  for (const [name, r] of [["before", before], ["after", after]] as const) {
    const dir = join(root, name);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "run.json"), renderJson(r));
    writeFileSync(join(dir, "REPORT.md"), renderMarkdown(r, "en"));
    writeFileSync(join(dir, "REPORT.th.md"), renderMarkdown(r, "th"));
    writeFileSync(join(dir, "report.sarif"), JSON.stringify(renderSarif(r), null, 2) + "\n");
    console.log(`${name}: execution=${r.executionStatus} findings=${r.findings.length} requests=${r.budget.requestsUsed} denials=${r.denials.length}`);
  }
  // The two fixtures listen on different ports; align origins so legitimate requests pair up.
  const norm = (r: typeof before, o: string) => ({ ...r, requests: r.requests.map((q) => ({ ...q, url: q.url.replace(o, "http://demo") })) });
  const c = compareRuns(norm(before, v.origin), norm(after, s.origin));
  writeFileSync(join(root, "compare.md"), renderCompareMarkdown(c));
  console.log(`compare verdict: ${c.verdict} fixed=${c.fixed.length} drift=${c.contractDrift.length}`);
}
