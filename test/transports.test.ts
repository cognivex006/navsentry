import { test } from "node:test";
import assert from "node:assert/strict";
import { CASES, CATEGORIES } from "../src/catalog.js";
import { buildCurlArgv, buildPwshArgv, PlaywrightBrowserAdapter, scrubbedEnv, VisualComputerUseAdapter } from "../src/transports/optional.js";
import { allAdapters, route } from "../src/transports/registry.js";
import { probePlaywright } from "../src/transports/playwright.js";

test("curl argv: -q first, no redirects, no shell metacharacter interpretation", () => {
  const argv = buildCurlArgv("GET", "https://a.test/x?y=1;rm -rf /", { accept: "*/*" });
  assert.equal(argv[0], "-q", "-q must be first so ~/.curlrc is ignored");
  assert.deepEqual(argv.slice(argv.indexOf("--max-redirs"), argv.indexOf("--max-redirs") + 2), ["--max-redirs", "0"]);
  assert.equal(argv.at(-2), "--");
  assert.throws(() => buildCurlArgv("GET", "https://a.test/", { "x-a": "v\r\nInjected: 1" }));
  assert.throws(() => buildCurlArgv("GET", "file:///etc/passwd", {}));
});

test("PowerShell argv passes values as parameters, never as script text", () => {
  const argv = buildPwshArgv("GET", "https://a.test/$(whoami)", { "x-a": "'; Remove-Item" });
  const script = argv[argv.indexOf("-Command") + 1]!;
  assert.ok(!script.includes("whoami") && !script.includes("Remove-Item"));
  assert.ok(script.includes("-MaximumRedirection 0"));
  assert.ok(argv.includes("-NoProfile"));
});

test("child environment is scrubbed", () => {
  process.env.NAVSENTRY_TEST_SECRET = "x";
  const env = scrubbedEnv();
  assert.equal(env.NAVSENTRY_TEST_SECRET, undefined);
  assert.equal(env.HTTPS_PROXY, undefined);
  delete process.env.NAVSENTRY_TEST_SECRET;
});

test("optional adapters are honest about availability", async () => {
  const pw = await new PlaywrightBrowserAdapter().probe();
  // Usable exactly when the approved playwright-core and its headless shell are installed (M1b).
  assert.equal(pw.usable, probePlaywright().usable);
  if (!pw.usable) assert.ok(pw.reason.length > 0);
  const vis = await new VisualComputerUseAdapter().probe();
  assert.equal(vis.available, false);
  assert.equal(vis.usable, false);
});

test("router picks the lowest-cost usable transport and never substitutes unavailable ones", async () => {
  const adapters = await Promise.all(allAdapters().map(async (a) => ({ capabilities: a.capabilities, status: await a.probe() })));
  const api = route({ allowedTransports: ["direct-http", "playwright-browser"] }, adapters);
  assert.equal(api.selected, "direct-http");
  const dom = route({ needsDOM: true, allowedTransports: ["direct-http", "playwright-browser", "visual-computer-use"] }, adapters);
  assert.equal(dom.selected, probePlaywright().usable ? "playwright-browser" : undefined, "DOM checks never silently use HTTP");
  assert.ok(dom.rejected.some((r) => r.id === "direct-http" && r.reason === "no DOM support"));
});

test("catalog integrity: unique IDs, valid categories, mappings present", () => {
  const ids = new Set<string>();
  for (const c of CASES) {
    assert.match(c.id, /^NSC-[A-Z]+-\d{3}$/);
    assert.ok(!ids.has(c.id), `duplicate ${c.id}`);
    ids.add(c.id);
    assert.ok(c.id.startsWith(`NSC-${c.category}-`), `${c.id} category prefix`);
    assert.ok(c.category in CATEGORIES);
    assert.ok(c.acceptance.length && c.webRecheck.length && c.evidence.length, `${c.id} needs evidence/acceptance/recheck`);
    if (c.category !== "INFO" || c.id !== "NSC-INFO-005") assert.ok(c.cwe.length, `${c.id} needs CWE`);
    for (const s of c.sources) assert.match(s.src, /^SRC-[A-F]$/);
  }
});

test("catalog stays anonymized (public repository)", () => {
  const blob = JSON.stringify(CASES);
  assert.ok(!/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(blob.replace(/CVE-\d+-\d+/g, "")), "no IP addresses");
  assert.ok(!/\.(go|cs|java|php|py)\b/.test(blob.replace(/Svc\.java/g, "")), "no source file paths");
  assert.ok(!/\.(or|co|go|ac|in)\.th\b/i.test(blob), "no organization domains");
  // Customer-specific names are checked by the local gate from an untracked terms file,
  // so the names themselves never land in this public repository.
});
