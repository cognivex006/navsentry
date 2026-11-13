import { test } from "node:test";
import assert from "node:assert/strict";
import { CASES, CATEGORIES } from "../src/catalog.js";
import { PlaywrightBrowserAdapter, scrubbedEnv, VisualComputerUseAdapter } from "../src/transports/optional.js";
import { buildPinnedCurlArgv, cliTransportCheck, parseCurlOutput, parsePwshOutput, pwshArgv, PWSH_PINNED_SCRIPT } from "../src/transports/cli-http.js";
import { allAdapters, route } from "../src/transports/registry.js";
import { probePlaywright } from "../src/transports/playwright.js";

test("curl argv: -q first, pinned with --resolve, no redirects, values stay argv entries", () => {
  const argv = buildPinnedCurlArgv("GET", "https://a.test/x?y=1;rm -rf /", "192.0.2.7", { accept: "*/*" }, 1024);
  assert.equal(argv[0], "-q", "-q must be first so ~/.curlrc is ignored");
  assert.deepEqual(argv.slice(argv.indexOf("--max-redirs"), argv.indexOf("--max-redirs") + 2), ["--max-redirs", "0"]);
  assert.deepEqual(argv.slice(argv.indexOf("--resolve"), argv.indexOf("--resolve") + 2), ["--resolve", "a.test:443:192.0.2.7"]);
  assert.deepEqual(argv.slice(argv.indexOf("--noproxy"), argv.indexOf("--noproxy") + 2), ["--noproxy", "*"]);
  assert.equal(argv.at(-2), "--");
  assert.ok(buildPinnedCurlArgv("GET", "http://[::1]:8080/", "::1", {}, 1).includes("::1:8080:[::1]"));
  assert.ok(buildPinnedCurlArgv("HEAD", "http://a.test/", "192.0.2.7", {}, 1).includes("--head"));
  assert.throws(() => buildPinnedCurlArgv("GET", "https://a.test/", "192.0.2.7", { "x-a": "v\r\nInjected: 1" }, 1));
  assert.throws(() => buildPinnedCurlArgv("GET", "file:///etc/passwd", "192.0.2.7", {}, 1));
});

test("PowerShell gets a fixed encoded script; request values travel as JSON on stdin", () => {
  const argv = pwshArgv();
  assert.ok(argv.includes("-NoProfile") && argv.includes("-NonInteractive"));
  const script = Buffer.from(argv[argv.indexOf("-EncodedCommand") + 1]!, "base64").toString("utf16le");
  assert.equal(script, PWSH_PINNED_SCRIPT, "the script is constant: no request value is ever script text");
  assert.match(script, /AllowAutoRedirect = \$false/);
  assert.match(script, /UseProxy = \$false/);
  assert.match(script, /Headers\.Host = \$u\.Authority/, "connects to the checked IP and sends the original Host");
});

test("curl and PowerShell output parsers", () => {
  const raw = Buffer.from("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nbody\r\n\r\nmore");
  const c = parseCurlOutput(raw, false);
  assert.equal(c.status, 404);
  assert.deepEqual(c.headers["set-cookie"], ["a=1", "b=2"]);
  assert.equal(c.body.toString(), "body\r\n\r\nmore");
  const one = parsePwshOutput(Buffer.from(JSON.stringify({ status: 200, headers: { k: "Server", v: "x" }, body: Buffer.from("hi").toString("base64"), truncated: false })));
  assert.deepEqual(one.headers, { server: ["x"] }, "PowerShell 5.1 unwraps a one-element array");
  assert.equal(one.body.toString(), "hi");
});

test("--transport preconditions refuse instead of substituting", () => {
  assert.match((cliTransportCheck("wget", ["wget"], "observe") as { refused: string }).refused, /must be curl-cli or powershell-http/);
  assert.match((cliTransportCheck("curl-cli", ["direct-http"], "observe") as { refused: string }).refused, /not in the manifest/);
  assert.match((cliTransportCheck("curl-cli", ["curl-cli"], "safe-validate") as { refused: string }).refused, /observe mode only/);
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
  // The visual driver runs on the playwright engine (ADR-0009), so it is usable exactly when that engine is.
  assert.equal(vis.usable, probePlaywright().usable);
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
