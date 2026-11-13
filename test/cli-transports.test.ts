/**
 * M3 parity (SPEC-0.4.0 D2): the same observe run through direct-http, curl and PowerShell must give the same
 * findings and check statuses on the local demo app, vulnerable and secure. A transport whose executable is
 * missing is skipped with the reason, never replaced.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { executeTest } from "../src/runner.js";
import { findExecutable, type CliKind } from "../src/transports/cli-http.js";
import { startDemo } from "./fixtures/demo-server.js";
import { localManifest } from "./helpers.js";

const KINDS: CliKind[] = ["curl-cli", "powershell-http"];
const ORDER = ["direct-http", "curl-cli", "powershell-http"];

async function signature(variant: "vulnerable" | "secure", kind?: CliKind) {
  const demo = await startDemo(variant);
  try {
    const m = localManifest(demo.origin, { transports: { order: ORDER } });
    const r = await executeTest(m, kind ? { httpTransport: { kind, file: findExecutable(kind)! } } : {});
    // Each demo instance listens on its own port; compare paths, not origins.
    const at = (t: string) => t.split(demo.origin).join("ORIGIN");
    return {
      transports: [...new Set(r.run.requests.map((q) => q.transport))],
      findings: r.run.findings.map((f) => at(`${f.ruleId} ${f.target}`)).sort(),
      checks: r.run.checks.filter((c) => c.transport !== "tls-probe").map((c) => at(`${c.ruleId} ${c.status} ${c.target}`)).sort(),
      errors: r.run.requests.filter((q) => q.error).map((q) => q.error),
    };
  } finally {
    await demo.close();
  }
}

for (const kind of KINDS) {
  const skip = findExecutable(kind) ? false : `${kind}: executable not found in trusted system locations`;
  for (const variant of ["vulnerable", "secure"] as const) {
    test(`${kind} gives the same findings as direct-http on the ${variant} demo`, { skip }, async () => {
      const ref = await signature(variant);
      const got = await signature(variant, kind);
      assert.deepEqual(got.errors, []);
      assert.deepEqual(got.transports, [kind], "every request went through the selected transport");
      assert.deepEqual(got.findings, ref.findings);
      assert.deepEqual(got.checks, ref.checks);
    });
  }
}
