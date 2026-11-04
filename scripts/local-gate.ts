/**
 * Local release/PR gate — the replacement for hosted CI. NavSentry deliberately uses NO
 * GitHub Actions or other hosted automation (docs/adr/0002-local-gates-no-hosted-ci.md).
 *
 * Each gate is PASS, FAIL or INCOMPLETE. Unknown/unavailable evidence is INCOMPLETE, never PASS.
 * Writes .navsentry/gate/GATE-REPORT.md and gate.json. Exit 0 only if every gate PASSes.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { diffSnapshots, snapshot } from "../src/workspace.js";

type G = "PASS" | "FAIL" | "INCOMPLETE";
interface Gate { id: string; title: string; status: G; detail: string; fixHint?: string }
const ROOT = process.cwd();
const gates: Gate[] = [];
const add = (id: string, title: string, status: G, detail: string, fixHint?: string) => gates.push({ id, title, status, detail, ...(fixHint ? { fixHint } : {}) });
// Run npm through its JS entry point (set by `npm run`) so no shell is ever involved.
const npmCli = process.env.npm_execpath;
const run = (cmd: string, args: string[], timeout = 300000) => spawnSync(cmd, args, { cwd: ROOT, encoding: "utf8", shell: false, timeout });
/** The full suite (browser tests, 300 MiB asset streams) takes ~4 min locally; leave headroom so a slow machine is not a FAIL. */
const TEST_TIMEOUT_MS = 15 * 60 * 1000;
const runNpm = (args: string[]) => (npmCli ? run(process.execPath, [npmCli, ...args]) : { status: -1, stdout: "", stderr: "run via `npm run gate` so npm_execpath is set" });

// G1 — owner policy: no hosted CI workflows.
const wf = join(ROOT, ".github", "workflows");
add("GATE-01", "No GitHub Actions workflows (owner policy)", existsSync(wf) && readdirSync(wf).length ? "FAIL" : "PASS", existsSync(wf) ? `found ${readdirSync(wf).join(", ")}` : ".github/workflows absent", "Delete .github/workflows; use `npm run gate` locally.");

// G9 (recorded here, reported after G8) — workspace hygiene: snapshot before and after the tests.
// Git status alone misses changes to an already-dirty path, so a filesystem snapshot is compared too.
const HYGIENE_IGNORE = ["dist/**"];
const gitState = () => run("git", ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching"]);
const gitBefore = gitState();
const fsBefore = snapshot(ROOT, HYGIENE_IGNORE);

// G2 — tests.
const t = run(process.execPath, ["--test", "--test-concurrency=1", "dist/test/"], TEST_TIMEOUT_MS);
const pass = /ℹ pass (\d+)/.exec(t.stdout)?.[1], fail = /ℹ fail (\d+)/.exec(t.stdout)?.[1], skipped = /ℹ skipped (\d+)/.exec(t.stdout)?.[1] ?? "0";
add("GATE-02", "Unit + fixture E2E tests", t.status === 0 ? "PASS" : "FAIL", `${t.status === null ? `timed out after ${TEST_TIMEOUT_MS / 60000} min (${t.signal ?? "killed"}); ` : ""}pass=${pass ?? "?"} fail=${fail ?? "?"} skipped=${skipped}${skipped !== "0" ? " (skipped tests did not run; see TESTING.md)" : ""} exit=${t.status}`, "Run `npm test` and fix failing assertions; never skip a test to pass the gate.");

// G3 — generated docs in sync with the catalog.
const d = run(process.execPath, ["dist/scripts/gen-catalog-docs.js", "--check"]);
add("GATE-03", "Generated case catalog / matrix up to date", d.status === 0 ? "PASS" : "FAIL", (d.stderr || "in sync").trim(), "Run `npm run docs:catalog` and commit the result.");

// G4 — dependency advisories (npm audit). Network failure is INCOMPLETE, not PASS.
const audit = (extra: string[]) => {
  const j = JSON.parse(runNpm(["audit", "--json", ...extra]).stdout) as { metadata?: { vulnerabilities?: Record<string, number> } };
  const v = j.metadata?.vulnerabilities;
  if (!v) throw new Error("no metadata");
  return { v, blocking: (v.high ?? 0) + (v.critical ?? 0) };
};
const counts = (v: Record<string, number>) => `critical=${v.critical ?? 0} high=${v.high ?? 0} moderate=${v.moderate ?? 0} low=${v.low ?? 0}`;
try {
  const { v, blocking } = audit([]);
  add("GATE-04", "Dependency advisories (npm audit, full tree)", blocking ? "FAIL" : "PASS", `${counts(v)} (checked ${new Date().toISOString()}; one database only — not proof of absence)`, "Upgrade or replace the affected package, or record a dated risk acceptance in governance/third-party.json.");
} catch {
  add("GATE-04", "Dependency advisories (npm audit, full tree)", "INCOMPLETE", "npm audit unavailable (offline or registry error)", "Re-run online; until then the release is blocked.");
}

// G5 — lockfile integrity and registry provenance.
try {
  const lock = JSON.parse(readFileSync(join(ROOT, "package-lock.json"), "utf8")) as { lockfileVersion: number; packages: Record<string, { version?: string; resolved?: string; integrity?: string }> };
  const bad = Object.entries(lock.packages).filter(([k]) => k).filter(([, p]) => !p.integrity?.startsWith("sha512-") || !p.resolved?.startsWith("https://registry.npmjs.org/"));
  add("GATE-05", "Lockfile integrity (sha512) + registry provenance", bad.length ? "FAIL" : "PASS", bad.length ? `unpinned/foreign: ${bad.map(([k]) => k).join(", ")}` : `${Object.keys(lock.packages).length - 1} packages, lockfileVersion ${lock.lockfileVersion}`, "Reinstall from the public registry with --save-exact; never use git/tarball URLs without review.");
} catch {
  add("GATE-05", "Lockfile integrity (sha512) + registry provenance", "FAIL", "package-lock.json missing or invalid", "Run `npm install --ignore-scripts`.");
}

// G6 — every locked package has a current third-party decision.
try {
  const lock = JSON.parse(readFileSync(join(ROOT, "package-lock.json"), "utf8")) as { packages: Record<string, { version?: string }> };
  const reg = JSON.parse(readFileSync(join(ROOT, "governance", "third-party.json"), "utf8")) as { components: { name: string; version: string; review_due: string; decision: string }[] };
  const missing: string[] = [], stale: string[] = [];
  for (const [k, p] of Object.entries(lock.packages)) {
    if (!k) continue;
    const name = k.replace(/^.*node_modules\//, "");
    const e = reg.components.find((c) => c.name === name && c.version === p.version);
    if (!e || e.decision !== "APPROVED") missing.push(`${name}@${p.version}`);
    else if (Date.parse(e.review_due) < Date.now()) stale.push(`${name} (due ${e.review_due})`);
  }
  add("GATE-06", "Third-party license/terms decisions (governance/third-party.json)", missing.length ? "FAIL" : stale.length ? "INCOMPLETE" : "PASS", missing.length ? `no approved decision: ${missing.join(", ")}` : stale.length ? `review overdue: ${stale.join(", ")}` : "all locked packages approved and in review window", "Study the package's license/terms per docs/THIRD-PARTY-GOVERNANCE.md and add a dated decision.");
} catch {
  add("GATE-06", "Third-party license/terms decisions", "FAIL", "governance/third-party.json missing or invalid");
}

// G7 — SBOM generation (local, no SaaS).
const s = runNpm(["sbom", "--sbom-format", "cyclonedx", "--omit", "optional"]);
if (s.status === 0 && s.stdout.includes("bomFormat")) {
  mkdirSync(join(ROOT, ".navsentry", "gate"), { recursive: true });
  writeFileSync(join(ROOT, ".navsentry", "gate", "sbom.cdx.json"), s.stdout);
  add("GATE-07", "SBOM (CycloneDX via npm sbom)", "PASS", ".navsentry/gate/sbom.cdx.json written");
} else add("GATE-07", "SBOM (CycloneDX via npm sbom)", "INCOMPLETE", `npm sbom failed (exit ${s.status})`, "Use npm >= 10.");

// G8 — publication safety: no customer identifiers or secrets in tracked files.
const termsFile = join(ROOT, ".navsentry", "forbidden-terms.txt");
const files = run("git", ["ls-files", "-co", "--exclude-standard"]).stdout.split(/\r?\n/).filter((f) => f && !f.startsWith("node_modules/") && existsSync(join(ROOT, f)) && statSync(join(ROOT, f)).size < 5_000_000);
const generic: [string, RegExp][] = [
  ["private key", /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ["GitHub token", /\bgh[pousr]_[A-Za-z0-9]{30,}\b/],
  ["AWS key", /\bAKIA[0-9A-Z]{16}\b/],
  ["organization domain (.or/.co/.go.th)", /\b[a-z0-9-]+\.(or|co|go)\.th\b/i],
];
const custom: [string, RegExp][] = existsSync(termsFile)
  ? readFileSync(termsFile, "utf8").split(/\r?\n/).filter((l) => l.trim() && !l.startsWith("#")).map((l, i) => [`forbidden term #${i + 1}`, new RegExp(l.trim(), "i")])
  : [];
const hits: string[] = [];
for (const f of files) {
  if (f.startsWith(".navsentry/")) continue;
  const text = readFileSync(join(ROOT, f), "utf8");
  for (const [n, re] of [...generic, ...custom]) if (re.test(text)) hits.push(`${f}: ${n}`);
}
add("GATE-08", "Publication safety (secrets, customer identifiers)", hits.length ? "FAIL" : custom.length ? "PASS" : "INCOMPLETE", hits.length ? hits.join("; ") : custom.length ? `${files.length} files scanned with ${generic.length} generic + ${custom.length} owner terms` : "generic scan clean, but .navsentry/forbidden-terms.txt (owner terms) is missing", "Remove/anonymize the content (use SRC-x labels). Keep owner terms in the untracked file.");

// G9 — workspace hygiene (SPEC-0.1.3 §7.3).
{
  const gitAfter = gitState();
  const fsAfter = snapshot(ROOT, HYGIENE_IGNORE);
  const problems: string[] = [];
  let incomplete = "";
  if (gitBefore.status !== 0 || gitAfter.status !== 0) incomplete = "git status failed";
  else if (!fsBefore.complete || !fsAfter.complete) incomplete = fsBefore.reason ?? fsAfter.reason ?? "snapshot incomplete";
  else {
    const d = diffSnapshots(fsBefore, fsAfter);
    for (const [k, v] of [["created", d.created], ["modified", d.modified], ["deleted", d.deleted]] as const) if (v.length) problems.push(`${k} during tests: ${v.slice(0, 10).join(", ")}${v.length > 10 ? ` (+${v.length - 10})` : ""}`);
    if (gitBefore.stdout !== gitAfter.stdout) problems.push("git status changed during tests");
  }
  // Untracked helper scripts outside the excluded trees fail independently; tracked scripts are not affected.
  const untracked = run("git", ["ls-files", "-o", "--exclude-standard", "-z"]).stdout.split("\0").filter(Boolean);
  const helper = /(^|\/)tmp[^/]*$|\.(cjs|py|ps1|sh)$/i;
  const helpers = untracked.filter((f) => !/^(node_modules|dist|\.navsentry)\//.test(f) && helper.test(f));
  if (helpers.length) problems.push(`untracked helper scripts: ${helpers.join(", ")}`);
  add("GATE-09", "Workspace hygiene (no leftovers, no changes during tests)", problems.length ? "FAIL" : incomplete ? "INCOMPLETE" : "PASS",
    problems.length ? problems.join("; ") : incomplete || `${fsAfter.entries.size} entries unchanged; no untracked helper scripts`,
    "Move helper scripts to the OS temp directory or the agent scratchpad; make tests write only under os.tmpdir().");
}

// G10 — QA-AT-10 self-test: the audit must flag a known-vulnerable fixture lockfile (never installed).
try {
  const { v, blocking } = audit(["--package-lock-only", "--prefix", join("test", "fixtures", "sca")]);
  add("GATE-10", "Dependency audit self-test (fixture lockfile must be flagged)", blocking ? "PASS" : "FAIL", blocking ? `fixture flagged: ${counts(v)}` : `fixture not flagged: ${counts(v)}`, "The audit no longer detects the pinned advisory; check npm audit behaviour or update test/fixtures/sca to a version with a current high advisory.");
} catch {
  add("GATE-10", "Dependency audit self-test (fixture lockfile must be flagged)", "INCOMPLETE", "npm audit unavailable (offline or registry error)", "Re-run online; until then the release is blocked.");
}

// Report
const overall: G = gates.some((g) => g.status === "FAIL") ? "FAIL" : gates.some((g) => g.status === "INCOMPLETE") ? "INCOMPLETE" : "PASS";
const md = [
  `# NavSentry local gate — ${overall}`, "", `Run at ${new Date().toISOString()} · node ${process.versions.node} · ${process.platform}`, "",
  "| Gate | Check | Status | Detail | If not PASS, do this |", "|---|---|---|---|---|",
  ...gates.map((g) => `| ${g.id} | ${g.title} | ${g.status} | ${g.detail.replace(/\|/g, "\\|")} | ${g.status === "PASS" ? "" : g.fixHint ?? ""} |`), "",
].join("\n");
mkdirSync(join(ROOT, ".navsentry", "gate"), { recursive: true });
writeFileSync(join(ROOT, ".navsentry", "gate", "GATE-REPORT.md"), md);
writeFileSync(join(ROOT, ".navsentry", "gate", "gate.json"), JSON.stringify({ overall, gates }, null, 2));
console.log(md);
console.log(`report: ${relative(ROOT, join(ROOT, ".navsentry", "gate", "GATE-REPORT.md"))}`);
process.exitCode = overall === "PASS" ? 0 : overall === "INCOMPLETE" ? 2 : 1;
