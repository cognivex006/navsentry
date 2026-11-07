/** SPEC-0.3.0 0.3.0-b: --json summaries, `navsentry next`, and the local stdio MCP server. 127.0.0.1 only. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { buildInitManifest } from "../src/init.js";
import { TOOLS, callTool, handleMessage } from "../src/mcp.js";
import { nextSteps, renderNext } from "../src/next.js";
import { securityResult } from "../src/report/render.js";
import { executeTest } from "../src/runner.js";
import { startDemoSite } from "./fixtures/demo-site.js";
import { localManifest } from "./helpers.js";

const CLI = resolve("dist/src/cli.js");
const ctx = (cwd: string) => ({ cliPath: CLI, cwd, sessions: new Map() });

test("MCP handshake: tools are listed; nothing writes manifests, approves flows or cleans workspaces", async () => {
  const c = ctx(process.cwd());
  const init = (await handleMessage(c, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } })) as { result: { protocolVersion: string; instructions: string; capabilities: object } };
  assert.equal(init.result.protocolVersion, "2025-06-18");
  assert.match(init.result.instructions, /Never answer authorization questions/);
  const old = (await handleMessage(c, { jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "1999-01-01" } })) as { result: { protocolVersion: string } };
  assert.equal(old.result.protocolVersion, "2025-06-18");
  assert.equal(await handleMessage(c, { jsonrpc: "2.0", method: "notifications/initialized" }), undefined);
  const list = (await handleMessage(c, { jsonrpc: "2.0", id: 3, method: "tools/list" })) as { result: { tools: { name: string; annotations: { openWorldHint: boolean } }[] } };
  const names = list.result.tools.map((t) => t.name);
  for (const forbidden of ["init", "approve", "clean", "update", "propose"]) assert.ok(!names.some((n) => n.includes(forbidden)), `no ${forbidden} tool`);
  for (const t of list.result.tools) if (/scan|browse_(start|click|scroll)/.test(t.name)) assert.equal(t.annotations.openWorldHint, true, `${t.name} is marked as sending traffic`);
  assert.ok(!JSON.stringify(list).includes("\"argv\""), "builders are not serialized");
  const bad = (await handleMessage(c, { jsonrpc: "2.0", id: 4, method: "nope" })) as { error: { code: number } };
  assert.equal(bad.error.code, -32601);
  assert.equal(TOOLS.length, names.length);
});

test("MCP tools refuse flag-like and malformed arguments before running anything", async () => {
  const c = ctx(process.cwd());
  for (const [name, args] of [["navsentry_scan", { url: "--config=x" }], ["navsentry_scan", { mode: "spider; rm" }], ["navsentry_compare", { before: "a" }], ["navsentry_browse_click", { session: "s", x: "1", y: 2 }], ["navsentry_next", { run: "a\nb" }], ["navsentry_scan", { cwd: "Z:/does/not/exist" }], ["navsentry_unknown", {}]] as const) {
    const r = await callTool(c, name, args as Record<string, unknown>);
    assert.equal(r.isError, true, `${name} ${JSON.stringify(args)}`);
  }
});

test("scan --json, next and MCP tools work end to end on the demo shop", async () => {
  const site = await startDemoSite("vulnerable");
  const dir = mkdtempSync(join(tmpdir(), "navsentry-mcp-"));
  try {
    writeFileSync(join(dir, "navsentry.json"), JSON.stringify(buildInitManifest({ url: `${site.origin}/`, environment: "local", owner: "me", allowPrivate: true })));
    const c = ctx(dir);
    const scan = await callTool(c, "navsentry_scan", { out: join(dir, "r1") });
    assert.equal(scan.isError, false);
    const summary = JSON.parse(scan.content[0]!.type === "text" ? scan.content[0]!.text.split("\n\nstderr")[0]!.split("\n\nexit code")[0]! : "{}");
    assert.equal(summary.kind, "navsentry-run-summary");
    assert.equal(summary.securityResult, "FINDINGS");
    assert.ok(summary.counts.IMMEDIATE + summary.counts.CAUTION > 0);
    assert.ok(summary.reports.html.endsWith("REPORT.html"));
    assert.ok(summary.suggestions.some((s: { command: string; network: boolean }) => s.command.startsWith("navsentry scan --deep") && s.network));
    const next = await callTool(c, "navsentry_next", { run: join(dir, "r1") });
    assert.equal(next.isError, false);
    const cmp = await callTool(c, "navsentry_compare", { before: join(dir, "r1"), after: join(dir, "r1") });
    assert.match(cmp.content[0]!.type === "text" ? cmp.content[0]!.text : "", /"verdict": "NO_CHANGE"/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    await site.close();
  }
});

test("next: actions by level, gaps and suggestions that mark network use and owner decisions", async () => {
  const site = await startDemoSite("vulnerable");
  try {
    const run = (await executeTest(localManifest(site.origin), {})).run;
    const n = nextSteps(run, undefined, "runs/r1", securityResult(run));
    assert.equal(n.kind, "navsentry-next");
    assert.ok(n.actions.length > 0 && n.actions[0]!.level === "IMMEDIATE");
    assert.ok(n.suggestions.every((s) => typeof s.network === "boolean"));
    assert.ok(n.suggestions.some((s) => s.command.startsWith("navsentry flow analyze") && !s.network));
    assert.ok(!n.suggestions.some((s) => /flow approve|init/.test(s.command) && !s.ownerOnly), "owner actions are marked");
    assert.match(renderNext(n), /\[sends traffic\]/);
  } finally {
    await site.close();
  }
});

test("stdio server: one JSON-RPC response per line, nothing else on stdout", async () => {
  const child = spawn(process.execPath, [CLI, "mcp"], { stdio: ["pipe", "pipe", "pipe"] });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } }) + "\n");
  child.stdin.write("not json\n");
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }) + "\n");
  child.stdin.end();
  await new Promise((r) => child.on("close", r));
  const lines = out.trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(lines.length, 3);
  assert.ok(lines.some((l) => l.id === 1 && l.result.serverInfo.name === "navsentry"));
  assert.ok(lines.some((l) => l.error?.code === -32700));
  assert.ok(lines.some((l) => l.id === 2 && JSON.stringify(l.result) === "{}"));
});
