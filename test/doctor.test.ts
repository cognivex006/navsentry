import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applySkillUpdate, compareVersions, launchCheck, findInstallations, manifestVersions, normalizeHost, planSkillUpdate, SKILLS, skillVersion, statusOf, DoctorError } from "../src/doctor.js";
import { TOOL_VERSION } from "../src/types.js";

const skill = (name: string, version?: string) => `---\nname: ${name}\ndescription: test\n${version ? `metadata:\n  version: "${version}"\n` : ""}---\n\nbody\n`;

function sandbox() {
  const dir = mkdtempSync(join(tmpdir(), "navsentry-doctor-"));
  return { home: join(dir, "home"), project: join(dir, "project"), backups: join(dir, "backups"), done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("every packaging manifest carries the CLI version", () => {
  const m = manifestVersions();
  for (const f of [".claude-plugin/plugin.json", ".claude-plugin/marketplace.json", ".codex-plugin/plugin.json", ".agents/plugins/marketplace.json", ".antigravity-plugin/plugin.json", "gemini-extension.json", ...SKILLS.map((s) => `skills/${s}/SKILL.md`)])
    assert.ok(m.some((x) => x.file === f), `missing ${f}`);
  for (const x of m) assert.equal(x.status, "CURRENT", `${x.file} has ${x.version}, CLI is ${TOOL_VERSION}`);
  assert.equal(JSON.parse(readFileSync("package.json", "utf8")).version, TOOL_VERSION);
});

test("version comparison and statuses", () => {
  assert.equal(compareVersions("0.1.0", "v0.1.0"), 0);
  assert.equal(compareVersions("0.1.0", "0.10.0"), -1);
  assert.equal(statusOf("0.0.9", "0.1.0"), "OUTDATED");
  assert.equal(statusOf("0.2.0", "0.1.0"), "NEWER");
  assert.equal(statusOf(null), "UNKNOWN");
  assert.equal(statusOf("local"), "UNKNOWN");
  assert.equal(normalizeHost("agy"), "antigravity");
  assert.equal(normalizeHost("cursor"), undefined);
});

test("finds plugin and skill installations per host without touching them", () => {
  const s = sandbox();
  try {
    const claudePlugin = join(s.home, ".claude", "plugins", "cache", "navsentry", "navsentry", "0.0.9");
    mkdirSync(join(claudePlugin, ".claude-plugin"), { recursive: true });
    writeFileSync(join(claudePlugin, ".claude-plugin", "plugin.json"), JSON.stringify({ name: "navsentry", version: "0.0.9" }));
    writeFileSync(join(s.home, ".claude", "plugins", "installed_plugins.json"), JSON.stringify({ version: 2, plugins: { "navsentry@navsentry": [{ scope: "user", installPath: claudePlugin, version: "0.0.9" }], "other@x": [{ scope: "user", installPath: "/x", version: "9.9.9" }] } }));
    const codex = join(s.home, ".codex", "plugins", "cache", "navsentry", "navsentry", "local", ".codex-plugin");
    mkdirSync(codex, { recursive: true });
    writeFileSync(join(codex, "plugin.json"), JSON.stringify({ name: "navsentry", version: TOOL_VERSION }));
    mkdirSync(join(s.home, ".gemini", "extensions", "navsentry"), { recursive: true });
    mkdirSync(join(s.project, ".claude", "skills", "navsentry"), { recursive: true });
    writeFileSync(join(s.project, ".claude", "skills", "navsentry", "SKILL.md"), skill("navsentry"));
    mkdirSync(join(s.home, ".gemini", "config", "plugins", "navsentry", ".antigravity-plugin"), { recursive: true });
    writeFileSync(join(s.home, ".gemini", "config", "plugins", "navsentry", ".antigravity-plugin", "plugin.json"), JSON.stringify({ name: "navsentry", version: "0.3.0" }));

    const found = findInstallations(["claude", "codex", "gemini", "antigravity"], s.home, s.project);
    const by = (host: string, kind: string) => found.filter((i) => i.host === host && i.kind === kind).map((i) => i.status);
    assert.deepEqual(by("claude", "plugin"), ["OUTDATED"]);
    assert.deepEqual(by("claude", "skill"), ["UNKNOWN"]);
    assert.deepEqual(by("codex", "plugin"), ["CURRENT"]);
    assert.deepEqual(by("gemini", "plugin"), ["UNKNOWN"]);
    assert.deepEqual(by("antigravity", "plugin"), ["NEWER"]);
  } finally { s.done(); }
});

test("skill update installs, then replaces with a backup outside the skills directory", () => {
  const s = sandbox();
  try {
    const first = planSkillUpdate("codex", "project", s.home, s.project);
    assert.ok(first.copies.every((c) => c.replaces === null));
    assert.equal(applySkillUpdate(first, s.backups), null);
    for (const k of SKILLS) assert.equal(skillVersion(join(s.project, ".agents", "skills", k, "SKILL.md")), TOOL_VERSION);

    writeFileSync(join(s.project, ".agents", "skills", "navsentry", "SKILL.md"), skill("navsentry", "0.0.1"));
    const second = planSkillUpdate("codex", "project", s.home, s.project);
    assert.equal(second.copies.find((c) => c.skill === "navsentry")?.replaces, "0.0.1");
    const backup = applySkillUpdate(second, s.backups);
    assert.ok(backup && existsSync(join(backup, "navsentry", "SKILL.md")));
    assert.equal(skillVersion(join(s.project, ".agents", "skills", "navsentry", "SKILL.md")), TOOL_VERSION);
  } finally { s.done(); }
});

test("skill update refuses foreign skills and the package itself", () => {
  const s = sandbox();
  try {
    mkdirSync(join(s.home, ".claude", "skills", "navsentry"), { recursive: true });
    writeFileSync(join(s.home, ".claude", "skills", "navsentry", "SKILL.md"), skill("someone-else"));
    assert.throws(() => planSkillUpdate("claude", "user", s.home, s.project), DoctorError);
    assert.throws(() => planSkillUpdate("codex", "project", s.home, process.cwd()), DoctorError);
  } finally { s.done(); }
});

test("launch check finds navsentry on PATH or gives an absolute MCP command", () => {
  const dir = mkdtempSync(join(tmpdir(), "navsentry-launch-"));
  try {
    const none = launchCheck(dir, "win32", "/pkg", "/node");
    assert.equal(none.onPath, null);
    assert.deepEqual(none.mcpCommand, { command: "/node", args: [join("/pkg", "dist", "src", "cli.js"), "mcp"] });
    writeFileSync(join(dir, "navsentry.cmd"), "");
    const win = launchCheck(`C:\nothing;${dir}`, "win32", "/pkg", "/node");
    assert.equal(win.onPath, join(dir, "navsentry.cmd"));
    assert.deepEqual(win.mcpCommand, { command: "navsentry", args: ["mcp"] });
    assert.equal(launchCheck(dir, "linux", "/pkg", "/node").onPath, null, "linux needs a file named navsentry");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
