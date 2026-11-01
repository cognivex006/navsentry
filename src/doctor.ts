/**
 * Version doctor: compares the running CLI with its own packaging manifests and with NavSentry
 * skill/plugin installations of each supported agent host. Read-only except `updateSkills`, which
 * copies the canonical skills into one host skills directory the user selected. No network.
 */
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { TOOL_VERSION } from "./types.js";

export const HOSTS = ["claude", "codex", "gemini", "antigravity"] as const;
export type Host = (typeof HOSTS)[number];
export type Scope = "user" | "project";
export type VersionStatus = "CURRENT" | "OUTDATED" | "NEWER" | "UNKNOWN";

/** Skills shipped by this package; every install copies all of them together. */
export const SKILLS = ["navsentry", "navsentry-doctor"] as const;
const REPO = "cognivex006/navsentry";

export interface ManifestVersion { file: string; version: string | null; status: VersionStatus }
export interface Installation { host: Host; kind: "plugin" | "skill"; scope: Scope; path: string; version: string | null; status: VersionStatus }
export interface DoctorReport { version: string; packageRoot: string; manifests: ManifestVersion[]; installations: Installation[] }

export function normalizeHost(h: string): Host | undefined {
  const v = h.toLowerCase() === "agy" ? "antigravity" : h.toLowerCase();
  return (HOSTS as readonly string[]).includes(v) ? (v as Host) : undefined;
}

/** dist/src/doctor.js → package root (also correct for an npm-installed tarball). */
export function packageRoot(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
}

export function compareVersions(a: string, b: string): number {
  const p = (v: string) => v.replace(/^v/, "").split(/[.+-]/).slice(0, 3).map((n) => Number.parseInt(n, 10) || 0);
  const [x, y] = [p(a), p(b)];
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) < (y[i] ?? 0) ? -1 : 1;
  return 0;
}

export function statusOf(version: string | null, current = TOOL_VERSION): VersionStatus {
  if (!version || !/^v?\d+\.\d+\.\d+/.test(version)) return "UNKNOWN";
  const c = compareVersions(version, current);
  return c === 0 ? "CURRENT" : c < 0 ? "OUTDATED" : "NEWER";
}

function readJson(path: string): unknown {
  try { return JSON.parse(readFileSync(path, "utf8")) as unknown; } catch { return undefined; }
}

function jsonVersion(path: string): string | null {
  const j = readJson(path) as { version?: unknown } | undefined;
  return typeof j?.version === "string" ? j.version : null;
}

/** Reads `metadata.version` from SKILL.md front matter. */
export function skillVersion(path: string): string | null {
  let text: string;
  try { text = readFileSync(path, "utf8"); } catch { return null; }
  const fm = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text)?.[1];
  return fm ? /^metadata:\s*\r?\n(?:[ \t]+.*\r?\n)*?[ \t]+version:\s*"?([^"\s]+)"?/m.exec(fm + "\n")?.[1] ?? null : null;
}

function skillName(path: string): string | null {
  try { return /^---\r?\nname:\s*(\S+)/.exec(readFileSync(path, "utf8"))?.[1] ?? null; } catch { return null; }
}

/** Every file in this package that carries a version; all must equal the CLI version. */
export function manifestVersions(root = packageRoot()): ManifestVersion[] {
  const out: ManifestVersion[] = [];
  const add = (file: string, version: string | null) => out.push({ file, version, status: statusOf(version) });
  const optional = (file: string, read: (p: string) => string | null) => { if (existsSync(join(root, file))) add(file, read(join(root, file))); };
  add("package.json", jsonVersion(join(root, "package.json")));
  optional(".claude-plugin/plugin.json", jsonVersion);
  optional(".claude-plugin/marketplace.json", (p) => {
    const m = readJson(p) as { plugins?: { name?: string; version?: string }[] } | undefined;
    return m?.plugins?.find((x) => x.name === "navsentry")?.version ?? null;
  });
  optional(".agents/plugins/marketplace.json", (p) => {
    const m = readJson(p) as { plugins?: { name?: string; source?: { ref?: string } }[] } | undefined;
    return m?.plugins?.find((x) => x.name === "navsentry")?.source?.ref ?? null;
  });
  optional(".codex-plugin/plugin.json", jsonVersion);
  optional(".antigravity-plugin/plugin.json", jsonVersion);
  optional("gemini-extension.json", jsonVersion);
  for (const s of SKILLS) add(`skills/${s}/SKILL.md`, skillVersion(join(root, "skills", s, "SKILL.md")));
  optional(".agents/skills/navsentry/SKILL.md", skillVersion);
  return out;
}

/** Host skill directories, most preferred first. Project paths are relative to the project. */
export function skillDirs(host: Host, scope: Scope, home: string, project: string): string[] {
  const u = (...p: string[]) => join(home, ...p), w = (...p: string[]) => join(project, ...p);
  const table: Record<Host, Record<Scope, string[]>> = {
    claude: { user: [u(".claude", "skills")], project: [w(".claude", "skills")] },
    codex: { user: [u(".agents", "skills"), u(".codex", "skills")], project: [w(".agents", "skills")] },
    gemini: { user: [u(".gemini", "skills")], project: [w(".gemini", "skills")] },
    antigravity: { user: [u(".gemini", "config", "skills"), u(".gemini", "antigravity-cli", "skills")], project: [w(".agents", "skills")] },
  };
  return table[host][scope];
}

function subdirs(path: string): string[] {
  try { return readdirSync(path, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => join(path, d.name)); } catch { return []; }
}

function pluginInstalls(host: Host, home: string, project: string): Installation[] {
  const out: Installation[] = [];
  const add = (scope: Scope, path: string, version: string | null) => out.push({ host, kind: "plugin", scope, path, version, status: statusOf(version) });
  if (host === "claude") {
    const reg = readJson(join(home, ".claude", "plugins", "installed_plugins.json")) as { plugins?: Record<string, { scope?: string; installPath?: string; version?: string }[]> } | undefined;
    for (const [id, entries] of Object.entries(reg?.plugins ?? {})) {
      if (!id.startsWith("navsentry@")) continue;
      for (const e of entries) add(e.scope === "project" || e.scope === "local" ? "project" : "user", e.installPath ?? id, (e.installPath && jsonVersion(join(e.installPath, ".claude-plugin", "plugin.json"))) || e.version || null);
    }
  } else if (host === "codex") {
    for (const market of subdirs(join(home, ".codex", "plugins", "cache")))
      for (const ver of subdirs(join(market, "navsentry"))) add("user", ver, jsonVersion(join(ver, ".codex-plugin", "plugin.json")));
  } else if (host === "gemini") {
    const ext = join(home, ".gemini", "extensions", "navsentry");
    if (existsSync(ext)) add("user", ext, jsonVersion(join(ext, "gemini-extension.json")));
  } else {
    for (const [scope, dir] of [["user", join(home, ".gemini", "config", "plugins", "navsentry")], ["project", join(project, ".agents", "plugins", "navsentry")]] as const) {
      if (!existsSync(dir)) continue;
      const nested = join(dir, ".antigravity-plugin", "plugin.json");
      add(scope, dir, jsonVersion(existsSync(nested) ? nested : join(dir, "plugin.json")));
    }
  }
  return out;
}

export function findInstallations(hosts: readonly Host[], home = homedir(), project = process.cwd()): Installation[] {
  const out: Installation[] = [];
  for (const host of hosts) {
    out.push(...pluginInstalls(host, home, project));
    for (const scope of ["user", "project"] as const)
      for (const dir of skillDirs(host, scope, home, project)) {
        const file = join(dir, "navsentry", "SKILL.md");
        if (!existsSync(file)) continue;
        const version = skillVersion(file);
        out.push({ host, kind: "skill", scope, path: join(dir, "navsentry"), version, status: statusOf(version) });
      }
  }
  return out;
}

export function doctorReport(hosts: readonly Host[] = HOSTS, home = homedir(), project = process.cwd()): DoctorReport {
  const root = packageRoot();
  return { version: TOOL_VERSION, packageRoot: root, manifests: manifestVersions(root), installations: findInstallations(hosts, home, project) };
}

/** Host-owned plugin commands. Printed for the user; doctor never runs them. */
export function pluginCommands(host: Host): { install: string[]; update: string[] } {
  switch (host) {
    case "claude": return { install: [`claude plugin marketplace add ${REPO}`, "claude plugin install navsentry@navsentry"], update: ["claude plugin marketplace update navsentry", "claude plugin update navsentry@navsentry"] };
    case "codex": return { install: [`codex plugin marketplace add ${REPO}`, "codex plugin add navsentry@navsentry"], update: ["codex plugin marketplace upgrade navsentry", "codex plugin add navsentry@navsentry"] };
    case "gemini": return { install: [`gemini extensions install https://github.com/${REPO}`], update: ["gemini extensions update navsentry"] };
    case "antigravity": return { install: [`agy plugin install https://github.com/${REPO}`], update: ["agy plugin uninstall navsentry", `agy plugin install https://github.com/${REPO}`] };
  }
}

export interface UpdatePlan { host: Host; scope: Scope; target: string; copies: { skill: string; from: string; to: string; replaces: string | null }[] }

export class DoctorError extends Error {}

export function planSkillUpdate(host: Host, scope: Scope, home = homedir(), project = process.cwd(), root = packageRoot()): UpdatePlan {
  const dirs = skillDirs(host, scope, home, project);
  const target = resolve(dirs.find((d) => existsSync(join(d, "navsentry"))) ?? dirs[0]!);
  const rel = relative(resolve(root), target);
  if (!rel.startsWith("..") && !rel.startsWith(sep) && !/^[A-Za-z]:/.test(rel)) throw new DoctorError(`refusing to install into the NavSentry package itself (${target}); choose another --project`);
  const copies = SKILLS.map((skill) => {
    const from = join(root, "skills", skill), to = join(target, skill);
    if (!existsSync(join(from, "SKILL.md"))) throw new DoctorError(`package skill missing: ${from}`);
    if (existsSync(to) && skillName(join(to, "SKILL.md")) !== skill) throw new DoctorError(`${to} exists but is not the ${skill} skill; leaving it untouched`);
    return { skill, from, to, replaces: existsSync(to) ? skillVersion(join(to, "SKILL.md")) ?? "unknown" : null };
  });
  return { host, scope, target, copies };
}

/** Applies a plan. Previous copies move to a backup outside the skills directory, so the host never sees duplicates. */
export function applySkillUpdate(plan: UpdatePlan, backupRoot = join(tmpdir(), "navsentry-doctor-backup")): string | null {
  const backup = join(backupRoot, new Date().toISOString().replace(/[:.]/g, "-"));
  let used = false;
  mkdirSync(plan.target, { recursive: true });
  for (const c of plan.copies) {
    if (c.replaces !== null) {
      mkdirSync(backup, { recursive: true });
      // Copy then remove: the backup may live on another drive, where rename fails.
      cpSync(c.to, join(backup, c.skill), { recursive: true });
      rmSync(c.to, { recursive: true, force: true });
      used = true;
    }
    cpSync(c.from, c.to, { recursive: true });
  }
  return used ? backup : null;
}
