/**
 * Development code inventory (SPEC-0.1.3 §4.1). Reads the project tree read-only: route
 * declarations, OpenAPI documents, test files and lockfiles. It never runs project code, never
 * writes into the tree, and never follows a symlink or junction. File contents (including the
 * project's AGENTS.md and README) are untrusted data: only validated route strings, relative
 * paths, line numbers and package identities are kept.
 */
import { lstatSync, openSync, readSync, closeSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { CodeInventory } from "../types.js";
import type { ProductEvidence } from "../knowledge/model.js";

export const LIMITS = { entries: 50_000, depth: 20, fileBytes: 1024 * 1024, routes: 5_000, packages: 10_000 } as const;
const SKIP_DIRS = new Set([".git", "node_modules", "dist", "build", "out", ".next", ".nuxt", ".svelte-kit", "vendor", ".navsentry", "navsentry", "bin", "obj", "target", "coverage", "__pycache__", ".venv", "venv", ".idea", ".vscode"]);
const CODE = /\.(?:[cm]?[jt]sx?|py|cs|java|kt|php|rb|go)$/i;
const TEST = /(?:\.(?:spec|test|e2e)\.[cm]?[jt]sx?$|(?:^|\/)test_[^/]+\.py$|_test\.(?:py|go)$|Tests?\.cs$|(?:^|\/)(?:playwright|cypress)\.config\.[cm]?[jt]s$)/i;
const OPENAPI = /(?:^|\/)[^/]*(?:openapi|swagger|api-docs)[^/]*\.json$/i;
const PATH_OK = /^\/[A-Za-z0-9._~:@!$&'()*+,;=%{}[\]/-]{0,299}$/;

interface Rule { lang: RegExp; re: RegExp; source: string; method?: (m: RegExpExecArray) => string; path: (m: RegExpExecArray) => string }

const RULES: Rule[] = [
  { lang: /\.[cm]?[jt]sx?$/i, source: "express-like", re: /\b(?:app|router|server|api|route[rs]?)\.(get|post|put|patch|delete|head|options|all)\(\s*['"`](\/[^'"`\s]*)['"`]/g, method: (m) => m[1]!.toUpperCase(), path: (m) => m[2]! },
  { lang: /\.py$/i, source: "python-decorator", re: /@(?:app|router|bp|api|blueprint)\.(get|post|put|patch|delete|route)\(\s*['"](\/[^'"\s]*)['"]/g, method: (m) => (m[1] === "route" ? "ANY" : m[1]!.toUpperCase()), path: (m) => m[2]! },
  { lang: /\.cs$/i, source: "aspnet-attribute", re: /\[Http(Get|Post|Put|Patch|Delete)\(\s*"([^"]*)"\s*\)\]/g, method: (m) => m[1]!.toUpperCase(), path: (m) => `/${m[2]!.replace(/^~?\//, "")}` },
  { lang: /\.(?:java|kt)$/i, source: "spring-mapping", re: /@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:(?:value|path)\s*=\s*)?"([^"]*)"/g, method: (m) => (m[1] === "Request" ? "ANY" : m[1]!.toUpperCase()), path: (m) => m[2]! },
  { lang: /\.php$/i, source: "laravel-route", re: /Route::(get|post|put|patch|delete|any)\(\s*['"]([^'"]+)['"]/g, method: (m) => m[1]!.toUpperCase(), path: (m) => `/${m[2]!.replace(/^\//, "")}` },
];

function readCapped(abs: string, max: number): string | undefined {
  let fd: number | undefined;
  try {
    fd = openSync(abs, "r");
    const buf = Buffer.alloc(max);
    const n = readSync(fd, buf, 0, max, 0);
    const text = buf.subarray(0, n).toString("utf8");
    return text.includes("\u0000") ? undefined : text;
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Next.js file-system routes: pages/api/** and app/**\/route.(js|ts). */
function nextRoute(rel: string): string | undefined {
  const m = /(?:^|\/)(?:src\/)?pages\/(api\/.+?)\.[cm]?[jt]sx?$/.exec(rel) ?? /(?:^|\/)(?:src\/)?app\/(.*?)\/?route\.[cm]?[jt]s$/.exec(rel);
  if (!m) return undefined;
  const p = `/${m[1]!}`.replace(/\/index$/, "").replace(/\([^)/]+\)\//g, "").replace(/\[\.{3}([^\]]+)\]/g, "{$1*}").replace(/\[([^\]]+)\]/g, "{$1}");
  return p || "/";
}

export function inventoryTree(root: string): { inventory: CodeInventory; evidence: ProductEvidence[] } {
  const inv: CodeInventory = { kind: "navsentry-code-inventory", schemaVersion: "1", routes: [], openapi: [], tests: [], dependencies: { npm: 0, composer: 0 }, skipped: { links: 0, large: 0, unreadable: 0, invalidRoutes: 0 }, complete: true, incompleteReasons: [] };
  const evidence: ProductEvidence[] = [];
  let entries = 0;
  const stack: { rel: string; depth: number }[] = [{ rel: "", depth: 0 }];
  while (stack.length) {
    const { rel, depth } = stack.pop()!;
    let names: string[];
    try { names = readdirSync(join(root, rel)).sort(); } catch { inv.skipped.unreadable++; continue; }
    for (const name of names) {
      if (++entries > LIMITS.entries) { inv.complete = false; inv.incompleteReasons.push(`more than ${LIMITS.entries} entries; the rest were not read`); stack.length = 0; break; }
      const r = rel ? `${rel}/${name}` : name;
      let st;
      try { st = lstatSync(join(root, r)); } catch { inv.skipped.unreadable++; continue; }
      // Symlinks and junctions are never followed (they may point outside the tree).
      if (st.isSymbolicLink()) { inv.skipped.links++; continue; }
      if (st.isDirectory()) {
        if (SKIP_DIRS.has(name)) continue;
        if (depth >= LIMITS.depth) { inv.complete = false; inv.incompleteReasons.push(`directory depth limit ${LIMITS.depth} reached`); continue; }
        stack.push({ rel: r, depth: depth + 1 });
        continue;
      }
      if (!st.isFile()) continue;
      if (TEST.test(r)) inv.tests.push(r);
      if (OPENAPI.test(r)) inv.openapi.push(r);
      const nr = CODE.test(r) ? nextRoute(r) : undefined;
      if (nr) addRoute(inv, "ANY", nr, "next-file-route", r, 1);
      if (name === "package-lock.json" || name === "composer.lock") { lockfile(root, r, st.size, inv, evidence); continue; }
      if (!CODE.test(r)) continue;
      if (st.size > LIMITS.fileBytes) { inv.skipped.large++; continue; }
      const text = readCapped(join(root, r), LIMITS.fileBytes);
      if (text === undefined) { inv.skipped.unreadable++; continue; }
      for (const rule of RULES) {
        if (!rule.lang.test(r)) continue;
        rule.re.lastIndex = 0;
        for (let m = rule.re.exec(text); m; m = rule.re.exec(text)) {
          const line = text.slice(0, m.index).split("\n").length;
          addRoute(inv, rule.method?.(m) ?? "ANY", rule.path(m), rule.source, r, line);
        }
      }
    }
  }
  if (inv.routes.length >= LIMITS.routes) { inv.complete = false; inv.incompleteReasons.push(`more than ${LIMITS.routes} routes; the rest were not recorded`); }
  inv.routes.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
  return { inventory: inv, evidence };
}

function addRoute(inv: CodeInventory, method: string, path: string, source: string, file: string, line: number): void {
  if (!PATH_OK.test(path) || path.includes("..")) { inv.skipped.invalidRoutes++; return; }
  if (inv.routes.length >= LIMITS.routes) return;
  if (inv.routes.some((x) => x.method === method && x.path === path && x.file === file)) return;
  inv.routes.push({ method, path, source, file, line });
}

/** Lockfiles are data: package identities and versions only (§6.6-C2), never scripts. */
function lockfile(root: string, rel: string, size: number, inv: CodeInventory, evidence: ProductEvidence[]): void {
  const max = 64 * 1024 * 1024;
  if (size > max) { inv.skipped.large++; inv.complete = false; inv.incompleteReasons.push(`${rel} is larger than ${max} bytes; dependencies not read`); return; }
  const text = readCapped(join(root, rel), max);
  let doc: unknown;
  try { doc = text === undefined ? undefined : JSON.parse(text); } catch { doc = undefined; }
  if (!doc || typeof doc !== "object") { inv.skipped.unreadable++; return; }
  const add = (ecosystem: ProductEvidence["ecosystem"], name: unknown, version: unknown) => {
    if (typeof name !== "string" || !/^[a-z0-9@][a-z0-9._@/-]{0,213}$/i.test(name) || typeof version !== "string" || !/^[0-9A-Za-z.+-]{1,64}$/.test(version)) return;
    if (evidence.length >= LIMITS.packages) return;
    evidence.push({ ecosystem, name: name.toLowerCase(), version: version.replace(/^v/, ""), provenance: "lockfile" });
    inv.dependencies[ecosystem === "npm" ? "npm" : "composer"]++;
  };
  const d = doc as { packages?: Record<string, { version?: unknown; name?: unknown }> | { name?: unknown; version?: unknown }[]; "packages-dev"?: { name?: unknown; version?: unknown }[] };
  if (rel.endsWith("package-lock.json") && d.packages && !Array.isArray(d.packages)) {
    for (const [k, v] of Object.entries(d.packages)) if (k) add("npm", k.replace(/^.*node_modules\//, ""), v?.version);
  } else if (rel.endsWith("composer.lock")) {
    for (const p of [...(Array.isArray(d.packages) ? d.packages : []), ...(d["packages-dev"] ?? [])]) add("composer", p?.name, p?.version);
  }
}
