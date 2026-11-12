/**
 * Run integrity manifest (M4, SPEC-0.4.0 §3): `MANIFEST.json` lists every file a run wrote with its size
 * and SHA-256, and `navsentry verify` checks a run folder against it.
 *
 * It detects files that changed, went missing or were added after the run. It is not a signature: anyone
 * who can edit the folder can also rewrite the manifest, so it proves nothing against a deliberate editor.
 */
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, relative, sep } from "node:path";

export const MANIFEST_FILE = "MANIFEST.json";

export interface ManifestEntry { path: string; bytes: number; sha256: string }
export interface RunManifest { kind: "navsentry-run-manifest"; schemaVersion: "1"; runId: string; toolVersion: string; algorithm: "sha256"; files: ManifestEntry[] }

export interface VerifyResult {
  status: "PASS" | "FAIL";
  runId: string;
  checked: number;
  modified: string[];
  missing: string[];
  added: string[];
  limitations: string[];
}

export const VERIFY_LIMITATIONS = [
  "MANIFEST.json is not signed: it detects accidental or partial changes, not a deliberate edit that also rewrites the manifest",
  "Symbolic links in the run folder are reported as added and never followed",
];

const sha256 = (b: Buffer): string => createHash("sha256").update(b).digest("hex");

/** Files under `dir` (relative, `/`-separated, sorted), skipping the manifest itself. Never follows links. */
export function listRunFiles(dir: string): { files: string[]; links: string[] } {
  const files: string[] = [], links: string[] = [];
  const walk = (d: string): void => {
    for (const n of readdirSync(d).sort()) {
      const p = join(d, n);
      const rel = relative(dir, p).split(sep).join("/");
      const st = lstatSync(p);
      if (st.isSymbolicLink()) links.push(rel);
      else if (st.isDirectory()) walk(p);
      else if (st.isFile() && rel !== MANIFEST_FILE) files.push(rel);
    }
  };
  walk(dir);
  return { files: files.sort(), links: links.sort() };
}

/** Manifest of the files this run wrote (`written`, relative paths); other files in `--out` are not listed. */
export function buildManifest(dir: string, runId: string, toolVersion: string, written: string[]): RunManifest {
  const files = [...new Set(written.map((w) => w.split(sep).join("/")))].filter((f) => f !== MANIFEST_FILE).sort();
  return {
    kind: "navsentry-run-manifest", schemaVersion: "1", runId, toolVersion, algorithm: "sha256",
    files: files.map((path) => { const b = readFileSync(join(dir, path)); return { path, bytes: b.length, sha256: sha256(b) }; }),
  };
}

export function parseManifest(text: string): RunManifest {
  let m: unknown;
  try { m = JSON.parse(text); } catch { throw new Error(`${MANIFEST_FILE} is not valid JSON`); }
  const o = m as Partial<RunManifest>;
  if (o?.kind !== "navsentry-run-manifest" || o.schemaVersion !== "1" || o.algorithm !== "sha256" || typeof o.runId !== "string" || !Array.isArray(o.files)) throw new Error(`${MANIFEST_FILE} is not a navsentry-run-manifest v1`);
  for (const f of o.files) {
    if (typeof f?.path !== "string" || typeof f.bytes !== "number" || typeof f.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(f.sha256)) throw new Error(`${MANIFEST_FILE} has a malformed entry`);
    // Entries must stay inside the run folder.
    if (f.path.startsWith("/") || f.path.split("/").some((s) => s === ".." || s === "") || /^[a-zA-Z]:/.test(f.path) || f.path.includes("\\")) throw new Error(`${MANIFEST_FILE} entry escapes the run folder`);
  }
  return o as RunManifest;
}

export function verifyRun(dir: string): VerifyResult {
  const mp = join(dir, MANIFEST_FILE);
  if (!existsSync(mp)) throw new Error(`${MANIFEST_FILE} not found in ${dir}; runs written before 0.4.0 have none`);
  const m = parseManifest(readFileSync(mp, "utf8"));
  const { files, links } = listRunFiles(dir);
  const present = new Set(files);
  const listed = new Set(m.files.map((f) => f.path));
  const modified: string[] = [], missing: string[] = [];
  for (const f of m.files) {
    if (!present.has(f.path)) { missing.push(f.path); continue; }
    const b = readFileSync(join(dir, f.path));
    if (b.length !== f.bytes || sha256(b) !== f.sha256) modified.push(f.path);
  }
  const added = [...files.filter((f) => !listed.has(f)), ...links].sort();
  const ok = !modified.length && !missing.length && !added.length;
  return { status: ok ? "PASS" : "FAIL", runId: m.runId, checked: m.files.length, modified, missing, added, limitations: VERIFY_LIMITATIONS };
}

export function renderVerify(v: VerifyResult): string {
  const lines = [`verify ${v.status}: run ${v.runId}, ${v.checked} file(s) in the manifest`];
  for (const [label, xs] of [["modified", v.modified], ["missing", v.missing], ["added", v.added]] as const) for (const x of xs) lines.push(`  ${label}: ${x}`);
  lines.push(...v.limitations.map((l) => `  note: ${l}`));
  return lines.join("\n");
}
