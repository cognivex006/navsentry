/**
 * Deterministic test-level classification (spec §6) and canonical hashing.
 * Pure functions: no I/O.
 */
import { createHash } from "node:crypto";
import type { TestLevel } from "../types.js";
import { UI_ACTIONS, type FlowDoc, type FlowStep } from "./parse.js";

export interface Classification {
  level: TestLevel;
  levelReasons: string[];
  executability: "full" | "partial" | "none";
  requiredTransports: string[];
  stateful: boolean;
  hasSecurityExpectations: boolean;
}

/** Transport a step needs. UI steps need a browser, which is not executable in this release. */
export function stepTransport(s: FlowStep): string {
  return UI_ACTIONS.has(s.action) ? "playwright-browser" : "direct-http";
}

export function classify(doc: FlowDoc, usable: ReadonlySet<string> = new Set(["direct-http"])): Classification {
  const ui = doc.steps.filter((s) => UI_ACTIONS.has(s.action));
  const nav = doc.steps.filter((s) => s.action === "navigate");
  let level: TestLevel;
  let levelReasons: string[];
  if (ui.length) {
    level = "e2e";
    levelReasons = ui.map((s) => `${s.id} ${s.action} needs a browser`);
  } else if (nav.length) {
    level = "e2e";
    levelReasons = nav.map((s) => `${s.id} navigate is a page journey step`);
  } else {
    level = "integration";
    levelReasons = ["all steps are API requests"];
  }
  const required = [...new Set(doc.steps.map(stepTransport))].sort();
  const runnable = doc.steps.filter((s) => usable.has(stepTransport(s))).length;
  return {
    level,
    levelReasons,
    executability: runnable === doc.steps.length ? "full" : runnable === 0 ? "none" : "partial",
    requiredTransports: required,
    stateful: doc.steps.some((s) => s.extract && Object.keys(s.extract).length > 0),
    hasSecurityExpectations: doc.steps.some((s) => s.expect?.access !== undefined),
  };
}

/** JSON with recursively sorted keys and no whitespace. */
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

const sha = (s: string) => createHash("sha256").update(s).digest("hex");

export function stepHash(s: FlowStep): string {
  return sha(canonical(s.raw));
}

/**
 * Content hash pinned by approval: header without `review`, then the steps in order. A flow with
 * `requires` also covers the sorted (flowId, recursive hash) pairs of its dependencies, so editing a
 * required flow invalidates every dependent approval (SPEC-0.1.3 §5.5). Flows without dependencies
 * keep their 0.1.2 hash. A missing or cyclic dependency hashes to a marker; lint reports it.
 */
export function flowHash(doc: FlowDoc, seen: ReadonlySet<string> = new Set()): string {
  const { review: _review, ...rest } = doc.header.raw;
  const own = sha([canonical(rest), ...doc.steps.map((s) => canonical(s.raw))].join("\n"));
  if (!doc.header.requires.length) return own;
  const next = new Set([...seen, doc.header.id]);
  const deps = doc.header.requires.map((id) => {
    const d = doc.deps?.find((x) => x.header.id === id);
    return `${id}:${!d ? "missing" : next.has(id) ? "cycle" : flowHash(d, next)}`;
  }).sort();
  return sha([own, ...deps].join("\n"));
}

export function flowSetHash(docs: FlowDoc[]): string {
  return sha(docs.map((d) => `${d.header.id}:${flowHash(d)}`).sort().join("\n"));
}

/** Method + path template + sorted query template; used to pair denied steps with positive controls. */
export function requestTemplate(s: FlowStep): string | undefined {
  if (!s.request) return undefined;
  const q = s.request.query ? Object.keys(s.request.query).sort().map((k) => `${k}=${s.request!.query![k]}`).join("&") : "";
  return `${s.request.method} ${s.request.path}${q ? `?${q}` : ""}`;
}
