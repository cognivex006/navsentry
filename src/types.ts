/** Shared NavSentry domain types. Wire shapes are versioned by REPORT_SCHEMA_VERSION. */

export const REPORT_SCHEMA_VERSION = "1";
export const TOOL_NAME = "navsentry";
export const TOOL_VERSION = "0.1.0";

/** Result of a single check execution. Only PASS/FAIL are conclusive. */
export type CheckStatus = "PASS" | "FAIL" | "INCONCLUSIVE" | "NOT_TESTED" | "ERROR";

/** Finding lifecycle. Observation-only evidence never reaches VALIDATED without a deterministic assertion. */
export type FindingLifecycle = "SUSPECTED" | "VALIDATED" | "NEEDS_REVIEW" | "DISMISSED";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";

/** Remediation urgency used by the reports (Thai: ทันที / รอได้ / ระวังผลกระทบ). */
export type Priority = "IMMEDIATE" | "PLANNED" | "CAUTION";

export type SafetyMode = "observe" | "safe-validate" | "active-approved";

export type HttpMethod = "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE" | "TRACE" | "CONNECT";

export const SAFE_METHODS: ReadonlySet<HttpMethod> = new Set(["GET", "HEAD", "OPTIONS"]);

export interface ObservedRequest {
  id: string;
  transport: string;
  actor: string;
  method: HttpMethod;
  /** Redacted URL (query values masked). */
  url: string;
  requestHeaders: Record<string, string>;
  startedAt: string;
  durationMs: number;
  status?: number;
  responseHeaders?: Record<string, string[]>;
  /** Redacted, size-bounded body excerpt; undefined when withheld. */
  bodyExcerpt?: string;
  bodyBytes?: number;
  /** Shape fingerprint of the response used by `compare` to detect contract regressions. */
  contract?: ResponseContract;
  error?: string;
  redaction: RedactionOutcome;
}

export interface ResponseContract {
  status: number;
  contentType: string;
  /** Sorted, lower-cased header names excluding volatile ones. */
  headerNames: string[];
  /** For JSON: sha256 of the recursive key/type skeleton. For others: undefined. */
  jsonShapeHash?: string;
  bodyLengthBucket: string;
}

export interface RedactionOutcome {
  applied: boolean;
  count: number;
  kinds: string[];
  /** false => evidence withheld, report marks it incomplete. */
  safe: boolean;
}

export interface CheckResult {
  ruleId: string;
  status: CheckStatus;
  target: string;
  transport: string;
  summary: string;
  /** Short factual observation strings (already redacted). */
  observations: string[];
  requestIds: string[];
  reason?: string;
}

export interface Finding {
  fingerprint: string;
  ruleId: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  lifecycle: FindingLifecycle;
  priority: Priority;
  target: string;
  expected: string;
  actual: string[];
  reproduction: string[];
  limitations: string[];
  recommendation: string;
  regressionGuard: string;
  mappings: RuleMappings;
  requestIds: string[];
}

export interface RuleMappings {
  owasp2021: string[];
  owasp2025: string[];
  cwe: string[];
  wstg: string[];
  asvs5Chapter: string[];
}

export interface CoverageRow {
  ruleId: string;
  status: CheckStatus;
  targets: number;
  reason?: string;
}

export interface TransportStatus {
  id: string;
  available: boolean;
  usable: boolean;
  reason: string;
  version?: string;
}

export interface RunResult {
  schemaVersion: string;
  tool: { name: string; version: string; node: string; platform: string };
  runId: string;
  startedAt: string;
  finishedAt: string;
  project: string;
  environment: string;
  mode: SafetyMode;
  scope: { origins: string[]; allowedPaths: string[]; deniedPaths: string[] };
  /** CLI execution status, independent of security outcome. */
  executionStatus: "COMPLETE" | "PARTIAL" | "FAILED";
  incompleteReasons: string[];
  transports: TransportStatus[];
  requests: ObservedRequest[];
  checks: CheckResult[];
  findings: Finding[];
  coverage: CoverageRow[];
  budget: { requestsUsed: number; requestsMax: number; deniedBeforeExecution: number };
  denials: { url: string; method: string; reason: string }[];
}
