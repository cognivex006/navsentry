/** Shared NavSentry domain types. Wire shapes are versioned by REPORT_SCHEMA_VERSION. */

export const REPORT_SCHEMA_VERSION = "1";
export const TOOL_NAME = "navsentry";
export const TOOL_VERSION = "0.1.2";

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
  /** Present when the request was made by a flow step. */
  flow?: { id: string; step: string; deniedProbe?: true };
  /** Streamed-capture completion metadata (0.1.3). */
  capture?: CaptureInfo;
}

/**
 * How completely a response body was read. `truncated`: NavSentry stopped at a budget.
 * `aborted`: the peer closed early or the request was cancelled. Only `complete` with
 * retainedBytes === decodedBytes supports a body-based PASS.
 */
export interface CaptureInfo {
  status: "complete" | "truncated" | "aborted";
  reason?: string;
  wireBytes: number;
  decodedBytes: number;
  /** Bytes kept in memory for checks (the prefix). */
  retainedBytes: number;
  /** sha256 of all bytes read, computed incrementally. */
  sha256: string;
  /** Non-identity content-encoding: bytes were not decoded and body checks are unsupported. */
  encoding?: string;
}

export type ScanMode = "page" | "spider" | "flow";
export type Engine = "http" | "playwright" | "computer-use";

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
  /** "draft-flow": evidence rests on an unapproved flow expectation; findings stay SUSPECTED. */
  basis?: "draft-flow";
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
  flowSet?: { flows: number; steps: number; sha256: string; resultFile: "flows.json" };
  // 0.1.3 additive fields. `mode` stays the safety mode; `scanMode` is separate.
  scanMode?: ScanMode;
  profile?: "development" | "production";
  engine?: { requested: Engine | "analyzer"; used: Engine; analyze: boolean };
  /** Authorization reference, production profile only. */
  authorizationReference?: string;
  capture?: { wireBytes: number; decodedBytes: number; truncated: number; aborted: number; partialBodies: number };
  workspace?: WorkspaceResult;
}

export interface WorkspaceResult {
  /** PASS: no unexpected change. FAIL: WORKSPACE_DIRTY (exit 4). NOT_TESTED: tree too large or unreadable. */
  status: "PASS" | "FAIL" | "NOT_TESTED";
  reason?: string;
  /** Redacted, project-relative display paths. */
  created: string[];
  modified: string[];
  deleted: string[];
  cleanup: "COMPLETE" | "FAILED";
  cleanupReason?: string;
  promoted: number;
  limitations: string[];
}

// ───────────────────────── Flows (0.1.2) ─────────────────────────
// Additive fields on the v1 run model:
//   ObservedRequest.flow, CheckResult.basis, RunResult.flowSet (all optional).

export const FLOW_FORMAT_VERSION = "1";
export const FLOW_RESULT_SCHEMA_VERSION = "1";

export type TestLevel = "integration" | "e2e";
export type FlowAction = "http" | "navigate" | "click" | "fill" | "select" | "submit" | "see" | "wait_for";
export type FlowStatus = "PASS" | "FAIL" | "INCOMPLETE" | "ERROR" | "NOT_TESTED";
export type FunctionalResult = "PASS" | "FAIL" | "INCOMPLETE";

export interface AssertionResult {
  kind: "status" | "content_type" | "header_present" | "header_absent" | "json" | "shape" | "text_present" | "text_absent" | "redirect_to" | "access";
  status: CheckStatus;
  /** From the linted flow file. */
  expected: string;
  /** Value-free: code, media type, JSON type, present/absent/matched/differs. */
  observed: string;
}

export interface StepResult {
  id: string;
  /** "<flowId>/<stepId>" */
  key: string;
  title: string;
  action: FlowAction;
  actor: string;
  /** Template form, e.g. "GET /api/orders/{{orderA}}". */
  request?: string;
  contentSha256: string;
  status: CheckStatus;
  reason?: string;
  assertions: AssertionResult[];
  requestIds: string[];
  securityCase?: string;
}

export interface FlowResult {
  id: string;
  title: string;
  story: string;
  /** Relative to the --flows root; never absolute. */
  file: string;
  declaredLevel: "auto" | TestLevel;
  level: TestLevel;
  levelReasons: string[];
  executability: "full" | "partial" | "none";
  review: { status: "draft" | "approved"; approvedBy?: string; approvedAt?: string; hashValid: boolean };
  contentSha256: string;
  status: FlowStatus;
  reasons: string[];
  steps: StepResult[];
  findings: string[];
  manualReplay: string[];
}

export interface FlowRunResult {
  kind: "navsentry-flow-result";
  schemaVersion: typeof FLOW_RESULT_SCHEMA_VERSION;
  runId: string;
  tool: RunResult["tool"];
  startedAt: string;
  finishedAt: string;
  project: string;
  environment: string;
  mode: SafetyMode;
  flowSet: { flows: number; steps: number; sha256: string };
  functionalResult: FunctionalResult;
  summary: Record<TestLevel, Record<FlowStatus, number>>;
  flows: FlowResult[];
}
