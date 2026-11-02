import { test } from "node:test";
import assert from "node:assert/strict";
import { ConfigError, parseManifest } from "../src/config.js";

const base = () => ({
  version: "1", project: "p", environment: "staging",
  authorization: { acknowledged: true, owner: "o", reference: "CHG-1", expires_at: "2099-01-01" },
  targets: { origins: ["https://staging.example.test"] },
});

function problems(x: unknown): string[] {
  try {
    parseManifest(x);
    return [];
  } catch (e) {
    assert.ok(e instanceof ConfigError);
    return e.problems;
  }
}

test("minimal manifest gets safe defaults", () => {
  const m = parseManifest(base());
  assert.equal(m.safety.mode, "observe");
  assert.deepEqual(m.safety.allowed_methods, ["GET", "HEAD", "OPTIONS"]);
  assert.equal(m.safety.allow_mutations, false);
  assert.deepEqual(m.transports.order, ["direct-http"]);
});

test("authorization must be acknowledged", () => {
  assert.ok(problems({ ...base(), authorization: { acknowledged: false, owner: "o" } }).some((p) => p.includes("acknowledged")));
  assert.ok(problems({ ...base(), authorization: { acknowledged: true, owner: "o", expires_at: "2001-01-01" } }).some((p) => p.includes("expired")));
});

test("plaintext secrets and unknown keys are rejected", () => {
  const p = problems({ ...base(), actors: { reader: { password: "hunter2" } } });
  assert.ok(p.some((x) => x.includes("plaintext secrets")));
  assert.ok(!p.join(" ").includes("hunter2"), "secret value is never echoed");
  assert.ok(problems({ ...base(), targts: {} }).some((x) => x.includes("unknown key")));
});

test("unsafe modes, methods and origins are refused", () => {
  assert.ok(problems({ ...base(), safety: { mode: "active-approved" } }).length);
  assert.ok(problems({ ...base(), environment: "production", safety: { mode: "safe-validate" } }).length);
  assert.ok(problems({ ...base(), safety: { allow_mutations: true } }).length);
  assert.ok(problems({ ...base(), safety: { allowed_methods: ["GET", "DELETE"] } }).length);
  assert.ok(problems({ ...base(), targets: { origins: ["https://x.test/path"] } }).length);
  assert.ok(problems({ ...base(), targets: { origins: ["javascript:alert(1)"] } }).length);
  assert.ok(problems({ ...base(), targets: { origins: ["https://x.test"], allowed_paths: ["/a/../b"] } }).length);
  assert.ok(problems({ ...base(), safety: { max_requests: 1e9 } }).some((x) => x.includes("max_requests")));
});

test("private network approval requires approver and reason", () => {
  assert.ok(problems({ ...base(), network: { allow_private: [{ host: "x" }] } }).length);
});
