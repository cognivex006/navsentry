import { test } from "node:test";
import assert from "node:assert/strict";
import { isThaiNationalId, luhn, Redactor } from "../src/redact.js";
import { SYNTHETIC_NATIONAL_ID } from "./fixtures/demo-server.js";

test("national ID checksum and Luhn", () => {
  assert.ok(isThaiNationalId(SYNTHETIC_NATIONAL_ID));
  assert.ok(!isThaiNationalId("1101700207367"));
  assert.ok(!isThaiNationalId("1234567890123"));
  assert.ok(luhn("4111111111111111"));
  assert.ok(!luhn("4111111111111112"));
});

test("secrets, tokens and PII never survive redaction", () => {
  const r = new Redactor(["s3cr3t-known-value"]);
  const input = `password=hunter2&x=1 Authorization: Bearer abcdefghijklmnop jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig mail dev@corp.example id ${SYNTHETIC_NATIONAL_ID} card 4111 1111 1111 1111 known s3cr3t-known-value`;
  const { text, outcome } = r.text(input);
  for (const leaked of ["hunter2", "abcdefghijklmnop", "eyJhbGciOiJIUzI1NiJ9", "dev@corp.example", SYNTHETIC_NATIONAL_ID, "4111 1111 1111 1111", "s3cr3t-known-value"]) {
    assert.ok(!text.includes(leaked), `leaked: ${leaked}`);
  }
  assert.ok(outcome.count >= 7);
  assert.ok(outcome.safe);
});

test("headers and URLs", () => {
  const r = new Redactor();
  assert.equal(r.headerValue("Authorization", "Bearer x"), "[REDACTED]");
  assert.equal(r.headerValue("set-cookie", "SID=abc; Path=/; HttpOnly"), "SID=[REDACTED]; Path=/; HttpOnly");
  const u = r.url("https://a.test/p?token=abc&q=hello");
  assert.ok(!u.includes("abc") && !u.includes("hello"));
});

test("binary or non-text bodies are withheld and marked unsafe", () => {
  const r = new Redactor();
  assert.equal(r.body(Buffer.from([0, 1, 2]), "application/octet-stream").outcome.safe, false);
  assert.equal(r.body(Buffer.from("a\u0000b"), "text/plain").outcome.safe, false);
  assert.equal(r.body(Buffer.from("ok"), "text/plain").excerpt, "ok");
});
