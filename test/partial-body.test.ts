/** Hard rule 5: a body check that saw only part of the body never reports PASS. Synthetic exchanges, no network. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkEmail, checkErrorDisclosure, checkInternalIp, checkPii, checkVersionDisclosure } from "../src/checks/passive.js";
import type { Exchange } from "../src/transports/types.js";
import type { CaptureInfo } from "../src/types.js";

const ex = (body: string, capture?: Partial<CaptureInfo>, status = 200): Exchange => ({
  record: { id: "r1", transport: "direct-http", actor: "anonymous", method: "GET", url: "http://127.0.0.1:4173/x" } as Exchange["record"],
  raw: {
    status,
    headers: { "content-type": ["text/html"] },
    body: Buffer.from(body),
    ...(capture ? { capture: { status: "complete", wireBytes: body.length, decodedBytes: body.length, retainedBytes: body.length, sha256: "0", ...capture } as CaptureInfo } : {}),
  },
});

test("clean complete body: PASS; truncated, aborted or partly retained body: INCONCLUSIVE with the reason", () => {
  const clean = "<html><body>hello</body></html>";
  for (const check of [checkErrorDisclosure, checkInternalIp, checkEmail, checkPii]) {
    assert.equal(check(ex(clean, {})).status, "PASS", check.name);
    const t = check(ex(clean, { status: "truncated", reason: "response exceeded capture.max_response_bytes (1048576)", decodedBytes: 5_000_000 }));
    assert.equal(t.status, "INCONCLUSIVE", check.name);
    assert.match(t.reason ?? "", /truncated/);
    assert.equal(check(ex(clean, { status: "aborted" })).status, "INCONCLUSIVE", `${check.name} aborted`);
    assert.equal(check(ex(clean, { retainedBytes: 10, decodedBytes: 900_000 })).status, "INCONCLUSIVE", `${check.name} partly retained`);
  }
  const v = checkVersionDisclosure(ex(clean, { status: "truncated" }, 500));
  assert.equal(v.status, "INCONCLUSIVE", "error-page scan on a truncated body");
  assert.equal(checkVersionDisclosure(ex(clean, { status: "truncated" }, 200)).status, "PASS", "a 200 page is judged on headers only");
});

test("a body longer than the scanned window is not a PASS; a match in the prefix is still a FAIL", () => {
  const long = "<html>" + "a".repeat(300_000) + "</html>";
  assert.equal(checkEmail(ex(long, {})).status, "INCONCLUSIVE");
  assert.match(checkEmail(ex(long, {})).reason ?? "", /only the first 262144 of/);
  const leak = "<html>contact admin@example.test " + "a".repeat(10) + "</html>";
  assert.equal(checkEmail(ex(leak, { status: "truncated" })).status, "FAIL", "evidence in the prefix stays a FAIL");
  assert.equal(checkErrorDisclosure(ex("Traceback (most recent call last):\n  x", { status: "truncated" })).status, "FAIL");
});
