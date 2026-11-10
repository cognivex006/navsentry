/** Hard rule 5: a body check that saw only part of the body never reports PASS. Synthetic exchanges, no network. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { BODY_SCAN_BYTES, checkEmail, checkErrorDisclosure, checkInternalIp, checkJwt, checkPii, checkVersionDisclosure } from "../src/checks/passive.js";
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
  assert.equal(checkEmail(ex("<html>" + "a".repeat(300_000) + "</html>", {})).status, "PASS", "a 300 KB page in memory is scanned whole");
  const long = "<html>" + "a".repeat(BODY_SCAN_BYTES + 10) + "</html>";
  assert.equal(checkEmail(ex(long, {})).status, "INCONCLUSIVE");
  assert.match(checkEmail(ex(long, {})).reason ?? "", new RegExp(`only the first ${BODY_SCAN_BYTES} of`));
  const leak = "<html>contact admin@example.test " + "a".repeat(10) + "</html>";
  assert.equal(checkEmail(ex(leak, { status: "truncated" })).status, "FAIL", "evidence in the prefix stays a FAIL");
  assert.equal(checkErrorDisclosure(ex("Traceback (most recent call last):\n  x", { status: "truncated" })).status, "FAIL");
});

test("an undecoded content-encoding is never a body PASS; JWT checks are bounded too", () => {
  const gz = checkErrorDisclosure(ex("\x1f\x8b compressed", { encoding: "gzip" }));
  assert.equal(gz.status, "INCONCLUSIVE");
  assert.match(gz.reason ?? "", /content-encoding gzip was not decoded/);
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const jwt = `${b64({ alg: "HS256" })}.${b64({ exp: 2, iat: 1, iss: "i", aud: "a" })}.sig`;
  assert.equal(checkJwt(ex(`token ${jwt}`, {})).status, "PASS");
  assert.equal(checkJwt(ex(`token ${jwt}`, { status: "truncated" })).status, "INCONCLUSIVE", "a later weak token could be in the cut part");
});

test("email and JWT scans are linear: hostile 8 MiB bodies finish quickly, real values are still found", async () => {
  const { findEmails, findJwts } = await import("../src/checks/passive.js");
  assert.deepEqual(findEmails("mail admin@example.test, or ops.team+x@mail.example.test now"), ["admin@example.test", "ops.team+x@mail.example.test"]);
  assert.deepEqual(findEmails("logo@2x.png xadmin@example.test"), ["logo@2x.png", "xadmin@example.test"]);
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const jwt = `${b64({ alg: "HS256" })}.${b64({ sub: "1" })}.sig`;
  assert.deepEqual(findJwts(`Bearer ${jwt} and x${jwt}`), [jwt]);
  for (const hostile of ["ab+".repeat(3_000_000), "a@".repeat(3_000_000), "eyJ-".repeat(2_000_000), "eyJaaaaaaaa.".repeat(600_000)]) {
    const t0 = Date.now();
    findEmails(hostile); findJwts(hostile);
    assert.ok(Date.now() - t0 < 5000, `took ${Date.now() - t0} ms on ${hostile.slice(0, 12)}…`);
  }
});

test("error signatures are bounded: still found, and hostile one-line bodies finish quickly", () => {
  for (const leak of [
    "at com.shop.web.OrderController.show(OrderController.java:42)",
    "   at Shop.Web.Orders.Show(Int32 id) in C:\\src\\Orders.cs:line 17",
    "Server Error in '/' Application.",
    "Error\n    at show (/srv/app/orders.js:10:5)",
    "Warning: Undefined variable $x in /var/www/index.php on line 3",
  ]) assert.equal(checkErrorDisclosure(ex(leak, {})).status, "FAIL", leak);
  for (const hostile of ["Warning: " + " in ".repeat(2_000_000), "at a" + ".b".repeat(3_000_000), "\n at " + "x (/".repeat(1_500_000), "Server Error in '" + "x".repeat(7_000_000)]) {
    const t0 = Date.now();
    checkErrorDisclosure(ex(hostile, {}));
    assert.ok(Date.now() - t0 < 5000, `took ${Date.now() - t0} ms on ${hostile.slice(0, 14)}…`);
  }
});
