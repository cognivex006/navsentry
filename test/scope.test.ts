import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyAddress, globToRegExp, ScopeGate } from "../src/scope.js";
import { localManifest } from "./helpers.js";
import { parseManifest } from "../src/config.js";

const publicManifest = () =>
  parseManifest({
    version: "1", project: "p", environment: "staging",
    authorization: { acknowledged: true, owner: "o" },
    targets: { origins: ["https://staging.example.test"], allowed_paths: ["/app/**", "/login"], denied_paths: ["/app/admin/**"] },
  });

test("off-origin, scheme, credentials and unsafe methods are denied before execution", () => {
  const g = new ScopeGate(publicManifest());
  assert.equal(g.checkRequest("https://staging.example.test/app/x", "GET").allowed, true);
  assert.equal(g.checkRequest("https://evil.example/app/x", "GET").allowed, false);
  assert.equal(g.checkRequest("http://staging.example.test/app/x", "GET").allowed, false, "scheme change is a different origin");
  assert.equal(g.checkRequest("https://staging.example.test:8443/app/x", "GET").allowed, false, "port change is a different origin");
  assert.equal(g.checkRequest("https://u:p@staging.example.test/app/x", "GET").allowed, false);
  assert.equal(g.checkRequest("ftp://staging.example.test/app/x", "GET").allowed, false);
  assert.equal(g.checkRequest("https://staging.example.test/app/x", "POST").allowed, false);
  assert.equal(g.checkRequest("https://staging.example.test/app/x", "DELETE").allowed, false);
});

test("path allow/deny rules, deny wins, encoded traversal refused", () => {
  const g = new ScopeGate(publicManifest());
  assert.equal(g.checkRequest("https://staging.example.test/app", "GET").allowed, true, "/app/** matches /app");
  assert.equal(g.checkRequest("https://staging.example.test/login", "GET").allowed, true);
  assert.equal(g.checkRequest("https://staging.example.test/loginx", "GET").allowed, false);
  assert.equal(g.checkRequest("https://staging.example.test/other", "GET").allowed, false);
  assert.equal(g.checkRequest("https://staging.example.test/app/admin/users", "GET").allowed, false);
  assert.equal(g.checkRequest("https://staging.example.test/app/../app/admin/users", "GET").allowed, false, "dot segments are normalized before matching");
  assert.equal(g.checkRequest("https://staging.example.test/app/%2e%2e/admin", "GET").allowed, false);
  assert.equal(g.checkRequest("https://staging.example.test/app/a%2fb", "GET").allowed, false);
});

test("address classification covers private, metadata, mapped and NAT64 forms", () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "fd00:ec2::254", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe"]) {
    assert.ok(classifyAddress(ip), `${ip} must be non-public`);
  }
  for (const ip of ["8.8.8.8", "172.32.0.1", "1.1.1.1", "2606:4700:4700::1111"]) assert.equal(classifyAddress(ip), undefined, `${ip} is public`);
  assert.equal(classifyAddress("::ffff:169.254.169.254"), "cloud metadata");
});

test("private addresses need explicit approval; metadata is blocked even with approval", () => {
  const m = localManifest("http://127.0.0.1:9");
  const g = new ScopeGate(m);
  assert.equal(g.checkResolvedAddress("127.0.0.1", "127.0.0.1").allowed, true);
  assert.equal(g.checkResolvedAddress("rebind.example.test", "127.0.0.1").allowed, false, "a different hostname resolving to loopback is refused (DNS rebinding)");
  assert.equal(g.checkResolvedAddress("127.0.0.1", "169.254.169.254").allowed, false);
  const pub = new ScopeGate(publicManifest());
  assert.equal(pub.checkResolvedAddress("staging.example.test", "10.0.0.5").allowed, false);
  assert.equal(pub.checkResolvedAddress("staging.example.test", "93.184.216.34").allowed, true);
});

test("glob semantics", () => {
  assert.ok(globToRegExp("/api/*").test("/api/x"));
  assert.ok(!globToRegExp("/api/*").test("/api/x/y"));
  assert.ok(globToRegExp("/api/**").test("/api/x/y"));
  assert.ok(globToRegExp("/**").test("/"));
});
