/**
 * TLS handshake probe (NSC-CRYPT-001 protocol versions, NSC-CRYPT-003 certificate).
 * A handshake is low impact. Scope and connect-time address checks still apply.
 * Honesty rule: when the local OpenSSL cannot even offer a legacy version, the result is
 * INCONCLUSIVE, never PASS.
 */
import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import tls from "node:tls";
import type { Budget } from "../budget.js";
import type { ScopeGate } from "../scope.js";
import type { CheckResult } from "../types.js";

type Ver = "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";
export type HandshakeOutcome = "accepted" | "refused" | "client-unsupported" | "error";

export interface HandshakeResult {
  version: Ver;
  outcome: HandshakeOutcome;
  detail: string;
  cert?: { keyType: string; bits?: number; curve?: string; validTo: string; authorized: boolean; authError?: string };
  cipher?: string;
}

const CLIENT_SIDE = /NO_PROTOCOLS_AVAILABLE|UNSUPPORTED_PROTOCOL|NO_CIPHERS_AVAILABLE|NO_SUITABLE|unsupported protocol|no protocols available/i;

export function handshake(gate: ScopeGate, host: string, port: number, version: Ver, timeoutMs = 8000): Promise<HandshakeResult> {
  const legacy = version === "TLSv1" || version === "TLSv1.1";
  return new Promise((resolve) => {
    let settled = false;
    const done = (r: HandshakeResult) => { if (!settled) { settled = true; sock.destroy(); resolve(r); } };
    const sock = tls.connect({
      host,
      port,
      servername: /^[\d.]+$|:/.test(host) ? undefined : host,
      minVersion: version,
      maxVersion: version,
      ...(legacy ? { ciphers: "DEFAULT@SECLEVEL=0" } : {}),
      rejectUnauthorized: false,
      timeout: timeoutMs,
      lookup: ((hn: string, opts: { all?: boolean; family?: number }, cb: (...a: unknown[]) => void) =>
        dnsLookup(hn, { all: true, family: opts?.family ?? 0 }, (err, addrs: LookupAddress[]) => {
          if (err) return cb(err);
          for (const a of addrs) {
            const d = gate.checkResolvedAddress(hn, a.address);
            if (!d.allowed) return cb(Object.assign(new Error(d.reason), { code: "NAVSENTRY_SCOPE_DENIED" }));
          }
          if (opts?.all) return cb(null, addrs);
          cb(null, addrs[0]?.address, addrs[0]?.family);
        })) as never,
    });
    sock.once("secureConnect", () => {
      const x = sock.getPeerX509Certificate();
      const det = x?.publicKey.asymmetricKeyDetails;
      const cipher = sock.getCipher()?.standardName ?? sock.getCipher()?.name;
      done({
        version,
        outcome: "accepted",
        detail: `negotiated ${sock.getProtocol()}`,
        ...(cipher ? { cipher } : {}),
        ...(x ? { cert: { keyType: x.publicKey.asymmetricKeyType ?? "unknown", ...(det?.modulusLength ? { bits: det.modulusLength } : {}), ...(det?.namedCurve ? { curve: det.namedCurve } : {}), validTo: x.validTo, authorized: sock.authorized, ...(sock.authorizationError ? { authError: String(sock.authorizationError) } : {}) } } : {}),
      });
    });
    sock.once("timeout", () => done({ version, outcome: "error", detail: "timeout" }));
    sock.once("error", (e: NodeJS.ErrnoException) => {
      const code = `${e.code ?? ""} ${e.message ?? ""}`;
      if (e.code === "NAVSENTRY_SCOPE_DENIED") return done({ version, outcome: "error", detail: `scope denied: ${e.message}` });
      if (CLIENT_SIDE.test(code)) return done({ version, outcome: "client-unsupported", detail: e.code ?? "client cannot offer this version" });
      if (/ECONNREFUSED|ENOTFOUND|EHOSTUNREACH|ETIMEDOUT|EAI_AGAIN/.test(code)) return done({ version, outcome: "error", detail: e.code ?? "network error" });
      done({ version, outcome: "refused", detail: e.code ?? "handshake failed" });
    });
  });
}

export async function probeTls(gate: ScopeGate, budget: Budget, origin: string): Promise<{ results: HandshakeResult[]; checks: CheckResult[] }> {
  const u = new URL(origin);
  const port = Number(u.port || 443);
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const target = `TLS ${origin}`;
  const d = gate.checkOrigin(origin);
  const mk = (ruleId: string, status: CheckResult["status"], summary: string, observations: string[], reason?: string): CheckResult => ({ ruleId, status, target, transport: "tls-probe", summary, observations, requestIds: [], ...(reason ? { reason } : {}) });
  if (!d.allowed) return { results: [], checks: [mk("NSC-CRYPT-001", "NOT_TESTED", "Out of scope", [], d.reason), mk("NSC-CRYPT-003", "NOT_TESTED", "Out of scope", [], d.reason)] };
  const results: HandshakeResult[] = [];
  for (const v of ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1"] as Ver[]) {
    await budget.acquire();
    results.push(await handshake(gate, host, port, v));
  }
  const obs = results.map((r) => `${r.version}: ${r.outcome} (${r.detail})`);
  const legacy = results.filter((r) => r.version === "TLSv1" || r.version === "TLSv1.1");
  const modern = results.filter((r) => r.version === "TLSv1.2" || r.version === "TLSv1.3");
  let c1: CheckResult;
  if (results.every((r) => r.outcome === "error")) c1 = mk("NSC-CRYPT-001", "ERROR", "TLS endpoint unreachable", obs, "all handshakes errored");
  else if (legacy.some((r) => r.outcome === "accepted")) c1 = mk("NSC-CRYPT-001", "FAIL", `Legacy protocol accepted: ${legacy.filter((r) => r.outcome === "accepted").map((r) => r.version).join(", ")}`, obs);
  else if (legacy.some((r) => r.outcome !== "refused")) c1 = mk("NSC-CRYPT-001", "INCONCLUSIVE", "Legacy versions could not be tested conclusively from this client", obs, "local OpenSSL cannot offer TLS 1.0/1.1 or probe errored; use a dedicated TLS scanner. SSLv3 is never probed.");
  else if (!modern.some((r) => r.outcome === "accepted")) c1 = mk("NSC-CRYPT-001", "INCONCLUSIVE", "No modern protocol accepted either", obs, "endpoint may not speak TLS");
  else c1 = mk("NSC-CRYPT-001", "PASS", "TLS 1.0/1.1 refused; TLS 1.2+/1.3 accepted (SSLv3 not probed)", obs);

  const certR = modern.find((r) => r.cert)?.cert;
  let c3: CheckResult;
  if (!certR) c3 = mk("NSC-CRYPT-003", "INCONCLUSIVE", "No certificate observed", obs, "no modern handshake succeeded");
  else {
    const problems: string[] = [];
    if (certR.keyType === "rsa" && (certR.bits ?? 0) < 2048) problems.push(`RSA ${certR.bits} bits < 2048`);
    if (certR.keyType === "ec" && certR.curve && !/256|384|521|prime256v1|secp384r1|secp521r1/i.test(certR.curve)) problems.push(`EC curve ${certR.curve}`);
    const days = (Date.parse(certR.validTo) - Date.now()) / 86400000;
    if (days < 0) problems.push("certificate expired");
    else if (days < 30) problems.push(`certificate expires in ${Math.floor(days)} days`);
    if (!certR.authorized) problems.push(`chain not trusted by this client (${certR.authError ?? "unknown"})`);
    const info = [`key: ${certR.keyType}${certR.bits ? ` ${certR.bits}` : ""}${certR.curve ? ` ${certR.curve}` : ""}`, `validTo: ${certR.validTo}`];
    c3 = problems.length ? mk("NSC-CRYPT-003", "FAIL", problems.join("; "), info) : mk("NSC-CRYPT-003", "PASS", "Certificate key size, validity and chain OK", info);
  }
  return { results, checks: [c1, c3] };
}
