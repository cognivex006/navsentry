/**
 * Authorization & scope policy gate. Every transport MUST call `checkRequest` before
 * sending and `checkResolvedAddress` at connect time (DNS rebinding defence). The gate is
 * enforced in code, never delegated to LLM instructions.
 */
import { isIP } from "node:net";
import type { Manifest } from "./config.js";
import type { HttpMethod } from "./types.js";

export interface Decision {
  allowed: boolean;
  reason: string;
}

const ALLOW: Decision = { allowed: true, reason: "in scope" };
const deny = (reason: string): Decision => ({ allowed: false, reason });

/** Cloud/link-local metadata endpoints: never reachable, even with private-network approval. */
const METADATA_ADDRESSES = new Set(["169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254", "192.0.0.192"]);

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

function inV4(ip: string, cidr: string): boolean {
  const [base, bitsS] = cidr.split("/") as [string, string];
  const bits = Number(bitsS);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

const V4_NON_PUBLIC: [string, string][] = [
  ["0.0.0.0/8", "unspecified"],
  ["10.0.0.0/8", "private"],
  ["100.64.0.0/10", "carrier-grade NAT"],
  ["127.0.0.0/8", "loopback"],
  ["169.254.0.0/16", "link-local"],
  ["172.16.0.0/12", "private"],
  ["192.0.0.0/24", "IETF protocol assignments"],
  ["192.168.0.0/16", "private"],
  ["198.18.0.0/15", "benchmarking"],
  ["224.0.0.0/4", "multicast"],
  ["240.0.0.0/4", "reserved"],
];

/** Expands an IPv6 address to 8 groups of 16-bit numbers. */
function expandV6(ip: string): number[] | undefined {
  let s = ip.toLowerCase().split("%")[0] as string;
  const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const n = ipv4ToInt(v4[1] as string);
    s = s.slice(0, -(v4[1] as string).length) + `${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return undefined;
  const head = halves[0] ? (halves[0] as string).split(":") : [];
  const tail = halves.length === 2 && halves[1] ? (halves[1] as string).split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  const groups = [...head, ...Array(fill).fill("0"), ...tail].map((g) => parseInt(g, 16));
  return groups.length === 8 && groups.every((g) => Number.isInteger(g) && g >= 0 && g <= 0xffff) ? groups : undefined;
}

/** Returns a non-public classification label, or undefined for public unicast addresses. */
export function classifyAddress(ip: string): string | undefined {
  const fam = isIP(ip);
  if (fam === 4) {
    if (METADATA_ADDRESSES.has(ip)) return "cloud metadata";
    for (const [c, label] of V4_NON_PUBLIC) if (inV4(ip, c)) return label;
    return undefined;
  }
  if (fam === 6) {
    const g = expandV6(ip);
    if (!g) return "unparseable";
    const norm = g.map((x) => x.toString(16)).join(":");
    if (METADATA_ADDRESSES.has(ip.toLowerCase()) || norm === "fd00:ec2:0:0:0:0:0:254") return "cloud metadata";
    if (g.every((x) => x === 0)) return "unspecified";
    if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return "loopback";
    // IPv4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::/96): classify the embedded IPv4.
    const mapped = g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff;
    const nat64 = g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0);
    if (mapped || nat64) {
      const v4 = `${(g[6] as number) >> 8}.${(g[6] as number) & 0xff}.${(g[7] as number) >> 8}.${(g[7] as number) & 0xff}`;
      return classifyAddress(v4) ?? (mapped ? undefined : "nat64");
    }
    const first = g[0] as number;
    if ((first & 0xfe00) === 0xfc00) return "unique-local";
    if ((first & 0xffc0) === 0xfe80) return "link-local";
    if ((first & 0xff00) === 0xff00) return "multicast";
    if (first === 0x2001 && g[1] === 0x0db8) return "documentation";
    return undefined;
  }
  return "not an IP address";
}

/** Glob: `**` matches any number of segments, `*` matches within one segment. */
export function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i] as string;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        // "/**" also matches the bare parent path.
        if (re.endsWith("/")) re = re.slice(0, -1) + "(?:/.*)?";
        else re += ".*";
        i++;
      } else re += "[^/]*";
    } else re += c.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

/** One placeholder value in a mutation path (SPEC-0.2.0 §3.3): never ".", "..", empty, or anything URL-special. */
export const MUTATION_ID = /^[A-Za-z0-9_-]{1,128}$/;

/** Validates an identifier from a create response or a run variable before it is put in a path. */
export function validMutationId(v: unknown): string | undefined {
  const s = typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? String(v) : v;
  return typeof s === "string" && MUTATION_ID.test(s) ? s : undefined;
}

/** A path template with `{{id}}` segments as an anchored matcher for one id-shaped segment each. */
export function templateRegExp(template: string): RegExp {
  const esc = template.split("{{id}}").map((x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("[A-Za-z0-9_-]{1,128}");
  return new RegExp(`^${esc}$`);
}

/** Fills `{{id}}` with a validated id. Throws on an invalid id so no URL is ever built from one. */
export function fillTemplate(template: string, id: string | undefined): string {
  if (!template.includes("{{id}}")) return template;
  const ok = validMutationId(id);
  if (!ok) throw new Error("identifier rejected by the safe-validate id rule");
  return template.split("{{id}}").join(ok);
}

export class ScopeGate {
  private readonly origins: Set<string>;
  private readonly allowed: RegExp[];
  private readonly denied: RegExp[];
  private readonly methods: Set<string>;
  private readonly privateHosts: Set<string>;

  constructor(private readonly manifest: Manifest) {
    this.origins = new Set(manifest.targets.origins);
    this.allowed = manifest.targets.allowed_paths.map(globToRegExp);
    this.denied = manifest.targets.denied_paths.map(globToRegExp);
    this.methods = new Set(manifest.safety.allowed_methods);
    this.privateHosts = new Set(manifest.network.allow_private.map((a) => a.host));
  }

  /**
   * safe-validate (SPEC-0.2.0 §3.3, S13): a non-observe request is allowed only when it matches a declared
   * entry exactly. Same URL, origin, path-glob and address checks as `checkRequest`; then the method must
   * equal the entry's and the *parsed, normalised* pathname must match the entry's template with one whole
   * segment per `{{id}}`. `checkRequest` itself keeps refusing every non-observe method.
   */
  checkMutation(rawUrl: string, method: HttpMethod, entry: { method: string; path: string }): Decision {
    if (this.manifest.safety.mode !== "safe-validate" || this.manifest.profile !== "development") return deny("mutations need safety.mode safe-validate in the development profile");
    if (method !== entry.method) return deny(`method ${method} does not match the declared ${entry.method}`);
    const base = this.checkPath(rawUrl);
    if (!base.allowed) return base;
    const path = new URL(rawUrl).pathname;
    if (!templateRegExp(entry.path).test(path)) return deny(`path ${path} does not match the declared template ${entry.path}`);
    return ALLOW;
  }

  /** Static (pre-DNS) check of a URL + method. */
  checkRequest(rawUrl: string, method: HttpMethod): Decision {
    if (!this.methods.has(method)) {
      const d = this.checkPath(rawUrl);
      return d.allowed ? deny(`method ${method} is not in safety.allowed_methods`) : d;
    }
    return this.checkPath(rawUrl);
  }

  /** URL, origin, path-glob and literal-address checks shared by observe and mutation requests. */
  private checkPath(rawUrl: string): Decision {
    let u: URL;
    try {
      u = new URL(rawUrl);
    } catch {
      return deny("malformed URL");
    }
    if (u.protocol !== "https:" && u.protocol !== "http:") return deny(`scheme ${u.protocol} is not allowed`);
    if (u.username || u.password) return deny("URLs with embedded credentials are not allowed");
    if (!this.origins.has(u.origin)) return deny(`origin ${u.origin} is not in targets.origins`);
    // Ambiguous encodings can bypass path rules on some servers; refuse rather than guess.
    if (/%2e|%2f|%5c|%00/i.test(u.pathname)) return deny("encoded dot, slash, backslash or NUL in path");
    const path = u.pathname;
    if (this.denied.some((r) => r.test(path))) return deny(`path ${path} matches targets.denied_paths`);
    if (!this.allowed.some((r) => r.test(path))) return deny(`path ${path} is not in targets.allowed_paths`);
    const literal = u.hostname.replace(/^\[|\]$/g, "");
    if (isIP(literal)) {
      const d = this.checkResolvedAddress(literal, literal);
      if (!d.allowed) return d;
    }
    return ALLOW;
  }

  /** Origin-level check for non-HTTP probes (e.g. TLS handshakes) that carry no path. */
  checkOrigin(origin: string): Decision {
    if (!this.origins.has(origin)) return deny(`origin ${origin} is not in targets.origins`);
    const literal = new URL(origin).hostname.replace(/^\[|\]$/g, "");
    return isIP(literal) ? this.checkResolvedAddress(literal, literal) : ALLOW;
  }

  /** Connect-time check of every resolved address (defends against DNS rebinding). */
  checkResolvedAddress(hostname: string, address: string): Decision {
    const cls = classifyAddress(address);
    if (cls === undefined) return ALLOW;
    if (cls === "cloud metadata") return deny(`resolved address ${address} is a cloud metadata endpoint (always blocked)`);
    const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
    if (this.privateHosts.has(host)) return { allowed: true, reason: `private network (${cls}) approved for ${host}` };
    return deny(`resolved address ${address} is ${cls}; add an explicit network.allow_private approval for ${host}`);
  }

  get mode() {
    return this.manifest.safety.mode;
  }
}
