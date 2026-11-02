/**
 * robots.txt parsing and matching per RFC 9309 (SPEC-0.1.3 §6.2).
 * Group selection: product token `NavSentry` (case-insensitive), otherwise `*`; matching groups
 * are merged. The longest matching rule wins and `allow` wins a tie; `*` and `$` are supported.
 */
export const ROBOTS_MAX_BYTES = 500 * 1024;
export const PRODUCT_TOKEN = "navsentry";

export interface RobotsRule {
  allow: boolean;
  path: string;
  re: RegExp;
}

export interface RobotsPolicy {
  rules: RobotsRule[];
  /** Which group was selected. */
  group: "navsentry" | "*" | "none";
}

function ruleRegExp(path: string): RegExp {
  let re = "";
  for (let i = 0; i < path.length; i++) {
    const c = path[i]!;
    if (c === "*") re += ".*";
    else if (c === "$" && i === path.length - 1) re += "$";
    else re += c.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}`);
}

export function parseRobots(text: string): RobotsPolicy {
  type Group = { agents: string[]; rules: RobotsRule[] };
  const groups: Group[] = [];
  let cur: Group | undefined;
  let lastWasAgent = false;
  for (const rawLine of text.slice(0, ROBOTS_MAX_BYTES).split(/\r\n|\r|\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    const m = /^([A-Za-z-]+)\s*:\s*(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1]!.toLowerCase();
    const val = m[2]!.trim();
    if (key === "user-agent") {
      if (!cur || !lastWasAgent) { cur = { agents: [], rules: [] }; groups.push(cur); }
      cur.agents.push(val.toLowerCase());
      lastWasAgent = true;
      continue;
    }
    lastWasAgent = false;
    if (!cur) continue;
    if (key === "allow" || key === "disallow") {
      // An empty Disallow allows everything and adds no rule.
      if (val === "") continue;
      cur.rules.push({ allow: key === "allow", path: val, re: ruleRegExp(val) });
    }
  }
  const mine = groups.filter((g) => g.agents.includes(PRODUCT_TOKEN));
  if (mine.length) return { group: "navsentry", rules: mine.flatMap((g) => g.rules) };
  const star = groups.filter((g) => g.agents.includes("*"));
  if (star.length) return { group: "*", rules: star.flatMap((g) => g.rules) };
  return { group: "none", rules: [] };
}

/** `pathAndQuery` is the URL path plus `?query`. `/robots.txt` itself is always allowed. */
export function robotsAllows(p: RobotsPolicy, pathAndQuery: string): boolean {
  if (pathAndQuery === "/robots.txt") return true;
  let best: RobotsRule | undefined;
  for (const r of p.rules) {
    if (!r.re.test(pathAndQuery)) continue;
    if (!best || r.path.length > best.path.length || (r.path.length === best.path.length && r.allow && !best.allow)) best = r;
  }
  return best ? best.allow : true;
}

export type RobotsOutcome =
  | { kind: "policy"; policy: RobotsPolicy }
  | { kind: "no-policy"; reason: string }
  | { kind: "unreachable"; reason: string };

/**
 * Status handling: 2xx text is parsed; 4xx other than 401/403 means no policy; 401/403, 5xx,
 * network errors, scope denials and budget exhaustion are unreachable. A 2xx body that is not a
 * text policy (for example an SPA HTML fallback) means no policy (owner decision D10, option a).
 */
export function classifyRobots(status: number | undefined, contentType: string, body: string): RobotsOutcome {
  if (status === undefined) return { kind: "unreachable", reason: "request failed or was not allowed" };
  if (status >= 200 && status < 300) {
    const ct = contentType.split(";")[0]!.trim().toLowerCase();
    if (ct === "text/html" || /^\s*<(!doctype|html)/i.test(body)) return { kind: "no-policy", reason: `2xx ${ct || "untyped"} body is not a text policy (recorded, D10)` };
    return { kind: "policy", policy: parseRobots(body) };
  }
  if (status === 401 || status === 403) return { kind: "unreachable", reason: `status ${status} (treated as unreachable)` };
  if (status >= 400 && status < 500) return { kind: "no-policy", reason: `status ${status}` };
  return { kind: "unreachable", reason: `status ${status}` };
}
