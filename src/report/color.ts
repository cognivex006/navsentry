/**
 * Terminal colour (SPEC-0.3.0 §4.3). Only on a TTY, never with NO_COLOR, --no-color or --json, so
 * piped output, files, JSON and agents always get plain text. Colour is never the only signal: the
 * words stay, and painting only inserts ANSI codes (strip(paint(x, true)) === x).
 * No dependency: plain SGR escape codes.
 */
const RED = "\x1b[31m", GREEN = "\x1b[32m", YELLOW = "\x1b[33m", BLUE = "\x1b[34m", GREY = "\x1b[90m", BOLD = "\x1b[1m", RESET = "\x1b[0m";

const COLOUR: Record<string, string> = {
  PASS: GREEN, COMPLETE: GREEN, NO_FINDINGS_IN_TESTED_SCOPE: GREEN, IMPROVED_NO_DRIFT: GREEN, OK: GREEN, USABLE: GREEN, CURRENT: GREEN, INSTALL: GREEN,
  FAIL: RED, FAILED: RED, FINDINGS: RED, IMMEDIATE: RED, REGRESSED: RED, FUNCTIONAL_REGRESSION: RED, ERROR: RED, NOT_FOUND: RED, WORKSPACE_DIRTY: RED,
  PARTIAL: YELLOW, INCOMPLETE: YELLOW, INCONCLUSIVE: YELLOW, CAUTION: YELLOW, IMPROVED_WITH_DRIFT: YELLOW, DRIFT_ONLY: YELLOW, DETECTED: YELLOW, OUTDATED: YELLOW, LEFTOVER: YELLOW, REPLACE: YELLOW, SUSPECTED: YELLOW,
  PLANNED: BLUE, OPTIONAL: BLUE, NEWER: BLUE, NOT_TESTED: GREY, INFO: GREY, NO_CHANGE: GREY, UNAVAILABLE: GREY, UNKNOWN: GREY,
};
const WORDS = new RegExp(`(?<![-\\w])(${Object.keys(COLOUR).join("|")})(?![-\\w])`, "g");
/** Path and pointer labels at the start of a line ("REPORT: <path>"), shown dim. */
const LABELS = /^(\s*)(REPORT|HTML|TEST-REPORT|FLOW|INVENTORY|ANALYSIS|IMPORT|RECORDING|SESSION|package|register|note|project|Open in a browser):(?= )/gm;
/** A heading: a Markdown heading, or a short unindented line that ends with ":" (Usage:, Next:, Limitations:). */
const HEADING = /^(#{1,3} [^\n]+|[A-Z][^\n:]{0,60}:|Transports|Package versions|Installations|Agent launch \(MCP\))$/gm;

export function colourEnabled(argv: readonly string[] = process.argv, env: NodeJS.ProcessEnv = process.env, tty = !!process.stdout.isTTY): boolean {
  return tty && env.NO_COLOR === undefined && !argv.includes("--no-color") && !argv.includes("--json");
}

/** Same rule for stderr, which can be a TTY while stdout is piped (and the other way round). */
export const stderrColourEnabled = (argv: readonly string[] = process.argv, env: NodeJS.ProcessEnv = process.env, tty = !!process.stderr.isTTY) => colourEnabled(argv, env, tty);

const wrap = (code: string) => (s: string, on: boolean) => (on && s ? `${code}${s}${RESET}` : s);
export const red = wrap(RED), green = wrap(GREEN), yellow = wrap(YELLOW), dim = wrap(GREY), bold = wrap(BOLD);

/** Removes every SGR code. */
export const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

/** Colours status words, headings and path labels; returns the text unchanged when colour is off. */
export function paint(text: string, on = colourEnabled()): string {
  if (!on) return text;
  return text
    .replace(WORDS, (w) => `${BOLD}${COLOUR[w]}${w}${RESET}`)
    .replace(HEADING, (h) => `${BOLD}${h}${RESET}`)
    .replace(LABELS, (_m, sp: string, l: string) => `${sp}${GREY}${l}:${RESET}`);
}

/** A stderr line: "warning: …" yellow, "using …" dim, everything else (errors, refusals) red. */
export function paintErr(line: string, on = stderrColourEnabled()): string {
  if (!on || !line) return line;
  if (line.startsWith("LEFTOVER ")) return yellow(line, true);
  if (line.startsWith("warning: ")) return `${BOLD}${YELLOW}warning:${RESET} ${line.slice(9)}`;
  if (/^(using |second signal)/.test(line)) return dim(line, true);
  if (line.startsWith("error: ")) return `${BOLD}${RED}error:${RESET} ${red(line.slice(7), true)}`;
  return red(line, true);
}
