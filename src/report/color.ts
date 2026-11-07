/**
 * Terminal colour (SPEC-0.3.0 §4.3). Only on a TTY, never with NO_COLOR or --no-color, so piped
 * output, files and agents always get plain text. Colour is never the only signal: the words stay.
 */
const RED = "\x1b[31m", GREEN = "\x1b[32m", YELLOW = "\x1b[33m", BLUE = "\x1b[34m", GREY = "\x1b[90m", BOLD = "\x1b[1m", RESET = "\x1b[0m";

const COLOUR: Record<string, string> = {
  PASS: GREEN, COMPLETE: GREEN, NO_FINDINGS_IN_TESTED_SCOPE: GREEN, IMPROVED_NO_DRIFT: GREEN,
  FAIL: RED, FAILED: RED, FINDINGS: RED, IMMEDIATE: RED, REGRESSED: RED, FUNCTIONAL_REGRESSION: RED, ERROR: RED,
  PARTIAL: YELLOW, INCOMPLETE: YELLOW, INCONCLUSIVE: YELLOW, CAUTION: YELLOW, IMPROVED_WITH_DRIFT: YELLOW, DRIFT_ONLY: YELLOW,
  PLANNED: BLUE, OPTIONAL: BLUE, NOT_TESTED: GREY, INFO: GREY, NO_CHANGE: GREY,
};
const WORDS = new RegExp(`(?<![-\w])(${Object.keys(COLOUR).join("|")})(?![-\w])`, "g");

export function colourEnabled(argv: readonly string[] = process.argv, env: NodeJS.ProcessEnv = process.env, tty = !!process.stdout.isTTY): boolean {
  return tty && env.NO_COLOR === undefined && !argv.includes("--no-color");
}

/** Colours status words; returns the text unchanged when colour is off. */
export function paint(text: string, on = colourEnabled()): string {
  if (!on) return text;
  return text.replace(WORDS, (w) => `${BOLD}${COLOUR[w]}${w}${RESET}`).replace(/^(REPORT|HTML|TEST-REPORT): /gm, `${GREY}$1:${RESET} `);
}
