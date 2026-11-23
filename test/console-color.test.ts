/** Console colour for human readers: TTY only; off for NO_COLOR, --no-color, --json and pipes; JSON byte-identical. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { colourEnabled, paint, paintErr, stderrColourEnabled, strip } from "../src/report/color.js";
import { main } from "../src/cli.js";

const ESC = /\x1b\[/;

test("colour is off for --json, NO_COLOR, --no-color and non-TTY streams", () => {
  assert.equal(colourEnabled(["doctor"], {}, true), true);
  assert.equal(colourEnabled(["doctor", "--json"], {}, true), false);
  assert.equal(colourEnabled(["doctor"], { NO_COLOR: "1" }, true), false);
  assert.equal(colourEnabled(["doctor", "--no-color"], {}, true), false);
  assert.equal(colourEnabled(["doctor"], {}, false), false);
  assert.equal(stderrColourEnabled(["x"], {}, false), false);
  assert.equal(paintErr("error: boom", false), "error: boom");
});

test("paint colours statuses, headings and labels, and only inserts ANSI codes", () => {
  const text = "Usage:\n  USABLE     playwright\n  DETECTED   curl\n  UNAVAILABLE pwsh\nverify FAIL: run x\n  note: limits\nREPORT: /r/REPORT.md\nTransports\n# Title";
  const on = paint(text, true);
  assert.equal(strip(on), text, "stripping the codes returns the exact plain text");
  assert.match(on, /\x1b\[1mUsage:/);
  assert.match(on, /\x1b\[32mUSABLE/);
  assert.match(on, /\x1b\[33mDETECTED/);
  assert.match(on, /\x1b\[90mUNAVAILABLE/);
  assert.match(on, /\x1b\[31mFAIL/);
  assert.match(on, /\x1b\[90mnote:/);
  assert.match(on, /\x1b\[90mREPORT:/);
  assert.match(on, /\x1b\[1mTransports/);
  assert.equal(paint(text, false), text);
  assert.ok(!ESC.test(paint("NSC-INFO-004 x-PASS PASS_X", true)), "IDs and compound words stay plain");
});

test("stderr lines: errors red, warnings yellow, plain text kept", () => {
  for (const l of ["error: boom", "warning: careful", "missing --config", "using navsentry.json in the current directory", "LEFTOVER a b: c"]) assert.equal(strip(paintErr(l, true)), l);
  assert.match(paintErr("error: boom", true), /\x1b\[31m/);
  assert.match(paintErr("warning: careful", true), /\x1b\[33mwarning:/);
});

async function capture(argv: string[], tty: boolean): Promise<string> {
  const out = process.stdout as NodeJS.WriteStream & { isTTY?: boolean };
  const prevTty = out.isTTY, prevWrite = out.write, prevArgv = process.argv, prevNo = process.env.NO_COLOR;
  let buf = "";
  delete process.env.NO_COLOR;
  out.isTTY = tty;
  process.argv = [prevArgv[0]!, prevArgv[1]!, ...argv];
  out.write = ((s: string) => { buf += s; return true; }) as typeof out.write;
  try { await main(argv); } finally {
    out.write = prevWrite; out.isTTY = prevTty; process.argv = prevArgv;
    if (prevNo !== undefined) process.env.NO_COLOR = prevNo;
  }
  return buf;
}

test("on a TTY human output is coloured; --json output is byte-identical to the piped output", async () => {
  const human = await capture(["catalog", "--category", "INFO"], true);
  assert.match(human, ESC, "human text is coloured on a TTY");
  assert.equal(strip(human), await capture(["catalog", "--category", "INFO"], false));
  const help = await capture(["help"], true);
  assert.match(help, /\x1b\[1mUsage:/);
  const jTty = await capture(["knowledge", "status", "--json"], true);
  const jPipe = await capture(["knowledge", "status", "--json"], false);
  assert.ok(!ESC.test(jTty), "no ANSI in JSON even on a TTY");
  assert.equal(jTty, jPipe);
  JSON.parse(jTty);
  const noColor = await capture(["help", "--no-color"], true);
  assert.ok(!ESC.test(noColor));
});

test("piped CLI output carries no ANSI codes", () => {
  const r = spawnSync(process.execPath, ["dist/src/cli.js", "help"], { encoding: "utf8", env: { ...process.env, NO_COLOR: undefined } as NodeJS.ProcessEnv });
  assert.equal(r.status, 0);
  assert.ok(!ESC.test(r.stdout) && !ESC.test(r.stderr));
  const e = spawnSync(process.execPath, ["dist/src/cli.js", "nope"], { encoding: "utf8" });
  assert.equal(e.status, 3);
  assert.ok(!ESC.test(e.stderr));
});
