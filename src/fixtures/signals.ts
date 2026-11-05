/**
 * Signal coordinator for `safe-validate` runs (SPEC-0.2.0 §6.2). It replaces the immediate exit of
 * `beginRun`: the first SIGINT/SIGTERM stops new requests and lets cleanup run (≤ 30 s) before the
 * reports are written; a second signal skips cleanup, records every registered object as a leftover,
 * keeps `fixtures.pending.json` on disk for the next sweep and exits at once.
 */
import type { FixtureLifecycle } from "./lifecycle.js";

export class SignalCoordinator {
  private count = 0;
  private lifecycle: FixtureLifecycle | undefined;
  private readonly onSig = (sig: NodeJS.Signals) => this.handle(sig);
  /** The first signal received, if any; the CLI exits 130/143 after reporting. */
  signal: NodeJS.Signals | undefined;

  /** `exit` is called on the second signal with the leftover lines already written to stderr. */
  constructor(private readonly exit: (code: number, lines: string[]) => void) {}

  install(): this {
    process.on("SIGINT", this.onSig);
    process.on("SIGTERM", this.onSig);
    return this;
  }

  dispose(): void {
    process.off("SIGINT", this.onSig);
    process.off("SIGTERM", this.onSig);
  }

  attach(l: FixtureLifecycle): void {
    this.lifecycle = l;
    if (this.signal) l.stop(`${this.signal} received`);
  }

  handle(sig: NodeJS.Signals): void {
    this.count++;
    if (this.count === 1) {
      this.signal = sig;
      this.lifecycle?.stop(`${sig} received; cleaning up (a second signal skips cleanup)`);
      return;
    }
    this.lifecycle?.abandon();
    const lines = (this.lifecycle?.leftovers ?? []).map((x) => `LEFTOVER ${x.fixture} ${x.displayId}: ${x.manualAction}`);
    this.exit(sig === "SIGINT" ? 130 : 143, lines);
  }
}
