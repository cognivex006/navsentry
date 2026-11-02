/**
 * Request-volume, rate, duration and authorization-deadline budget shared by all transports in a run.
 * Reservations are serialized, and limits are re-checked after the rate-limit wait (SPEC-0.1.3 §6.5-B).
 */
import { setTimeout as sleep } from "node:timers/promises";

export class BudgetExceeded extends Error {}

export class Budget {
  private used = 0;
  private lastAt = 0;
  private readonly startedAt = Date.now();
  private readonly minIntervalMs: number;
  private queue: Promise<void> = Promise.resolve();
  private readonly abort = new AbortController();
  private deadlineTimer?: NodeJS.Timeout;

  /**
   * @param deadline authorization `expires_at`; in-flight work is cancelled through `signal` when it is reached.
   */
  constructor(
    readonly maxRequests: number,
    maxPerSecond: number,
    private readonly maxDurationMs: number,
    private readonly deadline?: Date,
  ) {
    this.minIntervalMs = 1000 / maxPerSecond;
    if (deadline) {
      const ms = deadline.getTime() - Date.now();
      if (ms <= 0) this.abort.abort(new BudgetExceeded("authorization window ended"));
      // setTimeout overflows above 2^31-1 ms (~24.8 days); such deadlines are re-checked in acquire().
      else if (ms < 2 ** 31 - 1) {
        this.deadlineTimer = setTimeout(() => this.abort.abort(new BudgetExceeded("authorization window ended")), ms);
        this.deadlineTimer.unref();
      }
    }
  }

  get requestsUsed(): number {
    return this.used;
  }

  get remainingMs(): number {
    return Math.max(0, this.maxDurationMs - (Date.now() - this.startedAt));
  }

  /** Aborted when the authorization deadline passes; transports pass it to each connection. */
  get signal(): AbortSignal {
    return this.abort.signal;
  }

  /** Stops the deadline timer; call once the run has finished. */
  close(): void {
    if (this.deadlineTimer) clearTimeout(this.deadlineTimer);
  }

  private check(): void {
    if (this.deadline && Date.now() >= this.deadline.getTime()) throw new BudgetExceeded("authorization window ended");
    if (this.used >= this.maxRequests) throw new BudgetExceeded(`request budget exhausted (${this.maxRequests})`);
    if (this.remainingMs <= 0) throw new BudgetExceeded("duration budget exhausted");
  }

  /** Reserves one request slot, waiting to respect the rate limit. Throws when exhausted. */
  acquire(): Promise<void> {
    const next = this.queue.then(async () => {
      this.check();
      const wait = this.lastAt + this.minIntervalMs - Date.now();
      if (wait > 0) await sleep(wait);
      // Limits and the deadline may have run out during the wait.
      this.check();
      this.used++;
      this.lastAt = Date.now();
    });
    this.queue = next.catch(() => {});
    return next;
  }
}

/** Byte budgets for one run: decoded bytes and bytes on the wire (SPEC-0.1.3 §3.2). */
export class ByteBudget {
  private decoded = 0;
  private wire = 0;

  constructor(
    readonly maxRunBytes: number,
    readonly maxWireBytes: number,
  ) {}

  get decodedBytes(): number {
    return this.decoded;
  }

  get wireBytes(): number {
    return this.wire;
  }

  /** Records bytes; returns false once either run budget is exceeded. */
  take(wire: number, decoded: number): boolean {
    this.wire += wire;
    this.decoded += decoded;
    return this.wire <= this.maxWireBytes && this.decoded <= this.maxRunBytes;
  }
}
