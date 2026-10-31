/** Request-volume, rate and duration budget shared by all transports in a run. */
import { setTimeout as sleep } from "node:timers/promises";

export class BudgetExceeded extends Error {}

export class Budget {
  private used = 0;
  private lastAt = 0;
  private readonly startedAt = Date.now();
  private readonly minIntervalMs: number;

  constructor(
    readonly maxRequests: number,
    maxPerSecond: number,
    private readonly maxDurationMs: number,
  ) {
    this.minIntervalMs = 1000 / maxPerSecond;
  }

  get requestsUsed(): number {
    return this.used;
  }

  get remainingMs(): number {
    return Math.max(0, this.maxDurationMs - (Date.now() - this.startedAt));
  }

  /** Reserves one request slot, waiting to respect the rate limit. Throws when exhausted. */
  async acquire(): Promise<void> {
    if (this.used >= this.maxRequests) throw new BudgetExceeded(`request budget exhausted (${this.maxRequests})`);
    if (this.remainingMs <= 0) throw new BudgetExceeded("duration budget exhausted");
    const wait = this.lastAt + this.minIntervalMs - Date.now();
    if (wait > 0) await sleep(wait);
    this.used++;
    this.lastAt = Date.now();
  }
}
