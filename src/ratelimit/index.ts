// In-memory token-bucket rate limiter keyed by secret name.
//
// Each bucket uses capacity = policy.rate_limit.requests and refills
// continuously at capacity / window_seconds tokens per second. State lives
// in a Map inside the RateLimiter instance and is NOT persisted — a process
// restart resets every bucket. That is acceptable for Phase 1; a persistent
// limiter is out of scope.
//
// The clock is injectable so tests can exercise refill behavior without
// touching wall-clock time. Pass a fake `() => number` (ms) to the
// constructor; defaults to `() => Date.now()`.

import type { Policy } from "../policy/index.js";

export type RateDecision =
  | { allowed: true }
  | {
      allowed: false;
      reason: "rate_limit_exceeded";
      retry_after_seconds: number;
    };

export type Clock = () => number;

interface Bucket {
  tokens: number;
  lastRefillMs: number;
}

export class RateLimiter {
  private readonly clock: Clock;
  private readonly buckets = new Map<string, Bucket>();

  constructor(clock: Clock = () => Date.now()) {
    this.clock = clock;
  }

  async tryConsume(secretName: string, policy: Policy): Promise<RateDecision> {
    const capacity = policy.rate_limit.requests;
    const windowSeconds = policy.rate_limit.window_seconds;
    const now = this.clock();

    let bucket = this.buckets.get(secretName);
    if (!bucket) {
      bucket = { tokens: capacity, lastRefillMs: now };
      this.buckets.set(secretName, bucket);
    }

    const elapsedMs = Math.max(0, now - bucket.lastRefillMs);
    const elapsedSeconds = elapsedMs / 1000;
    const refilled =
      bucket.tokens + (elapsedSeconds * capacity) / windowSeconds;
    bucket.tokens = refilled > capacity ? capacity : refilled;
    bucket.lastRefillMs = now;

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { allowed: true };
    }

    const needed = 1 - bucket.tokens;
    const rawRetrySeconds = (needed * windowSeconds) / capacity;
    const retry_after_seconds = Math.max(0, Math.ceil(rawRetrySeconds));
    return {
      allowed: false,
      reason: "rate_limit_exceeded",
      retry_after_seconds,
    };
  }
}
