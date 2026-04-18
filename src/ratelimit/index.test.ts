import { describe, it, expect } from "vitest";
import { RateLimiter } from "./index.js";
import type { Policy } from "../policy/index.js";

function makePolicy(requests: number, windowSeconds: number): Policy {
  return {
    allowed_http_hosts: ["api.example.com"],
    allowed_commands: [
      { binary: "wrangler", allowed_args_patterns: ["^deploy$"] },
    ],
    allowed_env_vars: ["CLOUDFLARE_API_TOKEN"],
    rate_limit: { requests, window_seconds: windowSeconds },
  };
}

class FakeClock {
  private ms = 0;
  readonly read = (): number => this.ms;
  advanceSeconds(seconds: number): void {
    this.ms += seconds * 1000;
  }
  advanceMs(ms: number): void {
    this.ms += ms;
  }
}

describe("RateLimiter", () => {
  it("rate limit trips deny after N calls", async () => {
    const clock = new FakeClock();
    const limiter = new RateLimiter(clock.read);
    const policy = makePolicy(5, 60);

    for (let i = 0; i < 5; i += 1) {
      const decision = await limiter.tryConsume("API", policy);
      expect(decision.allowed).toBe(true);
    }

    const denied = await limiter.tryConsume("API", policy);
    expect(denied.allowed).toBe(false);
    if (denied.allowed) {
      throw new Error("expected denial");
    }
    expect(denied.reason).toBe("rate_limit_exceeded");
    expect(denied.retry_after_seconds).toBeGreaterThanOrEqual(0);
  });

  it("refills the bucket after one full window has elapsed", async () => {
    const clock = new FakeClock();
    const limiter = new RateLimiter(clock.read);
    const policy = makePolicy(3, 30);

    for (let i = 0; i < 3; i += 1) {
      await limiter.tryConsume("API", policy);
    }
    const beforeRefill = await limiter.tryConsume("API", policy);
    expect(beforeRefill.allowed).toBe(false);

    clock.advanceSeconds(30);

    for (let i = 0; i < 3; i += 1) {
      const decision = await limiter.tryConsume("API", policy);
      expect(decision.allowed).toBe(true);
    }
    const afterDrain = await limiter.tryConsume("API", policy);
    expect(afterDrain.allowed).toBe(false);
  });

  it("keeps independent buckets per secret name", async () => {
    const clock = new FakeClock();
    const limiter = new RateLimiter(clock.read);
    const policy = makePolicy(2, 60);

    expect((await limiter.tryConsume("A", policy)).allowed).toBe(true);
    expect((await limiter.tryConsume("A", policy)).allowed).toBe(true);
    expect((await limiter.tryConsume("A", policy)).allowed).toBe(false);

    expect((await limiter.tryConsume("B", policy)).allowed).toBe(true);
    expect((await limiter.tryConsume("B", policy)).allowed).toBe(true);
    expect((await limiter.tryConsume("B", policy)).allowed).toBe(false);
  });

  it("is async-safe across interleaved awaits (10 concurrent calls)", async () => {
    const clock = new FakeClock();
    const limiter = new RateLimiter(clock.read);
    const policy = makePolicy(4, 60);

    const results = await Promise.all(
      Array.from({ length: 10 }, () => limiter.tryConsume("API", policy)),
    );

    const allows = results.filter((r) => r.allowed).length;
    const denies = results.length - allows;
    expect(allows + denies).toBe(10);
    expect(allows).toBeLessThanOrEqual(4);
    expect(allows).toBe(4);
    expect(denies).toBe(6);
  });

  it("returns a retry_after_seconds that makes the next call succeed", async () => {
    const clock = new FakeClock();
    const limiter = new RateLimiter(clock.read);
    const policy = makePolicy(5, 60);

    for (let i = 0; i < 5; i += 1) {
      await limiter.tryConsume("API", policy);
    }
    const denied = await limiter.tryConsume("API", policy);
    expect(denied.allowed).toBe(false);
    if (denied.allowed) {
      throw new Error("expected denial");
    }
    expect(denied.retry_after_seconds).toBeGreaterThanOrEqual(0);

    clock.advanceSeconds(denied.retry_after_seconds);
    const retried = await limiter.tryConsume("API", policy);
    expect(retried.allowed).toBe(true);
  });

  it("does not over-refill past capacity across long idle periods", async () => {
    const clock = new FakeClock();
    const limiter = new RateLimiter(clock.read);
    const policy = makePolicy(3, 10);

    await limiter.tryConsume("API", policy);
    clock.advanceSeconds(3600);

    for (let i = 0; i < 3; i += 1) {
      const decision = await limiter.tryConsume("API", policy);
      expect(decision.allowed).toBe(true);
    }
    const beyond = await limiter.tryConsume("API", policy);
    expect(beyond.allowed).toBe(false);
  });

  it("partially refills proportional to elapsed time", async () => {
    const clock = new FakeClock();
    const limiter = new RateLimiter(clock.read);
    const policy = makePolicy(10, 10);

    for (let i = 0; i < 10; i += 1) {
      await limiter.tryConsume("API", policy);
    }
    expect((await limiter.tryConsume("API", policy)).allowed).toBe(false);

    clock.advanceSeconds(5);

    let allows = 0;
    for (let i = 0; i < 10; i += 1) {
      const decision = await limiter.tryConsume("API", policy);
      if (decision.allowed) {
        allows += 1;
      }
    }
    expect(allows).toBe(5);
  });
});
