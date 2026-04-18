import { describe, it, expect } from "vitest";
import { InMemoryAuditLogger } from "./in-memory-logger.js";
import type { AuditEvent } from "./types.js";

function baseEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    ts: "2026-04-18T10:00:00.000Z",
    secret_name: "API_TOKEN",
    tool: "http_request",
    target: "api.example.com",
    outcome: "allowed",
    request_id: "11111111-1111-1111-1111-111111111111",
    caller_cwd: "/tmp/proj",
    ...overrides,
  };
}

describe("InMemoryAuditLogger", () => {
  it("captures events in the order they were recorded", async () => {
    const logger = new InMemoryAuditLogger();
    const first = baseEvent({ secret_name: "FIRST" });
    const second = baseEvent({
      secret_name: "SECOND",
      outcome: "denied",
      reason: "host not in allowlist",
      code: "POLICY_DENIED",
    });
    await logger.record(first);
    await logger.record(second);
    expect(logger.events).toHaveLength(2);
    expect(logger.events[0]).toEqual(first);
    expect(logger.events[1]).toEqual(second);
  });

  it("copies events so later caller mutation does not leak into captured entries", async () => {
    const logger = new InMemoryAuditLogger();
    const event = baseEvent();
    await logger.record(event);
    event.secret_name = "MUTATED_BY_CALLER";
    const stored = logger.events[0];
    expect(stored).toBeDefined();
    expect(stored?.secret_name).toBe("API_TOKEN");
  });

  it("clear() empties the captured events", async () => {
    const logger = new InMemoryAuditLogger();
    await logger.record(baseEvent());
    logger.clear();
    expect(logger.events).toHaveLength(0);
  });
});
