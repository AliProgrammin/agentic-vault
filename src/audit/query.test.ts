import { describe, it, expect } from "vitest";
import {
  filterAuditEntries,
  findEntryById,
  parseAuditJsonl,
} from "./query.js";
import type { AuditEvent } from "./types.js";

function makeEvent(overrides: Partial<AuditEvent>): AuditEvent {
  return {
    ts: "2026-04-18T10:00:00.000Z",
    secret_name: "API_TOKEN",
    tool: "http_request",
    target: "api.example.com",
    outcome: "allowed",
    request_id: "req-q-0001",
    caller_cwd: "/tmp",
    ...overrides,
  };
}

describe("parseAuditJsonl", () => {
  it("parses valid lines and skips malformed lines", () => {
    const lines = [
      JSON.stringify(makeEvent({ request_id: "req-q-0001" })),
      "not-json-here",
      JSON.stringify(makeEvent({ request_id: "req-q-0002" })),
    ].join("\n");
    const parsed = parseAuditJsonl(lines);
    expect(parsed).toHaveLength(2);
    expect(parsed.map((e) => e.request_id)).toEqual(["req-q-0001", "req-q-0002"]);
  });
});

describe("filterAuditEntries", () => {
  const entries: AuditEvent[] = [
    makeEvent({ request_id: "a", surface: "mcp_http_request", outcome: "allowed", ts: "2026-04-18T10:00:00.000Z" }),
    makeEvent({ request_id: "b", surface: "mcp_run_command", outcome: "denied", code: "POLICY_DENIED", ts: "2026-04-18T11:00:00.000Z" }),
    makeEvent({ request_id: "c", surface: "mcp_run_command", outcome: "allowed", ts: "2026-04-18T12:00:00.000Z", secret_name: "OTHER" }),
  ];

  it("filters by surface", () => {
    const out = filterAuditEntries(entries, { surface: "mcp_run_command" });
    expect(out.map((e) => e.request_id)).toEqual(["b", "c"]);
  });

  it("filters by status", () => {
    const out = filterAuditEntries(entries, { status: "denied" });
    expect(out.map((e) => e.request_id)).toEqual(["b"]);
  });

  it("filters by secret", () => {
    const out = filterAuditEntries(entries, { secret: "OTHER" });
    expect(out.map((e) => e.request_id)).toEqual(["c"]);
  });

  it("filters by time range", () => {
    const out = filterAuditEntries(entries, {
      sinceMs: Date.parse("2026-04-18T10:30:00.000Z"),
      untilMs: Date.parse("2026-04-18T11:30:00.000Z"),
    });
    expect(out.map((e) => e.request_id)).toEqual(["b"]);
  });

  it("filters by code", () => {
    const out = filterAuditEntries(entries, { code: "POLICY_DENIED" });
    expect(out.map((e) => e.request_id)).toEqual(["b"]);
  });

  it("applies limit", () => {
    const out = filterAuditEntries(entries, { limit: 2 });
    expect(out.map((e) => e.request_id)).toEqual(["b", "c"]);
  });
});

describe("findEntryById", () => {
  it("returns the first matching record", () => {
    const entries = [
      makeEvent({ request_id: "a" }),
      makeEvent({ request_id: "b" }),
    ];
    expect(findEntryById(entries, "b")?.request_id).toBe("b");
    expect(findEntryById(entries, "zzz")).toBeUndefined();
  });
});
