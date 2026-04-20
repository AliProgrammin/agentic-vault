import { describe, it, expect } from "vitest";
import { buildRenderModel } from "./render.js";
import { formatAuditDetail } from "./cli-render.js";
import type { AuditEvent } from "./types.js";
import { classifyText } from "./body-artifact.js";

function base(over: Partial<AuditEvent> = {}): AuditEvent {
  return {
    ts: "2026-04-18T10:00:00.000Z",
    secret_name: "API_TOKEN",
    tool: "http_request",
    target: "api.example.com",
    outcome: "allowed",
    request_id: "req-cli-0001",
    caller_cwd: "/tmp/proj",
    ...over,
  };
}

describe("formatAuditDetail", () => {
  it("emits pure ASCII (no ANSI) when tty=false", () => {
    const model = buildRenderModel(base());
    const out = formatAuditDetail(model, { tty: false });
    expect(out).not.toMatch(/\x1b\[/);
    expect(out).toContain("Summary");
    expect(out).toContain("req-cli-0001");
  });

  it("includes ANSI escapes when tty=true", () => {
    const model = buildRenderModel(base());
    const out = formatAuditDetail(model, { tty: true });
    expect(out).toMatch(/\x1b\[/);
  });

  it("pre-F13 record renders with 'not captured' blocks", () => {
    const model = buildRenderModel(base());
    const out = formatAuditDetail(model, { tty: false });
    expect(out).toContain("not captured in this record");
  });

  it("renders scrubbed header badges and body truncation", () => {
    const ev = base({
      surface: "mcp_http_request",
      request: {
        method: "GET",
        url: "https://api.example.com/",
        headers: [
          { name: "Authorization", value: "Bearer [REDACTED:API_TOKEN]", scrubbed: true },
        ],
      },
      response: { status: 200, headers: [] },
    });
    const truncated = classifyText("x".repeat(100), { cap: 10 });
    const model = buildRenderModel(ev, {
      bodies: { request: classifyText(""), response: truncated },
    });
    const out = formatAuditDetail(model, { tty: false });
    expect(out).toContain("[SCRUBBED]");
    expect(out).toContain("truncated");
  });

  it("never emits plaintext secret values that were passed via in-scope scrub", () => {
    const ev = base({
      surface: "mcp_http_request",
      request: {
        method: "POST",
        url: "https://api.example.com/SEKRET123", // simulate bypass
        headers: [],
      },
      response: { status: 200, headers: [] },
    });
    const model = buildRenderModel(ev, {
      inScopeSecrets: [{ name: "API_TOKEN", value: "SEKRET123" }],
      bodies: { response: classifyText("the secret is SEKRET123") },
    });
    const out = formatAuditDetail(model, { tty: false });
    expect(out).not.toContain("SEKRET123");
    expect(out).toContain("[REDACTED:API_TOKEN]");
  });
});
