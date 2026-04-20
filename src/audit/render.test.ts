import { describe, it, expect } from "vitest";
import { buildRenderModel } from "./render.js";
import type { AuditEvent } from "./types.js";
import type { ScrubbableSecret } from "../scrub/index.js";
import { classifyText } from "./body-artifact.js";
import { BodyDecryptError } from "./body-store.js";

function baseEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    ts: "2026-04-18T10:00:00.000Z",
    secret_name: "API_TOKEN",
    tool: "http_request",
    target: "api.example.com",
    outcome: "allowed",
    request_id: "req-base-0001",
    caller_cwd: "/tmp/proj",
    ...overrides,
  };
}

describe("buildRenderModel", () => {
  it("pre-F13 record without new fields still renders (not captured)", () => {
    const model = buildRenderModel(baseEvent());
    expect(model.id).toBe("req-base-0001");
    expect(model.request.kind).toBe("none");
    expect(model.response.kind).toBe("none");
    expect(model.timeline.stages).toHaveLength(0);
    expect(model.injected_secrets).toHaveLength(0);
  });

  it("renders HTTP request + response from F13 fields", () => {
    const model = buildRenderModel(
      baseEvent({
        surface: "mcp_http_request",
        request: {
          method: "GET",
          url: "https://api.example.com/path",
          headers: [{ name: "Authorization", value: "Bearer xyz", scrubbed: true }],
        },
        response: {
          status: 200,
          headers: [{ name: "content-type", value: "application/json", scrubbed: false }],
        },
        body_ref: { blob_id: "req-base-0001" },
      }),
      {
        bodies: {
          request: classifyText("{}"),
          response: classifyText(`{"ok":true}`),
        },
      },
    );
    expect(model.request.kind).toBe("http");
    expect(model.response.kind).toBe("http");
    if (model.request.kind === "http") {
      expect(model.request.view.method).toBe("GET");
      expect(model.request.view.body.status).toBe("present");
    }
    if (model.response.kind === "http") {
      expect(model.response.view.status_code).toBe(200);
      expect(model.response.view.body.status).toBe("present");
    }
  });

  it("scrubs at render time (defense-in-depth) when in-scope secrets are provided", () => {
    // Simulate a storage-layer bug: the blob contains a raw secret. Render
    // should still replace it with [REDACTED:NAME].
    const secrets: ScrubbableSecret[] = [{ name: "API_TOKEN", value: "SEKRET123" }];
    const model = buildRenderModel(
      baseEvent({
        surface: "mcp_http_request",
        request: {
          method: "POST",
          url: "https://api.example.com/path?tok=SEKRET123",
          headers: [
            { name: "Authorization", value: "Bearer SEKRET123", scrubbed: true },
          ],
        },
        response: {
          status: 200,
          headers: [],
        },
      }),
      {
        inScopeSecrets: secrets,
        bodies: { response: classifyText("{\"token\":\"SEKRET123\"}") },
      },
    );
    if (model.request.kind === "http") {
      expect(model.request.view.url).not.toContain("SEKRET123");
      expect(model.request.view.url).toContain("[REDACTED:API_TOKEN]");
      expect(model.request.view.headers[0]?.value).toContain("[REDACTED:API_TOKEN]");
    }
    if (model.response.kind === "http") {
      const body = model.response.view.body;
      if (body.status === "present" && body.artifact?.kind === "text") {
        expect(body.artifact.text).not.toContain("SEKRET123");
        expect(body.artifact.text).toContain("[REDACTED:API_TOKEN]");
      } else {
        throw new Error("expected text body");
      }
    }
  });

  it("marks pruned bodies distinctly", () => {
    const model = buildRenderModel(
      baseEvent({
        surface: "mcp_http_request",
        request: {
          method: "GET",
          url: "https://api.example.com/x",
          headers: [],
        },
        response: { status: 200, headers: [] },
        body_ref: { blob_id: "gone" },
      }),
      { pruned: true },
    );
    if (model.request.kind === "http") {
      expect(model.request.view.body.status).toBe("pruned");
    }
  });

  it("marks decrypt failures distinctly", () => {
    const err = new BodyDecryptError("req-base-0001", "bad tag");
    const model = buildRenderModel(
      baseEvent({
        surface: "mcp_http_request",
        request: { method: "GET", url: "https://api.example.com/x", headers: [] },
        response: { status: 200, headers: [] },
        body_ref: { blob_id: "req-base-0001" },
      }),
      { bodiesError: err },
    );
    if (model.response.kind === "http") {
      expect(model.response.view.body.status).toBe("decrypt_failed");
    }
  });

  it("builds timeline with per-stage deltas", () => {
    const model = buildRenderModel(
      baseEvent({
        timing: {
          received_at: "2026-04-18T10:00:00.000Z",
          policy_checked_at: "2026-04-18T10:00:00.010Z",
          upstream_started_at: "2026-04-18T10:00:00.020Z",
          upstream_finished_at: "2026-04-18T10:00:00.100Z",
          returned_at: "2026-04-18T10:00:00.110Z",
        },
      }),
    );
    expect(model.timeline.stages).toHaveLength(5);
    expect(model.timeline.total_ms).toBe(110);
  });

  it("command request view renders binary/args/cwd/env_keys", () => {
    const model = buildRenderModel(
      baseEvent({
        tool: "run_command",
        surface: "mcp_run_command",
        target: "wrangler",
        request: {
          binary: "wrangler",
          args: ["deploy"],
          env_keys: ["CLOUDFLARE_API_TOKEN"],
        },
        response: {
          exit_code: 0,
        },
      }),
    );
    expect(model.request.kind).toBe("command");
    if (model.request.kind === "command") {
      expect(model.request.view.binary).toBe("wrangler");
      expect(model.request.view.args).toEqual(["deploy"]);
      expect(model.request.view.env_keys).toEqual(["CLOUDFLARE_API_TOKEN"]);
    }
    if (model.response.kind === "command") {
      expect(model.response.view.exit_code).toBe(0);
    }
  });
});
