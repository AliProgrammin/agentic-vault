import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { FileAuditLogger } from "./file-logger.js";
import { createRequestId } from "./request-id.js";
import type { AuditEvent } from "./types.js";

async function makeSandbox(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "secretproxy-audit-"));
}

async function readLines(filePath: string): Promise<string[]> {
  const content = await fs.readFile(filePath, "utf8");
  return content.split("\n").filter((l) => l.length > 0);
}

function parseEvent(line: string | undefined): AuditEvent {
  expect(line).toBeDefined();
  if (line === undefined) {
    throw new Error("line was undefined");
  }
  return JSON.parse(line) as AuditEvent;
}

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

describe("FileAuditLogger", () => {
  let sandbox: string;

  beforeEach(async () => {
    sandbox = await makeSandbox();
  });

  afterEach(async () => {
    await fs.rm(sandbox, { recursive: true, force: true });
  });

  it("writes a JSON line that round-trips to the original event", async () => {
    const logger = new FileAuditLogger({ baseDir: sandbox });
    const event = baseEvent({
      outcome: "denied",
      reason: "host 'api.other.com' is not in the allowed HTTP host list",
      code: "POLICY_DENIED",
    });
    await logger.record(event);

    const lines = await readLines(logger.filePath);
    expect(lines).toHaveLength(1);
    expect(parseEvent(lines[0])).toEqual(event);
  });

  it("records allowed and denied outcomes as exactly one line each", async () => {
    const logger = new FileAuditLogger({ baseDir: sandbox });
    await logger.record(baseEvent({ outcome: "allowed" }));
    await logger.record(
      baseEvent({
        outcome: "denied",
        reason: "rate limit exhausted",
        code: "RATE_LIMITED",
      }),
    );

    const lines = await readLines(logger.filePath);
    expect(lines).toHaveLength(2);
    expect(parseEvent(lines[0]).outcome).toBe("allowed");
    const second = parseEvent(lines[1]);
    expect(second.outcome).toBe("denied");
    expect(second.code).toBe("RATE_LIMITED");
    expect(second.reason).toBe("rate limit exhausted");
  });

  it("appends to a pre-existing log without overwriting earlier lines", async () => {
    const first = new FileAuditLogger({ baseDir: sandbox });
    await first.record(baseEvent({ secret_name: "FIRST" }));

    const second = new FileAuditLogger({ baseDir: sandbox });
    await second.record(baseEvent({ secret_name: "SECOND" }));
    await second.record(baseEvent({ secret_name: "THIRD" }));

    const lines = await readLines(first.filePath);
    expect(lines).toHaveLength(3);
    expect(parseEvent(lines[0]).secret_name).toBe("FIRST");
    expect(parseEvent(lines[1]).secret_name).toBe("SECOND");
    expect(parseEvent(lines[2]).secret_name).toBe("THIRD");
  });

  it("never writes the secret plaintext value during an injected + denied flow", async () => {
    const logger = new FileAuditLogger({ baseDir: sandbox });
    const SECRET_VALUE = "SEKRET123";
    const requestId = createRequestId();

    await logger.record(
      baseEvent({
        request_id: requestId,
        secret_name: "CLOUDFLARE_API_TOKEN",
        tool: "run_command",
        target: "wrangler",
        outcome: "allowed",
      }),
    );
    await logger.record(
      baseEvent({
        request_id: requestId,
        secret_name: "CLOUDFLARE_API_TOKEN",
        tool: "http_request",
        target: "api.attacker.com",
        outcome: "denied",
        reason: "host 'api.attacker.com' is not in the allowed HTTP host list",
        code: "POLICY_DENIED",
      }),
    );

    const content = await fs.readFile(logger.filePath, "utf8");
    expect(content).not.toContain(SECRET_VALUE);
  });

  it("creates the base directory with restrictive mode on POSIX on first record", async () => {
    const baseDir = path.join(sandbox, "fresh", "nested");
    const logger = new FileAuditLogger({ baseDir });
    await logger.record(baseEvent());

    const stat = await fs.stat(baseDir);
    expect(stat.isDirectory()).toBe(true);
    if (process.platform !== "win32") {
      expect(stat.mode & 0o777).toBe(0o700);
    }
  });

  it("reuses an existing base directory without chmodding it", async () => {
    const baseDir = path.join(sandbox, "preexisting");
    await fs.mkdir(baseDir, { recursive: true });
    if (process.platform !== "win32") {
      await fs.chmod(baseDir, 0o755);
    }
    const logger = new FileAuditLogger({ baseDir });
    await logger.record(baseEvent());

    if (process.platform !== "win32") {
      const stat = await fs.stat(baseDir);
      expect(stat.mode & 0o777).toBe(0o755);
    }
    const lines = await readLines(logger.filePath);
    expect(lines).toHaveLength(1);
  });

  it("shares request_id across events from the same invocation; different invocations differ", async () => {
    const logger = new FileAuditLogger({ baseDir: sandbox });
    const invocationA = createRequestId();
    const invocationB = createRequestId();
    expect(invocationA).not.toBe(invocationB);

    await logger.record(baseEvent({ request_id: invocationA, secret_name: "A1" }));
    await logger.record(baseEvent({ request_id: invocationA, secret_name: "A2" }));
    await logger.record(baseEvent({ request_id: invocationB, secret_name: "B1" }));

    const lines = await readLines(logger.filePath);
    expect(lines).toHaveLength(3);
    expect(parseEvent(lines[0]).request_id).toBe(invocationA);
    expect(parseEvent(lines[1]).request_id).toBe(invocationA);
    expect(parseEvent(lines[2]).request_id).toBe(invocationB);
  });

  it("omits optional fields when they are absent from the event", async () => {
    const logger = new FileAuditLogger({ baseDir: sandbox });
    await logger.record(baseEvent({ outcome: "allowed" }));

    const lines = await readLines(logger.filePath);
    expect(lines).toHaveLength(1);
    const firstLine = lines[0];
    expect(firstLine).toBeDefined();
    if (firstLine === undefined) return;
    expect(firstLine).not.toContain("reason");
    expect(firstLine).not.toContain("code");
    const parsed = parseEvent(firstLine);
    expect(parsed.reason).toBeUndefined();
    expect(parsed.code).toBeUndefined();
  });

  it("exposes the log file path under the configured base directory", () => {
    const logger = new FileAuditLogger({ baseDir: sandbox });
    expect(logger.filePath).toBe(path.join(sandbox, "audit.log"));
  });

  it("defaults the base directory to ~/.secretproxy when no override is provided", () => {
    const logger = new FileAuditLogger();
    expect(logger.filePath).toBe(path.join(os.homedir(), ".secretproxy", "audit.log"));
  });
});
