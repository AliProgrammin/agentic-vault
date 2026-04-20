import { promises as fs } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { makeTestDeps, makeTmpDir } from "../test-helpers.js";
import { cmdAuditList } from "./audit-list.js";

async function seed(deps: { auditLogPath: string }, records: Array<Record<string, unknown>>): Promise<void> {
  await fs.mkdir(path.dirname(deps.auditLogPath), { recursive: true });
  const lines = records.map((r) => JSON.stringify(r)).join("\n") + "\n";
  await fs.writeFile(deps.auditLogPath, lines);
}

describe("cmdAuditList", () => {
  let tmp: string;
  beforeEach(async () => { tmp = await makeTmpDir(); });
  afterEach(async () => { await fs.rm(tmp, { recursive: true, force: true }); });

  it("prints nothing when no records match", async () => {
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp });
    await seed(harness.deps, []);
    await cmdAuditList(harness.deps, { surface: "mcp_run_command" });
    expect(harness.stdout.text()).toBe("");
  });

  it("filters by surface + status + since + code", async () => {
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp });
    await seed(harness.deps, [
      { ts: "2026-04-18T09:00:00.000Z", secret_name: "A", tool: "run_command", target: "wrangler", outcome: "allowed", request_id: "r-a", caller_cwd: "/", surface: "mcp_run_command" },
      { ts: "2026-04-18T11:00:00.000Z", secret_name: "B", tool: "run_command", target: "wrangler", outcome: "denied", code: "POLICY_DENIED", request_id: "r-b", caller_cwd: "/", surface: "mcp_run_command" },
      { ts: "2026-04-18T12:00:00.000Z", secret_name: "C", tool: "http_request", target: "api.example.com", outcome: "denied", code: "RATE_LIMITED", request_id: "r-c", caller_cwd: "/", surface: "mcp_http_request" },
    ]);
    await cmdAuditList(harness.deps, {
      surface: "mcp_run_command",
      status: "denied",
      since: "2026-04-18T10:00:00.000Z",
    });
    const lines = harness.stdout.text().split("\n").filter((l) => l.length > 0);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("r-b");
    expect(lines[0]).toContain("POLICY_DENIED");
  });

  it("rejects invalid surface", async () => {
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp });
    await seed(harness.deps, []);
    await expect(cmdAuditList(harness.deps, { surface: "bogus" })).rejects.toThrow(/--surface/);
  });

  it("respects --limit (returns most recent N)", async () => {
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp });
    await seed(harness.deps, Array.from({ length: 5 }, (_, i) => ({
      ts: `2026-04-18T10:0${String(i)}:00.000Z`,
      secret_name: "X",
      tool: "http_request",
      target: "api.example.com",
      outcome: "allowed",
      request_id: `r-${String(i)}`,
      caller_cwd: "/",
      surface: "mcp_http_request",
    })));
    await cmdAuditList(harness.deps, { limit: 2 });
    const lines = harness.stdout.text().split("\n").filter((l) => l.length > 0);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain("r-3");
    expect(lines[1]).toContain("r-4");
  });
});
