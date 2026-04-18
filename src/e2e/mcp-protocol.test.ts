// End-to-end MCP protocol test.
//
// Asserts that the production wiring (as used in src/cli/commands/run.ts)
// registers all four tools when a real MCP client connects over the
// in-memory transport. Regression guard for the bug where run.ts called
// createMcpServer without extraTools, shipping a server that only
// advertised list_secrets + scan_env_requirement.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { InMemoryAuditLogger } from "../audit/index.js";
import {
  createMcpServer,
  registerHttpRequest,
  registerRunCommand,
  type HttpRequestDeps,
  type RunCommandDeps,
} from "../mcp/index.js";
import { RateLimiter } from "../ratelimit/index.js";
import { createVault, unlockVault, type KdfParams, type VaultHandle } from "../vault/index.js";

const FAST_KDF: KdfParams = { memory: 1024, iterations: 2, parallelism: 1 };
const PASSWORD = "mcp-proto-test-pw";

describe("MCP protocol — production wiring exposes all four tools", () => {
  let tmpDir: string;
  let handle: VaultHandle | null = null;

  beforeEach(async () => {
    tmpDir = await fs.realpath(
      await fs.mkdtemp(path.join(os.tmpdir(), "secretproxy-mcp-")),
    );
  });

  afterEach(async () => {
    if (handle && !handle.isClosed()) {
      handle.close();
    }
    handle = null;
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("client.listTools returns list_secrets, scan_env_requirement, http_request, run_command", async () => {
    const vaultPath = path.join(tmpDir, "global.enc");
    const created = await createVault(vaultPath, PASSWORD, { kdfParams: FAST_KDF });
    await created.save();
    created.close();
    handle = await unlockVault(vaultPath, PASSWORD);

    const sources = { global: handle };
    const audit = new InMemoryAuditLogger();
    const rateLimiter = new RateLimiter(() => 0);
    const httpDeps: HttpRequestDeps = { sources, audit, rateLimiter };
    const runDeps: RunCommandDeps = { sources, audit, rateLimiter };

    const server = createMcpServer(
      { sources },
      {
        extraTools: [
          (s) => registerHttpRequest(s, httpDeps),
          (s) => registerRunCommand(s, runDeps),
        ],
      },
    );

    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "test-client", version: "0.0.1" });
    await Promise.all([
      client.connect(clientTransport),
      server.connect(serverTransport),
    ]);

    try {
      const { tools } = await client.listTools();
      const names = tools.map((t) => t.name).sort();
      expect(names).toEqual([
        "http_request",
        "list_secrets",
        "run_command",
        "scan_env_requirement",
      ]);
    } finally {
      await client.close();
      await server.close();
    }
  });
});
