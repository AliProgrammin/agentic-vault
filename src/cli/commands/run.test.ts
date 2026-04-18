import { promises as fs } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { VaultLockedError } from "../../keychain/index.js";
import type { McpServerDeps } from "../../mcp/index.js";
import {
  createPopulatedGlobalVault,
  makeTestDeps,
  makeTmpDir,
  PoisonedTTY,
} from "../test-helpers.js";
import { cmdRun } from "./run.js";

describe("cmdRun", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await makeTmpDir();
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("unlocks the global vault and hands it to createMcpServer + connectStdio", async () => {
    const password = "run-vault-pw";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const h = await createPopulatedGlobalVault(vaultPath, password, [
      { name: "HELLO", value: "world" },
    ]);
    h.close();

    const createCalls: McpServerDeps[] = [];
    const connectCalls: McpServer[] = [];
    const fakeServer = {} as McpServer;

    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
      mcpOverrides: {
        createMcpServer: (deps) => {
          createCalls.push(deps);
          return fakeServer;
        },
        connectStdio: async (server) => {
          connectCalls.push(server);
        },
      },
    });

    await cmdRun(harness.deps);

    expect(createCalls).toHaveLength(1);
    expect(connectCalls).toHaveLength(1);
    expect(connectCalls[0]).toBe(fakeServer);
    const sources = createCalls[0]?.sources;
    expect(sources?.global).toBeDefined();
    expect(sources?.global?.get("HELLO")).toBe("world");
    // Regression guard: production wiring MUST pass two extraTools
    // (http_request + run_command). Without this, the injecting tools are
    // never registered and the MCP server only exposes the two read-only
    // tools — see src/mcp/server.ts.
    expect(harness.mcpCalls[0]?.opts?.extraTools).toHaveLength(2);
  });

  it("never prompts when no password is available: errors with VAULT_LOCKED", async () => {
    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      env: {},
      tty: new PoisonedTTY(),
    });
    await expect(cmdRun(harness.deps)).rejects.toBeInstanceOf(VaultLockedError);
  });
});
