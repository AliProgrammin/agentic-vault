import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  registerHttpRequest,
  registerRunCommand,
  type HttpRequestDeps,
  type McpServerDeps,
  type RunCommandDeps,
} from "../../mcp/index.js";
import type { VaultHandle } from "../../vault/index.js";
import type { CliDeps } from "../types.js";

export async function cmdRun(deps: CliDeps): Promise<void> {
  const password = deps.resolvePassword();
  let global: VaultHandle | null = null;
  let project: VaultHandle | null = null;
  try {
    if (await deps.fileExists(deps.globalVaultPath)) {
      global = await deps.unlockVault(deps.globalVaultPath, password);
    }
    const loc = await deps.discoverProjectVault(deps.cwd, deps.homedir);
    if (loc !== null) {
      project = await deps.unlockVault(loc.vaultPath, password);
    }
    const mcpDeps: McpServerDeps = { sources: { global, project } };
    const httpDeps: HttpRequestDeps = {
      ...mcpDeps,
      audit: deps.audit,
      rateLimiter: deps.rateLimiter,
    };
    const runDeps: RunCommandDeps = {
      ...mcpDeps,
      audit: deps.audit,
      rateLimiter: deps.rateLimiter,
    };
    const extraTools = [
      (s: McpServer): void => registerHttpRequest(s, httpDeps),
      (s: McpServer): void => registerRunCommand(s, runDeps),
    ];
    const server = deps.createMcpServer(mcpDeps, { extraTools });
    await deps.connectStdio(server);
  } catch (err) {
    global?.close();
    project?.close();
    throw err;
  }
}
