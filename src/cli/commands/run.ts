import * as path from "node:path";
import { watch } from "node:fs";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { EncryptedBodyStore } from "../../audit/index.js";
import {
  registerHttpRequest,
  registerRunCommand,
  type HttpRequestDeps,
  type McpServerDeps,
  type RunCommandDeps,
} from "../../mcp/index.js";
import type { VaultHandle } from "../../vault/index.js";
import type { CliDeps } from "../types.js";

const BODY_KEY_INFO = "secretproxy/audit-body-v1";

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
    const keyHolder = global ?? project;
    const bodyStore =
      keyHolder !== null
        ? new EncryptedBodyStore({
            baseDir: path.dirname(deps.auditLogPath),
            key: keyHolder.deriveSubkey(BODY_KEY_INFO),
          })
        : undefined;
    const httpDeps: HttpRequestDeps = {
      ...mcpDeps,
      audit: deps.audit,
      rateLimiter: deps.rateLimiter,
      ...(bodyStore !== undefined ? { bodyStore } : {}),
    };
    const runDeps: RunCommandDeps = {
      ...mcpDeps,
      audit: deps.audit,
      rateLimiter: deps.rateLimiter,
      ...(bodyStore !== undefined ? { bodyStore } : {}),
    };
    const extraTools = [
      (s: McpServer): void => registerHttpRequest(s, httpDeps),
      (s: McpServer): void => registerRunCommand(s, runDeps),
    ];
    const server = deps.createMcpServer(mcpDeps, { extraTools });
    const watchers = [
      global ? watch(deps.globalVaultPath, () => { void global!.reload(); }) : null,
      project && loc ? watch(loc.vaultPath, () => { void project!.reload(); }) : null,
    ].filter(Boolean);
    try {
      await deps.connectStdio(server);
    } finally {
      for (const w of watchers) w?.close();
    }
  } catch (err) {
    global?.close();
    project?.close();
    throw err;
  }
}
