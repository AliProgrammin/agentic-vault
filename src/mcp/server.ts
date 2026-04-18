// SecretProxy MCP server bootstrap.
//
// Registration pattern (IMPORTANT for F10/F11):
//   1. Each tool module lives in `src/mcp/<tool>.ts` and exports a
//      `register<ToolName>(server, deps)` function that calls
//      `server.registerTool(...)`.
//   2. `createMcpServer(deps)` calls the F9 registrars for the two
//      built-in tools (`list_secrets`, `scan_env_requirement`).
//   3. New tools (F10 `http_request`, F11 `run_command`) can be
//      registered WITHOUT modifying this file by passing
//      `{ extraTools: [registerHttpRequest, registerRunCommand] }`
//      via `CreateMcpServerOptions`. Alternatively, they may add
//      their registrars directly into `createMcpServer` in the
//      relevant PR — both styles are supported so the feature
//      branches do not conflict on this file.
//   4. Tools that need additional dependencies (audit logger, rate
//      limiter, scrubber, fetch, spawn) add them to `McpServerDeps`
//      as optional fields. F9's two tools only use `sources`.
//
// F9 tools are READ-ONLY and purely informational: they do NOT
// trigger policy enforcement or audit logging.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { MergeSources } from "../scope/index.js";
import { registerListSecrets } from "./list_secrets.js";
import { registerScanEnvRequirement } from "./scan_env_requirement.js";

export interface McpServerDeps {
  readonly sources: MergeSources;
}

export type ToolRegistrar = (server: McpServer, deps: McpServerDeps) => void;

export interface CreateMcpServerOptions {
  readonly extraTools?: readonly ToolRegistrar[];
}

export const SERVER_NAME = "secretproxy";
export const SERVER_VERSION = "0.0.1";

export function createMcpServer(
  deps: McpServerDeps,
  opts: CreateMcpServerOptions = {},
): McpServer {
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} } },
  );
  registerListSecrets(server, deps);
  registerScanEnvRequirement(server, deps);
  for (const registrar of opts.extraTools ?? []) {
    registrar(server, deps);
  }
  return server;
}
