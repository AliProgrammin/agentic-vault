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

export const SERVER_INSTRUCTIONS = `Agentic Vault (secretproxy) — per-secret policy-gated credential broker.

You do NOT have raw access to API keys or tokens. Instead, you reference them by NAME via the tools below. The vault injects the real value at call time and scrubs it from responses. Attempting to read, print, or exfiltrate secret values will not work — values never cross the tool boundary.

WHEN TO USE THIS SERVER:

• Any HTTP(S) API call that needs authentication (OpenAI, Anthropic, OpenRouter, GitHub, Stripe, Cloudflare, internal APIs, etc.) → use \`http_request\`. Do NOT use raw curl / fetch / shell, because those require the plaintext secret which you don't have.

• Any CLI binary that reads a secret from an env var (gh, aws, psql, stripe, terraform, etc.) → use \`run_command\` with \`inject_env\` mapping the env var name to the vault secret name.

• To discover what secrets exist and their allowed scopes → use \`list_secrets\`.

• To figure out which vault secret satisfies an env var a script expects → use \`scan_env_requirement\`.

TYPICAL WORKFLOW:
  1. Call \`list_secrets\` once at start of a task to see what's available.
  2. Pick the secret whose policy matches the host / binary you need.
  3. Call \`http_request\` or \`run_command\` with that secret NAME (not its value).
  4. If the call is denied with POLICY_DENIED, tell the user — do not retry with a different secret.

IMPORTANT CONVENTIONS:

• For Bearer-style Authorization headers, the template is "Bearer {{value}}" (include the "Bearer " prefix). See the \`http_request\` tool description for more patterns.
• The only placeholder supported in templates is \`{{value}}\`.
• Each secret is scoped to specific hosts (for http) and binaries (for run_command). Policy violations are hard denies, not warnings — there are no wildcards by default.

Read each tool's own description for concrete input examples before the first call.`;

export function createMcpServer(
  deps: McpServerDeps,
  opts: CreateMcpServerOptions = {},
): McpServer {
  const server = new McpServer(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} }, instructions: SERVER_INSTRUCTIONS },
  );
  registerListSecrets(server, deps);
  registerScanEnvRequirement(server, deps);
  for (const registrar of opts.extraTools ?? []) {
    registrar(server, deps);
  }
  return server;
}
