// list_secrets — read-only MCP tool.
//
// Returns one entry per secret in the merged scope (project-over-global)
// with a POLICY SUMMARY containing only counts + rate limit numbers.
//
// Least-privilege disclosure: the summary intentionally omits host
// FQDNs, binary names, env var names, regex patterns, and of course
// the secret value. Full detail is CLI-only via `policy show`.
//
// This tool does NOT trigger policy enforcement or audit logging.
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { listMerged, type SecretScope } from "../scope/index.js";
import { policySchema } from "../policy/index.js";
import type { McpServerDeps } from "./server.js";

export interface PolicySummary {
  allowed_http_host_count: number;
  allowed_command_count: number;
  allowed_env_var_count: number;
  rate_limit: { requests: number; window_seconds: number } | null;
}

export interface ListedSecret {
  name: string;
  scope: SecretScope;
  policy_summary: PolicySummary;
}

export interface ListSecretsResult {
  secrets: ListedSecret[];
}

const EMPTY_SUMMARY: PolicySummary = {
  allowed_http_host_count: 0,
  allowed_command_count: 0,
  allowed_env_var_count: 0,
  rate_limit: null,
};

function summarize(policy: unknown): PolicySummary {
  if (policy === undefined || policy === null) {
    return { ...EMPTY_SUMMARY };
  }
  const parsed = policySchema.safeParse(policy);
  if (!parsed.success) {
    return { ...EMPTY_SUMMARY };
  }
  const p = parsed.data;
  return {
    allowed_http_host_count: p.allowed_http_hosts.length,
    allowed_command_count: p.allowed_commands.length,
    allowed_env_var_count: p.allowed_env_vars.length,
    rate_limit: {
      requests: p.rate_limit.requests,
      window_seconds: p.rate_limit.window_seconds,
    },
  };
}

export function runListSecrets(deps: McpServerDeps): ListSecretsResult {
  const entries = listMerged(deps.sources);
  const secrets: ListedSecret[] = entries.map((e) => ({
    name: e.name,
    scope: e.scope,
    policy_summary: summarize(e.policy),
  }));
  return { secrets };
}

export const LIST_SECRETS_INPUT_SHAPE = {} as const;
export const listSecretsInputSchema = z.object(LIST_SECRETS_INPUT_SHAPE).strict();

export function registerListSecrets(server: McpServer, deps: McpServerDeps): void {
  server.registerTool(
    "list_secrets",
    {
      description:
        "List every secret currently in scope (project-over-global merge) with a policy summary containing counts only — no secret values, no hostnames, no binary names, no env var names, no regex patterns.",
      inputSchema: LIST_SECRETS_INPUT_SHAPE,
    },
    () => {
      const result = runListSecrets(deps);
      return {
        content: [{ type: "text", text: JSON.stringify(result) }],
        structuredContent: {
          secrets: result.secrets.map((s) => ({
            name: s.name,
            scope: s.scope,
            policy_summary: { ...s.policy_summary },
          })),
        },
      };
    },
  );
}
