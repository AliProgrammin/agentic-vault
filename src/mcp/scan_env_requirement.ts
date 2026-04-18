// scan_env_requirement — read-only MCP tool.
//
// Given a CLI binary name, returns the canonical environment variable
// names that CLI uses for authentication, from a built-in lookup
// table. Unknown binaries return `[]` (never an error) so the agent
// can gracefully fall back to asking the user.
//
// This tool does NOT trigger policy enforcement or audit logging.
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { McpServerDeps } from "./server.js";

export type KnownCli =
  | "wrangler"
  | "gh"
  | "aws"
  | "vercel"
  | "supabase"
  | "stripe"
  | "doctl"
  | "flyctl"
  | "heroku"
  | "npm"
  | "pnpm"
  | "docker"
  | "kubectl"
  | "railway"
  | "render"
  | "fly"
  | "cloudflared"
  | "turso"
  | "neon"
  | "planetscale";

export const KNOWN_CLIS: readonly KnownCli[] = [
  "wrangler",
  "gh",
  "aws",
  "vercel",
  "supabase",
  "stripe",
  "doctl",
  "flyctl",
  "heroku",
  "npm",
  "pnpm",
  "docker",
  "kubectl",
  "railway",
  "render",
  "fly",
  "cloudflared",
  "turso",
  "neon",
  "planetscale",
] as const;

export const ENV_REQUIREMENT_TABLE: Readonly<Record<KnownCli, readonly string[]>> = {
  // Cloudflare Workers CLI. Source:
  // https://developers.cloudflare.com/workers/wrangler/system-environment-variables/
  wrangler: ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"],
  // GitHub CLI. Source: `gh help environment`
  // https://cli.github.com/manual/gh_help_environment
  gh: ["GH_TOKEN", "GITHUB_TOKEN"],
  // AWS CLI v2. Source:
  // https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
  aws: [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_PROFILE",
  ],
  // Vercel CLI. Source:
  // https://vercel.com/docs/cli/global-options#token
  vercel: ["VERCEL_TOKEN"],
  // Supabase CLI. Source:
  // https://supabase.com/docs/reference/cli/introduction (access token auth)
  supabase: ["SUPABASE_ACCESS_TOKEN"],
  // Stripe CLI. Source:
  // https://docs.stripe.com/stripe-cli (CI authentication)
  stripe: ["STRIPE_API_KEY"],
  // DigitalOcean doctl. Source:
  // https://docs.digitalocean.com/reference/doctl/reference/auth/init/
  doctl: ["DIGITALOCEAN_ACCESS_TOKEN"],
  // Fly.io flyctl. Source:
  // https://fly.io/docs/flyctl/help/#environment-variables
  flyctl: ["FLY_API_TOKEN"],
  // Heroku CLI. Source:
  // https://devcenter.heroku.com/articles/using-the-cli#api-token-authentication
  heroku: ["HEROKU_API_KEY"],
  // npm CLI. Source:
  // https://docs.npmjs.com/cli/v10/configuring-npm/npmrc#auth-related-configuration
  // (NPM_TOKEN is the canonical CI env used via `//registry.../:_authToken=${NPM_TOKEN}`)
  npm: ["NPM_TOKEN", "NPM_CONFIG_TOKEN"],
  // pnpm follows npm's env conventions. Source:
  // https://pnpm.io/npmrc (auth-related configuration)
  pnpm: ["NPM_TOKEN", "NPM_CONFIG_TOKEN"],
  // Docker CLI. Source:
  // https://docs.docker.com/engine/reference/commandline/cli/#environment-variables
  docker: ["DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_CONFIG"],
  // kubectl. Source:
  // https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands
  // (KUBECONFIG is the canonical env for cluster credentials)
  kubectl: ["KUBECONFIG"],
  // Railway CLI. Source:
  // https://docs.railway.com/reference/cli-api#environment-variables
  railway: ["RAILWAY_TOKEN"],
  // Render CLI. Source:
  // https://render.com/docs/cli (API key authentication)
  render: ["RENDER_API_KEY"],
  // Fly.io `fly` is an alias of flyctl. Source:
  // https://fly.io/docs/flyctl/help/#environment-variables
  fly: ["FLY_API_TOKEN"],
  // Cloudflare Tunnel (cloudflared). Source:
  // https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/configure-tunnels/remote-tunnel-parameters/
  cloudflared: ["TUNNEL_TOKEN"],
  // Turso CLI. Source:
  // https://docs.turso.tech/cli/reference (API token authentication)
  turso: ["TURSO_API_TOKEN"],
  // Neon CLI. Source:
  // https://neon.tech/docs/reference/neon-cli#environment-variables
  neon: ["NEON_API_KEY"],
  // PlanetScale CLI. Source:
  // https://planetscale.com/docs/reference/authentication (service tokens)
  planetscale: ["PLANETSCALE_SERVICE_TOKEN", "PLANETSCALE_SERVICE_TOKEN_NAME"],
};

export interface ScanEnvRequirementInput {
  command: string;
}

export interface ScanEnvRequirementResult {
  env_vars: string[];
}

function isKnownCli(command: string): command is KnownCli {
  return Object.prototype.hasOwnProperty.call(ENV_REQUIREMENT_TABLE, command);
}

export function runScanEnvRequirement(
  input: ScanEnvRequirementInput,
): ScanEnvRequirementResult {
  if (!isKnownCli(input.command)) {
    return { env_vars: [] };
  }
  return { env_vars: [...ENV_REQUIREMENT_TABLE[input.command]] };
}

export const SCAN_ENV_REQUIREMENT_INPUT_SHAPE = {
  command: z.string().min(1, { message: "command must not be empty" }),
} as const;

export const scanEnvRequirementInputSchema = z
  .object(SCAN_ENV_REQUIREMENT_INPUT_SHAPE)
  .strict();

export function registerScanEnvRequirement(
  server: McpServer,
  _deps: McpServerDeps,
): void {
  server.registerTool(
    "scan_env_requirement",
    {
      description:
        "Return the canonical environment variable names a known CLI binary reads for authentication (from a built-in table). Unknown binaries return an empty array.",
      inputSchema: SCAN_ENV_REQUIREMENT_INPUT_SHAPE,
    },
    (args) => {
      const result = runScanEnvRequirement({ command: args.command });
      return {
        content: [{ type: "text", text: JSON.stringify(result) }],
        structuredContent: { env_vars: [...result.env_vars] },
      };
    },
  );
}
