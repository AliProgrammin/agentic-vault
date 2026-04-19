// Built-in per-secret policy templates.
//
// Keyed by canonical secret name. Each entry is a full Policy that
// passes policySchema (no wildcards, enumerated FQDNs, rate limit set).
// Hosts are sourced from each provider's public API docs; add a
// comment with the source URL when extending this table.
//
// Two consumers:
//   1. `secretproxy add <KEY> <VALUE>` applies this template when the
//      name matches and no explicit policy is given. Unknown names fall
//      through to deny-by-default and a one-line hint.
//   2. The UI policy editor exposes these as a "Template" dropdown so
//      users can pre-fill the form before customising.
//
// The default rate limit is conservative (60 requests / 60 seconds) so
// accidental runaway calls trip the limiter before a bill explodes.

import type { Policy } from "./schema.js";

const DEFAULT_RATE_LIMIT: Policy["rate_limit"] = {
  requests: 60,
  window_seconds: 60,
};

function policy(
  hosts: readonly string[],
  commands: Policy["allowed_commands"],
  envVars: readonly string[],
): Policy {
  return {
    allowed_http_hosts: [...hosts],
    allowed_commands: commands,
    allowed_env_vars: [...envVars],
    rate_limit: DEFAULT_RATE_LIMIT,
  };
}

// https://platform.openai.com/docs/api-reference
const OPENAI = policy(["api.openai.com"], [], ["OPENAI_API_KEY"]);
// https://openrouter.ai/docs/api-reference
const OPENROUTER = policy(["openrouter.ai"], [], ["OPENROUTER_API_KEY"]);
// https://docs.anthropic.com/en/api/getting-started
const ANTHROPIC = policy(["api.anthropic.com"], [], ["ANTHROPIC_API_KEY"]);
// https://developers.cloudflare.com/api/ and wrangler binary for run_command
const CLOUDFLARE = policy(
  ["api.cloudflare.com"],
  [
    {
      binary: "wrangler",
      allowed_args_patterns: ["^[a-z][a-z0-9:-]*$", "^--[a-z][a-z0-9-]*$", "^[a-z0-9][a-z0-9._/-]*$"],
    },
  ],
  ["CLOUDFLARE_API_TOKEN"],
);
// https://docs.github.com/en/rest and gh binary
const GITHUB = policy(
  ["api.github.com"],
  [
    {
      binary: "gh",
      allowed_args_patterns: ["^[a-z][a-z0-9:-]*$", "^--[a-z][a-z0-9-]*$", "^[a-z0-9][a-zA-Z0-9._/-]*$"],
    },
  ],
  ["GH_TOKEN", "GITHUB_TOKEN"],
);
// https://docs.stripe.com/api and stripe binary
const STRIPE = policy(
  ["api.stripe.com"],
  [
    {
      binary: "stripe",
      allowed_args_patterns: ["^[a-z][a-z0-9:-]*$", "^--[a-z][a-z0-9-]*$"],
    },
  ],
  ["STRIPE_API_KEY"],
);
// https://supabase.com/docs/reference/api
const SUPABASE = policy(["api.supabase.com"], [], ["SUPABASE_ACCESS_TOKEN"]);
// https://vercel.com/docs/rest-api
const VERCEL = policy(["api.vercel.com"], [], ["VERCEL_TOKEN"]);
// https://fly.io/docs/flyctl/ (API at api.fly.io/graphql)
const FLY = policy(["api.fly.io"], [], ["FLY_API_TOKEN"]);
// https://devcenter.heroku.com/articles/platform-api-reference
const HEROKU = policy(["api.heroku.com"], [], ["HEROKU_API_KEY"]);
// https://docs.railway.com/reference/public-api
const RAILWAY = policy(["backboard.railway.app"], [], ["RAILWAY_TOKEN"]);
// https://api-docs.render.com/
const RENDER = policy(["api.render.com"], [], ["RENDER_API_KEY"]);
// https://developers.digitalocean.com/documentation/v2/
const DIGITALOCEAN = policy(["api.digitalocean.com"], [], ["DIGITALOCEAN_ACCESS_TOKEN"]);
// https://docs.turso.tech/api-reference
const TURSO = policy(["api.turso.tech"], [], ["TURSO_API_TOKEN"]);
// https://neon.tech/docs/reference/api-reference
const NEON = policy(["console.neon.tech"], [], ["NEON_API_KEY"]);
// https://discord.com/developers/docs/reference
const DISCORD_BOT = policy(["discord.com"], [], ["DISCORD_BOT_TOKEN"]);
// https://api.slack.com/
const SLACK_BOT = policy(["slack.com"], [], ["SLACK_BOT_TOKEN"]);

export const DEFAULT_POLICIES: Readonly<Record<string, Policy>> = {
  OPENAI_API_KEY: OPENAI,
  OPENROUTER_API_KEY: OPENROUTER,
  ANTHROPIC_API_KEY: ANTHROPIC,
  CLOUDFLARE_API_TOKEN: CLOUDFLARE,
  GH_TOKEN: GITHUB,
  GITHUB_TOKEN: GITHUB,
  STRIPE_API_KEY: STRIPE,
  SUPABASE_ACCESS_TOKEN: SUPABASE,
  VERCEL_TOKEN: VERCEL,
  FLY_API_TOKEN: FLY,
  HEROKU_API_KEY: HEROKU,
  RAILWAY_TOKEN: RAILWAY,
  RENDER_API_KEY: RENDER,
  DIGITALOCEAN_ACCESS_TOKEN: DIGITALOCEAN,
  TURSO_API_TOKEN: TURSO,
  NEON_API_KEY: NEON,
  DISCORD_BOT_TOKEN: DISCORD_BOT,
  SLACK_BOT_TOKEN: SLACK_BOT,
};

export interface PolicyTemplateEntry {
  readonly name: string;
  readonly policy: Policy;
}

export function listPolicyTemplates(): readonly PolicyTemplateEntry[] {
  return Object.entries(DEFAULT_POLICIES)
    .map(([name, p]) => ({ name, policy: p }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export function lookupDefaultPolicy(secretName: string): Policy | null {
  const direct = DEFAULT_POLICIES[secretName];
  if (direct !== undefined) return direct;
  return null;
}
