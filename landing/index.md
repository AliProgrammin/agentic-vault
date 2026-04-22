# Agentic Vault — the secret gateway for AI agents

> Your agent asks. AgenticVault injects. It never sees the value.

MCP-native secrets gateway with encrypted audit and policy enforcement. Built for AI coding agents.

## The Problem

Your agent needs API keys to do its job. But every time you hand it a key, you're exposing credentials to the model context — where they can be logged, leaked, or misused.

1. **Raw values reach the model** — API keys passed in prompts or env vars land in the context window, where any future tool call or memory system can access them.
2. **No guardrails on actions** — Once an agent has a key, there's nothing stopping it from using it in unintended ways.
3. **No forensics after the fact** — When something goes wrong, you have no record of what the agent did with your credentials.

## The Solution

Agentic Vault sits between your agent and every API you've given it a key to.

- **Zero-plaintext injection** — Secret values are substituted at call time, inside the vault. The agent only sees the redacted result.
- **Encrypted vault** — AES-256-GCM encryption at rest with argon2id key derivation.
- **Policy engine** — Per-secret allow-lists for HTTP hosts, commands, and env vars. Deny by default.
- **Encrypted audit trail** — Every injection and denial is logged with full forensic detail.
- **Forensic detail view** — Drill into any audit entry: request, response, policy decision, timing.
- **Scoped vaults** — Global and project-local vaults; project overrides global on key collision.

## How It Works

1. **Agent requests** — The agent calls an Agentic Vault MCP tool, naming the secret it needs and the action it wants to take.
2. **Vault enforces policy** — Agentic Vault checks the request against the secret's policy (allowed hosts, commands, env vars, rate limits). Deny by default.
3. **Value injected, never exposed** — If allowed, the value is injected at the point of use. The agent sees only the scrubbed result.

## Agent Discovery

- MCP Server Card: <https://agenticvault.madhoob.dev/.well-known/mcp/server-card.json>
- API Catalog: <https://agenticvault.madhoob.dev/.well-known/api-catalog>
- Agent Skills: <https://agenticvault.madhoob.dev/.well-known/agent-skills/index.json>
- Sitemap: <https://agenticvault.madhoob.dev/sitemap.xml>

## Get Started

Request early access: [haaamcar@gmail.com](mailto:haaamcar@gmail.com?subject=AgenticVault)
