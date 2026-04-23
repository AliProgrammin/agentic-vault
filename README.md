# Agentic Vault

> MCP server that lets AI agents call APIs without ever seeing the credentials.

[![license: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](./LICENSE)
[![commercial license available](https://img.shields.io/badge/commercial%20license-available-green.svg)](./COMMERCIAL-LICENSE.md)
[![Node 20+](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)

Secrets live in a local encrypted vault. The server substitutes them at call time into outbound HTTP requests or subprocess environment variables, under a **per-secret allowlist policy**. The model only ever sees secret *names*, never values.

**Homepage:** <https://agenticvault.madhoob.dev>

---

## Why

Letting an AI agent make authenticated calls usually means giving it the raw API key. That breaks least-privilege, pollutes transcripts and logs, and means one jailbreak or prompt-injection is enough to exfiltrate the token.

Agentic Vault splits the two: **the agent picks a secret by name and a destination; the vault checks the policy and injects the value**. The plaintext never crosses the tool boundary.

## Install

```bash
npm install -g secretproxy
secretproxy init                # creates the global vault, stores master password in the OS keychain
secretproxy add OPENROUTER_API_KEY sk-or-...
secretproxy policy set OPENROUTER_API_KEY --host openrouter.ai
secretproxy run                 # start the MCP server over stdio
```

Then point any MCP client (Claude Code, Cursor, Cline, Codex, Zed) at `secretproxy run`.

## Tools exposed over MCP

| Tool | Purpose |
| --- | --- |
| `list_secrets` | Enumerate available secret names (no values) |
| `http_request` | Make an HTTP call with a secret injected into headers, query, or body |
| `run_command` | Run a subprocess with secrets injected as env vars |
| `scan_env_requirement` | Detect what env vars a project expects and match them to stored secrets |

## Features

- **Zero-plaintext injection** — values substituted inside the vault, never in the model context
- **Per-secret policy** — allow-lists for HTTP hosts, commands, env vars; deny by default; optional wildcards (strict mode rejects them)
- **AES-256-GCM vault** with argon2id key derivation
- **Encrypted audit trail** — every call logged with policy decision, surface, outcome
- **Scoped vaults** — global defaults + per-project overrides
- **OS-native password storage** — macOS Keychain, libsecret, Windows Credential Manager
- **Interactive TUI** (`secretproxy tui`) and local-only web UI (`secretproxy ui`)
- **Rate limiting** with token buckets
- **Zero telemetry** — no outbound calls, local-only by design

## Development

```bash
npm install
npm test            # 328 tests across 45 files
npm run build
npm run typecheck
```

Architecture primer: `src/vault/` owns encryption, `src/mcp/` owns the MCP tool surface, `src/policy/` owns allowlist enforcement, `src/audit/` owns the append-only log.

## License

**AGPL-3.0-or-later** for open-source use — see [LICENSE](./LICENSE).

If your use case is incompatible with AGPL's network-copyleft clause (embedding in a proprietary product, offering as a managed service without source disclosure, etc.), a **commercial license** is available — see [COMMERCIAL-LICENSE.md](./COMMERCIAL-LICENSE.md).

Contact: **haaamcar@gmail.com**
