# SecretProxy

Open-source MCP server that lets AI agents call APIs without ever seeing the credentials. Secrets live in an encrypted vault; the server injects them at call time into subprocess env vars or outbound HTTP requests under a per-secret allowlist policy.

## Manual verification — live `wrangler deploy`

The automated test suite (`npm test`) exercises the full unlock -> MCP -> `run_command` flow against a **mocked** `wrangler` binary. CI must not require live cloud credentials, so a real `wrangler deploy` is **not** a CI gate.

To verify the flow against real Cloudflare infrastructure end-to-end, do so manually on a developer machine:

1. `secretproxy init` (stashes the master password in the OS keychain).
2. `secretproxy add CLOUDFLARE_API_TOKEN <your-real-token>`.
3. `secretproxy policy set CLOUDFLARE_API_TOKEN --command 'wrangler:^deploy$' --env CLOUDFLARE_API_TOKEN --rate 10/60`.
4. Start the MCP server with `secretproxy run`.
5. From an MCP client, invoke `run_command` with `{ command: "wrangler", args: ["deploy"], inject_env: { CLOUDFLARE_API_TOKEN: "CLOUDFLARE_API_TOKEN" } }` against a test Worker.

This is a manual smoke check only — not required for merge. The automated E2E in `src/e2e/smoke.test.ts` asserts the security invariants (env injection, argv absence, stdout scrubbing, policy denial) without touching the network.
