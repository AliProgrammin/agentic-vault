import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createVault, type KdfParams, type VaultHandle } from "../vault/index.js";
import type { Policy } from "../policy/index.js";
import { runListSecrets, registerListSecrets } from "./list_secrets.js";
import { createMcpServer } from "./server.js";

const FAST_KDF: KdfParams = { memory: 1024, iterations: 2, parallelism: 1 };

async function mkTmpDir(prefix: string): Promise<string> {
  return fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), prefix)));
}

describe("list_secrets", () => {
  let root: string;
  const handles: VaultHandle[] = [];

  beforeEach(async () => {
    root = await mkTmpDir("list-secrets-");
  });

  afterEach(async () => {
    for (const h of handles) {
      if (!h.isClosed()) h.close();
    }
    handles.length = 0;
    await fs.rm(root, { recursive: true, force: true });
  });

  async function mkVault(name: string): Promise<VaultHandle> {
    const v = await createVault(path.join(root, name), "pw-correct-horse", {
      kdfParams: FAST_KDF,
    });
    handles.push(v);
    return v;
  }

  function samplePolicy(): Policy {
    return {
      allowed_http_hosts: ["api.secret-host.example", "edge.secret-host.example"],
      allowed_commands: [
        {
          binary: "wrangler",
          allowed_args_patterns: ["^deploy$"],
        },
      ],
      allowed_env_vars: ["CLOUDFLARE_API_TOKEN"],
      rate_limit: { requests: 5, window_seconds: 60 },
    };
  }

  it("returns every secret in merged scope with the correct scope label", async () => {
    const global = await mkVault("global.enc");
    const project = await mkVault("project.enc");
    global.set("GLOBAL_ONLY", "gval");
    global.set("SHARED", "global-shared");
    project.set("PROJECT_ONLY", "pval");
    project.set("SHARED", "project-shared");

    const result = runListSecrets({ sources: { global, project } });
    const byName = new Map(result.secrets.map((s) => [s.name, s]));

    expect(result.secrets).toHaveLength(3);
    expect(byName.get("GLOBAL_ONLY")?.scope).toBe("global");
    expect(byName.get("PROJECT_ONLY")?.scope).toBe("project");
    expect(byName.get("SHARED")?.scope).toBe("project");
  });

  it("produces a count-only policy_summary and rate_limit numbers", async () => {
    const global = await mkVault("global.enc");
    global.set("API", "val", samplePolicy());

    const result = runListSecrets({ sources: { global } });
    const summary = result.secrets[0]?.policy_summary;

    expect(summary).toEqual({
      allowed_http_host_count: 2,
      allowed_command_count: 1,
      allowed_env_var_count: 1,
      rate_limit: { requests: 5, window_seconds: 60 },
    });
  });

  it("reports zero counts and null rate_limit for a secret with no policy", async () => {
    const global = await mkVault("global.enc");
    global.set("NAKED", "val");

    const result = runListSecrets({ sources: { global } });
    expect(result.secrets[0]?.policy_summary).toEqual({
      allowed_http_host_count: 0,
      allowed_command_count: 0,
      allowed_env_var_count: 0,
      rate_limit: null,
    });
  });

  it("never leaks the plaintext secret value SEKRET123 in the serialized response", async () => {
    const global = await mkVault("global.enc");
    global.set("TOKEN", "SEKRET123", samplePolicy());

    const result = runListSecrets({ sources: { global } });
    const serialized = JSON.stringify(result);

    expect(serialized).not.toContain("SEKRET123");
  });

  it("never leaks host FQDNs, binary names, env var names, or regex patterns", async () => {
    const global = await mkVault("global.enc");
    global.set("TOKEN", "val", samplePolicy());

    const result = runListSecrets({ sources: { global } });
    const serialized = JSON.stringify(result);

    expect(serialized).not.toContain("api.secret-host.example");
    expect(serialized).not.toContain("edge.secret-host.example");
    expect(serialized).not.toContain("wrangler");
    expect(serialized).not.toContain("CLOUDFLARE_API_TOKEN");
    expect(serialized).not.toContain("^deploy$");
  });

  it("treats a malformed stored policy defensively as empty counts", async () => {
    const global = await mkVault("global.enc");
    global.set("TOKEN", "val", { not: "a policy" });

    const result = runListSecrets({ sources: { global } });
    expect(result.secrets[0]?.policy_summary).toEqual({
      allowed_http_host_count: 0,
      allowed_command_count: 0,
      allowed_env_var_count: 0,
      rate_limit: null,
    });
  });

  it("returns an empty list when no vaults are provided", () => {
    const result = runListSecrets({ sources: {} });
    expect(result.secrets).toEqual([]);
  });

  it("registers on an McpServer without throwing", async () => {
    const global = await mkVault("global.enc");
    global.set("TOKEN", "val");
    const server = createMcpServer({ sources: { global } });
    expect(server).toBeDefined();
    expect(registerListSecrets).toBeTypeOf("function");
  });
});
