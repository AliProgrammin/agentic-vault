import { promises as fs } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Policy } from "../../policy/index.js";
import { createPopulatedGlobalVault, makeTestDeps, makeTmpDir } from "../test-helpers.js";
import { cmdList } from "./list.js";

const SAMPLE_POLICY: Policy = {
  allowed_http_hosts: ["api.example.com"],
  allowed_commands: [
    { binary: "wrangler", allowed_args_patterns: ["^deploy$"] },
  ],
  allowed_env_vars: ["CLOUDFLARE_API_TOKEN"],
  rate_limit: { requests: 10, window_seconds: 60 },
};

describe("cmdList", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await makeTmpDir();
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("prints names, scopes, and policy counts but never the secret value", async () => {
    const password = "list-vault-pw-99";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const h = await createPopulatedGlobalVault(vaultPath, password, [
      { name: "ALPHA", value: "VALUE_ALPHA_NEVER_PRINT", policy: SAMPLE_POLICY },
      { name: "BETA", value: "VALUE_BETA_NEVER_PRINT" },
    ]);
    h.close();

    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      env: {},
      password,
      keychainPopulated: true,
    });

    await cmdList(harness.deps, { scope: "all" });

    const output = harness.stdout.text();
    expect(output).toContain("ALPHA");
    expect(output).toContain("BETA");
    expect(output).toContain("[global]");
    expect(output).toContain("hosts: 1 commands: 1 env: 1 rate: 10/60");
    expect(output).not.toContain("VALUE_ALPHA_NEVER_PRINT");
    expect(output).not.toContain("VALUE_BETA_NEVER_PRINT");
    // counts only — no hostnames, binary names, env var names
    expect(output).not.toContain("api.example.com");
    expect(output).not.toContain("wrangler");
    expect(output).not.toContain("CLOUDFLARE_API_TOKEN");
  });
});
