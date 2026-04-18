import { promises as fs } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Policy } from "../../policy/index.js";
import { unlockVault } from "../../vault/index.js";
import { createPopulatedGlobalVault, makeTestDeps, makeTmpDir } from "../test-helpers.js";
import { cmdRotate } from "./rotate.js";

const POLICY: Policy = {
  allowed_http_hosts: ["api.example.com"],
  allowed_commands: [],
  allowed_env_vars: ["TOKEN"],
  rate_limit: { requests: 5, window_seconds: 30 },
};

describe("cmdRotate", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await makeTmpDir();
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("updates the value and preserves the existing policy", async () => {
    const password = "rotate-vault-pw";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const h = await createPopulatedGlobalVault(vaultPath, password, [
      { name: "TOKEN", value: "old-value", policy: POLICY },
    ]);
    h.close();

    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
    });

    await cmdRotate(harness.deps, "TOKEN", "new-value", { project: false });

    const reopened = await unlockVault(vaultPath, password);
    expect(reopened.get("TOKEN")).toBe("new-value");
    const rec = reopened.getRecord("TOKEN");
    expect(rec?.policy).toEqual(POLICY);
    reopened.close();
  });
});
