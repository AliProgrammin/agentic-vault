import { promises as fs } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { unlockVault } from "../../vault/index.js";
import { CliError } from "../errors.js";
import { createPopulatedGlobalVault, makeTestDeps, makeTmpDir } from "../test-helpers.js";
import { cmdRemove } from "./remove.js";

describe("cmdRemove", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await makeTmpDir();
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("removes a secret from the global vault", async () => {
    const password = "remove-vault-pw";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const h = await createPopulatedGlobalVault(vaultPath, password, [
      { name: "GOODBYE", value: "bye" },
    ]);
    h.close();

    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
    });

    await cmdRemove(harness.deps, "GOODBYE", { project: false });

    const reopened = await unlockVault(vaultPath, password);
    expect(reopened.get("GOODBYE")).toBeUndefined();
    reopened.close();
  });

  it("throws a CliError when the secret does not exist", async () => {
    const password = "remove-missing-pw";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const h = await createPopulatedGlobalVault(vaultPath, password, []);
    h.close();

    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      password,
      keychainPopulated: true,
    });

    await expect(
      cmdRemove(harness.deps, "MISSING", { project: false }),
    ).rejects.toBeInstanceOf(CliError);
  });
});
