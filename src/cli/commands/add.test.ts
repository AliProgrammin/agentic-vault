import { promises as fs } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { VaultLockedError } from "../../keychain/index.js";
import {
  createPopulatedGlobalVault,
  makeTestDeps,
  makeTmpDir,
  PoisonedTTY,
} from "../test-helpers.js";
import { cmdAdd } from "./add.js";

describe("cmdAdd", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await makeTmpDir();
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("adds a secret to the global vault", async () => {
    const password = "global-vault-pw-12";
    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const handle = await createPopulatedGlobalVault(vaultPath, password, []);
    handle.close();

    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      env: {},
      password,
      keychainPopulated: true,
    });

    await cmdAdd(harness.deps, "MY_SECRET", "value123", { project: false });

    // reopen and confirm
    const { unlockVault } = await import("../../vault/index.js");
    const reopened = await unlockVault(vaultPath, password);
    expect(reopened.get("MY_SECRET")).toBe("value123");
    reopened.close();
  });

  it("creates .gitignore for --project when none exists", async () => {
    const password = "project-vault-pw";
    const home = await makeTmpDir();
    const projectCwd = await makeTmpDir();
    try {
      const harness = makeTestDeps({
        cwd: projectCwd,
        homedir: home,
        env: {},
        password,
        keychainPopulated: true,
      });

      await cmdAdd(harness.deps, "PROJ_SECRET", "proj-value", {
        project: true,
      });

      const gitignorePath = path.join(projectCwd, ".gitignore");
      const gitignore = await fs.readFile(gitignorePath, "utf8");
      expect(gitignore).toContain(".secretproxy.enc");

      const vaultPath = path.join(projectCwd, ".secretproxy.enc");
      const stat = await fs.stat(vaultPath);
      expect(stat.isFile()).toBe(true);
    } finally {
      await fs.rm(home, { recursive: true, force: true });
      await fs.rm(projectCwd, { recursive: true, force: true });
    }
  });

  it("refuses to touch stdin/TTY when the password is missing", async () => {
    // no env var, no keychain entry, poisoned TTY → expect VAULT_LOCKED.
    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      env: {},
      tty: new PoisonedTTY(),
    });

    await expect(
      cmdAdd(harness.deps, "X", "Y", { project: false }),
    ).rejects.toBeInstanceOf(VaultLockedError);
  });
});
