import { promises as fs } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { makeTmpDir, makeTestDeps, ScriptedTTY } from "../test-helpers.js";
import { cmdInit } from "./init.js";

describe("cmdInit", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await makeTmpDir();
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("creates the global vault and stashes the password in the keychain", async () => {
    const tty = new ScriptedTTY({ isTTY: false, stdin: "correct-horse-battery" });
    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      env: {},
      tty,
    });

    await cmdInit(harness.deps);

    const vaultPath = path.join(tmp, ".secretproxy.enc");
    const stat = await fs.stat(vaultPath);
    expect(stat.isFile()).toBe(true);
    expect(harness.backend.get("secretproxy", "master")).toBe(
      "correct-horse-battery",
    );
  });

  it("uses the SECRETPROXY_INIT_PASSWORD env var if set (no TTY/stdin touched)", async () => {
    const tty = new ScriptedTTY({ isTTY: true, prompts: [] });
    const harness = makeTestDeps({
      cwd: tmp,
      homedir: tmp,
      env: { SECRETPROXY_INIT_PASSWORD: "env-password-value" },
      tty,
    });

    await cmdInit(harness.deps);

    expect(harness.backend.get("secretproxy", "master")).toBe(
      "env-password-value",
    );
    expect(tty.prompts).toEqual([]);
  });

  it("confirms an existing vault's password instead of recreating it", async () => {
    const ttyA = new ScriptedTTY({ isTTY: false, stdin: "first-password-12" });
    const harnessA = makeTestDeps({ cwd: tmp, homedir: tmp, env: {}, tty: ttyA });
    await cmdInit(harnessA.deps);

    const ttyB = new ScriptedTTY({ isTTY: false, stdin: "first-password-12" });
    const harnessB = makeTestDeps({ cwd: tmp, homedir: tmp, env: {}, tty: ttyB });
    await cmdInit(harnessB.deps);

    expect(harnessB.backend.get("secretproxy", "master")).toBe(
      "first-password-12",
    );
  });
});
