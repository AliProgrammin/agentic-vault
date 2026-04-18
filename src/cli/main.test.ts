import { promises as fs } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { makeTestDeps, makeTmpDir } from "./test-helpers.js";
import { runCli } from "./main.js";

describe("runCli", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await makeTmpDir();
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("--help works without a vault or password and exits 0", async () => {
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, env: {} });
    const code = await runCli(["--help"], harness.deps);
    expect(code).toBe(0);
  });

  it("--version works without a vault or password and exits 0", async () => {
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, env: {} });
    const code = await runCli(["--version"], harness.deps);
    expect(code).toBe(0);
  });
});
