import { promises as fs } from "node:fs";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { makeTestDeps, makeTmpDir } from "../test-helpers.js";
import { cmdAudit } from "./audit.js";

describe("cmdAudit", () => {
  let tmp: string;
  beforeEach(async () => {
    tmp = await makeTmpDir();
  });
  afterEach(async () => {
    await fs.rm(tmp, { recursive: true, force: true });
  });

  it("prints nothing when the audit log is missing", async () => {
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, env: {} });
    await cmdAudit(harness.deps, { tail: 10 });
    expect(harness.stdout.text()).toBe("");
  });

  it("prints at most the requested number of trailing lines", async () => {
    const harness = makeTestDeps({ cwd: tmp, homedir: tmp, env: {} });
    const auditDir = path.dirname(harness.deps.auditLogPath);
    await fs.mkdir(auditDir, { recursive: true });
    const lines = Array.from({ length: 25 }, (_, i) => `{"i":${String(i)}}`);
    await fs.writeFile(harness.deps.auditLogPath, `${lines.join("\n")}\n`);

    await cmdAudit(harness.deps, { tail: 10 });
    const out = harness.stdout.text().split("\n").filter((l) => l.length > 0);
    expect(out).toHaveLength(10);
    expect(out[0]).toBe(`{"i":15}`);
    expect(out[9]).toBe(`{"i":24}`);
  });
});
