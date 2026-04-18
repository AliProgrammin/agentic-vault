import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { atomicWriteFile } from "./atomic.js";

async function mkTmpDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "vault-atomic-"));
}

describe("atomicWriteFile", () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkTmpDir();
  });

  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("writes the requested bytes to the destination", async () => {
    const dest = path.join(dir, "vault.enc");
    await atomicWriteFile(dest, Buffer.from("hello-world"));
    const read = await fs.readFile(dest, "utf8");
    expect(read).toBe("hello-world");
  });

  it("leaves the original file untouched if rename throws (simulated crash)", async () => {
    const dest = path.join(dir, "vault.enc");
    await fs.writeFile(dest, "ORIGINAL");

    const renameSpy = vi.spyOn(fs, "rename").mockImplementationOnce(() => {
      throw new Error("simulated crash between temp write and rename");
    });
    try {
      await expect(atomicWriteFile(dest, Buffer.from("NEWDATA"))).rejects.toThrow(
        /simulated crash/,
      );
    } finally {
      renameSpy.mockRestore();
    }

    const stillThere = await fs.readFile(dest, "utf8");
    expect(stillThere).toBe("ORIGINAL");

    const entries = await fs.readdir(dir);
    const tempFiles = entries.filter((e) => e !== "vault.enc");
    expect(tempFiles).toEqual([]);
  });

  it("writes with restrictive mode (posix)", async () => {
    if (process.platform === "win32") {
      return;
    }
    const dest = path.join(dir, "vault.enc");
    await atomicWriteFile(dest, Buffer.from("x"));
    const st = await fs.stat(dest);
    expect(st.mode & 0o077).toBe(0);
  });
});
