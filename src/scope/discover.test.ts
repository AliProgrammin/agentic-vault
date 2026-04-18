import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  VAULT_FILENAME,
  discoverProjectVault,
  getGlobalVaultPath,
} from "./discover.js";

async function mkTmpDir(prefix: string): Promise<string> {
  return fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), prefix)));
}

async function rmTmp(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

describe("scope discovery", () => {
  let root: string;

  beforeEach(async () => {
    root = await mkTmpDir("scope-discover-");
  });

  afterEach(async () => {
    await rmTmp(root);
  });

  it("getGlobalVaultPath joins homeDir with the vault filename", () => {
    expect(getGlobalVaultPath("/some/home")).toBe(
      path.join("/some/home", VAULT_FILENAME),
    );
  });

  it("finds a project vault in the current directory", async () => {
    const home = path.join(root, "home");
    const projectRoot = path.join(home, "project");
    await fs.mkdir(projectRoot, { recursive: true });
    const vaultPath = path.join(projectRoot, VAULT_FILENAME);
    await fs.writeFile(vaultPath, "x");

    const loc = await discoverProjectVault(projectRoot, home);
    expect(loc).not.toBeNull();
    expect(loc?.vaultPath).toBe(vaultPath);
    expect(loc?.projectRoot).toBe(projectRoot);
  });

  it("walks up across nested directories", async () => {
    const home = path.join(root, "home");
    const projectRoot = path.join(home, "proj");
    const deep = path.join(projectRoot, "a", "b", "c");
    await fs.mkdir(deep, { recursive: true });
    const vaultPath = path.join(projectRoot, VAULT_FILENAME);
    await fs.writeFile(vaultPath, "x");

    const loc = await discoverProjectVault(deep, home);
    expect(loc?.vaultPath).toBe(vaultPath);
    expect(loc?.projectRoot).toBe(projectRoot);
  });

  it("stops at $HOME exclusive so ~/.secretproxy.enc is NOT discovered", async () => {
    const home = path.join(root, "home");
    const deep = path.join(home, "a", "b");
    await fs.mkdir(deep, { recursive: true });
    // Place a vault file at HOME itself. It must NOT be returned.
    await fs.writeFile(path.join(home, VAULT_FILENAME), "x");

    const loc = await discoverProjectVault(deep, home);
    expect(loc).toBeNull();
  });

  it("returns null when cwd is $HOME itself", async () => {
    const home = path.join(root, "home");
    await fs.mkdir(home, { recursive: true });
    await fs.writeFile(path.join(home, VAULT_FILENAME), "x");

    const loc = await discoverProjectVault(home, home);
    expect(loc).toBeNull();
  });

  it("returns null for deep-under-home cwd with no project vault on the path", async () => {
    const home = path.join(root, "home");
    const deep = path.join(home, "a", "b", "c", "d");
    await fs.mkdir(deep, { recursive: true });

    const loc = await discoverProjectVault(deep, home);
    expect(loc).toBeNull();
  });

  it("walks to filesystem root when cwd is outside home", async () => {
    // cwd is outside home entirely. The walk should terminate at filesystem root (null if nothing found).
    const home = path.join(root, "home");
    const outside = path.join(root, "var", "tmp", "proj");
    await fs.mkdir(outside, { recursive: true });
    await fs.mkdir(home, { recursive: true });

    const loc = await discoverProjectVault(outside, home);
    expect(loc).toBeNull();
  });

  it("finds a vault on an outside-home ancestor path", async () => {
    const home = path.join(root, "home");
    const projectRoot = path.join(root, "var", "proj");
    const deep = path.join(projectRoot, "x", "y");
    await fs.mkdir(deep, { recursive: true });
    await fs.mkdir(home, { recursive: true });
    const vaultPath = path.join(projectRoot, VAULT_FILENAME);
    await fs.writeFile(vaultPath, "x");

    const loc = await discoverProjectVault(deep, home);
    expect(loc?.vaultPath).toBe(vaultPath);
    expect(loc?.projectRoot).toBe(projectRoot);
  });

  it("picks the nearest project vault when multiple exist on the path", async () => {
    const home = path.join(root, "home");
    const outer = path.join(home, "outer");
    const inner = path.join(outer, "inner");
    const cwd = path.join(inner, "deep");
    await fs.mkdir(cwd, { recursive: true });
    await fs.writeFile(path.join(outer, VAULT_FILENAME), "x");
    const innerVault = path.join(inner, VAULT_FILENAME);
    await fs.writeFile(innerVault, "x");

    const loc = await discoverProjectVault(cwd, home);
    expect(loc?.vaultPath).toBe(innerVault);
    expect(loc?.projectRoot).toBe(inner);
  });
});
