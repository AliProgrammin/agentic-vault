import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createVault, type KdfParams, type VaultHandle } from "../vault/index.js";
import { listMerged, resolveSecret } from "./merge.js";
import { ensureProjectVault } from "./ensure.js";
import { VAULT_FILENAME } from "./discover.js";

const FAST_KDF: KdfParams = { memory: 1024, iterations: 2, parallelism: 1 };

async function mkTmpDir(prefix: string): Promise<string> {
  return fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), prefix)));
}

async function rmTmp(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

describe("scope merge", () => {
  let root: string;
  const handles: VaultHandle[] = [];

  beforeEach(async () => {
    root = await mkTmpDir("scope-merge-");
  });

  afterEach(async () => {
    for (const h of handles) {
      if (!h.isClosed()) {
        h.close();
      }
    }
    handles.length = 0;
    await rmTmp(root);
  });

  async function mkVault(name: string): Promise<VaultHandle> {
    const file = path.join(root, name);
    const v = await createVault(file, "pw-correct-horse", { kdfParams: FAST_KDF });
    handles.push(v);
    return v;
  }

  it("resolveSecret returns project value when key exists in both scopes", async () => {
    const global = await mkVault("global.enc");
    const project = await mkVault("project.enc");
    global.set("API_KEY", "GLOBAL_VAL", { host: "global.example.com" });
    project.set("API_KEY", "PROJECT_VAL", { host: "project.example.com" });

    const resolved = resolveSecret("API_KEY", { global, project });
    expect(resolved?.value).toBe("PROJECT_VAL");
    expect(resolved?.scope).toBe("project");
    expect(resolved?.policy).toEqual({ host: "project.example.com" });
  });

  it("resolveSecret falls back to global when only global has the key", async () => {
    const global = await mkVault("global.enc");
    const project = await mkVault("project.enc");
    global.set("ONLY_GLOBAL", "G");
    project.set("SOMETHING_ELSE", "P");

    const resolved = resolveSecret("ONLY_GLOBAL", { global, project });
    expect(resolved?.value).toBe("G");
    expect(resolved?.scope).toBe("global");
  });

  it("resolveSecret returns undefined when neither scope has the key", async () => {
    const global = await mkVault("global.enc");
    const project = await mkVault("project.enc");
    global.set("A", "a");
    project.set("B", "b");

    expect(resolveSecret("C", { global, project })).toBeUndefined();
  });

  it("resolveSecret works when only global is provided", async () => {
    const global = await mkVault("global.enc");
    global.set("ONLY", "g");
    const resolved = resolveSecret("ONLY", { global });
    expect(resolved?.value).toBe("g");
    expect(resolved?.scope).toBe("global");
  });

  it("resolveSecret works when only project is provided", async () => {
    const project = await mkVault("project.enc");
    project.set("ONLY", "p");
    const resolved = resolveSecret("ONLY", { project });
    expect(resolved?.value).toBe("p");
    expect(resolved?.scope).toBe("project");
  });

  it("listMerged labels each entry with its scope and project wins on collision", async () => {
    const global = await mkVault("global.enc");
    const project = await mkVault("project.enc");
    global.set("ONLY_G", "g");
    global.set("BOTH", "GLOBAL", { rate: 1 });
    project.set("ONLY_P", "p");
    project.set("BOTH", "PROJECT", { rate: 2 });

    const merged = listMerged({ global, project });
    const byName = new Map(merged.map((e) => [e.name, e]));
    expect(byName.get("ONLY_G")?.scope).toBe("global");
    expect(byName.get("ONLY_P")?.scope).toBe("project");
    expect(byName.get("BOTH")?.scope).toBe("project");
    expect(byName.get("BOTH")?.policy).toEqual({ rate: 2 });
    expect(merged.length).toBe(3);
  });

  it("listMerged is safe when only one scope exists", async () => {
    const global = await mkVault("global.enc");
    global.set("A", "a");
    const merged = listMerged({ global });
    expect(merged.length).toBe(1);
    expect(merged[0]?.scope).toBe("global");
  });

  it("listMerged is safe when neither scope is provided", () => {
    expect(listMerged({})).toEqual([]);
  });

  it("ensureProjectVault creates the vault file and .gitignore on first call", async () => {
    const projectRoot = path.join(root, "proj");
    await fs.mkdir(projectRoot, { recursive: true });

    const result = await ensureProjectVault(projectRoot, "pw-correct-horse", {
      kdfParams: FAST_KDF,
    });
    handles.push(result.handle);

    expect(result.created).toBe(true);
    expect(result.gitignore.action).toBe("created");
    expect(result.vaultPath).toBe(path.join(projectRoot, VAULT_FILENAME));

    const gi = await fs.readFile(path.join(projectRoot, ".gitignore"), "utf8");
    expect(gi).toContain(VAULT_FILENAME);

    const vaultStat = await fs.stat(result.vaultPath);
    expect(vaultStat.isFile()).toBe(true);
  });

  it("ensureProjectVault unlocks an existing vault and leaves .gitignore untouched if already covering", async () => {
    const projectRoot = path.join(root, "proj2");
    await fs.mkdir(projectRoot, { recursive: true });
    await fs.writeFile(
      path.join(projectRoot, ".gitignore"),
      `node_modules\n${VAULT_FILENAME}\n`,
    );

    const first = await ensureProjectVault(projectRoot, "pw-correct-horse", {
      kdfParams: FAST_KDF,
    });
    first.handle.set("A", "a");
    await first.handle.save();
    first.handle.close();

    const second = await ensureProjectVault(projectRoot, "pw-correct-horse", {
      kdfParams: FAST_KDF,
    });
    handles.push(second.handle);
    expect(second.created).toBe(false);
    expect(second.gitignore.action).toBe("unchanged");
    expect(second.handle.get("A")).toBe("a");
  });
});
