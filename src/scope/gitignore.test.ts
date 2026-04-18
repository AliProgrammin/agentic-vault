import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  ensureProjectGitignore,
  gitignoreAlreadyCovers,
} from "./gitignore.js";
import { VAULT_FILENAME } from "./discover.js";

async function mkTmpDir(prefix: string): Promise<string> {
  return fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), prefix)));
}

async function rmTmp(dir: string): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
}

describe("scope gitignore hygiene", () => {
  let root: string;

  beforeEach(async () => {
    root = await mkTmpDir("scope-gi-");
  });

  afterEach(async () => {
    await rmTmp(root);
  });

  it("creates a new .gitignore when none exists", async () => {
    const res = await ensureProjectGitignore(root);
    expect(res.action).toBe("created");
    const contents = await fs.readFile(path.join(root, ".gitignore"), "utf8");
    expect(contents).toBe(`${VAULT_FILENAME}\n`);
  });

  it("leaves an existing exact ignore untouched", async () => {
    const original = `node_modules\n${VAULT_FILENAME}\ndist\n`;
    await fs.writeFile(path.join(root, ".gitignore"), original);
    const res = await ensureProjectGitignore(root);
    expect(res.action).toBe("unchanged");
    const contents = await fs.readFile(path.join(root, ".gitignore"), "utf8");
    expect(contents).toBe(original);
  });

  it("leaves an existing glob-covering pattern untouched", async () => {
    const original = `*.secretproxy.enc\n`;
    await fs.writeFile(path.join(root, ".gitignore"), original);
    const res = await ensureProjectGitignore(root);
    expect(res.action).toBe("unchanged");
    const contents = await fs.readFile(path.join(root, ".gitignore"), "utf8");
    expect(contents).toBe(original);
  });

  it("appends the vault filename to a non-matching .gitignore preserving existing lines", async () => {
    const original = "node_modules\ndist\n";
    await fs.writeFile(path.join(root, ".gitignore"), original);
    const res = await ensureProjectGitignore(root);
    expect(res.action).toBe("appended");
    const contents = await fs.readFile(path.join(root, ".gitignore"), "utf8");
    expect(contents).toBe(`node_modules\ndist\n${VAULT_FILENAME}\n`);
  });

  it("appends with a leading newline when file is missing trailing newline", async () => {
    const original = "node_modules";
    await fs.writeFile(path.join(root, ".gitignore"), original);
    const res = await ensureProjectGitignore(root);
    expect(res.action).toBe("appended");
    const contents = await fs.readFile(path.join(root, ".gitignore"), "utf8");
    expect(contents).toBe(`node_modules\n${VAULT_FILENAME}\n`);
  });

  it("treats a leading-slash exact path as a match", () => {
    expect(gitignoreAlreadyCovers(`/${VAULT_FILENAME}\n`)).toBe(true);
  });

  it("does not treat a comment that mentions the filename as a match", () => {
    expect(gitignoreAlreadyCovers(`# don't forget ${VAULT_FILENAME}\n`)).toBe(
      false,
    );
  });

  it("does not treat a negation line as a match", () => {
    expect(gitignoreAlreadyCovers(`!${VAULT_FILENAME}\n`)).toBe(false);
  });

  it("does not treat a directory-only pattern as a match", () => {
    expect(gitignoreAlreadyCovers(`secrets/\n`)).toBe(false);
  });

  it("treats a broad glob as a match", () => {
    expect(gitignoreAlreadyCovers("*.enc\n")).toBe(true);
  });

  it("ignores an unrelated glob", () => {
    expect(gitignoreAlreadyCovers("*.log\n")).toBe(false);
  });
});
