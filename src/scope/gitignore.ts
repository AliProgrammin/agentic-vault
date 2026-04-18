import { promises as fs } from "node:fs";
import * as path from "node:path";
import { VAULT_FILENAME } from "./discover.js";

const GITIGNORE = ".gitignore";

function globToRegExp(pattern: string): RegExp {
  let re = "";
  for (const ch of pattern) {
    if (ch === "*") {
      re += "[^/]*";
    } else if (ch === "?") {
      re += "[^/]";
    } else if (/[.+^${}()|[\]\\]/.test(ch)) {
      re += `\\${ch}`;
    } else {
      re += ch;
    }
  }
  return new RegExp(`^${re}$`);
}

function lineIgnoresVault(rawLine: string): boolean {
  const line = rawLine.trim();
  if (line === "" || line.startsWith("#") || line.startsWith("!")) {
    return false;
  }
  let pattern = line;
  if (pattern.startsWith("/")) {
    pattern = pattern.slice(1);
  }
  if (pattern.endsWith("/")) {
    return false;
  }
  if (pattern === VAULT_FILENAME) {
    return true;
  }
  if (pattern.includes("*") || pattern.includes("?")) {
    try {
      return globToRegExp(pattern).test(VAULT_FILENAME);
    } catch {
      return false;
    }
  }
  return false;
}

export function gitignoreAlreadyCovers(contents: string): boolean {
  const lines = contents.split(/\r?\n/);
  for (const line of lines) {
    if (lineIgnoresVault(line)) {
      return true;
    }
  }
  return false;
}

export interface GitignoreResult {
  path: string;
  action: "created" | "appended" | "unchanged";
}

export async function ensureProjectGitignore(
  projectRoot: string,
): Promise<GitignoreResult> {
  const gitignorePath = path.join(projectRoot, GITIGNORE);
  let existing: string | null;
  try {
    existing = await fs.readFile(gitignorePath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      existing = null;
    } else {
      throw err;
    }
  }

  if (existing === null) {
    await fs.writeFile(gitignorePath, `${VAULT_FILENAME}\n`, { encoding: "utf8" });
    return { path: gitignorePath, action: "created" };
  }

  if (gitignoreAlreadyCovers(existing)) {
    return { path: gitignorePath, action: "unchanged" };
  }

  const needsLeadingNewline = existing.length > 0 && !existing.endsWith("\n");
  const prefix = needsLeadingNewline ? "\n" : "";
  const appended = `${existing}${prefix}${VAULT_FILENAME}\n`;
  await fs.writeFile(gitignorePath, appended, { encoding: "utf8" });
  return { path: gitignorePath, action: "appended" };
}
