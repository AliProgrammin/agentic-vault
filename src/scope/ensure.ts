import { promises as fs } from "node:fs";
import * as path from "node:path";
import {
  createVault,
  unlockVault,
  type CreateVaultOptions,
  type VaultHandle,
} from "../vault/index.js";
import { VAULT_FILENAME } from "./discover.js";
import { ensureProjectGitignore, type GitignoreResult } from "./gitignore.js";

export interface EnsureProjectVaultResult {
  handle: VaultHandle;
  vaultPath: string;
  created: boolean;
  gitignore: GitignoreResult;
}

async function vaultFileExists(filePath: string): Promise<boolean> {
  try {
    const stat = await fs.stat(filePath);
    return stat.isFile();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw err;
  }
}

export async function ensureProjectVault(
  projectRoot: string,
  password: string,
  options: CreateVaultOptions = {},
): Promise<EnsureProjectVaultResult> {
  const vaultPath = path.join(projectRoot, VAULT_FILENAME);
  const exists = await vaultFileExists(vaultPath);

  let handle: VaultHandle;
  let created: boolean;
  if (exists) {
    handle = await unlockVault(vaultPath, password);
    created = false;
  } else {
    handle = await createVault(vaultPath, password, options);
    created = true;
  }

  const gitignore = await ensureProjectGitignore(projectRoot);
  return { handle, vaultPath, created, gitignore };
}
