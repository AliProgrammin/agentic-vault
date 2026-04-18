import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export const VAULT_FILENAME = ".secretproxy.enc";

export interface ProjectVaultLocation {
  vaultPath: string;
  projectRoot: string;
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    const stat = await fs.stat(filePath);
    return stat.isFile();
  } catch {
    return false;
  }
}

export function getGlobalVaultPath(homeDir?: string): string {
  const home = homeDir ?? os.homedir();
  return path.join(home, VAULT_FILENAME);
}

export async function discoverProjectVault(
  cwd: string,
  homeDir?: string,
): Promise<ProjectVaultLocation | null> {
  const home = path.resolve(homeDir ?? os.homedir());
  let dir = path.resolve(cwd);

  while (true) {
    if (dir === home) {
      return null;
    }

    const candidate = path.join(dir, VAULT_FILENAME);
    if (await fileExists(candidate)) {
      return { vaultPath: candidate, projectRoot: dir };
    }

    const parent = path.dirname(dir);
    if (parent === dir) {
      return null;
    }
    dir = parent;
  }
}
