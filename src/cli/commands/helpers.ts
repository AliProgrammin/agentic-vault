import type { VaultHandle } from "../../vault/index.js";
import { CliError, EXIT_USER } from "../errors.js";
import type { CliDeps } from "../types.js";

export async function openGlobalVault(
  deps: CliDeps,
  password: string,
): Promise<VaultHandle> {
  const exists = await deps.fileExists(deps.globalVaultPath);
  if (!exists) {
    throw new CliError(
      EXIT_USER,
      "global vault does not exist. Run `secretproxy init` first.",
    );
  }
  return deps.unlockVault(deps.globalVaultPath, password);
}

export async function openProjectVault(
  deps: CliDeps,
  password: string,
): Promise<VaultHandle> {
  const loc = await deps.discoverProjectVault(deps.cwd, deps.homedir);
  if (loc === null) {
    throw new CliError(
      EXIT_USER,
      "no project vault found in this directory or any parent.",
    );
  }
  return deps.unlockVault(loc.vaultPath, password);
}
