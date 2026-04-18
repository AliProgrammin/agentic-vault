import type { VaultHandle } from "../../vault/index.js";
import type { CliDeps } from "../types.js";

export async function cmdRun(deps: CliDeps): Promise<void> {
  const password = deps.resolvePassword();
  let global: VaultHandle | null = null;
  let project: VaultHandle | null = null;
  try {
    if (await deps.fileExists(deps.globalVaultPath)) {
      global = await deps.unlockVault(deps.globalVaultPath, password);
    }
    const loc = await deps.discoverProjectVault(deps.cwd, deps.homedir);
    if (loc !== null) {
      project = await deps.unlockVault(loc.vaultPath, password);
    }
    const server = deps.createMcpServer({ sources: { global, project } });
    await deps.connectStdio(server);
  } catch (err) {
    global?.close();
    project?.close();
    throw err;
  }
}
