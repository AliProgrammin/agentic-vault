import { resolveInitPassword } from "../../keychain/index.js";
import type { CliDeps } from "../types.js";

export async function cmdInit(deps: CliDeps): Promise<void> {
  const password = await resolveInitPassword({ env: deps.env, tty: deps.tty });

  const exists = await deps.fileExists(deps.globalVaultPath);
  if (exists) {
    const handle = await deps.unlockVault(deps.globalVaultPath, password);
    handle.close();
  } else {
    const handle = await deps.createVault(deps.globalVaultPath, password);
    handle.close();
  }

  deps.passwordStore.storeMasterPassword(password);
  deps.stdout(
    exists
      ? `vault password confirmed and stashed in keychain (${deps.globalVaultPath})\n`
      : `global vault initialized at ${deps.globalVaultPath}\n`,
  );
}
