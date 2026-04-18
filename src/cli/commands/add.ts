import type { CliDeps } from "../types.js";
import { openGlobalVault } from "./helpers.js";

export interface AddOptions {
  project: boolean;
}

export async function cmdAdd(
  deps: CliDeps,
  key: string,
  value: string,
  opts: AddOptions,
): Promise<void> {
  const password = deps.resolvePassword();

  if (opts.project) {
    const result = await deps.ensureProjectVault(deps.cwd, password);
    try {
      result.handle.set(key, value);
      await result.handle.save();
    } finally {
      result.handle.close();
    }
    deps.stdout(`added ${key} (scope: project, vault: ${result.vaultPath})\n`);
    if (result.gitignore.action === "created") {
      deps.stdout(`created ${result.gitignore.path}\n`);
    } else if (result.gitignore.action === "appended") {
      deps.stdout(`appended vault entry to ${result.gitignore.path}\n`);
    }
    return;
  }

  const handle = await openGlobalVault(deps, password);
  try {
    handle.set(key, value);
    await handle.save();
  } finally {
    handle.close();
  }
  deps.stdout(`added ${key} (scope: global)\n`);
}
