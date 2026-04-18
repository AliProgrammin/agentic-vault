import { CliError, EXIT_USER } from "../errors.js";
import type { CliDeps } from "../types.js";
import { openGlobalVault, openProjectVault } from "./helpers.js";

export interface RemoveOptions {
  project: boolean;
}

export async function cmdRemove(
  deps: CliDeps,
  key: string,
  opts: RemoveOptions,
): Promise<void> {
  const password = deps.resolvePassword();
  const handle = opts.project
    ? await openProjectVault(deps, password)
    : await openGlobalVault(deps, password);
  try {
    const removed = handle.remove(key);
    if (!removed) {
      throw new CliError(EXIT_USER, `secret not found: ${key}`);
    }
    await handle.save();
  } finally {
    handle.close();
  }
  deps.stdout(
    `removed ${key} (scope: ${opts.project ? "project" : "global"})\n`,
  );
}
