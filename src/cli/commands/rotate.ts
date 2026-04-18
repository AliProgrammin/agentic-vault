import { CliError, EXIT_USER } from "../errors.js";
import type { CliDeps } from "../types.js";
import { openGlobalVault, openProjectVault } from "./helpers.js";

export interface RotateOptions {
  project: boolean;
}

export async function cmdRotate(
  deps: CliDeps,
  key: string,
  value: string,
  opts: RotateOptions,
): Promise<void> {
  const password = deps.resolvePassword();
  const handle = opts.project
    ? await openProjectVault(deps, password)
    : await openGlobalVault(deps, password);
  try {
    const record = handle.getRecord(key);
    if (record === undefined) {
      throw new CliError(EXIT_USER, `secret not found: ${key}`);
    }
    // Omit the policy argument so VaultHandle.set preserves the prior policy.
    handle.set(key, value);
    await handle.save();
  } finally {
    handle.close();
  }
  deps.stdout(
    `rotated ${key} (scope: ${opts.project ? "project" : "global"})\n`,
  );
}
