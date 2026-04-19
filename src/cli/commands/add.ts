import { lookupDefaultPolicy } from "../../policy/index.js";
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
  const defaultPolicy = lookupDefaultPolicy(key);

  if (opts.project) {
    const result = await deps.ensureProjectVault(deps.cwd, password);
    try {
      result.handle.set(key, value, defaultPolicy ?? undefined);
      await result.handle.save();
    } finally {
      result.handle.close();
    }
    deps.stdout(`added ${key} (scope: project, vault: ${result.vaultPath})\n`);
    if (defaultPolicy !== null) {
      deps.stdout(
        `applied default policy: hosts=${String(defaultPolicy.allowed_http_hosts.length)} commands=${String(defaultPolicy.allowed_commands.length)}\n`,
      );
    } else {
      deps.stdout(
        `no default policy for ${key}; deny-by-default. Run \`secretproxy policy set ${key} --from-file policy.json\` to enable use.\n`,
      );
    }
    if (result.gitignore.action === "created") {
      deps.stdout(`created ${result.gitignore.path}\n`);
    } else if (result.gitignore.action === "appended") {
      deps.stdout(`appended vault entry to ${result.gitignore.path}\n`);
    }
    return;
  }

  const handle = await openGlobalVault(deps, password);
  try {
    handle.set(key, value, defaultPolicy ?? undefined);
    await handle.save();
  } finally {
    handle.close();
  }
  deps.stdout(`added ${key} (scope: global)\n`);
  if (defaultPolicy !== null) {
    deps.stdout(
      `applied default policy: hosts=${String(defaultPolicy.allowed_http_hosts.length)} commands=${String(defaultPolicy.allowed_commands.length)}\n`,
    );
  } else {
    deps.stdout(
      `no default policy for ${key}; deny-by-default. Run \`secretproxy policy set ${key} --from-file policy.json\` to enable use.\n`,
    );
  }
}
