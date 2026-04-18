import { policySchema } from "../../policy/index.js";
import { listMerged, type ScopedSecretEntry } from "../../scope/index.js";
import type { VaultHandle } from "../../vault/index.js";
import { CliError, EXIT_USER } from "../errors.js";
import type { CliDeps } from "../types.js";

export type ListScope = "global" | "project" | "all";

export interface ListOptions {
  scope: ListScope;
}

interface Summary {
  hosts: number;
  commands: number;
  env: number;
  rate: string;
}

function summarize(policy: unknown): Summary {
  if (policy === undefined || policy === null) {
    return { hosts: 0, commands: 0, env: 0, rate: "none" };
  }
  const parsed = policySchema.safeParse(policy);
  if (!parsed.success) {
    return { hosts: 0, commands: 0, env: 0, rate: "invalid" };
  }
  const p = parsed.data;
  return {
    hosts: p.allowed_http_hosts.length,
    commands: p.allowed_commands.length,
    env: p.allowed_env_vars.length,
    rate: `${String(p.rate_limit.requests)}/${String(p.rate_limit.window_seconds)}`,
  };
}

function formatEntry(entry: ScopedSecretEntry): string {
  const s = summarize(entry.policy);
  return `${entry.name} [${entry.scope}] — hosts: ${String(s.hosts)} commands: ${String(s.commands)} env: ${String(s.env)} rate: ${s.rate}`;
}

export async function cmdList(
  deps: CliDeps,
  opts: ListOptions,
): Promise<void> {
  const password = deps.resolvePassword();
  let global: VaultHandle | null = null;
  let project: VaultHandle | null = null;
  try {
    if (opts.scope === "global" || opts.scope === "all") {
      if (await deps.fileExists(deps.globalVaultPath)) {
        global = await deps.unlockVault(deps.globalVaultPath, password);
      }
    }
    if (opts.scope === "project" || opts.scope === "all") {
      const loc = await deps.discoverProjectVault(deps.cwd, deps.homedir);
      if (loc !== null) {
        project = await deps.unlockVault(loc.vaultPath, password);
      } else if (opts.scope === "project") {
        throw new CliError(
          EXIT_USER,
          "no project vault found in this directory or any parent.",
        );
      }
    }

    const entries = listMerged({ global, project });
    if (entries.length === 0) {
      deps.stdout("(no secrets)\n");
      return;
    }
    for (const entry of entries) {
      deps.stdout(`${formatEntry(entry)}\n`);
    }
  } finally {
    global?.close();
    project?.close();
  }
}
