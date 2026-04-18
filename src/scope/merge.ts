import type { VaultHandle } from "../vault/index.js";

export type SecretScope = "global" | "project";

export interface ResolvedSecret {
  name: string;
  value: string;
  scope: SecretScope;
  policy?: unknown;
}

export interface ScopedSecretEntry {
  name: string;
  scope: SecretScope;
  created_at: string;
  updated_at: string;
  policy?: unknown;
}

export interface MergeSources {
  global?: VaultHandle | null | undefined;
  project?: VaultHandle | null | undefined;
}

export function resolveSecret(
  name: string,
  sources: MergeSources,
): ResolvedSecret | undefined {
  const { global, project } = sources;
  if (project) {
    const rec = project.getRecord(name);
    if (rec !== undefined) {
      const value = project.get(name);
      if (value !== undefined) {
        const resolved: ResolvedSecret = { name, value, scope: "project" };
        if (rec.policy !== undefined) {
          resolved.policy = rec.policy;
        }
        return resolved;
      }
    }
  }
  if (global) {
    const rec = global.getRecord(name);
    if (rec !== undefined) {
      const value = global.get(name);
      if (value !== undefined) {
        const resolved: ResolvedSecret = { name, value, scope: "global" };
        if (rec.policy !== undefined) {
          resolved.policy = rec.policy;
        }
        return resolved;
      }
    }
  }
  return undefined;
}

export function listMerged(sources: MergeSources): ScopedSecretEntry[] {
  const merged = new Map<string, ScopedSecretEntry>();
  const { global, project } = sources;

  if (global) {
    for (const rec of global.list()) {
      const entry: ScopedSecretEntry = {
        name: rec.name,
        scope: "global",
        created_at: rec.created_at,
        updated_at: rec.updated_at,
      };
      if (rec.policy !== undefined) {
        entry.policy = rec.policy;
      }
      merged.set(rec.name, entry);
    }
  }

  if (project) {
    for (const rec of project.list()) {
      const entry: ScopedSecretEntry = {
        name: rec.name,
        scope: "project",
        created_at: rec.created_at,
        updated_at: rec.updated_at,
      };
      if (rec.policy !== undefined) {
        entry.policy = rec.policy;
      }
      merged.set(rec.name, entry);
    }
  }

  return Array.from(merged.values()).sort((a, b) => a.name.localeCompare(b.name));
}
