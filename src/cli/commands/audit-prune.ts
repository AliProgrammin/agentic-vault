// `secretproxy audit prune` — apply the configured body-retention policy.
//
// Defaults: 14 days or 64 MiB total blob bytes, whichever triggers first.
// Flags override either budget for emergency cleanup or a shorter retention
// in test environments.
//
// Pruning is crash-safe: per-id unlink operations are independent, and the
// JSONL audit log is NEVER rewritten by this command. If the process dies
// mid-prune the store is still consistent — the remaining files decrypt
// cleanly and the JSONL still points at whichever subset of blobs survives.

import * as path from "node:path";
import {
  DEFAULT_RETENTION_MAX_AGE_MS,
  DEFAULT_RETENTION_MAX_BYTES,
  EncryptedBodyStore,
  pruneBodies,
} from "../../audit/index.js";
import { CliError, EXIT_USER } from "../errors.js";
import type { CliDeps } from "../types.js";

export interface AuditPruneOptions {
  readonly maxAgeMs?: number;
  readonly maxBytes?: number;
}

const BODY_KEY_INFO = "secretproxy/audit-body-v1";

export async function cmdAuditPrune(
  deps: CliDeps,
  opts: AuditPruneOptions,
): Promise<void> {
  const password = deps.resolvePassword();
  let global = null;
  let project = null;
  try {
    if (await deps.fileExists(deps.globalVaultPath)) {
      global = await deps.unlockVault(deps.globalVaultPath, password);
    }
    const loc = await deps.discoverProjectVault(deps.cwd, deps.homedir);
    if (loc !== null) {
      project = await deps.unlockVault(loc.vaultPath, password);
    }
    const keyHolder = global ?? project;
    if (keyHolder === null) {
      throw new CliError(
        EXIT_USER,
        "no unlocked vault available — run `secretproxy init` first",
      );
    }
    const key = keyHolder.deriveSubkey(BODY_KEY_INFO);
    const store = new EncryptedBodyStore({
      baseDir: path.dirname(deps.auditLogPath),
      key,
    });
    const result = await pruneBodies(store, {
      maxAgeMs: opts.maxAgeMs ?? DEFAULT_RETENTION_MAX_AGE_MS,
      maxBytes: opts.maxBytes ?? DEFAULT_RETENTION_MAX_BYTES,
    });
    deps.stdout(
      `pruned ${String(result.removedByAge.length)} by age, ${String(result.removedBySize.length)} by size (${String(result.bytesBefore)} -> ${String(result.bytesAfter)} bytes)\n`,
    );
  } finally {
    global?.close();
    project?.close();
  }
}
