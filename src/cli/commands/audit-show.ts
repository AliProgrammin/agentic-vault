// `secretproxy audit show <id>` — render one audit entry.
//
// Reads the JSONL via `deps.readAuditLog`, finds the matching request_id,
// and (if the unlocked vault is available) decrypts the corresponding body
// blob via `EncryptedBodyStore`. Emits a sectioned, TTY-aware view through
// the shared rendering model so CLI and UI cannot drift.
//
// When `--json` is passed, the full AuditEvent is emitted verbatim as JSON;
// consumers that want machine-readable output (scripts, jq pipelines) use
// this flag rather than parsing the formatted block.

import * as path from "node:path";
import {
  EncryptedBodyStore,
  BodyStoreError,
  buildRenderModel,
  findEntryById,
  formatAuditDetail,
  readAuditEntries,
  type BodyBlobPayload,
  type BuildRenderOptions,
} from "../../audit/index.js";
import { listMerged, resolveSecret } from "../../scope/index.js";
import type { ScrubbableSecret } from "../../scrub/index.js";
import type { VaultHandle } from "../../vault/index.js";
import { CliError, EXIT_USER } from "../errors.js";
import type { CliDeps } from "../types.js";

export interface AuditShowOptions {
  readonly id: string;
  readonly json?: boolean;
}

const BODY_KEY_INFO = "secretproxy/audit-body-v1";

export async function cmdAuditShow(
  deps: CliDeps,
  opts: AuditShowOptions,
): Promise<void> {
  if (opts.id.length === 0) {
    throw new CliError(EXIT_USER, "audit show requires a non-empty id");
  }
  const entries = await readAuditEntries(deps.auditLogPath);
  const event = findEntryById(entries, opts.id);
  if (event === undefined) {
    throw new CliError(EXIT_USER, `no audit entry with id '${opts.id}'`);
  }
  if (opts.json === true) {
    deps.stdout(`${JSON.stringify(event, null, 2)}\n`);
    return;
  }

  // Unlock the vault (routine ops — never prompt) so we can decrypt the
  // body blob. If unlock fails, the render path still emits metadata.
  const buildOpts: BuildRenderOptions = {};
  let global: VaultHandle | null = null;
  let project: VaultHandle | null = null;
  try {
    const password = deps.resolvePassword();
    if (await deps.fileExists(deps.globalVaultPath)) {
      global = await deps.unlockVault(deps.globalVaultPath, password);
    }
    const loc = await deps.discoverProjectVault(deps.cwd, deps.homedir);
    if (loc !== null) {
      project = await deps.unlockVault(loc.vaultPath, password);
    }
    const inScope = collectInScopeSecrets(global, project);
    if (inScope.length > 0) {
      (buildOpts as { inScopeSecrets: readonly ScrubbableSecret[] }).inScopeSecrets = inScope;
    }

    const keyHolder = global ?? project;
    const bodyRef = event.body_ref;
    if (keyHolder !== null && bodyRef !== undefined) {
      const key = keyHolder.deriveSubkey(BODY_KEY_INFO);
      const bodyStore = new EncryptedBodyStore({
        baseDir: path.dirname(deps.auditLogPath),
        key,
      });
      try {
        if (await bodyStore.hasBody(bodyRef.blob_id)) {
          const payload: BodyBlobPayload = await bodyStore.readBody(bodyRef.blob_id);
          (buildOpts as { bodies?: BodyBlobPayload }).bodies = payload;
        } else {
          (buildOpts as { pruned?: boolean }).pruned = true;
        }
      } catch (err) {
        if (err instanceof BodyStoreError) {
          (buildOpts as { bodiesError?: BodyStoreError }).bodiesError = err;
        } else {
          throw err;
        }
      }
    }
    const model = buildRenderModel(event, buildOpts);
    const tty = process.stdout.isTTY === true;
    deps.stdout(`${formatAuditDetail(model, { tty })}\n`);
  } finally {
    global?.close();
    project?.close();
  }
}

function collectInScopeSecrets(
  global: VaultHandle | null,
  project: VaultHandle | null,
): readonly ScrubbableSecret[] {
  const sources = { global, project };
  const out: ScrubbableSecret[] = [];
  for (const entry of listMerged(sources)) {
    const r = resolveSecret(entry.name, sources);
    if (r !== undefined) {
      out.push({ name: r.name, value: r.value });
    }
  }
  return out;
}
