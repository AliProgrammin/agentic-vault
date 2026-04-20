// Audit body-blob retention.
//
// Two budgets, whichever triggers first:
//   - age: bodies older than `maxAgeMs` are removed.
//   - size: if total blob bytes exceed `maxBytes`, oldest-first blobs are
//     removed until the store is at or under the cap.
//
// Crash safety: pruning is a sequence of independent `unlink` calls on
// per-id files. A process crash in the middle leaves the remaining files
// intact and readable; the JSONL audit log is never touched.
//
// Metadata on the audit JSONL record stays — only the body blob is pruned.
// Renderers already handle the "body was pruned" case as a distinct state.

import type { BlobEntry, EncryptedBodyStore } from "./body-store.js";

export const DEFAULT_RETENTION_MAX_AGE_MS = 14 * 24 * 60 * 60 * 1000;
export const DEFAULT_RETENTION_MAX_BYTES = 64 * 1024 * 1024;

export interface PruneOptions {
  readonly maxAgeMs?: number;
  readonly maxBytes?: number;
  readonly now?: number;
}

export interface PruneResult {
  readonly removedByAge: readonly string[];
  readonly removedBySize: readonly string[];
  readonly bytesBefore: number;
  readonly bytesAfter: number;
}

export async function pruneBodies(
  store: EncryptedBodyStore,
  opts: PruneOptions = {},
): Promise<PruneResult> {
  const maxAgeMs = opts.maxAgeMs ?? DEFAULT_RETENTION_MAX_AGE_MS;
  const maxBytes = opts.maxBytes ?? DEFAULT_RETENTION_MAX_BYTES;
  const now = opts.now ?? Date.now();

  const initial = await store.listBlobs();
  const bytesBefore = initial.reduce((n, b) => n + b.bytes, 0);

  const removedByAge: string[] = [];
  const survivors: BlobEntry[] = [];
  for (const b of initial) {
    if (now - b.mtimeMs > maxAgeMs) {
      await store.deleteBody(b.blobId);
      removedByAge.push(b.blobId);
    } else {
      survivors.push(b);
    }
  }

  const removedBySize: string[] = [];
  let runningBytes = survivors.reduce((n, b) => n + b.bytes, 0);
  if (runningBytes > maxBytes) {
    // Oldest first.
    survivors.sort((a, b) => a.mtimeMs - b.mtimeMs);
    for (const b of survivors) {
      if (runningBytes <= maxBytes) break;
      await store.deleteBody(b.blobId);
      removedBySize.push(b.blobId);
      runningBytes -= b.bytes;
    }
  }

  return {
    removedByAge,
    removedBySize,
    bytesBefore,
    bytesAfter: runningBytes,
  };
}
