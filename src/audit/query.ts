// Audit JSONL reader + filter for F13 `audit list` / `audit show`.
//
// The JSONL store is append-only plaintext metadata; this module parses each
// line defensively (skip malformed), applies the CLI's filter predicates,
// and returns typed records. It does NOT touch the encrypted body store.

import { promises as fs } from "node:fs";
import type { AuditEvent, AuditOutcome, AuditSurface } from "./types.js";

export interface AuditFilter {
  readonly surface?: AuditSurface;
  readonly secret?: string;
  readonly status?: AuditOutcome;
  readonly code?: string;
  readonly sinceMs?: number;
  readonly untilMs?: number;
  readonly limit?: number;
}

export async function readAuditEntries(
  logPath: string,
): Promise<readonly AuditEvent[]> {
  let raw: string;
  try {
    raw = await fs.readFile(logPath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return [];
    }
    throw err;
  }
  return parseAuditJsonl(raw);
}

export function parseAuditJsonl(raw: string): readonly AuditEvent[] {
  const out: AuditEvent[] = [];
  for (const line of raw.split(/\r?\n/)) {
    if (line.length === 0) continue;
    try {
      const parsed = JSON.parse(line) as AuditEvent;
      if (parsed !== null && typeof parsed === "object" && typeof parsed.ts === "string") {
        out.push(parsed);
      }
    } catch {
      // skip malformed line
    }
  }
  return out;
}

export function filterAuditEntries(
  entries: readonly AuditEvent[],
  filter: AuditFilter,
): readonly AuditEvent[] {
  let out = entries.filter((ev) => matches(ev, filter));
  if (filter.limit !== undefined && filter.limit > 0) {
    out = out.slice(-filter.limit);
  }
  return out;
}

function matches(ev: AuditEvent, f: AuditFilter): boolean {
  if (f.surface !== undefined && ev.surface !== f.surface) return false;
  if (f.secret !== undefined && ev.secret_name !== f.secret) return false;
  if (f.status !== undefined && ev.outcome !== f.status) return false;
  if (f.code !== undefined && ev.code !== f.code) return false;
  if (f.sinceMs !== undefined || f.untilMs !== undefined) {
    const t = Date.parse(ev.ts);
    if (Number.isNaN(t)) return false;
    if (f.sinceMs !== undefined && t < f.sinceMs) return false;
    if (f.untilMs !== undefined && t > f.untilMs) return false;
  }
  return true;
}

export function findEntryById(
  entries: readonly AuditEvent[],
  id: string,
): AuditEvent | undefined {
  return entries.find((ev) => ev.request_id === id);
}
