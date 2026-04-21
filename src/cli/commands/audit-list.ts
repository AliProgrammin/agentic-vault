// `secretproxy audit list` — filtered view of audit entries.
//
// Reads the JSONL log and applies the caller's filters before emitting a
// short one-line-per-entry summary. Designed to be pipe-safe (no ANSI) so
// scripts can `grep`, `awk`, `jq` against the output without fuss.
//
// The existing `secretproxy audit --tail N` command is untouched — it
// continues to stream raw JSONL. `audit list` is the filter-friendly
// alternative.

import {
  AUDIT_ERROR_CODES,
  AUDIT_SURFACES,
  filterAuditEntries,
  readAuditEntries,
  type AuditErrorCode,
  type AuditFilter,
  type AuditOutcome,
  type AuditSurface,
} from "../../audit/index.js";
import { wildcardBadgeCompact } from "../../policy/index.js";
import { CliError, EXIT_USER } from "../errors.js";
import type { CliDeps } from "../types.js";

export interface AuditListOptions {
  readonly surface?: string;
  readonly secret?: string;
  readonly status?: string;
  readonly code?: string;
  readonly since?: string;
  readonly until?: string;
  readonly limit?: number;
}

function parseTs(flag: string, raw: string): number {
  const t = Date.parse(raw);
  if (Number.isNaN(t)) {
    throw new CliError(EXIT_USER, `${flag} expects an ISO-8601 timestamp, got '${raw}'`);
  }
  return t;
}

function parseSurface(raw: string): AuditSurface {
  for (const s of AUDIT_SURFACES) {
    if (s === raw) return s;
  }
  throw new CliError(
    EXIT_USER,
    `--surface must be one of: ${AUDIT_SURFACES.join(", ")} (got '${raw}')`,
  );
}

function parseStatus(raw: string): AuditOutcome {
  if (raw === "allowed" || raw === "denied") return raw;
  throw new CliError(EXIT_USER, `--status must be allowed|denied (got '${raw}')`);
}

function parseCode(raw: string): AuditErrorCode {
  for (const c of AUDIT_ERROR_CODES) {
    if (c === raw) return c;
  }
  throw new CliError(
    EXIT_USER,
    `--code must be one of: ${AUDIT_ERROR_CODES.join(", ")} (got '${raw}')`,
  );
}

export async function cmdAuditList(
  deps: CliDeps,
  opts: AuditListOptions,
): Promise<void> {
  const filter: AuditFilter = {};
  if (opts.surface !== undefined) (filter as { surface: AuditSurface }).surface = parseSurface(opts.surface);
  if (opts.secret !== undefined) (filter as { secret: string }).secret = opts.secret;
  if (opts.status !== undefined) (filter as { status: AuditOutcome }).status = parseStatus(opts.status);
  if (opts.code !== undefined) (filter as { code: AuditErrorCode }).code = parseCode(opts.code);
  if (opts.since !== undefined) (filter as { sinceMs: number }).sinceMs = parseTs("--since", opts.since);
  if (opts.until !== undefined) (filter as { untilMs: number }).untilMs = parseTs("--until", opts.until);
  if (opts.limit !== undefined) {
    if (!Number.isSafeInteger(opts.limit) || opts.limit <= 0) {
      throw new CliError(EXIT_USER, "--limit must be a positive integer");
    }
    (filter as { limit: number }).limit = opts.limit;
  }

  const all = await readAuditEntries(deps.auditLogPath);
  const matched = filterAuditEntries(all, filter);
  if (matched.length === 0) {
    return;
  }
  for (const ev of matched) {
    const surface = ev.surface ?? "-";
    const outcome = ev.outcome;
    const code = ev.code ?? "-";
    const badge =
      ev.wildcard_matched !== undefined
        ? `${wildcardBadgeCompact(ev.wildcard_matched.kind, { tty: false })} `
        : "";
    deps.stdout(
      `${badge}${ev.ts}  ${ev.request_id}  ${surface}  ${outcome}  ${code}  ${ev.secret_name}  ${ev.target}\n`,
    );
  }
}
