import { CliError, EXIT_USER } from "../errors.js";
import type { CliDeps } from "../types.js";

export interface AuditOptions {
  tail?: number;
}

const DEFAULT_TAIL = 50;

export async function cmdAudit(
  deps: CliDeps,
  opts: AuditOptions,
): Promise<void> {
  const tail = opts.tail ?? DEFAULT_TAIL;
  if (!Number.isFinite(tail) || !Number.isInteger(tail) || tail <= 0) {
    throw new CliError(EXIT_USER, "--tail must be a positive integer");
  }
  const contents = await deps.readAuditLog();
  if (contents === null) {
    return;
  }
  const lines = contents.split(/\r?\n/).filter((line) => line.length > 0);
  const taken = lines.slice(-tail);
  for (const line of taken) {
    deps.stdout(`${line}\n`);
  }
}
