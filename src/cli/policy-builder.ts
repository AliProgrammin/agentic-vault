import type { Policy } from "../policy/index.js";
import { CliError, EXIT_USER } from "./errors.js";

export interface ConvenienceFlags {
  host: readonly string[];
  command: readonly string[];
  env: readonly string[];
  rate?: string;
}

function parseRate(rate: string): Policy["rate_limit"] {
  const match = /^(\d+)\/(\d+)$/.exec(rate);
  if (!match) {
    throw new CliError(
      EXIT_USER,
      `invalid --rate format: expected <requests>/<seconds>, got '${rate}'`,
    );
  }
  const requests = Number(match[1]);
  const windowSeconds = Number(match[2]);
  if (!Number.isFinite(requests) || !Number.isFinite(windowSeconds)) {
    throw new CliError(EXIT_USER, `invalid --rate numbers: '${rate}'`);
  }
  return { requests, window_seconds: windowSeconds };
}

function parseCommandFlag(raw: string): { binary: string; pattern: string } {
  const idx = raw.indexOf(":");
  if (idx < 0) {
    throw new CliError(
      EXIT_USER,
      `invalid --command format: expected binary:regex, got '${raw}'`,
    );
  }
  const binary = raw.slice(0, idx);
  const pattern = raw.slice(idx + 1);
  if (binary.length === 0 || pattern.length === 0) {
    throw new CliError(
      EXIT_USER,
      `invalid --command format: both binary and regex required in '${raw}'`,
    );
  }
  return { binary, pattern };
}

// Convenience flags → full policy object. Never merges; always produces a
// complete policy shape. Multiple `--command` entries with the same binary
// are merged into a single allowed_commands entry whose patterns are the
// union of their regexes.
export function buildPolicyFromFlags(flags: ConvenienceFlags): unknown {
  if (flags.rate === undefined) {
    throw new CliError(
      EXIT_USER,
      "policy set via convenience flags requires --rate <requests>/<seconds>",
    );
  }

  const commandsByBinary = new Map<string, string[]>();
  for (const raw of flags.command) {
    const { binary, pattern } = parseCommandFlag(raw);
    const existing = commandsByBinary.get(binary);
    if (existing === undefined) {
      commandsByBinary.set(binary, [pattern]);
    } else {
      existing.push(pattern);
    }
  }

  const allowedCommands = Array.from(commandsByBinary.entries()).map(
    ([binary, patterns]) => ({
      binary,
      allowed_args_patterns: patterns,
    }),
  );

  return {
    allowed_http_hosts: [...flags.host],
    allowed_commands: allowedCommands,
    allowed_env_vars: [...flags.env],
    rate_limit: parseRate(flags.rate),
  };
}
