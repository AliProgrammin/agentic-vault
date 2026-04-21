import { promises as fs } from "node:fs";
import { ZodError } from "zod";
import { validatePolicy } from "../../policy/index.js";
import { CliError, EXIT_USER } from "../errors.js";
import { buildPolicyFromFlags } from "../policy-builder.js";
import type { CliDeps } from "../types.js";
import { formatZodError, stableStringify } from "../util.js";
import { openGlobalVault, openProjectVault } from "./helpers.js";

export interface PolicyShowOptions {
  project: boolean;
}

export interface PolicySetOptions {
  project: boolean;
  fromFile?: string;
  host: readonly string[];
  command: readonly string[];
  env: readonly string[];
  rate?: string;
}

export async function cmdPolicyShow(
  deps: CliDeps,
  key: string,
  opts: PolicyShowOptions,
): Promise<void> {
  const password = deps.resolvePassword();
  const handle = opts.project
    ? await openProjectVault(deps, password)
    : await openGlobalVault(deps, password);
  try {
    const record = handle.getRecord(key);
    if (record === undefined) {
      throw new CliError(EXIT_USER, `secret not found: ${key}`);
    }
    const policy = record.policy ?? null;
    deps.stdout(`${stableStringify(policy)}\n`);
  } finally {
    handle.close();
  }
}

function convenienceFlagsProvided(opts: PolicySetOptions): boolean {
  return (
    opts.host.length > 0 ||
    opts.command.length > 0 ||
    opts.env.length > 0 ||
    opts.rate !== undefined
  );
}

async function readPolicyFile(path: string): Promise<unknown> {
  let content: string;
  try {
    content = await fs.readFile(path, "utf8");
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      throw new CliError(EXIT_USER, `policy file not found: ${path}`);
    }
    throw err;
  }
  try {
    return JSON.parse(content) as unknown;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new CliError(EXIT_USER, `invalid JSON in ${path}: ${msg}`);
  }
}

export async function cmdPolicySet(
  deps: CliDeps,
  key: string,
  opts: PolicySetOptions,
): Promise<void> {
  const hasFile = opts.fromFile !== undefined;
  const hasFlags = convenienceFlagsProvided(opts);

  if (hasFile && hasFlags) {
    throw new CliError(
      EXIT_USER,
      "--from-file is mutually exclusive with --host, --command, --env, --rate",
    );
  }
  if (!hasFile && !hasFlags) {
    throw new CliError(
      EXIT_USER,
      "policy set requires either --from-file <path> or convenience flags (--host, --command, --env, --rate)",
    );
  }

  const candidate: unknown = hasFile
    ? await readPolicyFile(opts.fromFile as string)
    : buildPolicyFromFlags({
        host: opts.host,
        command: opts.command,
        env: opts.env,
        ...(opts.rate !== undefined ? { rate: opts.rate } : {}),
      });

  const password = deps.resolvePassword();
  const handle = opts.project
    ? await openProjectVault(deps, password)
    : await openGlobalVault(deps, password);
  try {
    const validated = validatePolicy(candidate, {
      strictMode: handle.getStrictMode(),
    });
    if (validated instanceof ZodError) {
      throw new CliError(
        EXIT_USER,
        `policy validation failed:\n${formatZodError(validated)}`,
      );
    }
    const value = handle.get(key);
    if (value === undefined) {
      throw new CliError(EXIT_USER, `secret not found: ${key}`);
    }
    handle.set(key, value, validated);
    await handle.save();
  } finally {
    handle.close();
  }
  deps.stdout(
    `policy updated for ${key} (scope: ${opts.project ? "project" : "global"})\n`,
  );
}
