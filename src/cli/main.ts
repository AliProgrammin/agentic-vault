import { Command, CommanderError } from "commander";
import {
  PasswordMismatchError,
  VaultLockedError,
  WeakPasswordError,
} from "../keychain/index.js";
import { VaultError, WrongPasswordError } from "../vault/index.js";
import { cmdAdd } from "./commands/add.js";
import { cmdAudit } from "./commands/audit.js";
import { cmdAuditList } from "./commands/audit-list.js";
import { cmdAuditPrune } from "./commands/audit-prune.js";
import { cmdAuditShow } from "./commands/audit-show.js";
import { cmdInit } from "./commands/init.js";
import { type ListScope, cmdList } from "./commands/list.js";
import { cmdPolicySet, cmdPolicyShow } from "./commands/policy.js";
import { cmdRemove } from "./commands/remove.js";
import { cmdRotate } from "./commands/rotate.js";
import { cmdRun } from "./commands/run.js";
import { cmdUi } from "./commands/ui.js";
import {
  CliError,
  EXIT_AUTH,
  EXIT_INTERNAL,
  EXIT_OK,
  EXIT_USER,
} from "./errors.js";
import type { CliDeps } from "./types.js";

export const CLI_NAME = "secretproxy";
export const CLI_VERSION = "0.0.1";

function collect(value: string, previous: readonly string[]): string[] {
  return [...previous, value];
}

function parsePositiveInt(raw: string): number {
  if (!/^\d+$/.test(raw)) {
    throw new CommanderError(
      EXIT_USER,
      "commander.invalidArgument",
      `expected a positive integer, got '${raw}'`,
    );
  }
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n <= 0) {
    throw new CommanderError(
      EXIT_USER,
      "commander.invalidArgument",
      `expected a positive integer, got '${raw}'`,
    );
  }
  return n;
}

function parseListScope(raw: string): ListScope {
  if (raw === "global" || raw === "project" || raw === "all") {
    return raw;
  }
  throw new CommanderError(
    EXIT_USER,
    "commander.invalidArgument",
    `--scope must be one of: global, project, all (got '${raw}')`,
  );
}

export function buildProgram(deps: CliDeps): Command {
  const program = new Command();
  program
    .name(CLI_NAME)
    .description(
      "SecretProxy — inject secrets into HTTP calls and subprocesses without exposing values to the agent.",
    )
    .version(CLI_VERSION)
    .option("--debug", "print stack traces on unexpected errors", false);

  program
    .command("init")
    .description(
      "Create the global vault (if missing), stash the master password in the OS keychain.",
    )
    .action(async () => {
      await cmdInit(deps);
    });

  program
    .command("add")
    .argument("<key>", "secret name")
    .argument("<value>", "secret value")
    .option("--project", "add to the project-local vault", false)
    .description("Add a secret to the global (default) or project vault.")
    .action(async (key: string, value: string, options: { project: boolean }) => {
      await cmdAdd(deps, key, value, { project: options.project });
    });

  program
    .command("remove")
    .argument("<key>", "secret name")
    .option("--project", "remove from the project-local vault", false)
    .description("Remove a secret from the specified scope.")
    .action(async (key: string, options: { project: boolean }) => {
      await cmdRemove(deps, key, { project: options.project });
    });

  program
    .command("list")
    .option("--scope <scope>", "global | project | all", parseListScope, "all")
    .description("List secret names and scopes. Values are never printed.")
    .action(async (options: { scope: ListScope }) => {
      await cmdList(deps, { scope: options.scope });
    });

  program
    .command("rotate")
    .argument("<key>", "secret name")
    .argument("<value>", "new secret value")
    .option("--project", "rotate in the project-local vault", false)
    .description("Update a secret's value while preserving its policy.")
    .action(async (key: string, value: string, options: { project: boolean }) => {
      await cmdRotate(deps, key, value, { project: options.project });
    });

  const policy = program
    .command("policy")
    .description("Inspect or replace per-secret policies.");

  policy
    .command("show")
    .argument("<key>", "secret name")
    .option("--project", "show the project-scope policy", false)
    .description("Print the secret's current policy as JSON.")
    .action(async (key: string, options: { project: boolean }) => {
      await cmdPolicyShow(deps, key, { project: options.project });
    });

  policy
    .command("set")
    .argument("<key>", "secret name")
    .option("--project", "set policy in the project-local vault", false)
    .option(
      "--from-file <path>",
      "read the full policy as JSON from the given file (mutually exclusive with convenience flags)",
    )
    .option("--host <fqdn>", "add an allowed HTTP host (repeatable)", collect, [])
    .option(
      "--command <binary:regex>",
      "add an allowed command with an anchored arg regex (repeatable)",
      collect,
      [],
    )
    .option(
      "--env <NAME>",
      "add an allowed env var name (repeatable)",
      collect,
      [],
    )
    .option(
      "--rate <requests>/<seconds>",
      "set the rate limit (required when using convenience flags)",
    )
    .description(
      "Replace a secret's policy. Full replacement — not a merge. Use --from-file for the authoritative path.",
    )
    .action(
      async (
        key: string,
        options: {
          project: boolean;
          fromFile?: string;
          host: string[];
          command: string[];
          env: string[];
          rate?: string;
        },
      ) => {
        await cmdPolicySet(deps, key, {
          project: options.project,
          ...(options.fromFile !== undefined ? { fromFile: options.fromFile } : {}),
          host: options.host,
          command: options.command,
          env: options.env,
          ...(options.rate !== undefined ? { rate: options.rate } : {}),
        });
      },
    );

  const audit = program
    .command("audit")
    .option("--tail <n>", "number of trailing lines to print", parsePositiveInt)
    .description(
      "Print the raw JSONL tail of the audit log. Use the subcommands for filtered listing, per-entry detail, and retention pruning.",
    )
    .action(async (options: { tail?: number }) => {
      await cmdAudit(deps, options.tail !== undefined ? { tail: options.tail } : {});
    });

  audit
    .command("show")
    .argument("<id>", "request id of the audit entry")
    .option("--json", "emit the full AuditEvent as JSON", false)
    .description(
      "Render one audit entry in full (sectioned terminal view, or --json for scripting).",
    )
    .action(async (id: string, options: { json: boolean }) => {
      await cmdAuditShow(deps, { id, json: options.json });
    });

  audit
    .command("list")
    .option("--surface <name>", "filter by surface (cli|mcp_http_request|mcp_run_command)")
    .option("--secret <name>", "filter by secret name")
    .option("--status <s>", "filter by outcome (allowed|denied)")
    .option("--code <code>", "filter by typed error code (e.g. POLICY_DENIED)")
    .option("--since <ts>", "only entries at or after this ISO-8601 timestamp")
    .option("--until <ts>", "only entries at or before this ISO-8601 timestamp")
    .option("--limit <n>", "cap the number of returned entries", (v): number => parsePositiveInt(v))
    .description("Filtered list of audit entries (one per line).")
    .action(
      async (options: {
        surface?: string;
        secret?: string;
        status?: string;
        code?: string;
        since?: string;
        until?: string;
        limit?: number;
      }) => {
        const listOpts: Parameters<typeof cmdAuditList>[1] = {};
        if (options.surface !== undefined) (listOpts as { surface: string }).surface = options.surface;
        if (options.secret !== undefined) (listOpts as { secret: string }).secret = options.secret;
        if (options.status !== undefined) (listOpts as { status: string }).status = options.status;
        if (options.code !== undefined) (listOpts as { code: string }).code = options.code;
        if (options.since !== undefined) (listOpts as { since: string }).since = options.since;
        if (options.until !== undefined) (listOpts as { until: string }).until = options.until;
        if (options.limit !== undefined) (listOpts as { limit: number }).limit = options.limit;
        await cmdAuditList(deps, listOpts);
      },
    );

  audit
    .command("prune")
    .option(
      "--max-age-ms <ms>",
      "retention age cap in milliseconds (default: 14 days)",
      (v): number => parsePositiveInt(v),
    )
    .option(
      "--max-bytes <bytes>",
      "retention size cap in bytes (default: 64 MiB)",
      (v): number => parsePositiveInt(v),
    )
    .description("Prune encrypted body blobs older than the retention window or beyond the size cap.")
    .action(async (options: { maxAgeMs?: number; maxBytes?: number }) => {
      const pruneOpts: Parameters<typeof cmdAuditPrune>[1] = {};
      if (options.maxAgeMs !== undefined) (pruneOpts as { maxAgeMs: number }).maxAgeMs = options.maxAgeMs;
      if (options.maxBytes !== undefined) (pruneOpts as { maxBytes: number }).maxBytes = options.maxBytes;
      await cmdAuditPrune(deps, pruneOpts);
    });

  program
    .command("run")
    .description("Start the SecretProxy MCP server over stdio.")
    .action(async () => {
      await cmdRun(deps);
    });

  program
    .command("ui")
    .description("Start the SecretProxy local web UI on 127.0.0.1.")
    .option(
      "--port <port>",
      "port to bind (default: 7381)",
      (v): number => parsePositiveInt(v),
    )
    .option("--no-open", "do not launch a browser automatically")
    .action(async (options: { port?: number; open?: boolean }) => {
      const uiOpts: Parameters<typeof cmdUi>[1] = {
        noOpen: options.open === false,
      };
      if (options.port !== undefined) uiOpts.port = options.port;
      await cmdUi(deps, uiOpts);
    });

  return program;
}

export function mapErrorToExitCode(err: unknown, deps: CliDeps): number {
  if (err instanceof CliError) {
    deps.stderr(`error: ${err.message}\n`);
    return err.exitCode;
  }
  if (err instanceof VaultLockedError) {
    deps.stderr(`error: VAULT_LOCKED: ${err.message}\n`);
    return EXIT_AUTH;
  }
  if (err instanceof WrongPasswordError) {
    deps.stderr(`error: ${err.message}\n`);
    return EXIT_AUTH;
  }
  if (err instanceof WeakPasswordError || err instanceof PasswordMismatchError) {
    deps.stderr(`error: ${err.message}\n`);
    return EXIT_USER;
  }
  if (err instanceof VaultError) {
    deps.stderr(`error: ${err.code}: ${err.message}\n`);
    return EXIT_INTERNAL;
  }
  const msg = err instanceof Error ? err.message : String(err);
  deps.stderr(`error: ${msg}\n`);
  if (deps.debug && err instanceof Error && err.stack !== undefined) {
    deps.stderr(`${err.stack}\n`);
  }
  return EXIT_INTERNAL;
}

export async function runCli(
  argv: readonly string[],
  deps: CliDeps,
): Promise<number> {
  const program = buildProgram(deps);
  program.exitOverride();
  try {
    await program.parseAsync([...argv], { from: "user" });
    return EXIT_OK;
  } catch (err) {
    if (err instanceof CommanderError) {
      if (
        err.code === "commander.helpDisplayed" ||
        err.code === "commander.version" ||
        err.code === "commander.help"
      ) {
        return EXIT_OK;
      }
      deps.stderr(`${err.message}\n`);
      return EXIT_USER;
    }
    return mapErrorToExitCode(err, deps);
  }
}
