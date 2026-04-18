import { Command, CommanderError } from "commander";
import {
  PasswordMismatchError,
  VaultLockedError,
  WeakPasswordError,
} from "../keychain/index.js";
import { VaultError, WrongPasswordError } from "../vault/index.js";
import { cmdAdd } from "./commands/add.js";
import { cmdAudit } from "./commands/audit.js";
import { cmdInit } from "./commands/init.js";
import { type ListScope, cmdList } from "./commands/list.js";
import { cmdPolicySet, cmdPolicyShow } from "./commands/policy.js";
import { cmdRemove } from "./commands/remove.js";
import { cmdRotate } from "./commands/rotate.js";
import { cmdRun } from "./commands/run.js";
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

  program
    .command("audit")
    .option("--tail <n>", "number of trailing lines to print", parsePositiveInt)
    .description("Print the raw JSONL tail of the audit log.")
    .action(async (options: { tail?: number }) => {
      await cmdAudit(deps, options.tail !== undefined ? { tail: options.tail } : {});
    });

  program
    .command("run")
    .description("Start the SecretProxy MCP server over stdio.")
    .action(async () => {
      await cmdRun(deps);
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
