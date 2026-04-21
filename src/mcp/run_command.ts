// SecretProxy MCP `run_command` tool.
//
// Spawns a subprocess with `child_process.spawn(..., { shell: false })`,
// injecting named secrets into specified environment variables at spawn
// time. Secret values NEVER appear in argv.
//
// MINIMAL ENV PASSTHROUGH: the child process receives ONLY the 8 keys in
// `PASSTHROUGH_ENV_KEYS` that are set on the parent (any that are not set
// are omitted), plus the injected values. No other parent env var leaks
// through to the subprocess. This prevents accidental bleed-through of
// credential-like env vars the user may have set on the host (AWS_*,
// GOOGLE_APPLICATION_CREDENTIALS, etc.) into a subprocess launched on an
// agent's behalf. The real anti-exfiltration boundary lives in the policy
// layer (F4); this allowlist is defense-in-depth.
//
// Output caps: stdout and stderr are each capped at 10 MB, enforced
// independently. Excess bytes are dropped and the returned payload sets
// `stdout_truncated` / `stderr_truncated`. Captured bytes (truncated or
// not) are scrubbed via F6 against every secret in scope before return.
//
// Timeout: 60 seconds per call. On POSIX the child is spawned detached so
// that its whole process group can be killed on timeout.

import { spawn as nodeSpawn } from "node:child_process";
import type { SpawnOptions } from "node:child_process";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { listMerged, resolveSecret } from "../scope/index.js";
import {
  checkCommand,
  checkEnvInjection,
  policySchema,
  FORBIDDEN_ENV_VAR_NAMES,
  type Policy,
  type WildcardMatch,
} from "../policy/index.js";
import { scrub, type ScrubbableSecret } from "../scrub/index.js";
import {
  createRequestId,
  AUDIT_DETAIL_CAP_BYTES,
  DEFAULT_RESPONSE_BODY_CAP_BYTES,
  classifyText,
  type AuditCommandRequest,
  type AuditCommandResponse,
  type AuditErrorCode,
  type AuditEvent,
  type AuditEventDetail,
  type AuditInjectedSecret,
  type AuditLogger,
  type AuditPolicyDecision,
  type AuditProcessContext,
  type AuditRateLimitState,
  type AuditTiming,
  type BodyBlobPayload,
  type EncryptedBodyStore,
} from "../audit/index.js";
import type { RateLimiter } from "../ratelimit/index.js";
import type { McpServerDeps } from "./server.js";

export const PASSTHROUGH_ENV_KEYS = [
  "PATH",
  "HOME",
  "USER",
  "LANG",
  "TZ",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "NO_PROXY",
] as const satisfies readonly string[];

const FORBIDDEN_SET: ReadonlySet<string> = new Set(FORBIDDEN_ENV_VAR_NAMES);
const ENV_NAME_PATTERN = /^[A-Z_][A-Z0-9_]*$/;

export const MAX_OUTPUT_BYTES = 10 * 1024 * 1024;
export const DEFAULT_TIMEOUT_MS = 60_000;
const TOOL_NAME = "run_command";

interface ChildStream {
  on(event: "data", listener: (chunk: Buffer | string) => void): unknown;
}

export interface SpawnedChild {
  readonly stdout: ChildStream | null;
  readonly stderr: ChildStream | null;
  readonly pid?: number | undefined;
  kill(signal?: NodeJS.Signals | number): boolean;
  on(
    event: "close",
    listener: (code: number | null, signal: NodeJS.Signals | null) => void,
  ): unknown;
  on(event: "error", listener: (err: Error) => void): unknown;
}

export type RunCommandSpawn = (
  command: string,
  args: readonly string[],
  options: SpawnOptions,
) => SpawnedChild;

const DEFAULT_SPAWN: RunCommandSpawn = (command, args, options) => {
  const child = nodeSpawn(command, [...args], options);
  return child as unknown as SpawnedChild;
};

export interface RunCommandDeps extends McpServerDeps {
  readonly audit: AuditLogger;
  readonly rateLimiter: RateLimiter;
  readonly spawn?: RunCommandSpawn;
  readonly timeoutMs?: number;
  readonly clock?: () => number;
  readonly parentEnv?: NodeJS.ProcessEnv;
  /** Encrypted body-blob store for F13 audit detail view. Optional. */
  readonly bodyStore?: EncryptedBodyStore;
  /** Injected in tests for deterministic process-context. */
  readonly processContextProvider?: () => AuditProcessContext;
}

export const RUN_COMMAND_INPUT_SHAPE = {
  command: z.string().min(1, { message: "command must not be empty" }),
  args: z.array(z.string()),
  cwd: z.string().optional(),
  inject_env: z.record(z.string()),
};

export const runCommandInputSchema = z.object(RUN_COMMAND_INPUT_SHAPE).strict();
export type RunCommandInput = z.infer<typeof runCommandInputSchema>;

export type RunCommandErrorCode =
  | "POLICY_DENIED"
  | "RATE_LIMITED"
  | "SECRET_NOT_FOUND"
  | "TIMEOUT"
  | "INVALID_INJECTION";

export type RunCommandOutcome =
  | {
      ok: true;
      exit_code: number;
      stdout: string;
      stderr: string;
      stdout_truncated?: boolean;
      stderr_truncated?: boolean;
    }
  | {
      ok: false;
      code: RunCommandErrorCode;
      reason: string;
    };

function nowIso(clock: () => number): string {
  return new Date(clock()).toISOString();
}

function coercePolicy(raw: unknown): Policy | undefined {
  if (raw === undefined || raw === null) return undefined;
  const parsed = policySchema.safeParse(raw);
  return parsed.success ? parsed.data : undefined;
}

function isAbsolutePath(p: string): boolean {
  if (p.length === 0) return false;
  if (p.startsWith("/")) return true;
  return /^[A-Za-z]:[\\/]/.test(p);
}

function truncateAudit(s: string): string {
  if (Buffer.byteLength(s, "utf8") <= AUDIT_DETAIL_CAP_BYTES) return s;
  return Buffer.from(s, "utf8")
    .subarray(0, AUDIT_DETAIL_CAP_BYTES)
    .toString("utf8") + "\u2026";
}

async function recordAudit(
  logger: AuditLogger,
  clock: () => number,
  requestId: string,
  secret_name: string,
  target: string,
  outcome: "allowed" | "denied",
  opts: {
    code?: AuditErrorCode;
    reason?: string;
    detail?: AuditEventDetail;
  } = {},
): Promise<void> {
  const event: AuditEvent = {
    ts: nowIso(clock),
    secret_name,
    tool: TOOL_NAME,
    target,
    outcome,
    request_id: requestId,
    caller_cwd: process.cwd(),
  };
  if (opts.reason !== undefined) event.reason = opts.reason;
  if (opts.code !== undefined) event.code = opts.code;
  if (opts.detail !== undefined) event.detail = opts.detail;
  await logger.record(event);
}

// Layers F13 fields on top of the legacy event. Used on the allowed / size-
// limit audit paths once the command has run to completion.
async function recordAuditExtended(
  logger: AuditLogger,
  clock: () => number,
  requestId: string,
  secret_name: string,
  target: string,
  outcome: "allowed" | "denied",
  opts: {
    code?: AuditErrorCode;
    reason?: string;
    detail?: AuditEventDetail;
  },
  f13: Partial<AuditEvent>,
): Promise<void> {
  const event: AuditEvent = {
    ts: nowIso(clock),
    secret_name,
    tool: TOOL_NAME,
    target,
    outcome,
    request_id: requestId,
    caller_cwd: process.cwd(),
    ...f13,
  };
  if (opts.reason !== undefined) event.reason = opts.reason;
  if (opts.code !== undefined) event.code = opts.code;
  if (opts.detail !== undefined) event.detail = opts.detail;
  await logger.record(event);
}

function buildChildEnv(
  parentEnv: NodeJS.ProcessEnv,
  injections: Record<string, string>,
): NodeJS.ProcessEnv {
  const child: NodeJS.ProcessEnv = {};
  for (const key of PASSTHROUGH_ENV_KEYS) {
    const v = parentEnv[key];
    if (typeof v === "string") {
      child[key] = v;
    }
  }
  for (const [k, v] of Object.entries(injections)) {
    child[k] = v;
  }
  return child;
}

function collectInScopeSecrets(deps: RunCommandDeps): ScrubbableSecret[] {
  const entries = listMerged(deps.sources);
  const out: ScrubbableSecret[] = [];
  for (const e of entries) {
    const resolved = resolveSecret(e.name, deps.sources);
    if (resolved) {
      out.push({ name: resolved.name, value: resolved.value });
    }
  }
  return out;
}

interface Accumulator {
  chunks: Buffer[];
  len: number;
  truncated: boolean;
}

function appendChunk(acc: Accumulator, chunk: Buffer): void {
  const remaining = MAX_OUTPUT_BYTES - acc.len;
  if (remaining <= 0) {
    acc.truncated = true;
    return;
  }
  if (chunk.length > remaining) {
    acc.chunks.push(chunk.subarray(0, remaining));
    acc.len += remaining;
    acc.truncated = true;
  } else {
    acc.chunks.push(chunk);
    acc.len += chunk.length;
  }
}

function toBuffer(chunk: Buffer | string): Buffer {
  return typeof chunk === "string" ? Buffer.from(chunk) : chunk;
}

interface ExitInfo {
  code: number | null;
  timedOut: boolean;
  error?: Error;
}

function killChild(child: SpawnedChild, isWindows: boolean): void {
  try {
    if (!isWindows && typeof child.pid === "number") {
      try {
        process.kill(-child.pid, "SIGTERM");
        return;
      } catch {
        // fall through to direct kill
      }
    }
    child.kill("SIGTERM");
  } catch {
    // ignore
  }
}

export async function runRunCommand(
  input: RunCommandInput,
  deps: RunCommandDeps,
): Promise<RunCommandOutcome> {
  const clock = deps.clock ?? (() => Date.now());
  const parentEnv = deps.parentEnv ?? process.env;
  const timeoutMs = deps.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const spawn = deps.spawn ?? DEFAULT_SPAWN;
  const requestId = createRequestId();
  const receivedAt = nowIso(clock);
  const processContext: AuditProcessContext =
    deps.processContextProvider !== undefined
      ? deps.processContextProvider()
      : { pid: process.pid, cwd: process.cwd(), tool_name: TOOL_NAME };

  const { command, args, cwd, inject_env } = input;

  if (cwd !== undefined) {
    if (!isAbsolutePath(cwd)) {
      const reason = "cwd must be an absolute path";
      await recordAudit(deps.audit, clock, requestId, "", command, "denied", {
        code: "INVALID_INJECTION",
        reason,
      });
      return { ok: false, code: "INVALID_INJECTION", reason };
    }
  }

  const injectEntries = Object.entries(inject_env);

  // Validate inject_env keys BEFORE any policy/spawn work.
  for (const [targetName, secretName] of injectEntries) {
    if (!ENV_NAME_PATTERN.test(targetName)) {
      const reason = `inject_env target '${targetName}' must match ^[A-Z_][A-Z0-9_]*$`;
      await recordAudit(deps.audit, clock, requestId, secretName, targetName, "denied", {
        code: "INVALID_INJECTION",
        reason,
      });
      return { ok: false, code: "INVALID_INJECTION", reason };
    }
    if (FORBIDDEN_SET.has(targetName)) {
      const reason = `inject_env target '${targetName}' is in the forbidden env var list`;
      await recordAudit(deps.audit, clock, requestId, secretName, targetName, "denied", {
        code: "INVALID_INJECTION",
        reason,
      });
      return { ok: false, code: "INVALID_INJECTION", reason };
    }
  }

  // Per-injection policy + rate limit enforcement.
  const injections: Record<string, string> = {};
  const scopeByTarget = new Map<string, "global" | "project">();
  const rateByTarget = new Map<string, AuditRateLimitState>();
  // If either the binary or the env var target was matched via a wildcard
  // entry, record it. Command wildcard wins over env-var wildcard when
  // both are present — command is the coarser-grained, more impactful
  // wildcard so it is the more useful signal to surface to operators.
  const wildcardByTarget = new Map<string, WildcardMatch>();
  for (const [targetName, secretName] of injectEntries) {
    const resolved = resolveSecret(secretName, deps.sources);
    if (!resolved) {
      const reason = `secret '${secretName}' not found in any scope`;
      await recordAudit(deps.audit, clock, requestId, secretName, targetName, "denied", {
        code: "SECRET_NOT_FOUND",
        reason,
      });
      return { ok: false, code: "SECRET_NOT_FOUND", reason };
    }

    const policy = coercePolicy(resolved.policy);

    const cmdDecision = checkCommand(policy, command, args);
    if (!cmdDecision.allowed) {
      await recordAudit(deps.audit, clock, requestId, secretName, command, "denied", {
        code: "POLICY_DENIED",
        reason: cmdDecision.reason,
      });
      return { ok: false, code: "POLICY_DENIED", reason: cmdDecision.reason };
    }
    const cmdWildcard: WildcardMatch | undefined = cmdDecision.wildcard_matched;

    const envDecision = checkEnvInjection(policy, targetName);
    if (!envDecision.allowed) {
      await recordAudit(deps.audit, clock, requestId, secretName, targetName, "denied", {
        code: "POLICY_DENIED",
        reason: envDecision.reason,
      });
      return { ok: false, code: "POLICY_DENIED", reason: envDecision.reason };
    }

    if (!policy) {
      const reason = "no policy attached to secret (deny-by-default)";
      await recordAudit(deps.audit, clock, requestId, secretName, command, "denied", {
        code: "POLICY_DENIED",
        reason,
      });
      return { ok: false, code: "POLICY_DENIED", reason };
    }

    const rate = await deps.rateLimiter.tryConsume(secretName, policy);
    if (!rate.allowed) {
      const reason = `rate limit exceeded for '${secretName}'; retry after ${String(rate.retry_after_seconds)}s`;
      await recordAudit(deps.audit, clock, requestId, secretName, command, "denied", {
        code: "RATE_LIMITED",
        reason,
      });
      return { ok: false, code: "RATE_LIMITED", reason };
    }

    injections[targetName] = resolved.value;
    scopeByTarget.set(targetName, resolved.scope);
    rateByTarget.set(targetName, {
      remaining: Math.max(0, rate.remaining),
      capacity: policy.rate_limit.requests,
      window_seconds: policy.rate_limit.window_seconds,
    });
    const wm = cmdWildcard ?? envDecision.wildcard_matched;
    if (wm !== undefined) {
      wildcardByTarget.set(targetName, wm);
    }
  }

  const policyCheckedAt = nowIso(clock);
  const childEnv = buildChildEnv(parentEnv, injections);
  const isWindows = process.platform === "win32";
  const spawnOpts: SpawnOptions = {
    env: childEnv,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
    detached: !isWindows,
  };
  if (cwd !== undefined) {
    spawnOpts.cwd = cwd;
  }

  const upstreamStartedAt = nowIso(clock);
  const child = spawn(command, args, spawnOpts);

  const stdoutAcc: Accumulator = { chunks: [], len: 0, truncated: false };
  const stderrAcc: Accumulator = { chunks: [], len: 0, truncated: false };

  child.stdout?.on("data", (c: Buffer | string) => {
    appendChunk(stdoutAcc, toBuffer(c));
  });
  child.stderr?.on("data", (c: Buffer | string) => {
    appendChunk(stderrAcc, toBuffer(c));
  });

  const exitInfo = await new Promise<ExitInfo>((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      killChild(child, isWindows);
      resolve({ code: null, timedOut: true });
    }, timeoutMs);
    if (typeof timer.unref === "function") {
      timer.unref();
    }
    child.on("close", (code: number | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, timedOut: false });
    });
    child.on("error", (err: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code: null, timedOut: false, error: err });
    });
  });

  const upstreamFinishedAt = nowIso(clock);
  const secretsInScope = collectInScopeSecrets(deps);
  const rawStdout = Buffer.concat(stdoutAcc.chunks, stdoutAcc.len).toString("utf8");
  const rawStderr = Buffer.concat(stderrAcc.chunks, stderrAcc.len).toString("utf8");
  const stdout = scrub(rawStdout, secretsInScope);
  const stderr = scrub(rawStderr, secretsInScope);

  if (exitInfo.timedOut) {
    const reason = `command '${command}' timed out after ${String(timeoutMs)}ms`;
    for (const [, secretName] of injectEntries) {
      await recordAudit(deps.audit, clock, requestId, secretName, command, "denied", {
        code: "TIMEOUT",
        reason,
      });
    }
    return { ok: false, code: "TIMEOUT", reason };
  }

  const scrubbedArgv = input.args.map((a) => scrub(a, secretsInScope));
  const exitCodeForDetail =
    exitInfo.error !== undefined ? -1 : exitInfo.code === null ? -1 : exitInfo.code;
  const allowedDetail: AuditEventDetail = {
    argv: scrubbedArgv,
    exit_code: exitCodeForDetail,
    stdout: truncateAudit(stdout),
    stderr: truncateAudit(stderr),
  };

  // ── F13 enrichment ───────────────────────────────────────────────────
  const injectedSecretsList: AuditInjectedSecret[] = injectEntries.map(
    ([targetName, secretName]) => ({
      secret_name: secretName,
      scope: scopeByTarget.get(targetName) ?? "global",
      target: targetName,
    }),
  );
  const envKeys = Object.keys(inject_env);
  const commandRequest: AuditCommandRequest = {
    binary: command,
    args: scrubbedArgv,
    env_keys: envKeys,
    ...(cwd !== undefined ? { cwd } : {}),
  };
  const commandResponse: AuditCommandResponse = {
    exit_code: exitCodeForDetail,
    ...(stdoutAcc.truncated ? { stdout_truncated: true } : {}),
    ...(stderrAcc.truncated ? { stderr_truncated: true } : {}),
  };
  const returnedAt = nowIso(clock);
  const timing: AuditTiming = {
    received_at: receivedAt,
    policy_checked_at: policyCheckedAt,
    upstream_started_at: upstreamStartedAt,
    upstream_finished_at: upstreamFinishedAt,
    returned_at: returnedAt,
  };
  const firstRateEntry = injectEntries.find(
    ([t]) => rateByTarget.get(t) !== undefined,
  );
  const firstRate =
    firstRateEntry !== undefined ? rateByTarget.get(firstRateEntry[0]) : undefined;
  const stdoutArtifact = classifyText(stdout, {
    cap: DEFAULT_RESPONSE_BODY_CAP_BYTES,
  });
  const stderrArtifact = classifyText(stderr, {
    cap: DEFAULT_RESPONSE_BODY_CAP_BYTES,
  });
  let blobWritten = false;
  if (deps.bodyStore !== undefined) {
    const payload: BodyBlobPayload = {
      stdout: stdoutArtifact,
      stderr: stderrArtifact,
    };
    try {
      await deps.bodyStore.writeBody(requestId, payload);
      blobWritten = true;
    } catch {
      // keep going — metadata-only audit record is still written
    }
  }
  const policyDecision: AuditPolicyDecision = { outcome: "allowed" };
  const f13Allowed = {
    surface: "mcp_run_command" as const,
    request: commandRequest,
    response: commandResponse,
    injected_secrets: injectedSecretsList,
    policy_decision: policyDecision,
    timing,
    process_context: processContext,
    ...(firstRate !== undefined ? { rate_limit_state: firstRate } : {}),
    ...(blobWritten ? { body_ref: { blob_id: requestId } } : {}),
  };

  for (const [targetName, secretName] of injectEntries) {
    const wm = wildcardByTarget.get(targetName);
    const perRowExtras: Partial<AuditEvent> = {
      ...f13Allowed,
      ...(wm !== undefined
        ? { wildcard_matched: { pattern: wm.pattern, kind: wm.kind } }
        : {}),
    };
    await recordAuditExtended(
      deps.audit,
      clock,
      requestId,
      secretName,
      command,
      "allowed",
      { detail: allowedDetail },
      perRowExtras,
    );
  }

  if (stdoutAcc.truncated || stderrAcc.truncated) {
    const which =
      stdoutAcc.truncated && stderrAcc.truncated
        ? "stdout+stderr"
        : stdoutAcc.truncated
          ? "stdout"
          : "stderr";
    const reason = `${which} truncated at ${String(MAX_OUTPUT_BYTES)} bytes`;
    for (const [targetName, secretName] of injectEntries) {
      const wm = wildcardByTarget.get(targetName);
      const perRowExtras: Partial<AuditEvent> = {
        ...f13Allowed,
        ...(wm !== undefined
          ? { wildcard_matched: { pattern: wm.pattern, kind: wm.kind } }
          : {}),
      };
      await recordAuditExtended(
        deps.audit,
        clock,
        requestId,
        secretName,
        command,
        "denied",
        { code: "SIZE_LIMIT", reason },
        perRowExtras,
      );
    }
  }

  const exitCode =
    exitInfo.error !== undefined ? -1 : exitInfo.code === null ? -1 : exitInfo.code;

  const result: RunCommandOutcome = {
    ok: true,
    exit_code: exitCode,
    stdout,
    stderr:
      exitInfo.error !== undefined
        ? stderr + (stderr.length > 0 ? "\n" : "") + `spawn error: ${exitInfo.error.message}`
        : stderr,
  };
  if (stdoutAcc.truncated) result.stdout_truncated = true;
  if (stderrAcc.truncated) result.stderr_truncated = true;
  return result;
}

export function registerRunCommand(server: McpServer, deps: RunCommandDeps): void {
  server.registerTool(
    "run_command",
    {
      description: `Spawn a subprocess (shell: false) with args passed as an array. Named secrets from the vault are injected into the specified environment variables at spawn time — their values never appear in argv. Policy (binary allowlist, arg pattern allowlist/denylist, env var target allowlist) and rate limits are enforced per injected secret. stdout and stderr are captured, capped at 10 MB each, scrubbed against all in-scope secrets, and returned.

USAGE EXAMPLE:
  command: "curl"
  args: ["-s", "https://api.example.com/endpoint"]
  inject_env: { "API_KEY": "MY_SECRET_NAME" }

This puts the secret value into the env var API_KEY for the subprocess. The secret value NEVER appears in args. inject_env maps env-var-name → vault-secret-name.`,
      inputSchema: RUN_COMMAND_INPUT_SHAPE,
    },
    async (rawArgs) => {
      const outcome = await runRunCommand(rawArgs as RunCommandInput, deps);
      return {
        content: [{ type: "text", text: JSON.stringify(outcome) }],
      };
    },
  );
}

// Used by tests (and the evaluator) to assert exact passthrough key count.
export const PASSTHROUGH_ENV_KEY_COUNT = PASSTHROUGH_ENV_KEYS.length;
