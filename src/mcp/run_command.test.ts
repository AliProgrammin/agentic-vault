import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { SpawnOptions } from "node:child_process";
import { createVault, type KdfParams, type VaultHandle } from "../vault/index.js";
import type { Policy } from "../policy/index.js";
import { InMemoryAuditLogger } from "../audit/index.js";
import { RateLimiter } from "../ratelimit/index.js";
import {
  registerRunCommand,
  runRunCommand,
  PASSTHROUGH_ENV_KEYS,
  PASSTHROUGH_ENV_KEY_COUNT,
  MAX_OUTPUT_BYTES,
  type RunCommandDeps,
  type RunCommandInput,
  type RunCommandSpawn,
  type SpawnedChild,
} from "./run_command.js";
import { createMcpServer } from "./server.js";

const FAST_KDF: KdfParams = { memory: 1024, iterations: 2, parallelism: 1 };

async function mkTmpDir(prefix: string): Promise<string> {
  return fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), prefix)));
}

class FakeChild extends EventEmitter {
  public readonly stdout = new EventEmitter();
  public readonly stderr = new EventEmitter();
  public pid: number | undefined = undefined;
  public readonly killSignals: Array<NodeJS.Signals | number | undefined> = [];
  kill(signal?: NodeJS.Signals | number): boolean {
    this.killSignals.push(signal);
    return true;
  }
}

interface SpawnCall {
  command: string;
  args: string[];
  options: SpawnOptions;
  child: FakeChild;
}

function createFakeSpawn(
  configure: (child: FakeChild) => void = () => {},
): { spawnFn: RunCommandSpawn; calls: SpawnCall[] } {
  const calls: SpawnCall[] = [];
  const spawnFn: RunCommandSpawn = (command, args, options) => {
    const child = new FakeChild();
    calls.push({ command, args: [...args], options, child });
    setImmediate(() => configure(child));
    return child as unknown as SpawnedChild;
  };
  return { spawnFn, calls };
}

function samplePolicy(): Policy {
  return {
    allowed_http_hosts: [],
    allowed_commands: [
      {
        binary: "wrangler",
        allowed_args_patterns: ["^deploy$", "^--name$", "^[a-z][a-z0-9-]*$"],
        forbidden_args_patterns: ["^--danger$"],
      },
    ],
    allowed_env_vars: ["CLOUDFLARE_API_TOKEN"],
    rate_limit: { requests: 100, window_seconds: 60 },
  };
}

interface TestCtx {
  vault: VaultHandle;
  audit: InMemoryAuditLogger;
  rateLimiter: RateLimiter;
}

async function makeDeps(
  ctx: TestCtx,
  spawnFn: RunCommandSpawn,
  overrides: Partial<RunCommandDeps> = {},
): Promise<RunCommandDeps> {
  return {
    sources: { global: ctx.vault },
    audit: ctx.audit,
    rateLimiter: ctx.rateLimiter,
    spawn: spawnFn,
    timeoutMs: 10_000,
    parentEnv: { PATH: "/usr/bin:/bin", HOME: "/home/user", LANG: "en_US.UTF-8" },
    ...overrides,
  };
}

describe("run_command", () => {
  let root: string;
  const handles: VaultHandle[] = [];

  beforeEach(async () => {
    root = await mkTmpDir("run-command-");
  });

  afterEach(async () => {
    for (const h of handles) {
      if (!h.isClosed()) h.close();
    }
    handles.length = 0;
    await fs.rm(root, { recursive: true, force: true });
  });

  async function mkVault(name: string): Promise<VaultHandle> {
    const v = await createVault(path.join(root, name), "pw-correct-horse", {
      kdfParams: FAST_KDF,
    });
    handles.push(v);
    return v;
  }

  async function mkCtx(): Promise<TestCtx> {
    const vault = await mkVault("global.enc");
    vault.set("TOKEN", "SEKRET123", samplePolicy());
    return {
      vault,
      audit: new InMemoryAuditLogger(),
      rateLimiter: new RateLimiter(() => 0),
    };
  }

  const HAPPY_INPUT: RunCommandInput = {
    command: "wrangler",
    args: ["deploy"],
    inject_env: { CLOUDFLARE_API_TOKEN: "TOKEN" },
  };

  it("allows a spawn on the happy path: declared args pass; env contains injected secret; argv has no plaintext", async () => {
    const ctx = await mkCtx();
    const { spawnFn, calls } = createFakeSpawn((child) => {
      child.stdout.emit("data", Buffer.from("deployed ok\n"));
      child.emit("close", 0, null);
    });
    const deps = await makeDeps(ctx, spawnFn);

    const result = await runRunCommand(HAPPY_INPUT, deps);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.exit_code).toBe(0);
    expect(result.stdout).toBe("deployed ok\n");
    expect(result.stdout_truncated).toBeUndefined();

    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call).toBeDefined();
    if (!call) return;
    expect(call.command).toBe("wrangler");
    expect(call.args).toEqual(["deploy"]);

    // Secret value is NEVER in argv.
    expect(call.args.some((a) => a.includes("SEKRET123"))).toBe(false);
    expect(call.command.includes("SEKRET123")).toBe(false);

    // Env contains the injected secret.
    const env = call.options.env;
    expect(env).toBeDefined();
    if (!env) return;
    expect(env["CLOUDFLARE_API_TOKEN"]).toBe("SEKRET123");

    // Audit: one allowed record with detail payload.
    const events = ctx.audit.events;
    expect(events).toHaveLength(1);
    const ev = events[0];
    expect(ev?.outcome).toBe("allowed");
    expect(ev?.secret_name).toBe("TOKEN");
    expect(ev?.detail?.argv).toEqual(["deploy"]);
    expect(ev?.detail?.exit_code).toBe(0);
    expect(ev?.detail?.stdout).toBe("deployed ok\n");
  });

  it("spawn options: shell:false, env has exactly the 8 passthrough keys that are set + injected keys; unrelated parent env does not leak", async () => {
    const ctx = await mkCtx();
    const { spawnFn, calls } = createFakeSpawn((child) => {
      child.emit("close", 0, null);
    });
    const deps = await makeDeps(ctx, spawnFn, {
      parentEnv: {
        PATH: "/usr/bin:/bin",
        HOME: "/home/user",
        USER: "alice",
        LANG: "en_US.UTF-8",
        TZ: "UTC",
        HTTPS_PROXY: "http://proxy:8080",
        HTTP_PROXY: "http://proxy:8080",
        NO_PROXY: "localhost",
        TOTALLY_UNRELATED_SECRET: "must-not-leak",
        AWS_SECRET_ACCESS_KEY: "must-not-leak-either",
      },
    });

    await runRunCommand(HAPPY_INPUT, deps);

    expect(PASSTHROUGH_ENV_KEY_COUNT).toBe(8);

    const call = calls[0];
    expect(call).toBeDefined();
    if (!call) return;
    expect(call.options.shell).toBe(false);
    expect(call.options.stdio).toEqual(["ignore", "pipe", "pipe"]);

    const env = call.options.env;
    expect(env).toBeDefined();
    if (!env) return;
    const keys = Object.keys(env).sort();
    const expectedPassthrough = [...PASSTHROUGH_ENV_KEYS].sort();
    expect(keys).toEqual([...expectedPassthrough, "CLOUDFLARE_API_TOKEN"].sort());

    // Sentinel unrelated parent env vars must be absent.
    expect(Object.prototype.hasOwnProperty.call(env, "TOTALLY_UNRELATED_SECRET")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(env, "AWS_SECRET_ACCESS_KEY")).toBe(false);
  });

  it("omits passthrough keys that are not set in the parent environment", async () => {
    const ctx = await mkCtx();
    const { spawnFn, calls } = createFakeSpawn((child) => child.emit("close", 0, null));
    const deps = await makeDeps(ctx, spawnFn, {
      parentEnv: { PATH: "/usr/bin", HOME: "/home/user" },
    });

    await runRunCommand(HAPPY_INPUT, deps);

    const call = calls[0];
    expect(call).toBeDefined();
    if (!call) return;
    const env = call.options.env ?? {};
    expect(Object.keys(env).sort()).toEqual(["CLOUDFLARE_API_TOKEN", "HOME", "PATH"]);
  });

  it("denied command blocks exec", async () => {
    const ctx = await mkCtx();
    const { spawnFn, calls } = createFakeSpawn();
    const deps = await makeDeps(ctx, spawnFn);

    const result = await runRunCommand(
      { command: "rm", args: ["-rf", "/"], inject_env: { CLOUDFLARE_API_TOKEN: "TOKEN" } },
      deps,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("POLICY_DENIED");
    expect(calls).toHaveLength(0);

    const events = ctx.audit.events;
    expect(events).toHaveLength(1);
    expect(events[0]?.outcome).toBe("denied");
    expect(events[0]?.code).toBe("POLICY_DENIED");
  });

  it("denied arg pattern blocks exec", async () => {
    const ctx = await mkCtx();
    const { spawnFn, calls } = createFakeSpawn();
    const deps = await makeDeps(ctx, spawnFn);

    const result = await runRunCommand(
      {
        command: "wrangler",
        args: ["PUBLISH"],
        inject_env: { CLOUDFLARE_API_TOKEN: "TOKEN" },
      },
      deps,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("POLICY_DENIED");
    expect(calls).toHaveLength(0);
    expect(ctx.audit.events[0]?.code).toBe("POLICY_DENIED");
  });

  it("forbidden arg pattern denies even when an allowed pattern also matches", async () => {
    const ctx = await mkCtx();
    const { spawnFn, calls } = createFakeSpawn();
    const deps = await makeDeps(ctx, spawnFn);

    const result = await runRunCommand(
      {
        command: "wrangler",
        args: ["--danger"],
        inject_env: { CLOUDFLARE_API_TOKEN: "TOKEN" },
      },
      deps,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("POLICY_DENIED");
    expect(calls).toHaveLength(0);
  });

  it("denies when the target env var is not in the policy's allowed_env_vars", async () => {
    const ctx = await mkCtx();
    const { spawnFn, calls } = createFakeSpawn();
    const deps = await makeDeps(ctx, spawnFn);

    const result = await runRunCommand(
      {
        command: "wrangler",
        args: ["deploy"],
        inject_env: { NOT_ALLOWED_ENV: "TOKEN" },
      },
      deps,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("POLICY_DENIED");
    expect(calls).toHaveLength(0);
  });

  it("rejects a lowercase inject_env key as INVALID_INJECTION", async () => {
    const ctx = await mkCtx();
    const { spawnFn, calls } = createFakeSpawn();
    const deps = await makeDeps(ctx, spawnFn);

    const result = await runRunCommand(
      {
        command: "wrangler",
        args: ["deploy"],
        inject_env: { ld_preload: "TOKEN" },
      },
      deps,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("INVALID_INJECTION");
    expect(calls).toHaveLength(0);
    expect(ctx.audit.events[0]?.code).toBe("INVALID_INJECTION");
  });

  it.each(["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS"])(
    "rejects forbidden env var name %s as INVALID_INJECTION regardless of policy",
    async (forbidden) => {
      const ctx = await mkCtx();
      // Even if we somehow stored a policy listing the forbidden name, the
      // MCP input validator rejects it before touching the policy.
      ctx.vault.set("TOKEN", "SEKRET123", {
        ...samplePolicy(),
        allowed_env_vars: [forbidden],
      });
      const { spawnFn, calls } = createFakeSpawn();
      const deps = await makeDeps(ctx, spawnFn);

      const result = await runRunCommand(
        {
          command: "wrangler",
          args: ["deploy"],
          inject_env: { [forbidden]: "TOKEN" },
        },
        deps,
      );

      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.code).toBe("INVALID_INJECTION");
      expect(calls).toHaveLength(0);
    },
  );

  it("rejects a relative cwd with INVALID_INJECTION and does not spawn", async () => {
    const ctx = await mkCtx();
    const { spawnFn, calls } = createFakeSpawn();
    const deps = await makeDeps(ctx, spawnFn);

    const result = await runRunCommand(
      {
        command: "wrangler",
        args: ["deploy"],
        cwd: "relative/path",
        inject_env: { CLOUDFLARE_API_TOKEN: "TOKEN" },
      },
      deps,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("INVALID_INJECTION");
    expect(calls).toHaveLength(0);
  });

  it("returns SECRET_NOT_FOUND when the referenced secret does not exist", async () => {
    const ctx = await mkCtx();
    const { spawnFn, calls } = createFakeSpawn();
    const deps = await makeDeps(ctx, spawnFn);

    const result = await runRunCommand(
      {
        command: "wrangler",
        args: ["deploy"],
        inject_env: { CLOUDFLARE_API_TOKEN: "MISSING_SECRET" },
      },
      deps,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("SECRET_NOT_FOUND");
    expect(calls).toHaveLength(0);
  });

  it("scrubs the secret value from stdout before returning", async () => {
    const ctx = await mkCtx();
    const { spawnFn } = createFakeSpawn((child) => {
      child.stdout.emit("data", Buffer.from("leaking: SEKRET123 at end\n"));
      child.emit("close", 0, null);
    });
    const deps = await makeDeps(ctx, spawnFn);

    const result = await runRunCommand(HAPPY_INPUT, deps);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.stdout).not.toContain("SEKRET123");
    expect(result.stdout).toContain("[REDACTED:TOKEN]");
  });

  it("kills the child and returns TIMEOUT when it never exits", async () => {
    const ctx = await mkCtx();
    const { spawnFn, calls } = createFakeSpawn(() => {
      /* never emit close */
    });
    const deps = await makeDeps(ctx, spawnFn, { timeoutMs: 30 });

    const result = await runRunCommand(HAPPY_INPUT, deps);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("TIMEOUT");
    const child = calls[0]?.child;
    expect(child?.killSignals).toEqual(["SIGTERM"]);

    const denied = ctx.audit.events.find((e) => e.code === "TIMEOUT");
    expect(denied).toBeDefined();
  });

  it("truncates stdout at the 10 MB cap, sets stdout_truncated, and still scrubs the secret", async () => {
    const ctx = await mkCtx();
    const secretBytes = Buffer.from("SEKRET123");
    const padding = Buffer.alloc(MAX_OUTPUT_BYTES - secretBytes.length + 1024, 0x41); // 'A'
    const over = Buffer.alloc(1024 * 1024, 0x42); // extra 1 MB of 'B' past the cap
    const { spawnFn } = createFakeSpawn((child) => {
      child.stdout.emit("data", secretBytes);
      child.stdout.emit("data", padding);
      child.stdout.emit("data", over);
      child.emit("close", 0, null);
    });
    const deps = await makeDeps(ctx, spawnFn);

    const result = await runRunCommand(HAPPY_INPUT, deps);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.stdout_truncated).toBe(true);
    expect(result.stdout).not.toContain("SEKRET123");
    expect(result.stdout).toContain("[REDACTED:TOKEN]");
    // Should NOT contain any 'B' bytes (those are past the cap).
    expect(result.stdout.includes("B")).toBe(false);

    const sizeLimit = ctx.audit.events.find((e) => e.code === "SIZE_LIMIT");
    expect(sizeLimit).toBeDefined();
  });

  it("argv-leak check: under every passing path the secret value is not in captured argv", async () => {
    const ctx = await mkCtx();
    const { spawnFn, calls } = createFakeSpawn((child) => child.emit("close", 0, null));
    const deps = await makeDeps(ctx, spawnFn);

    await runRunCommand(
      {
        command: "wrangler",
        args: ["deploy", "--name", "my-worker"],
        inject_env: { CLOUDFLARE_API_TOKEN: "TOKEN" },
      },
      deps,
    );

    const call = calls[0];
    expect(call).toBeDefined();
    if (!call) return;
    for (const arg of call.args) {
      expect(arg.includes("SEKRET123")).toBe(false);
    }
    expect(call.command.includes("SEKRET123")).toBe(false);
  });

  it("registers on an McpServer via extraTools without throwing", async () => {
    const ctx = await mkCtx();
    const { spawnFn } = createFakeSpawn();
    const deps = await makeDeps(ctx, spawnFn);
    const server = createMcpServer(
      { sources: deps.sources },
      { extraTools: [(s) => registerRunCommand(s, deps)] },
    );
    expect(server).toBeDefined();
    expect(registerRunCommand).toBeTypeOf("function");
  });
});
