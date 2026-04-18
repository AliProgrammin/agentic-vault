// Phase 1 end-to-end smoke test.
//
// Exercises the full unlock -> MCP assembly -> run_command flow against a
// mocked `wrangler` subprocess and asserts the three Phase 1 security
// invariants in a single run:
//   1. The injected env var reaches the spawned process.
//   2. stdout returned to the agent has the literal secret replaced with
//      [REDACTED:CLOUDFLARE_API_TOKEN].
//   3. Swapping the binary to `rm` (same secret, same env var) returns a
//      policy denial and never invokes spawn.
//
// The test uses createVault + unlockVault to exercise the real unlock path,
// and assembles the MCP server via createMcpServer with registerRunCommand
// passed as extraTools — the production wiring — with a real in-memory
// audit logger, a real rate limiter, and the real scrubber inside
// run_command. Only `spawn` is faked.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { EventEmitter } from "node:events";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { SpawnOptions } from "node:child_process";
import { createVault, unlockVault, type KdfParams, type VaultHandle } from "../vault/index.js";
import type { Policy } from "../policy/index.js";
import { InMemoryAuditLogger } from "../audit/index.js";
import { RateLimiter } from "../ratelimit/index.js";
import { createMcpServer } from "../mcp/server.js";
import {
  registerRunCommand,
  runRunCommand,
  type RunCommandDeps,
  type RunCommandSpawn,
  type SpawnedChild,
} from "../mcp/run_command.js";

const FAST_KDF: KdfParams = { memory: 1024, iterations: 2, parallelism: 1 };
const SECRET_NAME = "CLOUDFLARE_API_TOKEN";
const SECRET_VALUE = "SEKRET123";
const PASSWORD = "correct-horse-battery-staple";

function wranglerPolicy(): Policy {
  return {
    allowed_http_hosts: [],
    allowed_commands: [
      {
        binary: "wrangler",
        allowed_args_patterns: ["^deploy$", "^--name$", "^[a-z][a-z0-9-]*$"],
      },
    ],
    allowed_env_vars: [SECRET_NAME],
    rate_limit: { requests: 100, window_seconds: 60 },
  };
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

describe("E2E smoke — mocked wrangler flow", () => {
  let tmpDir: string;
  let vaultPath: string;
  let handle: VaultHandle | null = null;

  beforeEach(async () => {
    tmpDir = await fs.realpath(
      await fs.mkdtemp(path.join(os.tmpdir(), "secretproxy-e2e-")),
    );
    vaultPath = path.join(tmpDir, "global.enc");
  });

  afterEach(async () => {
    if (handle && !handle.isClosed()) {
      handle.close();
    }
    handle = null;
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("unlocks vault, enforces policy, injects env, scrubs stdout, and denies rm in one run", async () => {
    // 1. Create the vault with one secret + wrangler policy, save, then
    //    reopen via unlockVault to exercise the production unlock path.
    const created = await createVault(vaultPath, PASSWORD, { kdfParams: FAST_KDF });
    created.set(SECRET_NAME, SECRET_VALUE, wranglerPolicy());
    await created.save();
    created.close();

    handle = await unlockVault(vaultPath, PASSWORD);

    // 2. Assemble the MCP server exactly as production would: pass
    //    registerRunCommand via extraTools. Use real audit, real rate
    //    limiter; only spawn is faked.
    const calls: SpawnCall[] = [];
    const fakeSpawn: RunCommandSpawn = (command, args, options) => {
      const child = new FakeChild();
      calls.push({ command, args: [...args], options, child });
      setImmediate(() => {
        // Assert the injected env var reached the subprocess as spawned.
        // This is invariant (1): env contains the resolved secret value.
        expect(options.env?.[SECRET_NAME]).toBe(SECRET_VALUE);
        // Secret value must never appear in argv.
        for (const a of args) {
          expect(a.includes(SECRET_VALUE)).toBe(false);
        }
        expect(command.includes(SECRET_VALUE)).toBe(false);
        // Emit a stdout line that CONTAINS the literal secret value so the
        // scrubber has something to replace.
        child.stdout.emit("data", Buffer.from(`deployed: token=${SECRET_VALUE}\n`));
        child.emit("close", 0, null);
      });
      return child as unknown as SpawnedChild;
    };

    const deps: RunCommandDeps = {
      sources: { global: handle },
      audit: new InMemoryAuditLogger(),
      rateLimiter: new RateLimiter(() => 0),
      spawn: fakeSpawn,
      timeoutMs: 5_000,
      parentEnv: { PATH: "/usr/bin:/bin", HOME: "/home/user" },
    };

    const server = createMcpServer(
      { sources: deps.sources },
      { extraTools: [(s) => registerRunCommand(s, deps)] },
    );
    expect(server).toBeDefined();

    // 3. Happy path: wrangler deploy with the secret injected into
    //    CLOUDFLARE_API_TOKEN.
    const happy = await runRunCommand(
      {
        command: "wrangler",
        args: ["deploy"],
        inject_env: { [SECRET_NAME]: SECRET_NAME },
      },
      deps,
    );

    expect(happy.ok).toBe(true);
    if (!happy.ok) return;
    expect(happy.exit_code).toBe(0);
    // Invariant (2): scrubbed stdout — no plaintext, has redacted marker.
    expect(happy.stdout).not.toContain(SECRET_VALUE);
    expect(happy.stdout).toContain(`[REDACTED:${SECRET_NAME}]`);
    expect(calls).toHaveLength(1);

    // 4. Invariant (3): same invocation with binary `rm` is denied and
    //    does NOT invoke spawn.
    const denied = await runRunCommand(
      {
        command: "rm",
        args: ["-rf", "/"],
        inject_env: { [SECRET_NAME]: SECRET_NAME },
      },
      deps,
    );

    expect(denied.ok).toBe(false);
    if (denied.ok) return;
    expect(denied.code).toBe("POLICY_DENIED");
    // spawn call count did not increase.
    expect(calls).toHaveLength(1);

    // Audit captured both: one allowed wrangler, one denied rm.
    const events = (deps.audit as InMemoryAuditLogger).events;
    const allowed = events.filter((e) => e.outcome === "allowed");
    const deniedEvents = events.filter((e) => e.outcome === "denied");
    expect(allowed.some((e) => e.target === "wrangler")).toBe(true);
    expect(deniedEvents.some((e) => e.target === "rm" && e.code === "POLICY_DENIED")).toBe(
      true,
    );
  });
});
