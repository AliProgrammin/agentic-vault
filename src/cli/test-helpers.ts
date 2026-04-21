import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { InMemoryAuditLogger } from "../audit/index.js";
import {
  InMemoryKeychainBackend,
  VaultLockedError,
  createMasterPasswordStore,
  type TTYInterface,
} from "../keychain/index.js";
import type { CreateMcpServerOptions, McpServerDeps } from "../mcp/index.js";
import { RateLimiter } from "../ratelimit/index.js";
import {
  discoverProjectVault,
  ensureProjectVault,
  type EnsureProjectVaultResult,
} from "../scope/index.js";
import {
  createVault,
  unlockVault,
  type CreateVaultOptions,
  type KdfParams,
  type VaultHandle,
} from "../vault/index.js";
import type { CliDeps, Printer } from "./types.js";

// argon2 runs really slow at production KDF parameters. Tests use the
// weakest argon2id params the library will accept so the cost per vault
// op is a few milliseconds instead of 100+.
export const TEST_KDF: KdfParams = {
  memory: 1024,
  iterations: 2,
  parallelism: 1,
};

const TEST_VAULT_OPTS: CreateVaultOptions = { kdfParams: TEST_KDF };

async function fileExists(filePath: string): Promise<boolean> {
  try {
    const st = await fs.stat(filePath);
    return st.isFile();
  } catch {
    return false;
  }
}

export class CapturingPrinter {
  private readonly chunks: string[] = [];
  public readonly write: Printer = (text) => {
    this.chunks.push(text);
  };
  public text(): string {
    return this.chunks.join("");
  }
}

export class PoisonedTTY implements TTYInterface {
  public stdinIsTTY(): boolean {
    throw new Error("poisoned TTY: stdinIsTTY must not be called");
  }
  public readStdinAll(): Promise<string> {
    throw new Error("poisoned TTY: readStdinAll must not be called");
  }
  public promptHidden(): Promise<string> {
    throw new Error("poisoned TTY: promptHidden must not be called");
  }
  public promptConfirm(): Promise<boolean> {
    throw new Error("poisoned TTY: promptConfirm must not be called");
  }
}

export class ScriptedTTY implements TTYInterface {
  public stdinIsTTYResult: boolean;
  public readStdinResult: string;
  public prompts: string[] = [];
  public confirmPrompts: string[] = [];
  public confirmResponses: boolean[] = [];

  constructor(opts: {
    isTTY: boolean;
    stdin?: string;
    prompts?: string[];
    confirmResponses?: boolean[];
  }) {
    this.stdinIsTTYResult = opts.isTTY;
    this.readStdinResult = opts.stdin ?? "";
    if (opts.prompts !== undefined) {
      this.prompts = [...opts.prompts];
    }
    if (opts.confirmResponses !== undefined) {
      this.confirmResponses = [...opts.confirmResponses];
    }
  }

  public stdinIsTTY(): boolean {
    return this.stdinIsTTYResult;
  }

  public async readStdinAll(): Promise<string> {
    return this.readStdinResult;
  }

  public async promptHidden(): Promise<string> {
    const next = this.prompts.shift();
    if (next === undefined) {
      throw new Error("ScriptedTTY: no more prompts scripted");
    }
    return next;
  }

  public async promptConfirm(prompt: string): Promise<boolean> {
    this.confirmPrompts.push(prompt);
    const next = this.confirmResponses.shift();
    if (next === undefined) {
      throw new Error("ScriptedTTY: no more confirm responses scripted");
    }
    return next;
  }
}

export interface TestDepsOptions {
  cwd: string;
  env?: NodeJS.ProcessEnv;
  homedir?: string;
  password?: string;
  keychainPopulated?: boolean;
  tty?: TTYInterface;
  mcpOverrides?: {
    createMcpServer?: (
      deps: McpServerDeps,
      opts?: CreateMcpServerOptions,
    ) => McpServer;
    connectStdio?: (server: McpServer) => Promise<void>;
  };
  debug?: boolean;
}

export interface TestHarness {
  deps: CliDeps;
  stdout: CapturingPrinter;
  stderr: CapturingPrinter;
  warnings: CapturingPrinter;
  backend: InMemoryKeychainBackend;
  tty: TTYInterface;
  mcpCalls: {
    sources: McpServerDeps["sources"];
    opts: CreateMcpServerOptions | undefined;
    server: unknown;
  }[];
}

const SERVICE = "secretproxy";
const ACCOUNT = "master";

export function makeTestDeps(options: TestDepsOptions): TestHarness {
  const stdout = new CapturingPrinter();
  const stderr = new CapturingPrinter();
  const warnings = new CapturingPrinter();
  const backend = new InMemoryKeychainBackend();
  if (options.keychainPopulated === true && options.password !== undefined) {
    backend.set(SERVICE, ACCOUNT, options.password);
  }
  const store = createMasterPasswordStore(backend);
  const tty = options.tty ?? new PoisonedTTY();
  const globalVaultPath = path.join(
    options.homedir ?? options.cwd,
    ".secretproxy.enc",
  );
  const auditDir = path.join(options.homedir ?? options.cwd, ".secretproxy");
  const auditLogPath = path.join(auditDir, "audit.log");
  const mcpCalls: TestHarness["mcpCalls"] = [];
  const createMcpServerFn =
    options.mcpOverrides?.createMcpServer ??
    ((deps: McpServerDeps): McpServer => {
      const fake = { _sources: deps.sources } as unknown as McpServer;
      return fake;
    });
  const audit = new InMemoryAuditLogger();
  const rateLimiter = new RateLimiter(() => 0);
  const connectStdioFn =
    options.mcpOverrides?.connectStdio ??
    (async (): Promise<void> => {
      // default: no-op
    });
  const env = options.env ?? {};

  const deps: CliDeps = {
    cwd: options.cwd,
    env,
    homedir: options.homedir ?? options.cwd,
    stdout: stdout.write,
    stderr: stderr.write,
    warn: warnings.write,
    passwordStore: store,
    tty,
    globalVaultPath,
    auditLogPath,
    debug: options.debug === true,
    resolvePassword(): string {
      const envPw = env["SECRETPROXY_PASSWORD"];
      if (typeof envPw === "string" && envPw.length > 0) {
        warnings.write("fallback warning");
        return envPw;
      }
      try {
        return store.readMasterPassword();
      } catch {
        throw new VaultLockedError();
      }
    },
    createVault: (filePath, password, opts = {}) =>
      createVault(filePath, password, { ...TEST_VAULT_OPTS, ...opts }),
    unlockVault,
    ensureProjectVault: (
      projectRoot,
      password,
      opts = {},
    ): Promise<EnsureProjectVaultResult> =>
      ensureProjectVault(projectRoot, password, { ...TEST_VAULT_OPTS, ...opts }),
    discoverProjectVault: (cwd, homeDir) =>
      discoverProjectVault(cwd, homeDir ?? options.homedir ?? options.cwd),
    fileExists,
    readAuditLog: async (): Promise<string | null> => {
      try {
        return await fs.readFile(auditLogPath, "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") {
          return null;
        }
        throw err;
      }
    },
    audit,
    rateLimiter,
    createMcpServer(mcpDeps: McpServerDeps, opts?: CreateMcpServerOptions) {
      const server = createMcpServerFn(mcpDeps, opts);
      mcpCalls.push({ sources: mcpDeps.sources, opts, server });
      return server;
    },
    connectStdio: connectStdioFn,
  };

  return { deps, stdout, stderr, warnings, backend, tty, mcpCalls };
}

export async function makeTmpDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "secretproxy-cli-"));
}

export async function createPopulatedGlobalVault(
  filePath: string,
  password: string,
  secrets: { name: string; value: string; policy?: unknown }[],
): Promise<VaultHandle> {
  const handle = await createVault(filePath, password, TEST_VAULT_OPTS);
  for (const s of secrets) {
    handle.set(s.name, s.value, s.policy);
  }
  await handle.save();
  return handle;
}
