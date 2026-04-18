import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  NapiKeychainBackend,
  NodeTTYInterface,
  createMasterPasswordStore,
  createRoutineResolver,
} from "../keychain/index.js";
import { createMcpServer } from "../mcp/index.js";
import {
  discoverProjectVault,
  ensureProjectVault,
  getGlobalVaultPath,
} from "../scope/index.js";
import { createVault, unlockVault } from "../vault/index.js";
import type { CliDeps } from "./types.js";

const DEFAULT_AUDIT_DIR = ".secretproxy";
const DEFAULT_AUDIT_FILE = "audit.log";

async function fileExists(filePath: string): Promise<boolean> {
  try {
    const st = await fs.stat(filePath);
    return st.isFile();
  } catch {
    return false;
  }
}

async function readAuditLog(auditLogPath: string): Promise<string | null> {
  try {
    return await fs.readFile(auditLogPath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }
    throw err;
  }
}

export interface CreateDefaultDepsOptions {
  debug?: boolean;
}

export function createDefaultDeps(
  opts: CreateDefaultDepsOptions = {},
): CliDeps {
  const env = process.env;
  const cwd = process.cwd();
  const homedir = os.homedir();
  const stdout = (text: string): void => {
    process.stdout.write(text);
  };
  const stderr = (text: string): void => {
    process.stderr.write(text);
  };
  const warn = stderr;

  const backend = new NapiKeychainBackend();
  const passwordStore = createMasterPasswordStore(backend);
  const tty = new NodeTTYInterface();
  const resolver = createRoutineResolver({ env, store: passwordStore, warn });
  const auditLogPath = path.join(homedir, DEFAULT_AUDIT_DIR, DEFAULT_AUDIT_FILE);

  return {
    cwd,
    env,
    homedir,
    stdout,
    stderr,
    warn,
    passwordStore,
    tty,
    globalVaultPath: getGlobalVaultPath(homedir),
    auditLogPath,
    debug: opts.debug === true,
    resolvePassword: resolver,
    createVault,
    unlockVault,
    ensureProjectVault,
    discoverProjectVault,
    fileExists,
    readAuditLog: () => readAuditLog(auditLogPath),
    createMcpServer,
    connectStdio: async (server) => {
      const transport = new StdioServerTransport();
      await server.connect(transport);
    },
  };
}
