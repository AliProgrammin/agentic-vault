import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { MasterPasswordStore, TTYInterface } from "../keychain/index.js";
import type { McpServerDeps } from "../mcp/index.js";
import type {
  EnsureProjectVaultResult,
  ProjectVaultLocation,
} from "../scope/index.js";
import type { CreateVaultOptions, VaultHandle } from "../vault/index.js";

export type Printer = (text: string) => void;

export interface CliDeps {
  readonly cwd: string;
  readonly env: NodeJS.ProcessEnv;
  readonly homedir: string;
  readonly stdout: Printer;
  readonly stderr: Printer;
  readonly warn: Printer;
  readonly passwordStore: MasterPasswordStore;
  readonly tty: TTYInterface;
  readonly globalVaultPath: string;
  readonly auditLogPath: string;
  readonly debug: boolean;

  resolvePassword(): string;

  createVault(
    filePath: string,
    password: string,
    opts?: CreateVaultOptions,
  ): Promise<VaultHandle>;

  unlockVault(filePath: string, password: string): Promise<VaultHandle>;

  ensureProjectVault(
    projectRoot: string,
    password: string,
    opts?: CreateVaultOptions,
  ): Promise<EnsureProjectVaultResult>;

  discoverProjectVault(
    cwd: string,
    homeDir?: string,
  ): Promise<ProjectVaultLocation | null>;

  fileExists(filePath: string): Promise<boolean>;

  readAuditLog(): Promise<string | null>;

  createMcpServer(deps: McpServerDeps): McpServer;

  connectStdio(server: McpServer): Promise<void>;
}
