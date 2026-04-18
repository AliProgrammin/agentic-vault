import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import type { AuditEvent, AuditLogger } from "./types.js";

const DIR_MODE = 0o700;
const FILE_MODE = 0o600;
const DEFAULT_DIR_NAME = ".secretproxy";
const LOG_FILE_NAME = "audit.log";

export interface FileAuditLoggerOptions {
  baseDir?: string;
}

// Append-only JSONL writer. Each record() call opens the log in O_APPEND mode,
// writes one line, fsyncs the descriptor, and closes it. Durable across crashes
// once the sync resolves; no file handle is retained between calls. On Windows
// the POSIX directory mode is a no-op and is documented as such in the plan.
export class FileAuditLogger implements AuditLogger {
  private readonly baseDir: string;
  private readonly logPath: string;
  private dirEnsured = false;

  constructor(options: FileAuditLoggerOptions = {}) {
    this.baseDir = options.baseDir ?? path.join(os.homedir(), DEFAULT_DIR_NAME);
    this.logPath = path.join(this.baseDir, LOG_FILE_NAME);
  }

  get filePath(): string {
    return this.logPath;
  }

  async record(event: AuditEvent): Promise<void> {
    await this.ensureDir();
    const line = `${JSON.stringify(event)}\n`;
    const handle = await fs.open(this.logPath, "a", FILE_MODE);
    try {
      await handle.write(line);
      await handle.sync();
    } finally {
      await handle.close();
    }
  }

  private async ensureDir(): Promise<void> {
    if (this.dirEnsured) {
      return;
    }
    let existed = true;
    try {
      await fs.stat(this.baseDir);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") {
        throw err;
      }
      existed = false;
    }
    if (!existed) {
      await fs.mkdir(this.baseDir, { recursive: true, mode: DIR_MODE });
      if (process.platform !== "win32") {
        await fs.chmod(this.baseDir, DIR_MODE);
      }
    }
    this.dirEnsured = true;
  }
}
