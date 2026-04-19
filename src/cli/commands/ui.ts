import { exec } from "node:child_process";
import { startUiServer } from "../../ui/index.js";
import type { CliDeps } from "../types.js";

const DEFAULT_IDLE_MS = 15 * 60 * 1000;

export interface UiOptions {
  port?: number;
  noOpen?: boolean;
}

function openBrowser(url: string): void {
  const platform = process.platform;
  const cmd =
    platform === "darwin"
      ? `open "${url}"`
      : platform === "win32"
        ? `start "" "${url}"`
        : `xdg-open "${url}"`;
  exec(cmd, () => {
    // best-effort; user can open manually from the logged URL
  });
}

export async function cmdUi(deps: CliDeps, opts: UiOptions): Promise<void> {
  const serverOpts: Parameters<typeof startUiServer>[0] = {
    homedir: deps.homedir,
    cwd: deps.cwd,
    idleTimeoutMs: DEFAULT_IDLE_MS,
    onIdle: () => {
      deps.stderr(
        `secretproxy ui: idle for ${String(DEFAULT_IDLE_MS / 60000)} minutes, shutting down\n`,
      );
      void handle.close().then(() => process.exit(0));
    },
  };
  if (opts.port !== undefined) serverOpts.port = opts.port;
  const handle = await startUiServer(serverOpts);
  deps.stdout(`secretproxy ui listening on ${handle.url}\n`);
  deps.stdout("Press Ctrl-C to stop.\n");
  if (opts.noOpen !== true) {
    openBrowser(handle.url);
  }
  const shutdown = async (): Promise<void> => {
    deps.stderr("\nshutting down\n");
    await handle.close();
    process.exit(0);
  };
  process.on("SIGINT", () => {
    void shutdown();
  });
  process.on("SIGTERM", () => {
    void shutdown();
  });
  await new Promise<void>(() => {
    // hold until a signal or idle-shutdown path triggers process.exit
  });
}
