import type { ReadStream, WriteStream } from "node:tty";

export interface TTYInterface {
  stdinIsTTY(): boolean;
  readStdinAll(): Promise<string>;
  promptHidden(prompt: string): Promise<string>;
  /**
   * Show a yes/no confirmation prompt. Returns true only when the operator
   * explicitly types 'y' or 'Y'. Any other input (including empty) is
   * treated as a refusal. Used by `policy set` when the submitted policy
   * contains a wildcard entry — the only interactive prompt outside
   * `secretproxy init`.
   */
  promptConfirm(prompt: string): Promise<boolean>;
}

export class NodeTTYInterface implements TTYInterface {
  public stdinIsTTY(): boolean {
    return process.stdin.isTTY === true;
  }

  public async readStdinAll(): Promise<string> {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    }
    return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
  }

  public promptHidden(prompt: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const stdin = process.stdin as ReadStream;
      const stdout = process.stdout as WriteStream;
      try {
        stdout.write(prompt);
      } catch (err) {
        reject(err instanceof Error ? err : new Error(String(err)));
        return;
      }

      const wasRaw = stdin.isRaw;
      try {
        stdin.setRawMode(true);
      } catch (err) {
        reject(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      stdin.resume();
      stdin.setEncoding("utf8");

      let input = "";
      const cleanup = (): void => {
        stdin.removeListener("data", onData);
        try {
          stdin.setRawMode(wasRaw);
        } catch {
          // ignore — best-effort restore
        }
        stdin.pause();
        stdout.write("\n");
      };

      const onData = (chunk: string): void => {
        for (const ch of chunk) {
          if (ch === "\n" || ch === "\r" || ch === "\u0004") {
            cleanup();
            resolve(input);
            return;
          }
          if (ch === "\u0003") {
            cleanup();
            reject(new Error("prompt aborted"));
            return;
          }
          if (ch === "\u007f" || ch === "\b") {
            input = input.slice(0, -1);
            continue;
          }
          input += ch;
        }
      };

      stdin.on("data", onData);
    });
  }

  public promptConfirm(prompt: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const stdin = process.stdin as ReadStream;
      const stdout = process.stdout as WriteStream;
      try {
        stdout.write(prompt);
      } catch (err) {
        reject(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      const wasRaw = stdin.isRaw;
      try {
        stdin.setRawMode(true);
      } catch (err) {
        reject(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      stdin.resume();
      stdin.setEncoding("utf8");
      let input = "";
      const cleanup = (): void => {
        stdin.removeListener("data", onData);
        try {
          stdin.setRawMode(wasRaw);
        } catch {
          // best-effort restore
        }
        stdin.pause();
        stdout.write("\n");
      };
      const onData = (chunk: string): void => {
        for (const ch of chunk) {
          if (ch === "\n" || ch === "\r" || ch === "\u0004") {
            cleanup();
            const answer = input.trim().toLowerCase();
            resolve(answer === "y" || answer === "yes");
            return;
          }
          if (ch === "\u0003") {
            cleanup();
            reject(new Error("prompt aborted"));
            return;
          }
          if (ch === "\u007f" || ch === "\b") {
            input = input.slice(0, -1);
            stdout.write("\b \b");
            continue;
          }
          input += ch;
          stdout.write(ch);
        }
      };
      stdin.on("data", onData);
    });
  }
}
