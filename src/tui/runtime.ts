export interface RawModeStdin {
  readonly setRawMode?: (enabled: boolean) => void;
}

export interface SignalProcess {
  on(signal: "SIGINT" | "SIGTERM", listener: () => void): void;
  off(signal: "SIGINT" | "SIGTERM", listener: () => void): void;
}

export interface TerminalLifecycle {
  restore(): void;
}

export interface TerminalLifecycleOptions {
  readonly stdin: RawModeStdin;
  readonly processRef: SignalProcess;
  readonly onSignal: () => void;
}

export function installTerminalLifecycle(
  opts: TerminalLifecycleOptions,
): TerminalLifecycle {
  let restored = false;
  const restore = (): void => {
    if (restored) {
      return;
    }
    restored = true;
    opts.stdin.setRawMode?.(false);
    opts.processRef.off("SIGINT", handleSignal);
    opts.processRef.off("SIGTERM", handleSignal);
  };
  const handleSignal = (): void => {
    restore();
    opts.onSignal();
  };
  opts.stdin.setRawMode?.(true);
  opts.processRef.on("SIGINT", handleSignal);
  opts.processRef.on("SIGTERM", handleSignal);
  return { restore };
}
