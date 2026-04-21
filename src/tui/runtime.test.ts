import { describe, expect, it, vi } from "vitest";
import { installTerminalLifecycle } from "./runtime.js";

describe("installTerminalLifecycle", () => {
  it("registers SIGINT/SIGTERM handlers and restores raw mode on signal", () => {
    const listeners = new Map<string, () => void>();
    const stdin = { setRawMode: vi.fn() };
    let signaled = 0;
    const lifecycle = installTerminalLifecycle({
      stdin,
      processRef: {
        on(signal, listener) {
          listeners.set(signal, listener);
        },
        off(signal) {
          listeners.delete(signal);
        },
      },
      onSignal() {
        signaled += 1;
      },
    });

    expect(stdin.setRawMode).toHaveBeenCalledWith(true);
    expect(listeners.has("SIGINT")).toBe(true);
    expect(listeners.has("SIGTERM")).toBe(true);

    listeners.get("SIGINT")?.();

    expect(signaled).toBe(1);
    expect(stdin.setRawMode).toHaveBeenLastCalledWith(false);
    expect(listeners.size).toBe(0);

    lifecycle.restore();
    expect(stdin.setRawMode).toHaveBeenCalledTimes(2);
  });
});
