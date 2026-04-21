import { describe, expect, it, vi } from "vitest";

import { InMemoryKeychainBackend } from "./backend.js";
import {
  KeychainBackendError,
  PasswordMismatchError,
  VaultLockedError,
  WeakPasswordError,
} from "./errors.js";
import {
  createRoutineResolver,
  resolveInitPassword,
  INIT_ENV_VAR,
  ROUTINE_ENV_VAR,
} from "./resolver.js";
import { createMasterPasswordStore } from "./store.js";
import type { TTYInterface } from "./tty.js";
import type { KeychainBackend } from "./backend.js";

const SECRET = "correct-horse-12345";

function makeStore(): {
  store: ReturnType<typeof createMasterPasswordStore>;
  backend: InMemoryKeychainBackend;
} {
  const backend = new InMemoryKeychainBackend();
  return { store: createMasterPasswordStore(backend), backend };
}

describe("routine-ops resolver", () => {
  it("returns the env var value and emits exactly one stderr warning per process", () => {
    const { store } = makeStore();
    const warn = vi.fn();
    const resolver = createRoutineResolver({
      env: { [ROUTINE_ENV_VAR]: SECRET },
      store,
      warn,
    });

    expect(resolver()).toBe(SECRET);
    expect(resolver()).toBe(SECRET);
    expect(resolver()).toBe(SECRET);

    expect(warn).toHaveBeenCalledTimes(1);
    const warningText = String(warn.mock.calls[0]?.[0] ?? "");
    expect(warningText).toContain(ROUTINE_ENV_VAR);
    expect(warningText.toLowerCase()).toContain("init");
    expect(warningText).not.toContain(SECRET);
  });

  it("prefers env var over keychain when both are present", () => {
    const { store } = makeStore();
    store.storeMasterPassword("from-keychain-12345");
    const warn = vi.fn();
    const resolver = createRoutineResolver({
      env: { [ROUTINE_ENV_VAR]: SECRET },
      store,
      warn,
    });
    expect(resolver()).toBe(SECRET);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it("treats an empty SECRETPROXY_PASSWORD as unset and falls through to the keychain", () => {
    const { store } = makeStore();
    store.storeMasterPassword("from-keychain-12345");
    const warn = vi.fn();
    const resolver = createRoutineResolver({
      env: { [ROUTINE_ENV_VAR]: "" },
      store,
      warn,
    });
    expect(resolver()).toBe("from-keychain-12345");
    expect(warn).not.toHaveBeenCalled();
  });

  it("returns the keychain value and does not warn when env is unset", () => {
    const { store } = makeStore();
    store.storeMasterPassword(SECRET);
    const warn = vi.fn();
    const resolver = createRoutineResolver({ env: {}, store, warn });
    expect(resolver()).toBe(SECRET);
    expect(warn).not.toHaveBeenCalled();
  });

  it("throws VAULT_LOCKED without prompting when env is unset and keychain is empty", () => {
    const { store } = makeStore();
    const warn = vi.fn();
    const resolver = createRoutineResolver({ env: {}, store, warn });

    let caught: unknown;
    try {
      resolver();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(VaultLockedError);
    expect((caught as VaultLockedError).code).toBe("VAULT_LOCKED");
    expect(warn).not.toHaveBeenCalled();
  });

  it("propagates keychain backend errors as KeychainBackendError (distinct from VAULT_LOCKED)", () => {
    const brokenBackend: KeychainBackend = {
      get: () => {
        throw new KeychainBackendError("simulated backend failure");
      },
      set: () => {
        throw new KeychainBackendError("simulated backend failure");
      },
      delete: () => {
        throw new KeychainBackendError("simulated backend failure");
      },
    };
    const store = createMasterPasswordStore(brokenBackend);
    const warn = vi.fn();
    const resolver = createRoutineResolver({ env: {}, store, warn });

    let caught: unknown;
    try {
      resolver();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(KeychainBackendError);
    expect(caught).not.toBeInstanceOf(VaultLockedError);
  });
});

class RecordingTTY implements TTYInterface {
  public stdinIsTTYReturn: boolean;
  public stdinReadReturn: string;
  public readonly prompts: string[] = [];
  public readonly confirmPrompts: string[] = [];
  public readonly responses: string[];
  public readonly confirmResponses: boolean[];
  public readStdinCalls = 0;

  public constructor(options: {
    isTTY: boolean;
    stdinReturn?: string;
    responses?: string[];
    confirmResponses?: boolean[];
  }) {
    this.stdinIsTTYReturn = options.isTTY;
    this.stdinReadReturn = options.stdinReturn ?? "";
    this.responses = options.responses ?? [];
    this.confirmResponses = options.confirmResponses ?? [];
  }

  public stdinIsTTY(): boolean {
    return this.stdinIsTTYReturn;
  }

  public async readStdinAll(): Promise<string> {
    this.readStdinCalls += 1;
    return this.stdinReadReturn;
  }

  public async promptHidden(prompt: string): Promise<string> {
    this.prompts.push(prompt);
    const next = this.responses.shift();
    if (next === undefined) {
      throw new Error("RecordingTTY: no queued response for prompt: " + prompt);
    }
    return next;
  }

  public async promptConfirm(prompt: string): Promise<boolean> {
    this.confirmPrompts.push(prompt);
    const next = this.confirmResponses.shift();
    if (next === undefined) {
      throw new Error("RecordingTTY: no queued confirm response for prompt: " + prompt);
    }
    return next;
  }
}

describe("init-path resolver", () => {
  it("returns SECRETPROXY_INIT_PASSWORD without touching stdin or TTY", async () => {
    const tty = new RecordingTTY({ isTTY: true, responses: ["should-never-be-used"] });
    const result = await resolveInitPassword({
      env: { [INIT_ENV_VAR]: "from-init-env-12345" },
      tty,
    });
    expect(result).toBe("from-init-env-12345");
    expect(tty.prompts).toEqual([]);
    expect(tty.readStdinCalls).toBe(0);
  });

  it("reads from stdin when env is unset and stdin is non-TTY", async () => {
    const tty = new RecordingTTY({
      isTTY: false,
      stdinReturn: "piped-password-12345",
    });
    const result = await resolveInitPassword({ env: {}, tty });
    expect(result).toBe("piped-password-12345");
    expect(tty.readStdinCalls).toBe(1);
    expect(tty.prompts).toEqual([]);
  });

  it("invokes the hidden TTY prompt twice (set + confirm) when stdin is a TTY", async () => {
    const tty = new RecordingTTY({
      isTTY: true,
      responses: ["abcdefghijkl", "abcdefghijkl"],
    });
    const result = await resolveInitPassword({ env: {}, tty });
    expect(result).toBe("abcdefghijkl");
    expect(tty.prompts).toEqual(["Set master password: ", "Confirm: "]);
  });

  it("rejects passwords shorter than 12 characters with WeakPasswordError", async () => {
    const tty = new RecordingTTY({ isTTY: true, responses: ["short", "short"] });
    await expect(resolveInitPassword({ env: {}, tty })).rejects.toBeInstanceOf(
      WeakPasswordError,
    );
    expect(tty.prompts).toEqual(["Set master password: "]);
  });

  it("rejects mismatched confirmation with PasswordMismatchError", async () => {
    const tty = new RecordingTTY({
      isTTY: true,
      responses: ["abcdefghijkl", "mnopqrstuvwx"],
    });
    await expect(resolveInitPassword({ env: {}, tty })).rejects.toBeInstanceOf(
      PasswordMismatchError,
    );
    expect(tty.prompts).toEqual(["Set master password: ", "Confirm: "]);
  });

  it("treats an empty SECRETPROXY_INIT_PASSWORD as unset", async () => {
    const tty = new RecordingTTY({
      isTTY: false,
      stdinReturn: "piped-password-12345",
    });
    const result = await resolveInitPassword({ env: { [INIT_ENV_VAR]: "" }, tty });
    expect(result).toBe("piped-password-12345");
    expect(tty.readStdinCalls).toBe(1);
  });

  it("respects a caller-provided minLength override", async () => {
    const tty = new RecordingTTY({ isTTY: true, responses: ["abcd", "abcd"] });
    const result = await resolveInitPassword({ env: {}, tty, minLength: 4 });
    expect(result).toBe("abcd");
  });
});

describe("no-logging invariant", () => {
  it("does not print the password on the routine-ops env-fallback path", () => {
    const { store } = makeStore();
    const warn = vi.fn();
    const resolver = createRoutineResolver({
      env: { [ROUTINE_ENV_VAR]: "super-secret-plaintext" },
      store,
      warn,
    });

    const stdoutSpy = vi.spyOn(process.stdout, "write").mockReturnValue(true);
    const stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true);

    try {
      expect(resolver()).toBe("super-secret-plaintext");
    } finally {
      stdoutSpy.mockRestore();
      stderrSpy.mockRestore();
    }

    for (const call of stdoutSpy.mock.calls) {
      expect(String(call[0])).not.toContain("super-secret-plaintext");
    }
    for (const call of stderrSpy.mock.calls) {
      expect(String(call[0])).not.toContain("super-secret-plaintext");
    }
    for (const call of warn.mock.calls) {
      expect(String(call[0])).not.toContain("super-secret-plaintext");
    }
  });

  it("does not print the password on the init-path TTY flow", async () => {
    const tty = new RecordingTTY({
      isTTY: true,
      responses: ["another-secret-pw-1", "another-secret-pw-1"],
    });

    const stdoutSpy = vi.spyOn(process.stdout, "write").mockReturnValue(true);
    const stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true);

    try {
      const result = await resolveInitPassword({ env: {}, tty });
      expect(result).toBe("another-secret-pw-1");
    } finally {
      stdoutSpy.mockRestore();
      stderrSpy.mockRestore();
    }

    for (const call of stdoutSpy.mock.calls) {
      expect(String(call[0])).not.toContain("another-secret-pw-1");
    }
    for (const call of stderrSpy.mock.calls) {
      expect(String(call[0])).not.toContain("another-secret-pw-1");
    }
  });
});
