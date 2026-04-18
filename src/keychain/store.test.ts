import { describe, expect, it } from "vitest";

import { InMemoryKeychainBackend } from "./backend.js";
import { KeychainNoItemError } from "./errors.js";
import { createMasterPasswordStore, SERVICE_NAME, ACCOUNT_NAME } from "./store.js";

describe("master password store", () => {
  it("stores, reads, and deletes a password via the backend (round-trip)", () => {
    const backend = new InMemoryKeychainBackend();
    const store = createMasterPasswordStore(backend);

    store.storeMasterPassword("correct-horse-battery-staple");
    expect(store.readMasterPassword()).toBe("correct-horse-battery-staple");
    expect(backend.get(SERVICE_NAME, ACCOUNT_NAME)).toBe("correct-horse-battery-staple");

    store.deleteMasterPassword();
    expect(() => store.readMasterPassword()).toThrow(KeychainNoItemError);
  });

  it("throws KeychainNoItemError when no item is stored", () => {
    const store = createMasterPasswordStore(new InMemoryKeychainBackend());
    expect(() => store.readMasterPassword()).toThrow(KeychainNoItemError);
  });

  it("treats an empty string from the backend as 'no item' (defense-in-depth)", () => {
    const backend = new InMemoryKeychainBackend();
    backend.set(SERVICE_NAME, ACCOUNT_NAME, "");
    const store = createMasterPasswordStore(backend);
    expect(() => store.readMasterPassword()).toThrow(KeychainNoItemError);
  });

  it("delete on a missing item throws KeychainNoItemError", () => {
    const store = createMasterPasswordStore(new InMemoryKeychainBackend());
    expect(() => store.deleteMasterPassword()).toThrow(KeychainNoItemError);
  });

  it("uses the configured service and account names", () => {
    const backend = new InMemoryKeychainBackend();
    const store = createMasterPasswordStore(backend, "custom-svc", "custom-acct");
    store.storeMasterPassword("abc");
    expect(backend.get("custom-svc", "custom-acct")).toBe("abc");
    expect(backend.get(SERVICE_NAME, ACCOUNT_NAME)).toBeNull();
  });
});
