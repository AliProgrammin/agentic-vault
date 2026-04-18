import type { KeychainBackend } from "./backend.js";
import { NapiKeychainBackend } from "./backend.js";
import { KeychainNoItemError } from "./errors.js";

export const SERVICE_NAME = "secretproxy";
export const ACCOUNT_NAME = "master";

export interface MasterPasswordStore {
  storeMasterPassword(password: string): void;
  readMasterPassword(): string;
  deleteMasterPassword(): void;
}

export function createMasterPasswordStore(
  backend: KeychainBackend,
  service: string = SERVICE_NAME,
  account: string = ACCOUNT_NAME,
): MasterPasswordStore {
  return {
    storeMasterPassword(password: string): void {
      backend.set(service, account, password);
    },
    readMasterPassword(): string {
      const value = backend.get(service, account);
      if (value === null || value === "") {
        throw new KeychainNoItemError();
      }
      return value;
    },
    deleteMasterPassword(): void {
      const deleted = backend.delete(service, account);
      if (!deleted) {
        throw new KeychainNoItemError();
      }
    },
  };
}

let defaultStore: MasterPasswordStore | null = null;

function getDefaultStore(): MasterPasswordStore {
  if (defaultStore === null) {
    defaultStore = createMasterPasswordStore(new NapiKeychainBackend());
  }
  return defaultStore;
}

export function storeMasterPassword(password: string): void {
  getDefaultStore().storeMasterPassword(password);
}

export function readMasterPassword(): string {
  return getDefaultStore().readMasterPassword();
}

export function deleteMasterPassword(): void {
  getDefaultStore().deleteMasterPassword();
}
