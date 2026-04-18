import { Entry } from "@napi-rs/keyring";

import { KeychainBackendError } from "./errors.js";

export interface KeychainBackend {
  get(service: string, account: string): string | null;
  set(service: string, account: string, password: string): void;
  delete(service: string, account: string): boolean;
}

export class NapiKeychainBackend implements KeychainBackend {
  public get(service: string, account: string): string | null {
    try {
      const entry = new Entry(service, account);
      return entry.getPassword();
    } catch (err) {
      if (isNoEntryError(err)) {
        return null;
      }
      throw new KeychainBackendError(
        `keychain backend read failed for ${service}/${account}`,
        err,
      );
    }
  }

  public set(service: string, account: string, password: string): void {
    try {
      const entry = new Entry(service, account);
      entry.setPassword(password);
    } catch (err) {
      throw new KeychainBackendError(
        `keychain backend write failed for ${service}/${account}`,
        err,
      );
    }
  }

  public delete(service: string, account: string): boolean {
    try {
      const entry = new Entry(service, account);
      return entry.deleteCredential();
    } catch (err) {
      if (isNoEntryError(err)) {
        return false;
      }
      throw new KeychainBackendError(
        `keychain backend delete failed for ${service}/${account}`,
        err,
      );
    }
  }
}

function isNoEntryError(err: unknown): boolean {
  if (err instanceof Error) {
    const msg = err.message.toLowerCase();
    return msg.includes("no entry") || msg.includes("no matching entry") || msg.includes("not found");
  }
  return false;
}

export class InMemoryKeychainBackend implements KeychainBackend {
  private readonly store = new Map<string, string>();

  public get(service: string, account: string): string | null {
    const key = this.keyOf(service, account);
    return this.store.has(key) ? (this.store.get(key) ?? null) : null;
  }

  public set(service: string, account: string, password: string): void {
    this.store.set(this.keyOf(service, account), password);
  }

  public delete(service: string, account: string): boolean {
    return this.store.delete(this.keyOf(service, account));
  }

  private keyOf(service: string, account: string): string {
    return `${service}\u0000${account}`;
  }
}
