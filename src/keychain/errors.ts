export class KeychainError extends Error {
  public override readonly name: string = "KeychainError";
  public readonly code: string;

  public constructor(code: string, message: string, cause?: unknown) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.code = code;
  }
}

export class KeychainNoItemError extends KeychainError {
  public override readonly name = "KeychainNoItemError";

  public constructor(message = "no keychain item found for secretproxy master password") {
    super("KEYCHAIN_NO_ITEM", message);
  }
}

export class KeychainBackendError extends KeychainError {
  public override readonly name = "KeychainBackendError";

  public constructor(message: string, cause?: unknown) {
    super("KEYCHAIN_BACKEND", message, cause);
  }
}

export class VaultLockedError extends Error {
  public override readonly name = "VaultLockedError";
  public readonly code = "VAULT_LOCKED";

  public constructor(
    message = "vault is locked: master password not available. Run `secretproxy init` or set SECRETPROXY_PASSWORD.",
  ) {
    super(message);
  }
}

export class WeakPasswordError extends Error {
  public override readonly name = "WeakPasswordError";
  public readonly code = "WEAK_PASSWORD";

  public constructor(minLength: number) {
    super(`master password must be at least ${String(minLength)} characters`);
  }
}

export class PasswordMismatchError extends Error {
  public override readonly name = "PasswordMismatchError";
  public readonly code = "PASSWORD_MISMATCH";

  public constructor(message = "password confirmation did not match") {
    super(message);
  }
}
