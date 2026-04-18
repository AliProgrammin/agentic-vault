export class VaultError extends Error {
  public override readonly name: string = "VaultError";
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export class WrongPasswordError extends VaultError {
  public override readonly name = "WrongPasswordError";

  public constructor(message = "vault authentication failed: wrong password or tampered vault") {
    super("WRONG_PASSWORD", message);
  }
}

export class VaultFormatError extends VaultError {
  public override readonly name = "VaultFormatError";

  public constructor(message: string) {
    super("VAULT_FORMAT", message);
  }
}

export class VaultIdentifierError extends VaultError {
  public override readonly name = "VaultIdentifierError";

  public constructor(message: string) {
    super("INVALID_IDENTIFIER", message);
  }
}

export class VaultClosedError extends VaultError {
  public override readonly name = "VaultClosedError";

  public constructor(message = "vault handle is closed") {
    super("VAULT_CLOSED", message);
  }
}

export class VaultExistsError extends VaultError {
  public override readonly name = "VaultExistsError";

  public constructor(path: string) {
    super("VAULT_EXISTS", `vault already exists at ${path}`);
  }
}
