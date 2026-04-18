import { VaultIdentifierError } from "./errors.js";

const SECRET_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_-]*$/;
const MAX_SECRET_NAME_LENGTH = 128;

export function assertValidSecretName(name: unknown): asserts name is string {
  if (typeof name !== "string") {
    throw new VaultIdentifierError("secret name must be a string");
  }
  if (name.length === 0) {
    throw new VaultIdentifierError("secret name must not be empty");
  }
  if (name.length > MAX_SECRET_NAME_LENGTH) {
    throw new VaultIdentifierError(
      `secret name exceeds maximum length of ${String(MAX_SECRET_NAME_LENGTH)}`,
    );
  }
  if (!SECRET_NAME_PATTERN.test(name)) {
    throw new VaultIdentifierError(
      "secret name must match ^[A-Za-z_][A-Za-z0-9_-]*$ (no whitespace, control chars, or path separators)",
    );
  }
}

export function isValidSecretName(name: unknown): name is string {
  try {
    assertValidSecretName(name);
    return true;
  } catch {
    return false;
  }
}
